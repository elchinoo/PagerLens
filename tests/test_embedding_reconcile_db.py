"""A database created at one embedding size, started with another (the fleet's EMBEDDING_DIM change), against a disposable Postgres."""
import logging
import os

import pytest

if not os.environ.get("TEST_DATABASE_URL"):
    pytest.skip("set TEST_DATABASE_URL to run DB tests", allow_module_level=True)

from pgvector import Vector  # noqa: E402
from psycopg.errors import DataException  # noqa: E402

from pagerlens import (  # noqa: E402
    auth,
    cli,
    core,
    incidents,
    ingest,
    investigator,
    migrate,
    retrieval,
    simulator,
    vault,
)
from pagerlens.db import connect, connect_vector  # noqa: E402
from pagerlens.embeddings import EmbeddingError, hash_embed  # noqa: E402

H = {"X-PagerLens-CSRF": "1"}
PASSWORD = "correct-horse-battery"  # pragma: allowlist secret


class Provider:
    """Stub for the embedding provider: vectors of the configured size, or an outage."""

    def __init__(self, monkeypatch):
        self.down = False
        self.calls = 0
        self.texts: list[str] = []
        monkeypatch.setattr(retrieval, "embed", self)

    def __call__(self, texts, cfg=None):
        self.calls += 1
        if self.down:
            raise EmbeddingError("embeddings endpoint returned HTTP 503: upstream unavailable")
        self.texts += texts
        return [hash_embed(t, (cfg or retrieval.embedcfg.from_env()).dim) for t in texts]


@pytest.fixture
def provider(monkeypatch):
    return Provider(monkeypatch)


@pytest.fixture
def db768(monkeypatch, client):
    """A database created when the dimension was 768, with the runbooks and one incident in it; the env then says 1536."""
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    for v in ("PAGERLENS_API_KEY", "PAGERLENS_ALLOW_ANONYMOUS", "PAGERLENS_ENCRYPTION_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("PAGERLENS_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("LLM_API_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv("EMBEDDING_DIM", "768")
    core.auth.limiter.clear()
    core.local._setup_code = None
    vault.lock()
    with connect() as c:
        c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        c.commit()
    migrate.run()
    with connect_vector() as c:
        simulator.seed_runbooks(c)
        simulator.trigger(c, "bad_deploy")
        c.commit()
    monkeypatch.setenv("EMBEDDING_DIM", "1536")
    migrate._job.update(state="idle", done=0, total=0, message="")
    return None


def dims(conn):
    return {t: migrate.column_dim(conn, t) for t in ("incident", "runbook")}


def nulls(conn):
    return {t: conn.execute(f"SELECT count(*) AS n FROM {t} WHERE embedding IS NULL").fetchone()["n"]  # noqa: S608
            for t in ("incident", "runbook")}


def sizes(conn, table):
    return {r["d"] for r in conn.execute(f"SELECT vector_dims(embedding) AS d FROM {table} WHERE embedding IS NOT NULL")}  # noqa: S608


def start(monkeypatch):
    monkeypatch.setattr(cli, "_serve", lambda: None)
    return cli._start()


# ---- the incident --------------------------------------------------------------------------------

def test_old_insert_crashes_exactly_like_the_incident(db768, provider):
    """What the old seed_runbooks did: embed first, then INSERT a 1536-vector into the 768-dim column."""
    with connect_vector() as c, pytest.raises(DataException, match="expected 768 dimensions, not 1536"):
        c.execute("INSERT INTO runbook (title, category, body, embedding) VALUES ('x','x','x',%s)",
                  (Vector(hash_embed("x", 1536)),))


def test_ensure_runbooks_no_longer_crashes_on_a_768_column_with_1536_embeddings(db768, provider):
    with connect_vector() as c:
        c.execute("DELETE FROM runbook")    # a database that still needs its runbooks (the crashing path)
        c.commit()
    cli._ensure_runbooks()                  # used to raise DataException and exit the container
    with connect_vector() as c:
        assert c.execute("SELECT count(*) AS n FROM runbook").fetchone()["n"] == len(simulator.RUNBOOKS)
        assert nulls(c)["runbook"] == len(simulator.RUNBOOKS)       # stored without vectors, text search still works
        assert dims(c)["runbook"] == 768
        assert retrieval.search_runbooks(c, "database connection pool saturation")[0]["title"]


def test_seed_runbooks_does_not_embed_rows_that_already_exist(db768, provider):
    with connect_vector() as c:
        assert simulator.seed_runbooks(c) == 0
    assert provider.calls == 0


# ---- startup -----------------------------------------------------------------------------------

def test_startup_reconciles_768_to_1536(db768, provider, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="pagerlens.embeddings")
    assert start(monkeypatch) == 0
    with connect_vector() as c:
        assert dims(c) == {"incident": 1536, "runbook": 1536}
        assert nulls(c) == {"incident": 0, "runbook": 0}
        assert sizes(c, "runbook") == {1536} and sizes(c, "incident") == {1536}
        assert c.execute("SELECT count(*) AS n FROM pg_indexes WHERE indexname IN ('incident_embedding','runbook_embedding')"
                         ).fetchone()["n"] == 2
        assert retrieval.search_runbooks(c, "memory leak oom")[0]["title"]
        st = migrate.embedding_status(c)
    assert st["recorded"] == {"model": "builtin-hash", "dim": 1536, "complete": True}
    assert not st["needs_reembedding"]
    assert any("resized" in r.message for r in caplog.records)


def test_second_start_is_a_noop(db768, provider, monkeypatch):
    assert start(monkeypatch) == 0
    calls = provider.calls
    assert start(monkeypatch) == 0
    assert provider.calls == calls
    with connect_vector() as c:
        r = migrate.reconcile_embedding_dim(c)
    assert not r["changed"] and not any(r["embedded"].values()) and not r["deferred"]


def test_startup_with_the_provider_down_comes_up_with_null_embeddings_then_retries(db768, provider, monkeypatch, caplog):
    provider.down = True
    assert start(monkeypatch) == 0
    failures = [r for r in caplog.records if "HTTP 503" in r.getMessage()]
    assert len(failures) == 1               # ONE clear line, not one per row
    with connect_vector() as c:
        assert dims(c) == {"incident": 1536, "runbook": 1536}
        assert nulls(c)["runbook"] == len(simulator.RUNBOOKS) and nulls(c)["incident"] == 1
        assert retrieval.search_runbooks(c, "tls certificate expired")       # text search still answers
        assert migrate.embedding_status(c)["needs_reembedding"]
    provider.down = False                   # the next start retries
    assert start(monkeypatch) == 0
    with connect_vector() as c:
        assert nulls(c) == {"incident": 0, "runbook": 0}


def test_dimension_above_the_hnsw_limit_is_refused_and_the_old_columns_kept(db768, provider, monkeypatch, capsys):
    monkeypatch.setenv("EMBEDDING_DIM", "3072")
    before = provider.calls
    with connect_vector() as c:
        r = migrate.reconcile_embedding_dim(c)
    assert "2000" in r["refused"] and not r["changed"]
    assert start(monkeypatch) == 0          # still comes up
    assert "embedding size not applied" in capsys.readouterr().err
    with connect_vector() as c:
        assert dims(c) == {"incident": 768, "runbook": 768}
        assert nulls(c)["runbook"] == 0     # old data untouched
        assert migrate.embedding_status(c)["indexable"] is False
    assert provider.calls == before


def test_large_corpus_changes_columns_at_startup_and_reembeds_in_the_background(db768, provider):
    with connect_vector() as c:
        r = migrate.reconcile_embedding_dim(c, defer_above=2)       # 13 rows > 2
        assert r["deferred"] and r["changed"]
        assert dims(c) == {"incident": 1536, "runbook": 1536}
    migrate.wait_background()
    with connect_vector() as c:
        assert nulls(c) == {"incident": 0, "runbook": 0}
        assert migrate.embedding_status(c)["recorded"]["complete"] is True
    assert migrate.job_status()["state"] == "done"


def test_incident_vectors_are_recomputed_from_stored_text_including_signatures(db768, provider):
    monkey_dim = None  # noqa: F841 - documents that the incident was investigated at 768 first
    with connect_vector() as c:
        iid = c.execute("SELECT id FROM incident").fetchone()["id"]
        investigator.investigate(c, iid)
        incidents.resolve(c, iid, "bad_deploy")
        c.commit()
    provider.texts.clear()
    with connect_vector() as c:
        migrate.reconcile_embedding_dim(c)
    incident_texts = [t for t in provider.texts if t.startswith("checkout-api: ")]
    assert incident_texts and all(" | " in t for t in incident_texts)       # symptom plus the error signatures, as when resolved
    assert any("PromoCalculator" in t for t in incident_texts)


# ---- retrieval during a mismatch -----------------------------------------------------------------

def test_retrieval_during_a_mismatch_does_not_raise(db768, provider, caplog):
    with connect_vector() as c:
        assert dims(c)["runbook"] == 768                       # reconciliation has not happened
        rows = retrieval.search_runbooks(c, "database connection pool saturation", limit=3)
        assert rows and "pool" in rows[0]["title"].lower()     # text-only results
        assert retrieval.similar_incidents(c, "checkout errors after deploy") == []
        retrieval.remember_incident(c, c.execute("SELECT id FROM incident").fetchone()["id"], ["x"])
        out = ingest.raise_alert(c, "checkout-api", "HighErrorRate", summary="5xx above 5%")   # the webhook path
        assert out["incident_id"]
        c.commit()
    assert any("does not match" in r.getMessage() for r in caplog.records)


def test_retrieval_with_the_provider_down_degrades_instead_of_raising(db768, provider, monkeypatch):
    monkeypatch.setenv("EMBEDDING_DIM", "768")
    provider.down = True
    with connect_vector() as c:
        assert retrieval.search_runbooks(c, "sudden traffic spike")
        assert retrieval.similar_incidents(c, "x") == []


# ---- CLI and API ------------------------------------------------------------------------------

def test_reembed_cli_resizes_and_reembeds_everything(db768, provider, capsys):
    assert cli.main(["reembed"]) == 0
    assert "vector size 1536" in capsys.readouterr().out
    with connect_vector() as c:
        assert dims(c) == {"incident": 1536, "runbook": 1536} and nulls(c) == {"incident": 0, "runbook": 0}
    provider.texts.clear()
    assert cli.main(["reembed"]) == 0           # explicit: re-embeds all rows even at the right size (a new model)
    assert len(provider.texts) == len(simulator.RUNBOOKS) + 1


def test_reembed_cli_fails_fast_and_changes_nothing_when_the_provider_is_down(db768, provider, capsys):
    provider.down = True
    assert cli.main(["reembed"]) == 1
    assert "no changes were made" in capsys.readouterr().err
    with connect_vector() as c:
        assert dims(c) == {"incident": 768, "runbook": 768} and nulls(c)["runbook"] == 0


def test_status_api_flags_needs_reembedding_and_the_admin_action_fixes_it(db768, provider, client):
    with connect() as c:
        auth.set_admin_password(c, PASSWORD)
    assert client.post("/api/login", json={"password": PASSWORD}, headers=H).status_code == 200
    st = client.get("/api/embeddings/status").json()
    assert st["mismatch"] and st["needs_reembedding"] and st["columns"]["runbook"] == 768
    assert st["configured"]["dimension"] == 1536
    assert client.post("/api/embeddings/reembed", headers=H).json() == {"started": True}
    migrate.wait_background()
    st = client.get("/api/embeddings/status").json()
    assert not st["needs_reembedding"] and st["columns"] == {"incident": 1536, "runbook": 1536}
    assert st["job"]["state"] == "done"
