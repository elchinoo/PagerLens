"""Sealed boot (APGKIT_SEALED): the app starts sealed, serves only /_seal/* and the health checks, then works after the operator unseals it.

Each case runs in a fresh interpreter because the sealed state is decided when `pagerlens.api` is imported."""
import json
import os
import subprocess
import sys

import pytest
from apgkit import sealed as sealing

PASSPHRASE = "correct-horse-battery-staple-9"  # pragma: allowlist secret

SCRIPT = r'''
import json, os, sys
from fastapi.testclient import TestClient
from apgkit import sealed as sealing
from apgkit.config import database_url, read_secret
from pagerlens import api, core

mode = sys.argv[1]
out = {}
if mode == "stubbed":      # no database: the callbacks are replaced by a recorder
    calls = []
    api.sealed._callbacks[:] = [lambda s, p: calls.append("cb")]
with TestClient(api.app) as c:
    out["sealed_state"] = api.sealed.state
    out["dashboard_sealed"] = c.get("/api/dashboard").status_code
    out["mcp_sealed"] = c.post("/mcp/", json={}).status_code
    out["healthz_sealed"] = c.get("/healthz").status_code
    out["config_sealed"] = [database_url() == "", read_secret("PAGERLENS_OIDC_CLIENT_SECRET") == ""]
    key = c.get("/_seal/key").json()["public_key"]
    r = c.post("/_seal/unseal", json=sealing.make_envelope(key, os.environ["PASSPHRASE"]))
    out["unseal"] = r.status_code
    out["state"] = api.sealed.state
    out["config_unsealed"] = [database_url() != "", read_secret("PAGERLENS_OIDC_CLIENT_SECRET") == "from-the-blob"]
    out["dashboard_unsealed"] = c.get("/api/dashboard").status_code
    if mode == "stubbed":
        out["calls"] = calls
    else:
        out["vault_unlocked"] = core.vault.is_unlocked()
print(json.dumps(out))
'''


def _run(mode, secrets):
    env = {k: v for k, v in os.environ.items() if k not in {"DATABASE_URL", "DB_EXTERNAL_DSN", "PSQL_CONNECTION_STRING", "TEST_DATABASE_URL"}}
    env.update({"APGKIT_SEALED": sealing.seal(secrets, PASSPHRASE), "PASSPHRASE": PASSPHRASE, "PAGERLENS_HOUSEKEEPING": "false",
                "PAGERLENS_API_KEY_FILE": "/nonexistent/key", "PAGERLENS_ENCRYPTION_KEY_FILE": "/nonexistent/key", "PAGERLENS_ALLOW_ANONYMOUS": "",
                "PAGERLENS_OIDC_ISSUER": ""})
    done = subprocess.run([sys.executable, "-I", "-c", SCRIPT, mode], env=env, capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_sealed_app_is_closed_until_unsealed_and_reads_secrets_late():
    out = _run("stubbed", {"DATABASE_URL": "postgresql://u:p@127.0.0.1:1/none", "PAGERLENS_OIDC_CLIENT_SECRET": "from-the-blob"})
    assert out["sealed_state"] == "sealed"
    assert out["dashboard_sealed"] == 503 and out["mcp_sealed"] == 503
    assert out["healthz_sealed"] == 200
    assert out["config_sealed"] == [True, True]            # nothing is readable before the operator unseals
    assert out["unseal"] == 200 and out["state"] == "unsealed"
    assert out["config_unsealed"] == [True, True]
    assert out["calls"] == ["cb"]
    assert out["dashboard_unsealed"] != 503


def test_without_a_blob_nothing_changes():
    from pagerlens import api
    assert api.sealed.enabled is False                      # the test process itself runs unsealed: nothing changed for dev and tests
    assert sealing.active() is api.sealed


def test_oidc_client_secret_is_not_read_at_import(monkeypatch):
    import importlib

    from pagerlens import core
    monkeypatch.setenv("PAGERLENS_OIDC_ISSUER", "https://idp.example.test")
    monkeypatch.delenv("PAGERLENS_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("PAGERLENS_OIDC_CLIENT_SECRET_FILE", "/nonexistent/secret")
    fed = core._federation()
    assert fed.enabled and fed.rp._secret is not None      # confidential-capable even though no secret exists yet
    monkeypatch.setenv("PAGERLENS_OIDC_CLIENT_SECRET", "late")
    assert fed.rp._secret() == "late"
    importlib.invalidate_caches()


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="set TEST_DATABASE_URL to run DB tests")
def test_unseal_migrates_unlocks_the_vault_and_serves():
    out = _run("real", {"DATABASE_URL": os.environ.get("TEST_DATABASE_URL", ""), "PAGERLENS_OIDC_CLIENT_SECRET": "from-the-blob"})
    assert out["dashboard_sealed"] == 503 and out["healthz_sealed"] == 200
    assert out["unseal"] == 200 and out["state"] == "unsealed"
    assert out["vault_unlocked"] is True
    assert out["dashboard_unsealed"] != 503
