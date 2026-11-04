import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pagerlens")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate", help="apply SQL migrations")
    sub.add_parser("seed", help="load the demo fleet, runbooks and a healthy baseline")
    sim = sub.add_parser("simulate", help="break the demo fleet with a scenario and open an incident")
    sim.add_argument("scenario", nargs="?", help="scenario key (omit to list them)")
    inv = sub.add_parser("investigate", help="investigate an incident from the terminal")
    inv.add_argument("incident_id", type=int)
    inv.add_argument("--no-memory", action="store_true")
    inv.add_argument("--mode", choices=["rules", "llm", "hybrid", "aidb", "aidb_hybrid"], default="rules")
    inv.add_argument("--account", default=None, help="chat account id, or 'env' (LLM_BASE_URL, LLM_API_KEY, LLM_CHAT_MODEL)")
    ev = sub.add_parser("eval", help="before/after learning evaluation on the simulator (resets demo telemetry)")
    ev.add_argument("--mode", choices=["rules", "llm", "hybrid"], default="rules")
    ev.add_argument("--account", default=None, help="chat account id, or 'env'; AI modes spend provider credit")
    tn = sub.add_parser("tuning", help="propose-and-approve tuning of PagerLens' own database (never touches monitored systems)")
    tn.add_argument("action", choices=["scan", "list"], help="scan: look for improvements and record proposals; list: show them")
    sub.add_parser("reembed", help="resize the vector columns to EMBEDDING_DIM if needed and re-embed incidents and runbooks")
    sub.add_parser("serve", help="run the API + MCP server")
    rk = sub.add_parser("rotate-key", help="replace the vault data key and re-encrypt every stored secret (asks for the admin password)")
    rk.add_argument("--confirm", action="store_true", help="required: restart every other replica afterwards")
    sub.add_parser("adopt-rowmacs", help="sign existing provider accounts, runbooks, the embedding choice, sessions and API tokens that have no "
                                         "row MAC (trusts the database as it is now; asks for the admin password)")
    sub.add_parser("aidb-setup", help="OPERATOR: set up AIDB mode (pipelines, evidence-view purpose, SQL tools, agent, seals); idempotent. Needs an admin "
                                      "connection string (PAGERLENS_AIDB_ADMIN_DSN or a hidden prompt, never stored) and the admin password")
    ast = sub.add_parser("aidb-status", help="report AIDB mode: pipelines, knowledge bases, agent, purpose, denials and whether the sealed definitions still verify")
    ast.add_argument("--json", action="store_true", help="print the full report as JSON")
    sub.add_parser("reset-admin", help="forget the admin password and delete stored provider keys (recovery)")
    sub.add_parser("start", help="container entrypoint: migrate, optionally seed (AUTO_SEED=true), serve")
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        from .migrate import run

        applied = run()
        print("applied:", ", ".join(applied) if applied else "nothing (up to date)")
    elif args.cmd == "seed":
        _seed()
    elif args.cmd == "simulate":
        from . import simulator
        from .db import connect_vector

        if not args.scenario:
            for s in simulator.catalog():
                print(f"{s['key']:20} {s['title']}: {s['blurb']}")
            return 0
        with connect_vector() as conn:
            info = simulator.trigger(conn, args.scenario)
            conn.commit()
        print(f"incident #{info['incident_id']} opened on {info['service']}: {info['title']}")
    elif args.cmd == "investigate":
        from . import incidents, investigator
        from .db import connect_vector

        with connect_vector() as conn:
            cfg = _chat_cfg(conn, args.mode, args.account)
            run_id = investigator.investigate(conn, args.incident_id, mode=args.mode, use_memory=not args.no_memory,
                                              account=args.account, chat_cfg=cfg)
            print(incidents.get_incident(conn, args.incident_id)["report"]["markdown"])
        print(f"\n(run #{run_id})")
    elif args.cmd == "tuning":
        from . import tuning
        from .db import connect

        with connect() as conn:
            if args.action == "scan":
                out = tuning.scan(conn, "cli")
                print(f"{len(out['created'])} new proposal(s), {out['skipped']} already known")
                for note in out["notes"]:
                    print("note:", note)
            else:
                for r in tuning.list_proposals(conn):
                    print(f"#{r['id']:<4} {r['status']:9} {r['source']:10} {r['target']:14} {r['statement'][:90]}")
    elif args.cmd == "eval":
        from . import evaluate
        from .db import connect_vector

        with connect_vector() as conn:
            r = evaluate.run(conn, mode=args.mode, chat_cfg=_chat_cfg(conn, args.mode, args.account))
        for phase in ("cold", "warm"):
            print(f"{phase}: top-1 {r[phase + '_top1']:.0%}, top-3 {r[phase + '_top3']:.0%}")
        if args.mode != "rules":
            print(f"tokens used: {r['tokens']['prompt']} prompt, {r['tokens']['completion']} completion")
    elif args.cmd == "reembed":
        return _reembed()
    elif args.cmd == "rotate-key":
        return _rotate_key(args.confirm)
    elif args.cmd == "adopt-rowmacs":
        return _adopt_rowmacs()
    elif args.cmd == "aidb-setup":
        return _aidb_setup()
    elif args.cmd == "aidb-status":
        return _aidb_status(args.json)
    elif args.cmd == "reset-admin":
        from . import auth
        from .db import connect

        with connect() as conn:
            auth.reset_admin(conn)
        print("admin password, vault and stored provider keys were cleared; the setup code flow is active again. Row MACs were under the "
              "old data key: after setting the new admin password run `pagerlens adopt-rowmacs`")
    elif args.cmd == "serve":
        _serve()
    elif args.cmd == "start":
        return _start()
    return 0


def _chat_cfg(conn, mode: str, account: str | None):
    if mode == "rules":
        return None
    if not account:
        raise SystemExit("the AI modes need --account <id|env>")
    from . import accounts

    cfg = accounts.chat_config_for(conn, account if account == "env" else int(account))
    cfg.api_key()  # a stored key is locked outside the web app (vault); use 'env' for the CLI
    return cfg


def _ensure_runbooks() -> None:
    """Runbooks are reference material, not demo data: make sure they exist even when the Lab is never used.
    Embedding problems (provider down, size mismatch) are logged and the row stored without a vector; they never stop startup."""
    from . import simulator
    from .db import connect_vector

    try:
        with connect_vector() as conn:
            added = simulator.seed_runbooks(conn)
            conn.commit()
    except Exception as exc:  # noqa: BLE001 - the web app must come up; runbooks are retried on the next start
        print(f"runbook seeding skipped: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return
    if added:
        print(f"runbooks added: {added}")


def _reconcile_embeddings() -> None:
    """Resize the vector columns when EMBEDDING_DIM changed, then fill in missing embeddings. Never stops startup."""
    from .db import connect_vector
    from .migrate import reconcile_embedding_dim

    try:
        with connect_vector() as conn:
            r = reconcile_embedding_dim(conn)
    except Exception as exc:  # noqa: BLE001 - startup must survive any embedding or index problem
        print(f"embedding reconciliation skipped: {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return
    if r["refused"]:
        print(f"embedding size not applied: {r['refused']}", file=sys.stderr)
    elif r["skipped"] and r["skipped"].startswith("the embedding account"):
        print(f"embeddings left as they are: {r['skipped']}", file=sys.stderr)
    elif r["changed"] or any(r["embedded"].values()) or r["deferred"]:
        print(f"embeddings: {r['dimension']} dimensions, re-embedded {r['embedded']}"
              + (" (continuing in the background)" if r["deferred"] else "")
              + (f", stopped early: {r['failed']}" if r["failed"] else ""))


def _rotate_key(confirm: bool) -> int:
    """Replace the vault data key. The admin password comes from a prompt (or PAGERLENS_ADMIN_PASSWORD for automation); nothing
    secret is logged. Other replicas hold the old key in memory and must be restarted afterwards."""
    import getpass
    import logging
    import os

    from . import accounts, core, rowmac
    from .db import connect

    if not confirm:
        print("rotate-key replaces the data key and re-encrypts every stored secret; re-run with --confirm. "
              "Restart every other replica afterwards.", file=sys.stderr)
        return 2
    with connect() as conn:
        if not core.vault.is_initialized(conn):
            print("there is no vault to rotate", file=sys.stderr)
            return 1
        password = None
        if core.vault.has_password_wrap(conn):
            password = os.environ.get("PAGERLENS_ADMIN_PASSWORD") or getpass.getpass("admin password: ")
            if not core.vault.unlock_with_password(conn, password):
                print("wrong admin password", file=sys.stderr)
                return 1
        elif not core.vault.try_unlock_with_platform_secret(conn):
            print("the vault is locked and no platform secret is set", file=sys.stderr)
            return 1
        conn.commit()
        accounts.upgrade_stored_keys(conn)
        try:
            counts = rowmac.rotate_data_key(conn, password)      # re-encrypts, then re-signs the rows that verified
        except Exception as exc:  # noqa: BLE001 - nothing was changed: the rotation is one transaction
            print(f"rotation failed, nothing was changed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    logging.getLogger("pagerlens.security").warning("vault data key rotated from the command line; re-encrypted %s", counts)
    print(f"data key rotated; re-encrypted: {counts or 'nothing'}. Restart every other replica now.")
    return 0


def _adopt_rowmacs() -> int:
    """Sign every covered row that has no row MAC (a database that existed before row MACs). It TRUSTS THE DATABASE AS IT IS AT THIS
    MOMENT: run it once, after migrating, on a database you believe untampered. The admin password comes from a prompt (or
    PAGERLENS_ADMIN_PASSWORD for automation), never from an argument; nothing secret is printed."""
    import getpass
    import os

    from . import core, rowmac
    from .db import connect

    with connect() as conn:
        if not core.vault.is_initialized(conn):
            print("there is no vault yet: nothing can be signed (row MACs are checked only while the vault is unlocked)", file=sys.stderr)
            return 1
        if core.vault.has_password_wrap(conn) and not core.vault.is_unlocked():
            password = os.environ.get("PAGERLENS_ADMIN_PASSWORD") or getpass.getpass("admin password: ")
            if not core.vault.unlock_with_password(conn, password):
                print("wrong admin password", file=sys.stderr)
                return 1
        elif not core.vault.is_unlocked() and not core.vault.try_unlock_with_platform_secret(conn):
            print("the vault is locked and no platform secret is set", file=sys.stderr)
            return 1
        conn.commit()
        counts = rowmac.adopt(conn)
    print("signed rows without a MAC: " + ", ".join(f"{t} {n}" for t, n in counts.items()) +
          ". This trusted the database as it was now; rows written by anything else from here on are ignored.")
    return 0


def _open_vault(conn, *, optional: bool = False) -> bool:
    """Unlock the vault for a command that must read or write seals: the platform secret, else the admin password (a prompt, or
    PAGERLENS_ADMIN_PASSWORD for automation; never an argument). With `optional` an empty answer means 'skip'."""
    import getpass
    import os

    from . import core

    if not core.vault.is_initialized(conn):
        print("there is no vault yet: nothing can be sealed or verified (create the admin password in the web app first)", file=sys.stderr)
        return False
    if core.vault.is_unlocked():
        return True
    if core.vault.try_unlock_with_platform_secret(conn):
        conn.commit()
        return True
    if core.vault.has_password_wrap(conn):
        password = os.environ.get("PAGERLENS_ADMIN_PASSWORD") or getpass.getpass(
            "admin password" + (" (Enter to skip verification)" if optional else "") + ": ")
        if optional and not password:
            return False
        if core.vault.unlock_with_password(conn, password):
            conn.commit()
            return True
        print("wrong admin password", file=sys.stderr)
        return False
    print("the vault is locked and no platform secret is set", file=sys.stderr)
    return False


def _aidb_setup() -> int:
    """OPERATOR command. The administrator's connection string comes from PAGERLENS_AIDB_ADMIN_DSN or a hidden prompt; it is used for this
    command only: never stored, logged, written to a file or put in the app's environment. Idempotent: a second run reports `unchanged`."""
    import getpass
    import os

    import psycopg
    from psycopg.rows import dict_row

    from . import aidb_mode, aidb_setup, core
    from .db import connect
    from .migrate import run as migrate_run

    migrate_run()          # the evidence views are created by the app's migrations (as the table owner)
    with connect() as conn:
        role = conn.execute("SELECT current_user AS u").fetchone()["u"]
        if not _open_vault(conn):
            return 1
    dsn = os.environ.get("PAGERLENS_AIDB_ADMIN_DSN") or getpass.getpass("administrator connection string for this database (not stored): ")
    if not dsn.strip():
        print("no administrator connection string given", file=sys.stderr)
        return 1
    try:
        admin = psycopg.connect(dsn.strip(), row_factory=dict_row)
    except psycopg.Error as exc:
        print(f"could not connect with the administrator connection string: {type(exc).__name__}", file=sys.stderr)
        return 1
    finally:
        del dsn
    try:
        rep = aidb_setup.setup(admin, vault=core.vault, runtime_role=role, gateway=aidb_setup.Gateway.from_env())
    except (aidb_setup.aidb.AidbError, psycopg.Error) as exc:
        admin.rollback()
        print(f"aidb-setup failed: {type(exc).__name__}: {str(exc).strip().splitlines()[0][:300] if str(exc).strip() else ''}", file=sys.stderr)
        return 1
    finally:
        admin.close()
    aidb_mode.reset()
    for what, action in rep.steps:
        print(f"  {what}: {action}")
    for p in rep.problems:
        print(f"  PROBLEM: {p}", file=sys.stderr)
    print("changed something" if rep.changed else "nothing changed (already set up)")
    return 1 if rep.problems else 0


def _aidb_status(as_json: bool) -> int:
    import json

    from . import aidb_mode
    from .db import connect

    with connect() as conn:
        verified = _open_vault(conn, optional=True)
        rep = aidb_mode.status(conn)
    rep["verification"]["note"] = "" if verified else "verification skipped: the vault is locked"
    problems = list(rep.get("problems", [])) + [f"{d['kind']} {d['name']}: {d['problem']} (changed outside the app)" for d in rep["verification"]["drift"]]
    if as_json:
        print(json.dumps(rep, indent=2, default=str))
        return 1 if problems else 0
    a = rep["aidb"]
    print(f"AIDB: {'available, version ' + a['version'] if a['available'] else 'not available (' + a['reason'] + ')'}")
    print(f"retrieval backend requested: {rep['requested_backend']}" + (f"; in effect: {rep['retrieval']}" if "retrieval" in rep else ""))
    if a["available"]:
        for p in rep["pipelines"] if isinstance(rep.get("pipelines"), list) else []:
            print(f"  pipeline {p['name']}: {p['mode']}, {p['embedded_rows']}/{p['source_rows']} rows embedded, lag {p['lag']}, errors {p['record_errors']}")
        for ag in rep["agents"] if isinstance(rep.get("agents"), list) else []:
            print(f"  agent {ag['name']}: model {ag['model']}, purpose {ag['purpose']}, tools {len(ag['tools'] or [])}")
        dn = rep.get("denials", {})
        print(f"  purpose denials (24 h): {dn.get('count', dn.get('unavailable', '?'))}")
    v = rep["verification"]
    print("  seals: " + ("all definitions verify" if v["checked"] and not v["drift"] else v["note"] or v["reason"] if not v["checked"] else "DRIFT"))
    for p in problems:
        print(f"  PROBLEM: {p}")
    return 1 if problems else 0


def _reembed() -> int:
    from .db import connect_vector
    from .migrate import reconcile_embedding_dim

    try:
        with connect_vector() as conn:
            r = reconcile_embedding_dim(conn, defer_above=None, force=True, strict=True)
    except Exception as exc:  # noqa: BLE001 - strict mode: the provider probe failed before anything changed
        print(f"reembed failed (no changes were made): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if r["refused"]:
        print(f"reembed refused: {r['refused']}", file=sys.stderr)
        return 1
    if r["skipped"]:
        print(f"reembed skipped: {r['skipped']} (re-embed from the admin API after signing in, or switch embeddings back "
              "to the environment)", file=sys.stderr)
        return 1
    if r["failed"]:
        print(f"reembed stopped early: {r['failed']} (re-run later; rows without a vector use text search)", file=sys.stderr)
        return 1
    done = ", ".join(f"{n} {t}s" for t, n in r["embedded"].items())
    print(f"done: vector size {r['dimension']}" + (f" (was {r['previous']})" if r["changed"] else "") + f", re-embedded {done}")
    return 0


def _seed() -> None:
    from . import simulator
    from .db import connect_vector

    with connect_vector() as conn:
        simulator.baseline(conn)
        conn.commit()
        n = conn.execute("SELECT count(*) AS n FROM runbook").fetchone()["n"]
    print(f"demo fleet ready: {len(simulator.FLEET)} services, {n} runbooks, healthy baseline telemetry")


def _serve() -> None:
    import os

    import uvicorn

    from .config import bind_host

    # Trust X-Forwarded-* only from the proxy (default: this machine), never "*": see PAGERLENS_FORWARDED_ALLOW_IPS in the guide.
    uvicorn.run("pagerlens.api:app", host=bind_host(), port=int(os.environ.get("PORT", "8000")), proxy_headers=True,
                forwarded_allow_ips=os.environ.get("PAGERLENS_FORWARDED_ALLOW_IPS", "127.0.0.1"))


def prepare_database() -> int:
    """Everything `start` does before serving: migrations, embedding reconciliation, runbooks and the optional demo seed.
    With sealed boot this runs after the operator unseals (the database URL is inside the sealed blob), not at process start."""
    import os

    from .migrate import run

    try:
        applied = run()  # db.connect retries with backoff, so a waking database is tolerated
    except Exception as exc:  # noqa: BLE001 - surface a readable cause, then fail the container
        print(f"startup failed while migrating: {exc}\n"
              "Check that the database is reachable. If the error mentions an extension, enable it first "
              "(it may need elevated rights), e.g. on AgentPG:\n"
              "  agentpg extensions create <instance-id> vector\n"
              "  agentpg extensions create <instance-id> pg_trgm", file=sys.stderr)
        return 1
    print("migrations applied:", ", ".join(applied) if applied else "none (up to date)")
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    _reconcile_embeddings()
    _ensure_runbooks()
    if os.environ.get("AUTO_SEED", "").lower() in {"1", "true", "yes"}:
        from .db import connect

        with connect() as conn:
            empty = conn.execute("SELECT NOT EXISTS (SELECT 1 FROM service) AS e").fetchone()["e"]
        if empty:
            _seed()
    return 0


def _start() -> int:
    """Zero-touch startup for sandboxes where the user cannot run separate migrate/seed jobs."""
    from apgkit import sealed as sealing

    # Sealed: the database URL does not exist yet, so the server starts first and the app prepares the database when it is unsealed.
    if not sealing.Sealed.from_env().enabled:
        code = prepare_database()
        if code:
            return code
    _serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
