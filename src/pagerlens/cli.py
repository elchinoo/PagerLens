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
    inv.add_argument("--mode", choices=["rules", "llm", "hybrid"], default="rules")
    inv.add_argument("--account", default=None, help="chat account id, or 'env' (LLM_BASE_URL, LLM_API_KEY, LLM_CHAT_MODEL)")
    ev = sub.add_parser("eval", help="before/after learning evaluation on the simulator (resets demo telemetry)")
    ev.add_argument("--mode", choices=["rules", "llm", "hybrid"], default="rules")
    ev.add_argument("--account", default=None, help="chat account id, or 'env'; AI modes spend provider credit")
    sub.add_parser("serve", help="run the API + MCP server")
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
    elif args.cmd == "eval":
        from . import evaluate
        from .db import connect_vector

        with connect_vector() as conn:
            r = evaluate.run(conn, mode=args.mode, chat_cfg=_chat_cfg(conn, args.mode, args.account))
        for phase in ("cold", "warm"):
            print(f"{phase}: top-1 {r[phase + '_top1']:.0%}, top-3 {r[phase + '_top3']:.0%}")
        if args.mode != "rules":
            print(f"tokens used: {r['tokens']['prompt']} prompt, {r['tokens']['completion']} completion")
    elif args.cmd == "reset-admin":
        from . import auth
        from .db import connect

        with connect() as conn:
            auth.reset_admin(conn)
        print("admin password, vault and stored provider keys were cleared; the setup code flow is active again")
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

    uvicorn.run("pagerlens.api:app", host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8000")))


def _start() -> int:
    """Zero-touch startup for sandboxes where the user cannot run separate migrate/seed jobs."""
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
    if os.environ.get("AUTO_SEED", "").lower() in {"1", "true", "yes"}:
        from .db import connect

        with connect() as conn:
            empty = conn.execute("SELECT NOT EXISTS (SELECT 1 FROM service) AS e").fetchone()["e"]
        if empty:
            _seed()
    _serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
