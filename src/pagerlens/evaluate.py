"""Before/after evaluation of the learning loop against the simulator's ground truth.

Cold pass: every scenario is investigated with no memory, then resolved with its true cause (teaching the memory).
Warm pass: the same scenarios again with memory on. Reports top-1 / top-3 accuracy and the rank of the true cause.
In llm/hybrid mode it calls your chat provider (18 investigations) and spends credit.
Warning: this resets the demo telemetry and removes the incidents it created when it finishes.
"""
from . import incidents, investigator, simulator


def _rank(conn, run_id: int, category: str) -> int | None:
    row = conn.execute("SELECT rank FROM hypothesis WHERE run_id=%s AND category=%s ORDER BY rank LIMIT 1",
                       (run_id, category)).fetchone()
    return row["rank"] if row else None


def run(conn, *, mode: str = "rules", chat_cfg=None, progress=print) -> dict:
    created: list[int] = []
    out: dict = {"cold": [], "warm": [], "mode": mode}
    try:
        for phase, memory, seed in (("cold", False, 7), ("warm", True, 11)):  # warm replays the shapes with different noise
            for key, sc in simulator.SCENARIOS.items():
                info = simulator.trigger(conn, key, seed=seed)
                conn.commit()
                created.append(info["incident_id"])
                run_id = investigator.investigate(conn, info["incident_id"], mode=mode, use_memory=memory, chat_cfg=chat_cfg)
                rank = _rank(conn, run_id, sc.category)
                out[phase].append({"scenario": key, "truth": sc.category, "rank": rank})
                progress(f"{phase:5} {key:20} truth={sc.category:20} rank={rank}")
                incidents.resolve(conn, info["incident_id"], sc.category, f"simulated {key}")
                conn.commit()
        usage = conn.execute("SELECT coalesce(sum((usage->>'prompt_tokens')::int),0) AS p, coalesce(sum((usage->>'completion_tokens')::int),0) AS c "
                             "FROM run WHERE incident_id = ANY(%s)", (created,)).fetchone()
        out["tokens"] = {"prompt": usage["p"], "completion": usage["c"]}
        for phase in ("cold", "warm"):
            rows = out[phase]
            out[f"{phase}_top1"] = sum(1 for r in rows if r["rank"] == 1) / len(rows)
            out[f"{phase}_top3"] = sum(1 for r in rows if r["rank"] and r["rank"] <= 3) / len(rows)
    finally:
        for iid in created:
            conn.execute("DELETE FROM incident WHERE id=%s", (iid,))
        conn.commit()
    return out
