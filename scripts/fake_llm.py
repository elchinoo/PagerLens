#!/usr/bin/env python3
"""DEMO STAND-IN, NOT A REAL MODEL.

A tiny OpenAI-compatible server (POST /v1/chat/completions, POST /v1/embeddings, GET /v1/models) for recording and
rehearsing PagerLens's AI investigation without a provider key or any network access. It listens on loopback only,
needs nothing but the Python standard library and is fully deterministic.

What it does, so nobody mistakes it for intelligence:
* chat: the first turn of an investigation asks for the read-only tools (service_overview, metrics_overview,
  error_signatures, recent_deploys) on the alerting service; the second turn answers with a JSON hypothesis picked by a
  fixed keyword table over the tool results and cites the observation ids it was shown. A plain "reply OK" request
  gets "OK".
* ask: when the request offers the Ask PagerLens tools (list_incidents, get_incident, database_health ...), it answers three
  plain-English questions deterministically BY ACTUALLY CALLING those tools, so a recording is reproducible and the server's
  citation check has real, verifiable [incident #N] / [evidence #N] / [runbook #N] markers to verify:
    "Why is checkout-api failing?"    list_incidents -> get_incident -> get_evidence + search_runbooks -> answer
    "Have we seen this before?"       list_incidents -> get_incident -> similar_incidents -> answer
    "What is slow in the database?"   database_health + list_services + list_incidents -> slow_queries per service -> answer
  It honours `tool_choice: "required"` (a request that requires a tool gets a tool call even for a question it does not know), and
  `--reject-tool-choice` makes it answer 400 to such requests so the client's retry-without path can be rehearsed.
  Any other question gets one honest line saying the stand-in only knows those three. The wording is a template filled from the
  tool results: it is not reasoning.
* embeddings: a signed feature-hashing vector (lexical, not semantic), of the requested `dimensions` (default 768).

With a real model the investigation reads the same on screen; only the wording and the reasoning differ.

Use (PagerLens reads these through its environment account; loopback providers from the environment are trusted):

    python scripts/fake_llm.py --port 8099 &
    LLM_BASE_URL=http://127.0.0.1:8099/v1 LLM_API_KEY=demo LLM_CHAT_MODEL=demo-chat EMBEDDING_MODEL=demo-embed \\
        pagerlens serve
"""
import argparse
import hashlib
import itertools
import json
import math
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REJECT_TOOL_CHOICE = False      # --reject-tool-choice: answer 400 to a request carrying tool_choice, like some providers do
BANNER = "DEMO STAND-IN: deterministic fake model, not an AI"
TOOLS_FIRST = ("service_overview", "metrics_overview", "error_signatures", "recent_deploys")

# (keyword regex over the tool results, category). First match wins; order matters.
KEYWORDS = [
    (re.compile(r'"deploys": \[\{'), "bad_deploy", "A release was deployed shortly before the errors began"),
    (re.compile(r"acquiring connection|connection pool|too many connections", re.I), "db_saturation",
     "The database connection pool is saturated"),
    (re.compile(r"OutOfMemory|heap space|OOMKilled", re.I), "resource_exhaustion", "The service is running out of memory"),
    (re.compile(r"x509|certificate", re.I), "expired_certificate", "A TLS certificate is expired or invalid"),
    (re.compile(r"timed out|returned HTTP 5", re.I), "dependency_outage", "A dependency of the service is failing"),
]

_TOKEN = re.compile(r"[a-z0-9]+")


def hash_embed(text: str, dim: int) -> list[float]:
    vec = [0.0] * dim
    tokens = _TOKEN.findall(text.lower())
    for tok in tokens + [f"{a}_{b}" for a, b in itertools.pairwise(tokens)]:
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        vec[h % dim] += 1.0 if (h >> 63) & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _text(content) -> str:
    return content if isinstance(content, str) else json.dumps(content)


# --- Ask PagerLens (conversational diagnostics) ---------------------------------------------------------------------------
ASK_TOOLS = {"list_incidents", "get_incident", "database_health", "similar_incidents", "search_runbooks", "slow_queries"}
_FENCE = re.compile(r"<untrusted_data>\n(.*)\n</untrusted_data>", re.S)
_SERVICE = re.compile(r"\b([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\b")
_NOTE = f"({BANNER}: a template filled from the tool results, not reasoning.)"


def _tool_call(n: int, name: str, args: dict) -> dict:
    return {"id": f"call_{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _ask_state(messages: list) -> tuple[str, dict]:
    """The question being answered and what the tools returned for it: {tool name: [payload, ...]} in call order."""
    asking = max((i for i, m in enumerate(messages) if m.get("role") == "user"
                  and not _text(m.get("content")).startswith(("Answer now", "Correction:"))), default=-1)
    question = _text(messages[asking].get("content")) if asking >= 0 else ""
    names, got = {}, {}
    for m in messages[asking + 1:]:
        for c in m.get("tool_calls") or []:
            names[c.get("id")] = (c.get("function") or {}).get("name")
        if m.get("role") == "tool":
            found = _FENCE.search(_text(m.get("content")))
            try:
                payload = json.loads(found.group(1)) if found else {}
            except ValueError:
                payload = {}
            got.setdefault(names.get(m.get("tool_call_id")), []).append(payload)
    return question, got


def _pick_incident(listing: dict) -> dict | None:
    rows = listing.get("incidents") or []
    return next((r for r in rows if r.get("status") != "resolved"), rows[0] if rows else None)


def _known(q: str) -> bool:
    return bool(("slow" in q and re.search(r"database|quer|sql", q)) or re.search(r"seen (this|it|that)? ?before|happened before|similar", q)
                or "fail" in q or "why" in q)


def ask_reply(body: dict) -> dict:
    question, got = _ask_state(body.get("messages") or [])
    q = question.lower()
    reply = lambda text: {"role": "assistant", "content": text}  # noqa: E731
    calls = lambda *specs: {"role": "assistant", "content": None,  # noqa: E731
                            "tool_calls": [_tool_call(i, n, a) for i, (n, a) in enumerate(specs, 1)]}
    if body.get("tool_choice") == "required" and not got and not _known(q):
        return calls(("list_services", {}))            # a required lookup is honoured even when the question is not one it knows
    if "slow" in q and re.search(r"database|quer|sql", q):
        if not got:
            return calls(("database_health", {"limit": 5}), ("list_services", {}), ("list_incidents", {"limit": 10}))
        health, services = (got.get("database_health") or [{}])[0], ((got.get("list_services") or [{}])[0].get("services") or [])
        if "slow_queries" not in got and len(got) < 4:
            pick = [s["name"] for s in services if s.get("open_incidents")] or [s["name"] for s in services]
            return calls(*[("slow_queries", {"service": n}) for n in pick[:4]]) if pick else reply("No services are monitored yet. " + _NOTE)
        cite = {i.get("service"): i.get("cite") for i in reversed((got.get("list_incidents") or [{}])[0].get("incidents") or [])
                if i.get("status") != "resolved"}
        lines = []
        for r in got.get("slow_queries") or []:
            for f in r.get("queries") or []:
                lines.append(f"query {f['queryid']} in {r.get('service')} went from {f['baseline_ms']:g} ms to {f['current_ms']:g} ms "
                             f"(x{f['ratio']:g}) {cite.get(r.get('service'), '')}".strip())
        head = (f"In the monitored services: {'; '.join(lines)}." if lines else "No monitored service reports a statement that got slower.")
        tq = health.get("top_queries") or {}
        own = (f"PagerLens's own database: slowest statement {tq['queries'][0]['queryid']} averages {tq['queries'][0]['mean_ms']:g} ms."
               if tq.get("available") and tq.get("queries") else
               f"PagerLens's own database statistics are not available here ({tq.get('reason', 'no reason given')}).")
        tun, adv = health.get("tuner") or {}, health.get("advisor") or {}
        tail = (f"The tuner has {len(tun.get('recommendations') or [])} recommendation(s) and the advisor "
                f"{len(adv.get('suggestions') or [])} index hint(s)" if tun.get("available") or adv.get("available") else
                "The tuner and the advisor are not available on this database")
        return reply(f"{head} {own} {tail}; {health.get('open_tuning_proposals', 0)} tuning proposal(s) wait in the Tuning tab. {_NOTE}")
    if re.search(r"seen (this|it|that)? ?before|happened before|similar", q):
        if not got:
            return calls(("list_incidents", {"limit": 3}))
        cur = _pick_incident((got.get("list_incidents") or [{}])[0])
        if cur is None:
            return reply("There are no incidents yet, so there is nothing to compare. " + _NOTE)
        if "get_incident" not in got:
            return calls(("get_incident", {"incident_id": cur["id"]}))
        inc = got["get_incident"][0]
        if "similar_incidents" not in got:
            return calls(("similar_incidents", {"text": f"{inc.get('service')}: {inc.get('title')} {inc.get('symptom') or ''}"[:400]}))
        sim = (got["similar_incidents"][0].get("incidents") or [])
        if not sim:
            return reply(f"No resolved incident looks like {inc.get('cite')} yet: this may be the first time, or earlier ones were never "
                         f"marked with a cause. {_NOTE}")
        parts = [f"{s['cite']} {s['title']} ({s['service']}), resolved as {s['root_cause_category']} (similarity {s['similarity']:g})" for s in sim[:3]]
        return reply(f"Yes. {inc.get('cite')} looks like {len(sim)} earlier incident(s): {'; '.join(parts)}. {_NOTE}")
    if "fail" in q or "why" in q:
        service = (_SERVICE.search(q) or [None, None])[1]
        if not got:
            return calls(("list_incidents", {"limit": 3, **({"service": service} if service else {})}))
        cur = _pick_incident((got.get("list_incidents") or [{}])[0])
        if cur is None:
            return reply(f"I found no incident for {service or 'any service'}, so there is nothing to explain. {_NOTE}")
        if "get_incident" not in got:
            return calls(("get_incident", {"incident_id": cur["id"]}))
        inc = got["get_incident"][0]
        hyp = (inc.get("hypotheses") or [None])[0]
        if hyp is None:
            return reply(f"{inc.get('cite')} ({inc.get('service')}) has not been investigated yet, so there is no ranked cause to read. "
                         f"Ask an investigator to run one. {_NOTE}")
        ev = (hyp.get("evidence") or [None])[0]
        if "get_evidence" not in got and "search_runbooks" not in got:
            return calls(*([("get_evidence", {"evidence_id": int(re.search(r"#(\d+)", ev["cite"]).group(1))})] if ev else []),
                         ("search_runbooks", {"query": f"{hyp.get('title')} {inc.get('service')}", "category": hyp.get("category")}))
        seen_ev = (got.get("get_evidence") or [None])[0]
        rb = ((got.get("search_runbooks") or [{}])[0].get("runbooks") or [None])[0]
        text = (f"{inc.get('service')} is failing in {inc.get('cite')}: the top-ranked cause is \"{hyp['title']}\" "
                f"(score {hyp['score']:.0%}, {hyp['source']}).")
        if seen_ev:
            text += f" Evidence {seen_ev['cite']} ({seen_ev['source']}): {str(seen_ev['summary']).rstrip('.')}."
        if rb:
            text += f" Suggested manual steps: runbook {rb['cite']} \"{rb['title']}\"."
        return reply(f"{text} {_NOTE}")
    return reply("This demo stand-in only knows three questions: why a service is failing, whether we have seen this before, and what is "
                 "slow in the database. A real model would answer anything. " + _NOTE)


def chat_reply(body: dict) -> dict:
    """The assistant message for one chat-completions request."""
    if ASK_TOOLS <= {(t.get("function") or {}).get("name") for t in body.get("tools") or []}:
        return ask_reply(body)
    messages = body.get("messages") or []
    last_user = next((_text(m.get("content")) for m in reversed(messages) if m.get("role") == "user"), "")
    if not body.get("tools") and "single word OK" in last_user:
        return {"role": "assistant", "content": "OK"}
    brief = next((_text(m.get("content")) for m in messages if m.get("role") == "user"), "")
    service = (re.search(r"Alerting service: ([a-z0-9-]+)", brief) or [None, "checkout-api"])[1]
    results = [_text(m.get("content")) for m in messages if m.get("role") == "tool"]
    if body.get("tools") and not results:
        calls = [{"id": f"call_{i}", "type": "function",
                  "function": {"name": name, "arguments": json.dumps({"service": service})}}
                 for i, name in enumerate(TOOLS_FIRST, 1)]
        return {"role": "assistant", "content": None, "tool_calls": calls}
    evidence = "\n".join(results)
    ids = sorted({int(i) for i in re.findall(r'"observation_id": (\d+)', evidence)})
    category, why = next(((c, w) for pattern, c, w in KEYWORDS if pattern.search(evidence)),
                         ("unknown", "The evidence does not point to one cause"))
    answer = {"summary": f"{why}. ({BANNER}.)",
              "hypotheses": [{"category": category, "suspect": service, "title": f"{why} ({service})",
                              "explanation": f"{why}; the cited observations show the change and the errors. {BANNER}.",
                              "confidence": 0.8 if category != "unknown" else 0.2, "supports": ids[:4], "refutes": []}]}
    return {"role": "assistant", "content": json.dumps(answer)}


class Handler(BaseHTTPRequestHandler):
    server_version = "pagerlens-fake-llm"

    def _send(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):  # one short line per request, never request bodies
        print(f"[fake-llm] {self.command} {self.path.split('?')[0]}")

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            return self._send(200, {"object": "list", "data": [{"id": "demo-chat", "object": "model"},
                                                              {"id": "demo-embed", "object": "model"}]})
        self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):  # noqa: N802
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        except ValueError:
            return self._send(400, {"error": {"message": "invalid JSON"}})
        path = self.path.split("?")[0]
        if path.endswith("/embeddings"):
            inputs = body.get("input")
            inputs = inputs if isinstance(inputs, list) else [str(inputs or "")]
            dim = int(body.get("dimensions") or 768)
            data = [{"object": "embedding", "index": i, "embedding": hash_embed(str(t), dim)} for i, t in enumerate(inputs)]
            return self._send(200, {"object": "list", "model": body.get("model", "demo-embed"), "data": data,
                                    "usage": {"prompt_tokens": 1, "total_tokens": 1}})
        if path.endswith("/chat/completions"):
            if REJECT_TOOL_CHOICE and "tool_choice" in body:
                return self._send(400, {"error": {"message": "tool_choice is not supported by this model"}})
            msg = chat_reply(body)
            return self._send(200, {"id": "chatcmpl-demo", "object": "chat.completion", "created": int(time.time()),
                                    "model": body.get("model", "demo-chat"),
                                    "choices": [{"index": 0, "message": msg,
                                                 "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
                                    "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140}})
        self._send(404, {"error": {"message": "not found"}})


def main() -> None:
    ap = argparse.ArgumentParser(description=BANNER)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--reject-tool-choice", action="store_true", help="answer 400 to requests that carry tool_choice")
    args = ap.parse_args()
    global REJECT_TOOL_CHOICE
    REJECT_TOOL_CHOICE = args.reject_tool_choice
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)  # loopback only, on purpose
    print(f"[fake-llm] {BANNER}; listening on http://127.0.0.1:{args.port}/v1")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
