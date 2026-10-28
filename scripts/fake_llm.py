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


def chat_reply(body: dict) -> dict:
    """The assistant message for one chat-completions request."""
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
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)  # loopback only, on purpose
    print(f"[fake-llm] {BANNER}; listening on http://127.0.0.1:{args.port}/v1")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
