"""A tiny OpenAI-compatible server for the AIDB integration tests: chat completions answer from a script (a reply per call, first in
first out, default 'plain answer'), embeddings return a constant vector. It records every request."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class Fake:
    def __init__(self, port: int = 0):
        self.log: list[tuple[str, str | None, dict]] = []
        self.script: list[str] = []
        self.delay = 0.0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
                outer.log.append((self.path, self.headers.get("authorization"), body))
                if outer.delay:
                    time.sleep(outer.delay)
                if self.path.endswith("/chat/completions"):
                    text = outer.script.pop(0) if outer.script else "plain answer"
                    out = {"id": "x", "object": "chat.completion", "created": 0, "model": body.get("model"),
                           "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
                else:
                    inp = body["input"] if isinstance(body["input"], list) else [body["input"]]
                    out = {"object": "list", "model": body.get("model"), "usage": {"prompt_tokens": 1, "total_tokens": 1},
                           "data": [{"object": "embedding", "index": i, "embedding": [0.1] * 8} for i, _ in enumerate(inp)]}
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = HTTPServer(("0.0.0.0", port), Handler)           # nosec B104: test server, reachable from the container
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
