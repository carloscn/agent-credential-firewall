"""Local test upstream for the Milestone 0 demo.

Answers GET /profile only when it receives the expected bearer token, and
echoes the Authorization header into a field the profile does not allowlist,
so the demo shows the gateway dropping it.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

EXPECTED = "Bearer " + os.environ["DEMO_TOKEN"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        authorized = self.headers.get("Authorization") == EXPECTED
        status = 200 if self.path == "/profile" and authorized else 401
        body = json.dumps(
            {
                "user": "demo",
                "authenticated": authorized,
                "debug_authorization_echo": self.headers.get("Authorization"),
            }
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
