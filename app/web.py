"""Request handler base for tls-peek's two local servers: the start page and the capture UI."""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# ui\ sits next to app\ in the source tree, and next to the modules inside the frozen exe.
UI_DIR = (Path(__file__).parent if getattr(sys, "frozen", False) else Path(__file__).parent.parent) / "ui"


class LocalHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, body, ctype="application/json", headers=()):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        """Blocks DNS rebinding: only accept requests addressed to our own origin."""
        port = self.server.server_address[1]
        ok = self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")
        if not ok:
            self.send(403, {"error": "bad host"})
        return ok

    def json_body(self):
        """The POSTed JSON. Requiring the JSON content type forces a CORS preflight, so other sites cannot post here."""
        if self.headers.get("Content-Type") != "application/json":
            raise ValueError("bad request")
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def send_static(self, path):
        """Serves /ui/NAME.js, .css or .svg. False when path is not one of those files."""
        m = re.fullmatch(r"/ui/([\w-]+\.(js|css|svg))", path)
        if not m or not (UI_DIR / m[1]).is_file():
            return False
        ctype = {"js": "text/javascript", "css": "text/css", "svg": "image/svg+xml"}[m[2]]
        self.send(200, (UI_DIR / m[1]).read_bytes(), ctype + "; charset=utf-8")
        return True
