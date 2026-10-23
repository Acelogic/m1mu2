"""Loopback-only, passive view of an explicitly selected Switch session."""
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import ns2


PAGE = Path(__file__).with_name("ns2_view.html")


def inventory(root):
    records = []
    for path in ns2.report_files(root):
        report = ns2.read_json(path)
        if report.get("session") != root.name:
            raise ValueError("Capture report belongs to another session")
        for row in ns2.capture_records(report, path, root):
            identity = str(path) + row["metadata"] + str(row.get("sha256"))
            row["id"] = hashlib.sha256(identity.encode()).hexdigest()
            row["name"] = Path(row["outputFile"]).name
            records.append(row)
    return records


def verified_bytes(root, capture_id):
    row = next((r for r in inventory(root) if r["id"] == capture_id), None)
    if row is None:
        raise ValueError("Unknown capture")
    if not row.get("complete") or not row.get("bytesVerified"):
        raise ValueError("Capture is incomplete or unverified")
    filename = ns2.inside(row["outputFile"], root)
    ns2.bounded(row["address"], row["length"])
    if filename.stat().st_size != row["length"]:
        raise ValueError("Capture length changed")
    with filename.open("rb") as stream:
        data = stream.read(row["length"] + 1)
    if len(data) != row["length"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError("Capture bytes changed")
    return row, data


def make_server(session_dir, port=8788):
    root = Path(session_dir).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Session directory required")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, code, data, mime="application/json"):
            if not isinstance(data, bytes):
                data = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            expected = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != expected:
                return self.respond(403, {"error": "Local access only"})
            url = urlsplit(self.path)
            try:
                if url.path == "/":
                    return self.respond(200, PAGE.read_bytes(), "text/html; charset=utf-8")
                if url.path == "/api/status":
                    return self.respond(200, ns2.local_status(root))
                if url.path == "/api/captures":
                    return self.respond(200, {"mode": "saved-evidence", "captures": inventory(root)})
                if url.path in {"/api/preview", "/api/download"}:
                    capture_id = parse_qs(url.query).get("id", [""])[0]
                    row, data = verified_bytes(root, capture_id)
                    if url.path == "/api/download":
                        return self.respond(200, data, "application/octet-stream")
                    return self.respond(200, {"name": row["name"], "address": row["address"],
                                             "length": len(data), "sha256": row["sha256"],
                                             "hex": data[:4096].hex(), "previewLength": min(len(data), 4096)})
                self.respond(404, {"error": "Unknown action"})
            except (ns2.Refusal, ValueError, OSError, KeyError, TypeError) as error:
                self.respond(409, {"error": str(error)})

        def do_POST(self):
            self.respond(405, {"error": "This viewer has no device or write operations"})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(session_dir, port=8788):
    server = make_server(session_dir, port)
    print(f"NS2 capture viewer: http://127.0.0.1:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
