#!/usr/bin/env python3
"""Actual CLI/REPL subprocess verification using a simulated loopback RPC only."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid

REPO = Path(__file__).resolve().parents[1]
SDK = 0x123400000
OFFSET = 0x4CC0
ADDRESS = SDK + OFFSET
DATA = bytes(range(32))
TOKEN = "simulated-rpc-credential-never-save"
SEQUENCE = ["status", "query", "read", "query", "status"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = (args.output or REPO / "verification/artifacts" / (
        "ns2-rpc-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])).resolve()
    output.mkdir(parents=True, exist_ok=False)
    results, events = [], []
    with tempfile.TemporaryDirectory(prefix="m1mu2-rpc-e2e-", dir="/tmp") as temporary:
        work = Path(temporary).resolve()
        isolated = work / "isolated"
        shutil.copytree(REPO / "m1mu2", isolated / "m1mu2", ignore=shutil.ignore_patterns("__pycache__"))
        root = work / "fixture-session"
        root.mkdir()
        report_path = root / "switch2/memory/report.json"
        mode = {"name": "ok", "queries": 0}
        mapping = {"address": SDK, "size": 0x10000, "permissions": 5, "type": 3,
                   "attributes": 0, "ipcReferences": 0, "deviceReferences": 0}

        def mutate(relative, field, value):
            path = root / relative
            current = json.loads(path.read_text())
            current[field] = value
            write(path, current)

        class Server(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                command = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                events.append(command)
                assert self.path == "/" and self.headers["Authorization"] == "Bearer " + TOKEN
                name = command["command"]
                if name == "status":
                    assert command == {"command": "status"}
                    # Match the real bridge: no live platform/session identity fields.
                    response = {"ready": mode["name"] != "unready", "calls": len(events)}
                    if mode["name"] == "stale":
                        response["session"] = "wrong-session"
                elif name == "query":
                    assert command == {"command": "query", "address": ADDRESS}
                    mode["queries"] += 1
                    response = {**mapping, "address": str(mapping["address"]), "size": str(mapping["size"])}
                    if mode["name"] == "non-rx" or mode["name"] == "mapping-change" and mode["queries"] == 2:
                        response["permissions"] = 3
                    if mode["name"] == "short-region":
                        response["size"] = str(OFFSET + 16)
                    if mode["name"] == "malformed-region":
                        response["permissions"] = True
                    if mode["name"] == "metadata-before" and mode["queries"] == 1:
                        mutate("qualification.json", "completed", "changed")
                    if mode["name"] == "metadata-after" and mode["queries"] == 2:
                        mutate("qualification.json", "completed", "changed")
                elif name == "read":
                    assert command == {"command": "read", "address": ADDRESS, "length": 32}
                    if mode["name"] == "close":
                        self.close_connection = True
                        return
                    data = DATA[:-1] if mode["name"] == "short-read" else b"x" * 32 if mode["name"] == "wrong-bytes" else DATA
                    response = {"data": base64.b64encode(data).decode()}
                    if mode["name"] == "bad-base64":
                        response["data"] = "@@@"
                    if mode["name"] == "missing-data":
                        response = {}
                else:
                    raise AssertionError("Unsafe/unexpected RPC command: " + name)
                body = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Server)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def reset(name="ok"):
            mode.update(name=name, queries=0)
            write(root / "connection.json", {"port": server.server_port, "token": TOKEN,
                  "addresses": {"platform": 2, "session": root.name, "sdk": SDK}})
            write(root / "system-access.json", {"session": root.name, "error": "simulated FS failure",
                  "stages": [{"name": "acquire", "state": "failed"}], "finished": "fixture"})
            write(root / "qualification.json", {"platform": 2, "verified": True, "completed": "fixture",
                  "scratchRestored": True, "importRestored": True})
            write(root / "switch2/app/qualification.json", {"session": root.name, "verified": True,
                  "cleanedUp": True, "completed": "fixture"})
            write(root / "switch2/app/memory-map.json", {"session": root.name, "complete": True,
                  "regions": [mapping]})
            write(root / "switch2/app/verified-instructions.json", {"session": root.name, "sdk": SDK,
                  "code": {str(OFFSET): DATA.hex() + "c0035fd6"}})
            write(root / "switch2/current-acquisition.json", {"session": root.name, "report": str(report_path)})
            write(report_path, {"session": root.name, "finished": "fixture", "cleanedUp": True,
                  "retainedMemory": {"operations": []}, "memoryControl": {"operations": []}})

        def run(name, command, expected, success=True, stdin=None):
            start = len(events)
            proc = subprocess.run([sys.executable, "-m", "m1mu2", "ns2", *command],
                                  input=stdin, cwd=isolated, capture_output=True, text=True, timeout=25)
            assert (proc.returncode == 0) == success, (name, proc.returncode, proc.stderr, proc.stdout)
            observed = events[start:]
            assert [item["command"] for item in observed] == expected, (name, observed, proc.stderr)
            if success:
                parsed = [json.loads(line) for line in proc.stdout.splitlines()] if stdin is not None else json.loads(proc.stdout)
            else:
                parsed = None
            results.append({"name": name, "passed": True, "returncode": proc.returncode,
                            "argv": command, "stdin": stdin, "requests": observed,
                            "stdout": proc.stdout, "stderr": proc.stderr})
            print("PASS", name)
            return parsed

        cli = ["rpc-probe", "--session-dir", str(root), "--captures", str(output / "captures")]
        repl = ["repl", "--session-dir", str(root), "--captures", str(output / "captures")]
        try:
            reset()
            plan = run("dry-run-zero-requests", cli, [])
            assert plan["address"] == ADDRESS and plan["length"] == 32 and not plan["sysmoduleAccessProven"]
            local_failures = [
                ("session-binding", "system-access.json", "session", "wrong-session"),
                ("baseline-unqualified", "qualification.json", "verified", False),
                ("scratch-not-restored", "qualification.json", "scratchRestored", False),
                ("import-not-restored", "qualification.json", "importRestored", False),
                ("app-not-clean", "switch2/app/qualification.json", "cleanedUp", False),
                ("instruction-identity", "switch2/app/verified-instructions.json", "sdk", SDK + 16),
                ("instruction-missing", "switch2/app/verified-instructions.json", "code", {}),
                ("map-incomplete", "switch2/app/memory-map.json", "complete", False),
                ("acquisition-not-clean", str(report_path), "cleanedUp", False),
                ("acquisition-pending", str(report_path), "memoryControl", {"pending": {"operation": "read"}}),
                ("acquisition-unfinished", str(report_path), "retainedMemory", {"operations": [{"started": "fixture"}]}),
                ("busy-stage", "system-access.json", "stages", [{"name": "acquire", "state": "running"}]),
            ]
            for name, relative, field, value in local_failures:
                reset(); mutate(relative, field, value)
                run(name + "-refused-before-transport", cli + ["--live"], [], False)
            reset()
            run("arbitrary-address-not-exposed", cli + ["--live", "--address", "0x123"], [], False)
            for name, expected in [
                ("unready", ["status"]), ("stale", ["status"]),
                ("non-rx", ["status", "query"]), ("short-region", ["status", "query"]),
                ("malformed-region", ["status", "query"]), ("metadata-before", ["status", "query"]),
                ("short-read", ["status", "query", "read"]), ("wrong-bytes", ["status", "query", "read"]),
                ("bad-base64", ["status", "query", "read"]), ("missing-data", ["status", "query", "read"]),
                ("close", ["status", "query", "read"]),
                ("mapping-change", ["status", "query", "read", "query"]), ("metadata-after", SEQUENCE),
            ]:
                reset(name)
                run(name + "-refused-without-retry", cli + ["--live"], expected, False)
            reset()
            saved = run("fixed-sdk-read-success-simulated", cli + ["--live"], SEQUENCE)
            assert saved["sha256"] == sha(DATA) and saved["matchesVerifiedInstructions"]
            assert saved["scope"] == "application-sdk" and not saved["sysmoduleAccessProven"]
            receipt = Path(saved["receipt"])
            metadata = json.loads(receipt.read_text())
            binary = receipt.parent / metadata["binFile"]
            assert binary.read_bytes() == DATA and metadata["expectedSha256"] == sha(DATA)
            run("saved-sdk-bytes-offline-replay", ["replay", "--capture", str(receipt)], [])
            reset()
            answers = run("repl-dry-rpc-zero-requests", repl, [], stdin="rpc-probe\nquit\n")
            assert answers[1]["mode"] == "dry-run"
            answers = run("repl-live-rpc-success-simulated", repl + ["--live"], SEQUENCE,
                          stdin="rpc-probe\nquit\n")
            assert answers[1]["sha256"] == sha(DATA)
            reset("close")
            run("repl-ambiguous-read-halts-next-line", repl + ["--live"], ["status", "query", "read"],
                False, stdin="rpc-probe\nrpc-probe\nquit\n")
            reset()
            run("repl-rpc-arbitrary-arguments-rejected", repl + ["--live"], [], False,
                stdin="rpc-probe 0x123 4096\nrpc-probe\n")
            write(output / "transcript.json", {"evidence": "simulated-loopback-only", "cases": results})
            summary = {"schema": "m1mu2.ns2.rpc.e2e.v1", "passed": True, "cases": len(results),
                       "evidence": "simulated HTTP fixture; no hardware contact",
                       "scope": "fixed 32-byte application SDK read; no sysmodule proof",
                       "entrypoint": "python -m m1mu2 ns2 rpc-probe; python -m m1mu2 ns2 repl",
                       "repeat": "python verification/ns2_rpc_e2e.py --output NEW_DIRECTORY",
                       "captureReceipt": str(receipt), "fireRedDependenciesAbsent": True,
                       "artifactSha256": {str(p.relative_to(output)): sha(p.read_bytes())
                                          for p in output.rglob("*") if p.is_file()},
                       "sourceSha256": {str(p.relative_to(isolated)): sha(p.read_bytes())
                                        for p in (isolated / "m1mu2").glob("*.py")}}
            summary["sourceSha256"]["verification/ns2_rpc_e2e.py"] = sha(Path(__file__).read_bytes())
            write(output / "receipt.json", summary)
            for p in output.rglob("*"):
                if p.is_file():
                    assert TOKEN.encode() not in p.read_bytes(), "Fixture credential leaked"
            print(json.dumps({"receipt": str(output / "receipt.json"), "cases": len(results)}))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
