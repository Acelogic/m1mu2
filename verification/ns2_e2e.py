#!/usr/bin/env python3
"""Subprocess/protocol E2E; loopback fixtures only, never hardware.

Run: python verification/ns2_e2e.py [--output NEW_DIRECTORY]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
ADDRESS = 0x123400000
DATA = bytes(range(256)) * 2
TOKEN = "fixture-only-credential-never-persist"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or REPO / "verification" / "artifacts" / (
        "ns2-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results, events = [], []
    with tempfile.TemporaryDirectory(prefix="m1mu2-e2e-", dir="/tmp") as temporary:
        work = Path(temporary).resolve()
        isolated = work / "isolated"
        shutil.copytree(REPO / "m1mu2", isolated / "m1mu2",
                        ignore=shutil.ignore_patterns("__pycache__"))
        # No vendored FireRed tree or dependencies exist in this package copy.
        session = work / "fixture-session"
        session.mkdir()
        report_file = session / "switch2" / "memory" / "report.json"
        prior = session / "prior.bin"
        prior.write_bytes(DATA)
        socket_path = session / "retained.sock"
        config = {"mode": "ok", "infoCalls": 0}

        def report():
            return {"session": session.name, "cases": [{"id": 1}],
                    "retainedMemory": {"ready": True, "zeroCountVerified": True,
                                       "corruptionCount": 1, "operations": [],
                                       "captures": [{"address": ADDRESS, "length": len(DATA),
                                                     "outputFile": str(prior), "sha256": digest(DATA)}]},
                    "memoryControl": {"ready": True, "socketPath": str(socket_path), "operations": []}}

        class HTTP(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                command = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                events.append({"transport": "http", "command": command})
                assert command == {"command": "status"}
                assert self.headers["Authorization"] == "Bearer " + TOKEN
                reply = {"ready": True, "platform": 2,
                         "session": "stale-session" if config["mode"] == "stale" else session.name}
                body = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class UNIX(socketserver.StreamRequestHandler):
            def handle(self):
                command = json.loads(self.rfile.readline())
                events.append({"transport": "unix", "command": command})
                if command == {"command": "retained-info"}:
                    config["infoCalls"] += 1
                    reply = {"ready": True, "steadyStateReliable": True, "requiresCorruption": False,
                             "session": session.name, "report": str(report_file), "corruptionCount": 1,
                             "controlAddress": ADDRESS + 0x10000, "dataOffset": 16}
                    if config["mode"] == "identity-change" and config["infoCalls"] > 1:
                        reply["controlAddress"] += 16
                    if config["mode"] == "info-mismatch":
                        reply["corruptionCount"] = 2
                    if config["mode"] == "became-busy":
                        write_json(session / "system-access.json", {"session": session.name,
                                   "stages": [{"name": "acquire", "state": "running"}]})
                else:
                    assert command == {"command": "retained-read", "address": ADDRESS, "length": 32}
                    if config["mode"] == "close":
                        return  # Ambiguous EOF after accepting the command: must not replay.
                    data = DATA[:31] if config["mode"] == "short" else DATA[:32]
                    capture = session / "response.bin"
                    capture.write_bytes(data)
                    reply = {"address": ADDRESS, "length": 32, "requiresCorruption": False,
                             "corruptionCount": 1, "outputFile": str(capture), "sha256": digest(data)}
                    if config["mode"] == "hash":
                        reply["sha256"] = "0" * 64
                    if config["mode"] == "escape":
                        reply["outputFile"] = str(work / "outside.bin")
                    if config["mode"] == "address":
                        reply["address"] += 1
                    # Real retained reads append to both collections and save the
                    # report before the endpoint sends its final response.
                    updated = json.loads(report_file.read_text())
                    saved_capture = {k: reply[k] for k in ["address", "length", "outputFile", "sha256"]}
                    updated["retainedMemory"]["captures"].append(saved_capture)
                    updated["retainedMemory"]["operations"].append(
                        {**reply, "command": "read", "started": "fixture", "finished": "fixture"})
                    write_json(report_file, updated)
                self.wfile.write(json.dumps(reply).encode() + b"\n")

        http = ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        unix = socketserver.ThreadingUnixStreamServer(str(socket_path), UNIX)
        for server in [http, unix]:
            threading.Thread(target=server.serve_forever, daemon=True).start()

        def reset(mode="ok"):
            config.update(mode=mode, infoCalls=0)
            prior.write_bytes(DATA)
            write_json(report_file, report())
            write_json(session / "connection.json", {"port": http.server_port, "token": TOKEN,
                       "addresses": {"session": session.name, "platform": 2}})
            write_json(session / "system-access.json", {"session": session.name, "verified": True,
                       "stages": [{"name": "retained", "state": "complete"}], "finished": "fixture"})
            write_json(session / "switch2" / "current-acquisition.json",
                       {"session": session.name, "report": str(report_file)})

        def run(name, command, success=True, expected=None, stdin=None):
            before = len(events)
            proc = subprocess.run([sys.executable, "-m", "m1mu2", "ns2", *command],
                                  cwd=isolated, capture_output=True, text=True, input=stdin, timeout=30)
            assert (proc.returncode == 0) == success, (name, proc.returncode, proc.stderr, proc.stdout)
            observed = events[before:]
            if expected is not None:
                assert [e["command"]["command"] for e in observed] == expected, (name, observed, proc.stderr)
            if stdin is not None and success:
                value = [json.loads(line) for line in proc.stdout.splitlines()]
            else:
                value = json.loads(proc.stdout if success else proc.stderr)
            results.append({"name": name, "passed": True, "returncode": proc.returncode,
                            "argv": command, "transport": observed,
                            "stdin": stdin, "stdout": proc.stdout, "stderr": proc.stderr})
            print("PASS", name)
            return value

        def terminal_repl(command):
            before = len(events)
            master, slave = pty.openpty()
            transcript = bytearray()
            proc = subprocess.Popen([sys.executable, "-m", "m1mu2", "ns2", *command],
                                    cwd=isolated, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
            os.close(slave)

            def receive_prompts(count):
                deadline = time.monotonic() + 15
                while transcript.count(b"ns2[DRY]> ") < count:
                    assert time.monotonic() < deadline, "Terminal REPL timed out"
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if ready:
                        transcript.extend(os.read(master, 65536))

            try:
                receive_prompts(1)
                for index, line in enumerate(["status", f"peek {hex(ADDRESS)} 32", "help"], 2):
                    os.write(master, (line + "\n").encode())
                    receive_prompts(index)
                os.write(master, b"quit\n")
                assert proc.wait(timeout=10) == 0
                text = transcript.decode()
                assert '"mode": "offline"' in text and '"mode": "dry-run"' in text
                assert '"reads": "dry-run"' in text and '"targetByteWrites": false' in text
                assert events[before:] == []
                results.append({"name": "terminal-repl-status-dry-run-help-quit", "passed": True,
                                "returncode": 0, "argv": command, "transport": [],
                                "terminal": True, "stdout": text})
                print("PASS terminal-repl-status-dry-run-help-quit")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                os.close(master)

        base = ["read", "--session-dir", str(session), "--report", str(report_file),
                "--address", hex(ADDRESS), "--length", "32", "--captures", str(output / "captures")]
        try:
            reset()
            run("offline-status-is-dependency-independent", ["status", "--session-dir", str(session)], expected=[])
            listing = run("offline-capture-discovery", ["captures", "--session-dir", str(session)], expected=[])
            assert listing["captures"][0]["complete"]
            run("default-dry-run", base, expected=[])
            with (session / ".m1mu2-read.lock").open("a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                run("concurrent-reader-refused", base + ["--live"], False, [])
                fcntl.flock(lock, fcntl.LOCK_UN)
            mismatch = report(); mismatch["session"] = "stale-session"
            write_json(report_file, mismatch)
            run("local-session-mismatch-refused", base + ["--live"], False, [])
            reset()
            unavailable = report(); unavailable["retainedMemory"]["ready"] = False
            write_json(report_file, unavailable)
            run("retained-not-ready-refused", base + ["--live"], False, [])
            reset()
            state = {"session": session.name, "stages": [{"name": "acquire", "state": "running"}]}
            write_json(session / "system-access.json", state)
            assert run("busy-offline-status", ["status", "--session-dir", str(session)], expected=[])["busy"]
            run("busy-refused-before-transport", base + ["--live"], False, [])
            reset()
            state["stages"][0]["state"] = "complete"
            write_json(session / "system-access.json", state)
            run("unfinished-stage-refused", base + ["--live"], False, [])
            reset()
            r = report(); r["retainedMemory"]["pending"] = {"operation": "read"}
            write_json(report_file, r)
            run("pending-refused-before-transport", base + ["--live"], False, [])
            reset()
            r = report(); r["retainedMemory"]["operations"] = [{"started": "fixture"}]
            write_json(report_file, r)
            run("inflight-refused-before-transport", base + ["--live"], False, [])
            reset()
            r = report()
            r["retainedMemory"]["operations"] = [
                {"command": "retained-bootstrap-move", "started": "fixture", "verified": True},
                {"command": "retained-bootstrap-move", "started": "fixture", "missed": True}]
            write_json(report_file, r)
            run("completed-and-missed-bootstrap-moves-accepted", base + ["--live"], expected=
                ["status", "retained-info", "retained-read", "status", "retained-info"])
            updated = json.loads(report_file.read_text())
            assert len(updated["retainedMemory"]["operations"]) == 3
            assert len(updated["retainedMemory"]["captures"]) == 2
            reset()
            r = report(); r["retainedMemory"]["operations"] = [
                {"command": "unknown-operation", "started": "fixture", "verified": True}]
            write_json(report_file, r)
            run("unknown-unfinished-verified-operation-refused", base + ["--live"], False, [])
            reset()
            r = report(); r["retainedMemory"]["operations"] = [
                {"command": "retained-bootstrap-move", "started": "fixture", "verified": True,
                 "pending": True}]
            write_json(report_file, r)
            run("pending-bootstrap-move-still-refused", base + ["--live"], False, [])
            reset()
            out_of_range = base.copy(); out_of_range[out_of_range.index("--address") + 1] = hex(ADDRESS + 0x1000)
            run("range-refused-before-transport", out_of_range + ["--live"], False, [])
            too_long = base.copy(); too_long[too_long.index("--length") + 1] = str(0x600001)
            run("oversized-refused-before-transport", too_long + ["--live"], False, [])
            noncanonical = base.copy(); noncanonical[noncanonical.index("--address") + 1] = "12"
            run("noncanonical-refused-before-transport", noncanonical + ["--live"], False, [])
            prior.write_bytes(DATA[:-1])
            assert not run("partial-capture-distinguished", ["captures", "--session-dir", str(session)], expected=[])["captures"][0]["complete"]
            run("partial-capture-cannot-authorize-read", base + ["--live"], False, [])
            reset("stale")
            run("stale-boot-refused", base + ["--live"], False, ["status"])
            reset("info-mismatch")
            run("retained-identity-refused", base + ["--live"], False, ["status", "retained-info"])
            reset("became-busy")
            run("busy-race-before-read-refused", base + ["--live"], False, ["status", "retained-info"])
            for mode in ["short", "hash", "escape", "address", "close"]:
                reset(mode)
                run(mode + "-response-not-replayed", base + ["--live"], False,
                    ["status", "retained-info", "retained-read"])
            reset("identity-change")
            run("readback-identity-change-refused", base + ["--live"], False,
                ["status", "retained-info", "retained-read", "status", "retained-info"])
            reset()
            saved = run("capture-success-simulated", base + ["--live"], expected=
                        ["status", "retained-info", "retained-read", "status", "retained-info"])
            receipt = Path(saved["receipt"])
            replayed = run("offline-replay", ["replay", "--capture", str(receipt)], expected=[])
            assert replayed["sha256"] == digest(DATA[:32]) and replayed["first64Hex"] == DATA[:32].hex()
            metadata = json.loads(receipt.read_text())
            binary = receipt.parent / metadata["binFile"]
            before = binary.read_bytes()
            # Corrupt a separate replay copy; retain the original verified evidence.
            corrupt_dir = output / "corrupt-replay"
            corrupt_dir.mkdir()
            shutil.copyfile(receipt, corrupt_dir / receipt.name)
            (corrupt_dir / binary.name).write_bytes(b"x" * 32)
            run("replay-tamper-refused", ["replay", "--capture", str(corrupt_dir / receipt.name)], False, [])
            assert binary.read_bytes() == before
            reset()
            repl_command = ["repl", "--session-dir", str(session), "--report", str(report_file),
                            "--captures", str(output / "captures")]
            answers = run("piped-repl-offline-commands", repl_command, expected=[],
                          stdin="status\ncaptures\nhelp\nquit\n")
            assert answers[0]["mode"] == "read-only-repl" and answers[1]["mode"] == "offline"
            assert answers[2]["captures"][0]["complete"]
            answers = run("piped-repl-default-dry-peek", repl_command, expected=[],
                          stdin=f"peek {hex(ADDRESS)} 32\nquit\n")
            assert answers[1]["mode"] == "dry-run"
            terminal_repl(repl_command)
            run("piped-repl-missing-report-refused", ["repl", "--session-dir", str(session)],
                False, [], stdin=f"read {hex(ADDRESS)} 32\nquit\n")
            for unsafe in [f"write {hex(ADDRESS)} 32", "status; echo unsafe", "__import__('os')",
                           "read --session-dir /another-session"]:
                run("piped-repl-unsafe-command-refused-" + str(len(results)), repl_command + ["--live"],
                    False, [], stdin=unsafe + f"\nread {hex(ADDRESS)} 32\n")
            answers = run("piped-repl-live-read", repl_command + ["--live"], expected=
                          ["status", "retained-info", "retained-read", "status", "retained-info"],
                          stdin=f"read {hex(ADDRESS)} 32\nquit\n")
            assert answers[0]["reads"] == "live" and answers[1]["length"] == 32
            spaced_dir = output / "replay with spaces"
            spaced_dir.mkdir()
            shutil.copyfile(receipt, spaced_dir / receipt.name)
            shutil.copyfile(binary, spaced_dir / binary.name)
            answers = run("piped-repl-quoted-offline-replay", repl_command, expected=[],
                          stdin="replay " + shlex.quote(str(spaced_dir / receipt.name)) + "\nquit\n")
            assert answers[1]["verifiedSavedBytes"]
            reset("close")
            run("piped-repl-failed-read-halts-without-retry", repl_command + ["--live"], False,
                ["status", "retained-info", "retained-read"],
                stdin=f"read {hex(ADDRESS)} 32\nread {hex(ADDRESS)} 32\nquit\n")
            write_json(output / "transcript.json", {"evidence": "simulated-loopback-only", "cases": results})
            hashes = {str(p.relative_to(output)): digest(p.read_bytes()) for p in output.rglob("*") if p.is_file()}
            summary = {"schema": "m1mu2.ns2.e2e.v1", "passed": True, "cases": len(results),
                       "evidence": "simulated HTTP/UNIX fixtures; not hardware verified",
                       "entrypoint": "python -m m1mu2 ns2", "fireRedDependenciesAbsent": True,
                       "repeat": "python verification/ns2_e2e.py --output NEW_DIRECTORY",
                       "captureReceipt": str(receipt), "artifactSha256": hashes}
            summary["sourceSha256"] = {str(p.relative_to(REPO)): digest(p.read_bytes()) for p in [
                REPO / "m1mu2/ns2.py", REPO / "m1mu2/entry.py", REPO / "m1mu2/journal.py",
                REPO / "verification/ns2_failure_model.md", Path(__file__).resolve()]}
            write_json(output / "receipt.json", summary)
            for p in output.rglob("*"):
                if p.is_file():
                    assert TOKEN.encode() not in p.read_bytes(), "Fixture credential leaked into artifact"
            print(json.dumps({"receipt": str(output / "receipt.json"), "cases": len(results)}))
        finally:
            for server in [http, unix]:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
