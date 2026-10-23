"""Read verified saved captures or an already-retained ns2jb FS endpoint.

Retained reads and a fixed application SDK RPC probe are implemented. Reads can
update upstream pointer/scratch state; source-byte writes are not exposed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import sys
import uuid

from .journal import Journal

MAX_READ = 0x600000
MAX_JSON = 16 * 1024 * 1024
TIMEOUT = 15


class Refusal(Exception):
    """A failed local prerequisite or unverified response."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def bounded(address, length):
    require(integer(address) and integer(length) and 0 < length <= MAX_READ
            and 2**32 <= address and address + length < 2**39,
            "Read requires a canonical FS address and 1..6 MiB wholly below 2^39")


def inside(path, root):
    candidate = Path(path)
    candidate = (root / candidate if not candidate.is_absolute() else candidate).resolve()
    require(candidate.is_relative_to(root), "Referenced path escapes the session directory")
    return candidate


def read_json(path):
    require(Path(path).stat().st_size <= MAX_JSON, "JSON metadata exceeds its size limit")
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_JSON, "JSON metadata exceeds its size limit")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Refusal("Malformed JSON metadata") from None
    require(isinstance(obj, dict), "Expected a JSON object")
    return obj


def system_state(root):
    file = root / "system-access.json"
    state = read_json(file) if file.exists() else {}
    stages = state.get("stages", [])
    require(isinstance(stages, list), "Invalid system-access stage list")
    busy = any(isinstance(s, dict) and s.get("state", s.get("status")) == "running"
               for s in stages) or bool(stages and not state.get("finished"))
    return state, busy


def report_files(root):
    found = set()
    pointer = root / "switch2" / "current-acquisition.json"
    if pointer.exists():
        current = read_json(pointer)
        require(isinstance(current.get("report"), str), "Acquisition pointer has no report")
        found.add(inside(current["report"], root))
    for base in [root / "switch2" / "memory", root / "switch2" / "retained"]:
        if base.exists():
            for p in base.glob("*.json"):
                obj = read_json(inside(p, root))
                if "cases" in obj and "session" in obj:
                    found.add(p.resolve())
    return sorted(found)


def capture_records(report, report_file, root):
    """Unknown range/length stays unknown; no file size is invented as a range."""
    records = []

    def walk(value, location="$", unsafe=False):
        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}[{index}]", unsafe)
        elif isinstance(value, dict):
            unsafe = unsafe or bool(value.get("pending") or value.get("partial"))
            if location != "$":
                unsafe = unsafe or bool(value.get("error")) or value.get("complete") is False
            for key, filename in value.items():
                if not key.endswith("File") or not isinstance(filename, str):
                    continue
                prefix = key[:-4]
                digest = value.get(prefix + "Sha256", value.get("sha256") if key == "outputFile" else None)
                address = value.get("address") if key == "outputFile" else None
                length = value.get("length") if key == "outputFile" else None
                row = {"report": str(report_file), "metadata": location + "." + key,
                       "session": report.get("session"), "outputFile": filename,
                       "address": address, "length": length, "sha256": digest,
                       "complete": False, "state": "unverified"}
                try:
                    p = inside(filename, root)
                    row["outputFile"] = str(p)
                    size = p.stat().st_size
                    row["actualLength"] = size
                    require(size <= MAX_JSON, "Capture exceeds inspection size limit")
                    data = p.read_bytes()
                    row["actualSha256"] = sha256(data)
                    require(isinstance(digest, str) and sha256(data) == digest,
                            "Capture hash missing or mismatched")
                    row["bytesVerified"] = True
                    bounded(address, length)
                    require(len(data) == length and not unsafe, "Capture is partial or pending")
                    row.update(complete=True, state="complete")
                except (OSError, Refusal):
                    row["state"] = "partial-or-unverified"
                records.append(row)
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    walk(child, location + "." + key, unsafe)
    walk(report)
    return records


def local_status(root):
    state, busy = system_state(root)
    reports = report_files(root)
    return {"mode": "offline", "hardwareVerified": False, "sessionDir": str(root),
            "session": state.get("session", root.name), "busy": busy,
            "systemAccess": "running" if busy else "failed" if state.get("error") else
                            "verified" if state.get("verified") is True else "unverified",
            "stages": [{"name": s.get("name"), "state": s.get("state", s.get("status"))}
                       for s in state.get("stages", []) if isinstance(s, dict)],
            "reports": [str(p) for p in reports], "liveReadiness": "not-contacted"}


def binding(root, report_file):
    state, busy = system_state(root)
    require(not busy, "system-access has a running or unfinished stage; no transport attempted")
    report = read_json(report_file)
    connection_path = inside(root / "connection.json", root)
    connection = read_json(connection_path)
    identity = connection.get("addresses", {})
    session = report.get("session")
    require(isinstance(session, str) and session == root.name and
            identity.get("session") == session and identity.get("platform") == 2,
            "Session/report/connection identity mismatch")
    require(not state or state.get("session") == session, "system-access session mismatch")
    pointer = root / "switch2" / "current-acquisition.json"
    if pointer.exists():
        current = read_json(pointer)
        require(current.get("session") == session and
                inside(current.get("report", ""), root) == report_file,
                "Report is not the current acquisition for this session")
    retained, control = report.get("retainedMemory", {}), report.get("memoryControl", {})
    require(retained.get("ready") is True and retained.get("zeroCountVerified") is True,
            "Report has no ready, zero-count-verified retained endpoint")
    require(not retained.get("pending") and not control.get("pending") and
            not retained.get("inflight") and not control.get("inflight"),
            "Retained endpoint has a pending/inflight operation")
    for group in [retained.get("operations", []), control.get("operations", [])]:
        require(isinstance(group, list), "Invalid operation list")
        require(not any(unfinished_operation(op) for op in group),
                "Retained endpoint has an unfinished operation")
    require(isinstance(report.get("cases"), list), "Report has no corruption-count history")
    require(isinstance(control.get("socketPath"), str), "Report has no retained socket")
    # Upstream run-control creates /tmp/ns2-*/memory.sock, outside the session.
    # The explicit report binds it; captured output files still stay in-session.
    endpoint = Path(control["socketPath"])
    require(endpoint.is_absolute(), "Retained socket path must be absolute")
    endpoint = endpoint.resolve()
    endpoint_stat = endpoint.stat()
    require(stat.S_ISSOCK(endpoint_stat.st_mode) and endpoint_stat.st_uid == os.geteuid()
            and not endpoint_stat.st_mode & 0o022,
            "Retained endpoint is not a privately writable UNIX socket owned by this user")
    require(integer(connection.get("port")) and 0 < connection["port"] < 65536 and
            isinstance(connection.get("token"), str) and connection["token"],
            "Invalid local status RPC connection")
    snapshot = (sha256(connection_path.read_bytes()), session, str(endpoint),
                endpoint_stat.st_dev, endpoint_stat.st_ino, len(report["cases"]),
                state.get("finished"), retained.get("corruptionCount"))
    return report, connection, endpoint, snapshot


def unfinished_operation(operation):
    if not isinstance(operation, dict):
        return True
    if operation.get("pending"):
        return True
    if not operation.get("started") or operation.get("finished"):
        return False
    # retained-memory.cjs moveBootstrap uses these explicit terminal states,
    # never a finished timestamp. Do not generalize this to other commands.
    completed_move = (operation.get("command") == "retained-bootstrap-move" and
                      not operation.get("error") and
                      ((operation.get("verified") is True) !=
                       (operation.get("missed") is True)))
    return not completed_move


def rpc_status(connection, session):
    conn = http.client.HTTPConnection("127.0.0.1", connection["port"], timeout=TIMEOUT)
    try:
        conn.request("POST", "/", body=b'{"command":"status"}',
                     headers={"Authorization": "Bearer " + connection["token"],
                              "Content-Type": "application/json"})
        reply = conn.getresponse()
        body = reply.read(MAX_JSON + 1)
        require(reply.status == 200 and len(body) <= MAX_JSON, "Status RPC failed")
        obj = json.loads(body)
        require(isinstance(obj, dict) and not obj.get("error"), "Status RPC returned an error")
        boot = {**connection["addresses"], **obj}
        require(boot.get("ready") is True and boot.get("platform") == 2 and
                boot.get("session") == session, "Boot is stale, unready, or not Switch 2")
    finally:
        conn.close()


def endpoint_request(endpoint, command):
    require(command.get("command") in {"retained-info", "retained-read"},
            "Command is outside the read-only allowlist")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect(str(endpoint))
        sock.sendall(json.dumps(command).encode() + b"\n")
        parts, total = [], 0
        while True:
            part = sock.recv(65536)
            if not part:
                break
            total += len(part)
            require(total <= MAX_JSON, "Retained response exceeds its size limit")
            parts.append(part)
    try:
        obj = json.loads(b"".join(parts))
    except (ValueError, UnicodeError):
        raise Refusal("Ambiguous or malformed endpoint response; request was not replayed") from None
    require(isinstance(obj, dict) and not obj.get("error"),
            "Endpoint rejected request; request was not replayed")
    return obj


def info_identity(info, report, report_file):
    require(info.get("ready") is True and info.get("steadyStateReliable") is True and
            info.get("requiresCorruption") is False and info.get("session") == report["session"]
            and info.get("report") == str(report_file) and
            integer(info.get("corruptionCount")) and info["corruptionCount"] == len(report["cases"]),
            "Retained endpoint identity/readiness/corruption count does not match")
    return {k: info.get(k) for k in ["session", "report", "corruptionCount", "controlAddress", "dataOffset"]}


@contextmanager
def session_lock(root):
    path = root / ".m1mu2-read.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal("Another m1mu2 read is in flight for this session") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def save_capture(directory, data, metadata):
    directory.mkdir(parents=True, exist_ok=True)
    stem = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex
    binary, receipt = directory / (stem + ".bin"), directory / (stem + ".json")
    metadata = {"schema": "m1mu2.ns2.capture.v1", **metadata, "binFile": binary.name,
                "length": len(data), "sha256": sha256(data),
                "utc": datetime.now(timezone.utc).isoformat()}
    for path, body in [(binary, data), (receipt, (json.dumps(metadata, indent=2) + "\n").encode())]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o400)
    return receipt, metadata


def read_command(args):
    root = args.session_dir.resolve()
    report_file = inside(args.report, root)
    bounded(args.address, args.length)
    # Every offline preflight happens before contacting either endpoint.
    report, connection, endpoint, snapshot = binding(root, report_file)
    records = capture_records(report, report_file, root)
    sources = [r for r in records if r["complete"] and r["address"] <= args.address and
               args.address + args.length <= r["address"] + r["length"]]
    require(sources, "Requested range is outside prior complete verified captures")
    plan = {"mode": "live" if args.live else "dry-run", "session": report["session"],
            "report": str(report_file), "address": args.address, "length": args.length,
            "commands": ["status", "retained-info", "retained-read", "status", "retained-info"],
            "source": sources[0], "targetByteWrites": False,
            "internalPointerStateMayChange": True, "hardwareVerified": False}
    if not args.live:
        return plan
    journal = Journal(args.captures.resolve() / "journal.jsonl")
    with session_lock(root):
        current, connection, endpoint, now = binding(root, report_file)
        require(now == snapshot, "Session state changed before read")
        rpc_status(connection, report["session"])
        info = endpoint_request(endpoint, {"command": "retained-info"})
        identity = info_identity(info, report, report_file)
        _, _, _, before_read = binding(root, report_file)
        require(before_read == snapshot, "Session state changed before retained-read")
        seq = journal.append("ns2-read-start", session=report["session"], report=str(report_file),
                             address=args.address, length=args.length)
        try:
            response = endpoint_request(endpoint, {"command": "retained-read",
                                                   "address": args.address, "length": args.length})
            require(integer(response.get("address")) and integer(response.get("length")) and
                    integer(response.get("corruptionCount")) and
                    response.get("address") == args.address and response.get("length") == args.length
                    and response.get("requiresCorruption") is False and
                    response.get("corruptionCount") == info["corruptionCount"],
                    "Read response address/length/corruption count differs")
            require(isinstance(response.get("outputFile"), str), "Read response has no output file")
            output = inside(response["outputFile"], root)
            require(output.stat().st_size == args.length, "Saved read has the wrong byte count")
            data = output.read_bytes()
            require(len(data) == args.length and sha256(data) == response.get("sha256"),
                    "Saved read hash or length differs")
            current, current_connection, current_endpoint, after = binding(root, report_file)
            require(after == snapshot, "Session state changed during read")
            rpc_status(current_connection, report["session"])
            after_info = endpoint_request(current_endpoint, {"command": "retained-info"})
            require(info_identity(after_info, current, report_file) == identity,
                    "Retained identity changed during read")
            receipt, metadata = save_capture(args.captures.resolve(), data,
                {"session": report["session"], "report": str(report_file),
                 "address": args.address, "endpointIdentity": identity,
                 "sourceCapture": sources[0], "upstreamOutputFile": str(output),
                 "targetByteWrites": False, "internalPointerStateMayChange": True,
                 "evidence": "retained-protocol-read", "journalStartSeq": seq})
            journal.append("ns2-read-complete", startSeq=seq, receipt=str(receipt),
                           sha256=metadata["sha256"], length=len(data))
            return {"mode": "live", "receipt": str(receipt), "address": args.address,
                    "length": len(data), "sha256": metadata["sha256"],
                    "evidence": "retained-protocol-read", "hardwareIdentityIndependentlyVerified": False}
        except Exception:
            journal.append("ns2-read-failed", startSeq=seq, requestReplayed=False,
                           outcome="unverified; request may have executed")
            raise


def replay(path):
    path = path.resolve()
    metadata = read_json(path)
    require(metadata.get("schema") == "m1mu2.ns2.capture.v1", "Unsupported capture receipt schema")
    require(isinstance(metadata.get("binFile"), str), "Receipt has no binary")
    binary = inside(metadata["binFile"], path.parent)
    bounded(metadata.get("address"), metadata.get("length"))
    require(binary.stat().st_size == metadata["length"], "Replay byte count differs")
    data = binary.read_bytes()
    require(len(data) == metadata["length"] and sha256(data) == metadata.get("sha256"),
            "Replay hash or length differs")
    return {"mode": "offline-replay", "receipt": str(path), "session": metadata.get("session"),
            "address": metadata["address"], "length": len(data), "sha256": sha256(data),
            "first64Hex": data[:64].hex(), "verifiedSavedBytes": True, "hardwareVerified": False}


def captures(root):
    return {"mode": "offline", "sessionDir": str(root), "captures": [
        record for path in report_files(root)
        for record in capture_records(read_json(path), path, root)]}


def repl(args):
    """A fixed-session, fixed-mode command loop; every read uses read_command."""
    root = args.session_dir.resolve()
    require(root.is_dir(), "REPL session directory does not exist")
    selected_report = inside(args.report, root) if args.report is not None else None
    capture_dir = args.captures.resolve()
    interactive = sys.stdin.isatty()
    print(json.dumps({"mode": "read-only-repl", "sessionDir": str(root),
                      "report": str(selected_report) if selected_report else None,
                      "reads": "live" if args.live else "dry-run",
                      "commands": ["status", "captures", "rpc-probe", "read ADDRESS LENGTH", "peek ADDRESS LENGTH",
                                   "replay RECEIPT", "help", "quit"],
                      "targetByteWrites": False, "internalPointerStateMayChange": True}), flush=True)
    while True:
        if interactive:
            print("ns2[" + ("LIVE" if args.live else "DRY") + "]> ", end="", flush=True)
        line = sys.stdin.readline()
        if not line:
            return 0
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            raise Refusal("Malformed REPL command quoting; REPL halted") from None
        if not words:
            continue
        command, *operands = words
        if command == "quit" and not operands:
            return 0
        if command == "help" and not operands:
            result = {"commands": ["status", "captures", "rpc-probe", "read ADDRESS LENGTH", "peek ADDRESS LENGTH",
                                   "replay RECEIPT", "help", "quit"],
                      "note": "Session and live/dry-run mode are fixed at startup; any failure halts."}
        elif command == "status" and not operands:
            result = local_status(root)
        elif command == "captures" and not operands:
            result = captures(root)
        elif command == "rpc-probe" and not operands:
            from .ns2_rpc import probe
            result = probe(args)
        elif command in {"read", "peek"} and len(operands) == 2:
            require(selected_report is not None, "REPL reads require --report at startup; REPL halted")
            try:
                address, length = (int(value, 0) for value in operands)
            except ValueError:
                raise Refusal("Read expects ADDRESS LENGTH integers; REPL halted") from None
            result = read_command(argparse.Namespace(session_dir=root, report=selected_report,
                                  address=address, length=length, live=args.live, captures=capture_dir))
        elif command == "replay" and len(operands) == 1:
            result = replay(Path(operands[0]))
        else:
            raise Refusal("Unknown command or invalid arguments; REPL halted")
        print(json.dumps(result), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="m1mu2 ns2", description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["status", "captures", "read", "rpc-probe"]:
        command = commands.add_parser(name)
        command.add_argument("--session-dir", type=Path, required=True)
        if name in {"read", "rpc-probe"}:
            command.add_argument("--live", action="store_true")
            command.add_argument("--captures", type=Path, default=Path("captures/ns2"))
        if name == "read":
            command.add_argument("--report", type=Path, required=True)
            command.add_argument("--address", type=lambda s: int(s, 0), required=True)
            command.add_argument("--length", type=lambda s: int(s, 0), required=True)
    command = commands.add_parser("replay")
    command.add_argument("--capture", type=Path, required=True)
    command = commands.add_parser("view", help="serve a passive local capture viewer")
    command.add_argument("--session-dir", type=Path, required=True)
    command.add_argument("--port", type=int, default=8788)
    command = commands.add_parser("repl", help="fixed-session read-only command shell")
    command.add_argument("--session-dir", type=Path, required=True)
    command.add_argument("--report", type=Path)
    command.add_argument("--live", action="store_true")
    command.add_argument("--captures", type=Path, default=Path("captures/ns2"))
    args = parser.parse_args(argv)
    try:
        if args.command == "view":
            from .ns2_view import serve
            return serve(args.session_dir, args.port)
        if args.command == "repl":
            return repl(args)
        if args.command == "status":
            result = local_status(args.session_dir.resolve())
        elif args.command == "captures":
            root = args.session_dir.resolve()
            result = captures(root)
        elif args.command == "replay":
            result = replay(args.capture)
        elif args.command == "rpc-probe":
            from .ns2_rpc import probe
            result = probe(args)
        else:
            result = read_command(args)
        print(json.dumps(result, indent=2))
        return 0
    except (Refusal, OSError, ValueError, TypeError, KeyError, http.client.HTTPException) as error:
        # Never reflect server errors or connection tokens into logs or artifacts.
        detail = str(error) if isinstance(error, Refusal) else "Local metadata or transport failed"
        print(json.dumps({"error": detail, "requestReplayed": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
