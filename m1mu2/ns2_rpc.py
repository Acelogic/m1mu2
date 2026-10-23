"""Fixed-window probe of an existing, qualified application RPC session."""
import base64
import binascii
import http.client
import json
from pathlib import Path

from .ns2 import (Journal, MAX_JSON, TIMEOUT, Refusal, bounded, inside, integer,
                  read_json, require, rpc_status, save_capture, session_lock,
                  sha256, system_state, unfinished_operation)

FIELDS = ("address", "size", "type", "attributes", "permissions",
          "ipcReferences", "deviceReferences")
SDK_OFFSET = 0x4CC0


def region(value):
    require(isinstance(value, dict), "Invalid application mapping")
    result = {}
    for field in FIELDS:
        item = value.get(field)
        if isinstance(item, str) and item.isascii() and item.isdecimal():
            item = int(item)
        require(integer(item) and 0 <= item < 2**39, "Invalid application mapping field")
        result[field] = item
    return result


def binding(root):
    snapshots = {}

    def load(relative):
        path = inside(relative, root)
        before = sha256(path.read_bytes())
        value = read_json(path)
        require(sha256(path.read_bytes()) == before, "RPC metadata changed while reading")
        snapshots[str(path)] = before
        return value

    state = load("system-access.json")
    _, busy = system_state(root)
    require(not busy and state.get("session") == root.name,
            "Application RPC session is busy or mismatched")
    connection = load("connection.json")
    addresses = connection.get("addresses", {})
    require(isinstance(addresses, dict) and addresses.get("session") == root.name and addresses.get("platform") == 2,
            "Application RPC connection identity mismatch")
    require(integer(connection.get("port")) and 0 < connection["port"] < 65536 and
            isinstance(connection.get("token"), str) and connection["token"],
            "Invalid application RPC connection")
    baseline = load("qualification.json")
    require(baseline.get("platform") == 2 and baseline.get("verified") is True and
            baseline.get("completed") and baseline.get("scratchRestored") is True and
            baseline.get("importRestored") is True,
            "Application RPC baseline is not qualified and restored")
    app = load("switch2/app/qualification.json")
    require(app.get("session") == root.name and app.get("verified") is True and
            app.get("completed") and app.get("cleanedUp") is True,
            "Application qualification is incomplete")
    pointer = root / "switch2/current-acquisition.json"
    if pointer.exists():
        current = load(pointer)
        require(current.get("session") == root.name and isinstance(current.get("report"), str),
                "Acquisition pointer identity mismatch")
        report = load(current["report"])
        require(report.get("session") == root.name and report.get("finished") and
                report.get("cleanedUp") is True,
                "Acquisition cleanup is not confirmed; no application probe attempted")
        for key in ("retainedMemory", "memoryControl"):
            control = report.get(key, {})
            require(isinstance(control, dict) and not control.get("pending") and
                    not control.get("inflight"), "Acquisition has pending operations")
            operations = control.get("operations", [])
            require(isinstance(operations, list) and
                    not any(unfinished_operation(op) for op in operations),
                    "Acquisition has unfinished operations")
    else:
        require(not state.get("error"), "Failed acquisition has no cleanup receipt")
    memory_map = load("switch2/app/memory-map.json")
    require(memory_map.get("session") == root.name and memory_map.get("complete") is True and
            isinstance(memory_map.get("regions"), list), "Application map is incomplete")
    sdk = addresses.get("sdk")
    require(integer(sdk), "Invalid SDK base")
    instructions = load("switch2/app/verified-instructions.json")
    require(instructions.get("session") == root.name and instructions.get("sdk") == sdk and
            isinstance(instructions.get("code"), dict), "SDK instruction identity mismatch")
    signature = instructions["code"].get(str(SDK_OFFSET))
    require(isinstance(signature, str) and len(signature) >= 64 and
            all(c in "0123456789abcdefABCDEF" for c in signature), "Missing SDK instruction signature")
    expected = bytes.fromhex(signature[:64])
    address = sdk + SDK_OFFSET
    bounded(address, 32)
    matches = [region(item) for item in memory_map["regions"]
               if isinstance(item, dict) and integer(item.get("address")) and integer(item.get("size")) and
               item["address"] <= address and address + 32 <= item["address"] + item["size"]]
    require(len(matches) == 1, "SDK probe window is absent or ambiguous in the saved map")
    mapping = matches[0]
    require(mapping["permissions"] == 5 and mapping["type"] == 3 and
            not any(mapping[key] for key in ("attributes", "ipcReferences", "deviceReferences")),
            "SDK probe window is not unshared RX code")
    require(all(sha256(Path(path).read_bytes()) == digest
                for path, digest in snapshots.items()), "RPC metadata changed during preflight")
    return connection, address, mapping, snapshots, expected


def request(connection, command):
    require(command.get("command") in {"query", "read"}, "Unsupported application probe command")
    conn = http.client.HTTPConnection("127.0.0.1", connection["port"], timeout=TIMEOUT)
    try:
        conn.request("POST", "/", body=json.dumps(command).encode(),
                     headers={"Authorization": "Bearer " + connection["token"],
                              "Content-Type": "application/json"})
        reply = conn.getresponse()
        body = reply.read(MAX_JSON + 1)
        require(reply.status == 200 and len(body) <= MAX_JSON, "Application RPC probe failed")
        result = json.loads(body)
        require(isinstance(result, dict) and not result.get("error"), "Application RPC rejected probe")
        return result
    finally:
        conn.close()


def probe(args):
    root = args.session_dir.resolve()
    connection, address, mapping, snapshot, expected = binding(root)
    plan = {"mode": "live" if args.live else "dry-run", "session": root.name,
            "scope": "application-sdk", "address": address, "length": 32,
            "commands": ["status", "query", "read", "query", "status"],
            "sourceByteWrites": False, "rpcScratchMayChange": True,
            "expectedSha256": sha256(expected),
            "sysmoduleAccessProven": False}
    if not args.live:
        return plan
    journal = Journal(args.captures.resolve() / "journal.jsonl")
    with session_lock(root):
        require(binding(root)[3] == snapshot, "Application RPC metadata changed before probe")
        seq = journal.append("ns2-rpc-probe-start", session=root.name, address=address, length=32)
        try:
            rpc_status(connection, root.name)
            require(region(request(connection, {"command": "query", "address": address})) == mapping,
                    "Live SDK mapping differs from saved qualification")
            require(binding(root)[3] == snapshot, "Application RPC metadata changed before read")
            response = request(connection, {"command": "read", "address": address, "length": 32})
            require(isinstance(response.get("data"), str), "Application read has no byte data")
            try:
                data = base64.b64decode(response["data"], validate=True)
            except (ValueError, binascii.Error):
                raise Refusal("Application read contains invalid base64") from None
            require(len(data) == 32, "Application read returned the wrong byte count")
            require(data == expected, "Application SDK bytes differ from verified instructions")
            require(region(request(connection, {"command": "query", "address": address})) == mapping,
                    "SDK mapping changed during probe")
            rpc_status(connection, root.name)
            require(binding(root)[3] == snapshot, "Application RPC metadata changed during probe")
            receipt, metadata = save_capture(args.captures.resolve(), data,
                {"session": root.name, "address": address, "mapping": mapping,
                 "scope": "application-sdk", "sourceByteWrites": False,
                 "rpcScratchMayChange": True, "sysmoduleAccessProven": False,
                 "expectedSha256": sha256(expected), "matchesVerifiedInstructions": True,
                 "evidence": "application-rpc-read", "journalStartSeq": seq})
            journal.append("ns2-rpc-probe-complete", startSeq=seq, receipt=str(receipt),
                           sha256=metadata["sha256"], length=32)
            return {**plan, "receipt": str(receipt), "sha256": metadata["sha256"],
                    "matchesVerifiedInstructions": True,
                    "first32Hex": data.hex(), "evidence": "application-rpc-read",
                    "hardwareIdentityIndependentlyVerified": False}
        except Exception:
            journal.append("ns2-rpc-probe-failed", startSeq=seq, requestReplayed=False,
                           outcome="unverified; request may have executed")
            raise
