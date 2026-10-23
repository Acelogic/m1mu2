"""Real CLI/HTTP viewer verification against labeled local evidence fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def main():
    artifacts = ROOT / "verification" / "artifacts"
    artifacts.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="ns2-view-", dir=artifacts))
    session = run / "session-view-fixture"
    memory = session / "switch2" / "memory"
    memory.mkdir(parents=True)
    blob = memory / "capture-<b>.bin"
    data = b"SIMULATED NS2 VIEW FIXTURE".ljust(64, b"\x00")
    blob.write_bytes(data)
    report = memory / "report.json"
    report.write_text(json.dumps({"session": session.name, "cases": [], "retainedMemory": {
        "captures": [{"command": "retained-read", "address": 2**32, "length": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "outputFile": str(blob)}]}}))
    state = session / "system-access.json"
    state.write_text(json.dumps({"session": session.name, "error": "Fixture acquisition failure",
                                 "finished": "fixture", "stages": [{"name": "Fixture acquisition", "state": "failed"}]}))
    cmd = [sys.executable, "-m", "m1mu2", "ns2", "view", "--session-dir", str(session), "--port", "0"]
    process = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    checks = []
    transcript = []
    try:
        line = process.stdout.readline().strip()
        assert line.startswith("NS2 capture viewer: http://127.0.0.1:"), line
        url = line.split(": ", 1)[1].rstrip("/")

        def request(path, *, host=None, data=None):
            headers = {"Host": host} if host else {}
            req = urllib.request.Request(url + path, headers=headers, data=data)
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    code, content = response.status, response.read()
            except urllib.error.HTTPError as error:
                code, content = error.code, error.read()
            transcript.append({"path": path, "method": "POST" if data is not None else "GET", "status": code})
            return code, content

        code, content = request("/")
        assert code == 200 and b"Saved evidence" in content and b"No device requests" in content
        checks.append("real CLI serves passive viewer")
        code, content = request("/api/status")
        status = json.loads(content)
        assert code == 200 and status["systemAccess"] == "failed" and status["liveReadiness"] == "not-contacted"
        checks.append("failed acquisition is not labeled hardware ready")
        code, content = request("/api/captures")
        capture = json.loads(content)["captures"][0]
        assert code == 200 and capture["complete"] and capture["bytesVerified"]
        capture_id = capture["id"]
        code, content = request("/api/preview?id=" + capture_id)
        preview = json.loads(content)
        assert code == 200 and bytes.fromhex(preview["hex"]) == data
        code, content = request("/api/download?id=" + capture_id)
        assert code == 200 and content == data
        checks.append("verified capture preview and byte-identical download")
        assert request("/api/status", host="attacker.invalid")[0] == 403
        assert request("/api/preview?id=../../keys/private")[0] == 409
        assert request("/api/read", data=b"{}")[0] == 405
        checks.append("foreign host, arbitrary path and device operation rejected")
        blob.write_bytes(b"X" * len(data))
        assert request("/api/preview?id=" + capture_id)[0] == 409
        assert request("/api/download?id=" + capture_id)[0] == 409
        checks.append("mutated capture rejected before preview or download")
        blob.write_bytes(data)
        state.write_text(json.dumps({"session": session.name, "stages": [{"name": "Fixture acquisition", "state": "running"}]}))
        code, content = request("/api/status")
        assert code == 200 and json.loads(content)["busy"] is True
        checks.append("inflight state read without contacting a device")
    finally:
        process.terminate()
        process.wait(timeout=5)
    receipt = {"schema": "m1mu2.ns2.viewer.e2e.v1", "fixtureOnly": True, "hardwareVerified": False,
               "command": cmd, "checks": checks, "requests": transcript, "artifacts": str(run),
               "sourceHashes": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in [ROOT / "m1mu2/ns2_view.py", ROOT / "m1mu2/ns2_view.html"]}}
    target = ROOT / "verification/ns2_view_receipt.json"
    target.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": len(checks), "fixtureOnly": True, "receipt": str(target)}))


if __name__ == "__main__":
    main()
