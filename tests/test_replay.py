"""replay: journal + capture files -> the same verdicts, offline. Captures are SYNTHETIC
(tests/fixtures/logs/README.txt) and written into tmp_path."""
import os
import subprocess
from pathlib import Path

import pytest

from m1mu2 import replay
from m1mu2.journal import Journal
from m1mu2.pack import compile_program, health_join, prev, probe
from m1mu2.upstream import bs

LOGS = Path(__file__).parent / "fixtures" / "logs"
EIGHT = (0x49, 0x4A, 0x4B, 0x50, 0x52, 0x53, 0x54, 0x53)
MAC = "20:50:0d:d1:15:20"


def health_answer():
    """The health pair's result block, both calls returned [asm/sloop-svc.s]."""
    block = bytearray(bs.sloop_svc_answer_size(0))
    for at, value in ((0, bs.SLOOP_REACHED), (4, 2), (8, bs.SLOOP_RETURNED), (0x10, 0x4770DF53),
                      (0x24, 0x4770DF4A)):
        block[at:at + 4] = value.to_bytes(4, "little")
    return bytes(block)


@pytest.fixture(autouse=True)
def no_subprocesses(monkeypatch):
    """Replay reads files and prints; anything that would start a process fails the test."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"replay tried to run a process: {args!r}")
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, "system", refuse)


def record(journal, join, log_path, bin_path, verdict, *, window=None):
    start = journal.append(
        "join-start", label=join.label, script=join.script, host_args=join.host_args(),
        command=["sudo", "-nE", "python", "frlg_mg_host.py", *join.host_args()],
        env={"POKELDN_RADIO": "esp32:/dev/cu.usbserial-0001"}, log_path=log_path,
        bin_path=bin_path, radio_mac=MAC)
    journal.append("join-end", label=join.label, start_seq=start, exit_status=0,
                   verdict=verdict, fault_window=window, log_path=log_path, bin_path=bin_path)
    return start


def test_replays_an_answered_join(tmp_path, capsys):
    journal = Journal(tmp_path / "journal.jsonl")
    log_path, bin_path = tmp_path / "health.log", tmp_path / "health.bin"
    log_path.write_text((LOGS / "health-answered.log").read_text())
    bin_path.write_bytes(health_answer())
    journal.append("plan", label="health")
    record(journal, health_join(), log_path, bin_path, "answered")
    assert replay.main([str(journal.path)]) == 0
    out = capsys.readouterr().out
    assert "health: sloop-svc, 2 step(s)" in out
    assert "health: answered" in out
    assert "0x4770DF53" in out and "0x4770DF4A" in out
    assert "journal seq 2" in out and f"radio {MAC}" in out
    assert "1 join(s) replayed" in out and "note:" not in out


def test_replays_a_crash_with_its_fault_window(tmp_path, capsys):
    journal = Journal(tmp_path / "journal.jsonl")
    eight = compile_program([probe.svc(n) for n in EIGHT], label="eight")[0]
    log_path = tmp_path / "eight.log"
    log_path.write_text((LOGS / "crash-8svc.log").read_text())
    record(journal, eight, log_path, tmp_path / "eight.bin", "crashed", window=(1, 8))
    assert replay.main([str(journal.path)]) == 0
    out = capsys.readouterr().out
    assert "eight: crashed, fault in steps 1..8" in out
    assert "no answer file at" in out
    assert "the journal recorded" not in out


def test_missing_capture_files_are_noted_and_replay_continues(tmp_path, capsys):
    journal = Journal(tmp_path / "journal.jsonl")
    chain = compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev)],
                            label="var4024")[0]
    record(journal, chain, tmp_path / "gone.log", tmp_path / "gone.bin", "answered")
    log_path, bin_path = tmp_path / "health.log", tmp_path / "health.bin"
    log_path.write_text((LOGS / "health-answered.log").read_text())
    bin_path.write_bytes(health_answer())
    record(journal, health_join(), log_path, bin_path, "answered")
    assert replay.main([str(journal.path)]) == 0
    out = capsys.readouterr().out
    assert "gone.log is missing" in out
    assert "var4024: not-started" in out
    assert "the journal recorded 'answered'; replay classifies it 'not-started'" in out
    assert "health: answered" in out and "2 join(s) replayed" in out


def test_unfinished_and_orphaned_entries(tmp_path, capsys):
    journal = Journal(tmp_path / "journal.jsonl")
    journal.append("join-start", label="half", host_args=health_join().host_args(),
                   log_path=tmp_path / "half.log", bin_path=None)
    journal.append("join-end", label="orphan", start_seq=42, verdict="ghost")
    failed = journal.append("join-start", label="boom", host_args=health_join().host_args())
    journal.append("join-error", label="boom", start_seq=failed, error="OSError('no tty')")
    assert replay.main([str(journal.path)]) == 0
    out = capsys.readouterr().out
    assert "join-start 'half' has no join-end" in out
    assert "seq 42, which the journal does not have" in out
    assert "join 'boom' never finished: the runner failed (OSError('no tty'))" in out
    assert "'boom' has no join-end" not in out


def test_missing_journal(tmp_path, capsys):
    assert replay.main([str(tmp_path / "none.jsonl")]) == 1
    assert "no journal at" in capsys.readouterr().out
