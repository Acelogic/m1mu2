"""Session: invocation rendering, scheduling, the dry-run and live paths. Every collaborator that
touches the world (runner, gate, journal, log reader) is a fake; nothing here spawns a process."""
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from m1mu2 import session as sessionmod
from m1mu2.pack import compile_program, health_join, prev, probe
from m1mu2.session import (DEFAULT_KEYS, SUDO, BudgetError, DryRun, Invocation, Session,
                           capture_paths, run_host, utcstamp)
from m1mu2.upstream import HOST_SCRIPT, VENV_PYTHON, HostCheck

FIXED = datetime(2026, 10, 15, 3, 45, 1, tzinfo=timezone.utc)
STAMP = "20261015T034501Z"
HALTING = frozenset({"crashed", "ghost", "not-started", "no-answer"})
RESERVED = ("seq", "utc", "kind")


class FakeJournal:
    def __init__(self, path=None):
        self.path = path
        self.rows = []

    def append(self, kind, **fields):
        assert not set(fields) & set(RESERVED), "the journal owns seq/utc/kind"
        seq = len(self.rows) + 1
        self.rows.append({"seq": seq, "kind": kind, **fields})
        return seq

    def entries(self):
        return list(self.rows)

    def kinds(self):
        return [row["kind"] for row in self.rows]

    def one(self, kind):
        rows = [row for row in self.rows if row["kind"] == kind]
        assert len(rows) == 1, (kind, self.kinds())
        return rows[0]


@dataclass
class FakeOutcome:
    verdict: str
    label: str = ""
    fault_window: tuple | None = None
    evidence: tuple = ()

    @property
    def halted(self):
        return self.verdict in HALTING

    def describe(self):
        return [f"{self.label}: {self.verdict}"]


class FakeLoader:
    """load_outcome that hands back scripted verdicts and remembers its calls."""

    def __init__(self, *verdicts, window=None):
        self.verdicts = list(verdicts)
        self.window = window
        self.calls = []

    def __call__(self, join, log_path, bin_path, *, journal_seq=None):
        self.calls.append((join, log_path, bin_path, journal_seq))
        return FakeOutcome(self.verdicts.pop(0), join.label, self.window)


class FakeRunner:
    def __init__(self, *statuses):
        self.statuses = list(statuses) or [0]
        self.invocations = []

    def __call__(self, inv):
        self.invocations.append(inv)
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]


def never(*args, **kwargs):
    raise AssertionError("must not be called")


def var4024():
    return compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev),
                            probe.read32(0x030042D0)], label="var4024")


def risky():
    return compile_program([probe.read32(0x03005008), probe.read16(prev + 0x290)], label="sb")


def two_joins():
    return compile_program([probe.svc(0x53), probe.read32(0x03005008)], label="two")


def make(tmp_path, **kwargs):
    lines = []
    kwargs.setdefault("journal", FakeJournal())
    kwargs.setdefault("captures_dir", tmp_path / "captures")
    kwargs.setdefault("now", FIXED)
    kwargs.setdefault("runner", never)
    kwargs.setdefault("confirm", never)
    kwargs.setdefault("load_outcome", never)
    kwargs.setdefault("bisection_plan", never)
    session = Session(out=lines.append, **kwargs)
    return session, lines


def live(tmp_path, **kwargs):
    keys = tmp_path / "prod.keys"
    keys.write_text("not a key\n")
    kwargs.setdefault("confirm", lambda prompt: True)
    return make(tmp_path, live=True, keys=keys, **kwargs)


# -- names and paths ----------------------------------------------------------------------------

def test_utcstamp_is_utc_and_compact():
    assert utcstamp(FIXED) == STAMP
    assert utcstamp(datetime(2026, 10, 15, 3, 45, 1)) == STAMP        # naive is UTC
    assert len(utcstamp()) == len(STAMP)


def test_capture_paths_sanitize_the_label(tmp_path):
    log, bin_, err = capture_paths(tmp_path, "a b/../c:d", STAMP)
    assert [p.name for p in (log, bin_, err)] == [
        f"{STAMP}-a-b-..-c-d.log", f"{STAMP}-a-b-..-c-d.bin", f"{STAMP}-a-b-..-c-d.stderr.log"]
    assert {p.parent for p in (log, bin_, err)} == {tmp_path}


def test_invocations_never_share_capture_paths(tmp_path):
    session, _ = make(tmp_path)
    join = var4024()[0]
    first, second = session.invocation(join), session.invocation(join)
    assert first.bin_path.name == f"{STAMP}-var4024.bin"
    assert second.bin_path.name == f"{STAMP}-var4024-2.bin"


# -- the command line ---------------------------------------------------------------------------

def test_golden_invocation_command(tmp_path):
    join = var4024()[0]
    log, bin_, err = capture_paths(tmp_path, join.label, STAMP)
    inv = Invocation(join, DEFAULT_KEYS, "/dev/cu.usbserial-0001", log, bin_, err)
    assert inv.command() == [
        "sudo", "-nE", str(VENV_PYTHON), "-u", str(HOST_SCRIPT),
        "--keys", str(DEFAULT_KEYS), "--expect-console", "firered",
        "--buffer-script", "call-chain",
        "--chain-step", "call:GetVarPointer,0x4024",
        "--chain-step", "read16:prev",
        "--chain-step", "read32:0x30042D0",
        "--dump-file", str(tmp_path / f"{STAMP}-var4024.bin")]
    assert inv.env() == {"POKELDN_RADIO": "esp32:/dev/cu.usbserial-0001"}
    export, command = inv.render().split("\n")
    assert export == "export POKELDN_RADIO=esp32:/dev/cu.usbserial-0001"
    assert command == " ".join(inv.command()) + f" | tee {log}"


def test_host_argv_paths_are_absolute_and_expect_console_optional(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    join = var4024()[0]
    inv = Invocation(join, "keys/prod.keys", "/dev/x", *capture_paths("cap", "v", STAMP),
                     expect_console=None)
    argv = inv.host_argv()
    assert "--expect-console" not in argv
    assert argv[1] == str(tmp_path / "keys" / "prod.keys")
    assert argv[-2:] == ["--dump-file", str(tmp_path / "cap" / f"{STAMP}-v.bin")]
    assert inv.command()[:2] == list(SUDO)


def test_sudo_false_execs_the_venv_python_directly(tmp_path):
    session, _ = make(tmp_path, sudo=False)
    inv = session.invocation(var4024()[0])
    assert inv.command()[:3] == [str(VENV_PYTHON), "-u", str(HOST_SCRIPT)]
    assert inv.env() == {"POKELDN_RADIO": "esp32:/dev/cu.usbserial-0001"}
    assert "sudo -nE" not in inv.render()


# -- scheduling ---------------------------------------------------------------------------------

def test_risky_join_gets_the_health_pair(tmp_path):
    session, _ = make(tmp_path)
    joins = risky()
    assert joins[0].risky
    plan = session.schedule(joins)
    assert [j.label for j in plan] == ["sb", "sb-health"]
    assert plan[1].host_args() == health_join().host_args()


def test_non_risky_join_is_scheduled_alone(tmp_path):
    session, _ = make(tmp_path)
    joins = var4024()
    assert not joins[0].risky
    assert session.schedule(joins) == list(joins)


def test_health_pair_already_next_is_not_doubled(tmp_path):
    session, _ = make(tmp_path)
    plan = session.schedule([*risky(), health_join("mine")])
    assert [j.label for j in plan] == ["sb", "mine"]


def test_budget_overflow_raises(tmp_path):
    session, _ = make(tmp_path, budget=1)
    with pytest.raises(BudgetError, match="needs 2 join.*health pair.*budget has 1 left"):
        session.schedule(risky())
    session.budget, session.used = 2, 1
    with pytest.raises(BudgetError, match="budget has 1 left.*1 fired"):
        session.schedule(two_joins())
    session.used = 0
    assert len(session.schedule(two_joins())) == 2


# -- dry run ------------------------------------------------------------------------------------

def test_dry_run_prints_checks_and_journals_without_capture_files(tmp_path):
    session, lines = make(tmp_path)
    results = session.go(risky())
    assert [type(r) for r in results] == [DryRun, DryRun]
    assert all(r.check.ok and not r.halted for r in results)
    assert session.used == 0 and session.stopped is None
    assert not (tmp_path / "captures").exists()
    rows = session.journal.rows
    assert [r["kind"] for r in rows] == ["dry-run", "dry-run"]
    assert rows[0]["label"] == "sb"
    assert rows[0]["host_args"] == risky()[0].host_args()
    assert rows[0]["command"][:2] == ["sudo", "-nE"]
    assert rows[0]["env"] == {"POKELDN_RADIO": "esp32:/dev/cu.usbserial-0001"}
    assert rows[0]["bin_path"].name == f"{STAMP}-sb.bin"
    assert rows[1]["label"] == "sb-health"
    assert any(line.startswith("sudo -nE ") for line in lines)
    assert sum(line.startswith("host check: the host accepts") for line in lines) == 2


def test_dry_run_does_not_spend_budget(tmp_path):
    session, _ = make(tmp_path, budget=2)
    session.go(risky())
    session.go(risky())
    assert session.used == 0


def test_host_check_refusal_blocks_the_run(tmp_path, monkeypatch):
    seen = []

    def refuse(argv):
        seen.append(argv)
        return HostCheck(False, "argument --chain-step: no")

    monkeypatch.setattr(sessionmod, "check_host_argv", refuse)
    session, lines = live(tmp_path, confirm=never)
    assert session.go(var4024()) == []
    assert session.stopped == "refused" and session.used == 0
    row = session.journal.one("plan")
    assert row["refused"] == "argument --chain-step: no" and row["label"] == "var4024"
    assert any("argument --chain-step: no" in line for line in lines)
    assert seen and seen[0][:1] == ["--keys"]


def test_refusal_of_a_later_join_costs_nothing(tmp_path, monkeypatch):
    real = sessionmod.check_host_argv

    def refuse_svc(argv):
        return HostCheck(False, "no sloop") if "sloop-svc" in argv else real(argv)

    monkeypatch.setattr(sessionmod, "check_host_argv", refuse_svc)
    session, _ = live(tmp_path, budget=2, confirm=never)
    assert session.go(risky()) == []                     # sb is fine, sb-health is refused
    assert session.journal.kinds() == ["plan"]


# -- live, with every effect faked --------------------------------------------------------------

def test_live_decline_runs_nothing(tmp_path):
    prompts = []
    session, lines = live(tmp_path, confirm=lambda p: prompts.append(p) or False)
    assert session.go(var4024()) == []
    assert session.used == 0 and session.stopped == "declined"
    assert session.journal.kinds() == ["decline"]
    assert len(prompts) == 1 and "go" in prompts[0]
    assert sessionmod.PRECONDITION in lines


def test_live_accept_runs_once_and_journals(tmp_path):
    runner, loader = FakeRunner(0), FakeLoader("answered")
    session, lines = live(tmp_path, runner=runner, load_outcome=loader,
                          radio_mac="20:50:0d:d1:15:20")
    outcomes = session.go(var4024())
    assert [o.verdict for o in outcomes] == ["answered"]
    assert session.used == 1 and session.stopped is None
    (inv,) = runner.invocations
    assert isinstance(inv, Invocation) and inv.join.label == "var4024"
    assert session.journal.kinds() == ["join-start", "join-end"]
    start, end = session.journal.rows
    assert start["radio_mac"] == "20:50:0d:d1:15:20"
    assert start["command"] == inv.command() and start["log_path"] == inv.log_path
    assert end["start_seq"] == start["seq"] and end["exit_status"] == 0
    assert end["verdict"] == "answered"
    assert loader.calls == [(inv.join, inv.log_path, inv.bin_path, start["seq"])]
    assert sessionmod.PRECONDITION in lines and "var4024: answered" in lines


def test_exit_status_is_recorded_not_trusted(tmp_path):
    runner, loader = FakeRunner(1, 1), FakeLoader("answered", "answered")
    session, _ = live(tmp_path, runner=runner, load_outcome=loader)
    outcomes = session.go(two_joins())
    assert [o.verdict for o in outcomes] == ["answered", "answered"]
    assert session.used == 2 and session.stopped is None
    ends = [r for r in session.journal.rows if r["kind"] == "join-end"]
    assert [(e["exit_status"], e["verdict"]) for e in ends] == [(1, "answered")] * 2


def test_crash_halts_and_prints_bisection_plan(tmp_path):
    runner, loader = FakeRunner(0), FakeLoader("crashed", window=(1, 1))
    plans = []

    def plan(join, window):
        plans.append((join.label, window))
        return ["next: two-1 steps 1..1 alone"]

    session, lines = live(tmp_path, runner=runner, load_outcome=loader, bisection_plan=plan)
    outcomes = session.go(two_joins())
    assert [o.verdict for o in outcomes] == ["crashed"]
    assert len(runner.invocations) == 1 and session.used == 1
    assert session.stopped == "halted"
    assert session.journal.kinds() == ["join-start", "join-end", "halt", "bisect-plan"]
    assert session.journal.one("halt")["skipped"] == ["two-2"]
    assert session.journal.one("bisect-plan")["plan"] == ["next: two-1 steps 1..1 alone"]
    assert plans == [("two-1", (1, 1))]
    assert any("HALTED" in line and "save and close normally" in line for line in lines)
    assert "  next: two-1 steps 1..1 alone" in lines


def test_other_halting_verdicts_halt_without_bisection(tmp_path):
    runner, loader = FakeRunner(1), FakeLoader("no-answer")
    session, _ = live(tmp_path, runner=runner, load_outcome=loader)
    session.go(two_joins())
    assert len(runner.invocations) == 1 and session.stopped == "halted"
    assert "bisect-plan" not in session.journal.kinds()


def test_live_risky_join_fires_its_health_pair(tmp_path):
    runner, loader = FakeRunner(0), FakeLoader("answered", "answered")
    session, _ = live(tmp_path, runner=runner, load_outcome=loader)
    session.go(risky())
    assert [inv.join.label for inv in runner.invocations] == ["sb", "sb-health"]
    assert session.used == 2
    with pytest.raises(BudgetError):
        session.go(var4024())


def test_live_without_keys_is_refused(tmp_path):
    session, _ = make(tmp_path, live=True, keys=tmp_path / "missing.keys")
    assert session.go(var4024()) == []
    assert session.stopped == "refused"
    assert "no keys file" in session.journal.one("plan")["refused"]


# -- the real runner refuses here ---------------------------------------------------------------

def test_run_host_refuses_under_pytest(tmp_path, monkeypatch):
    monkeypatch.setattr(sessionmod.subprocess, "Popen", never)
    inv = Invocation(var4024()[0], DEFAULT_KEYS, "/dev/x",
                     *capture_paths(tmp_path / "cap", "v", STAMP))
    with pytest.raises(RuntimeError, match="PYTEST_CURRENT_TEST"):
        run_host(inv, out=never)
    assert not (tmp_path / "cap").exists()


def test_run_host_refuses_with_no_live_env(tmp_path, monkeypatch):
    monkeypatch.setattr(sessionmod.subprocess, "Popen", never)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setenv("M1MU2_NO_LIVE", "1")
    inv = Invocation(var4024()[0], DEFAULT_KEYS, "/dev/x",
                     *capture_paths(tmp_path / "cap", "v", STAMP))
    with pytest.raises(RuntimeError, match="M1MU2_NO_LIVE"):
        run_host(inv, out=never)


def test_default_runner_refuses_and_halts(tmp_path, monkeypatch):
    monkeypatch.setattr(sessionmod.subprocess, "Popen", never)
    session, _ = live(tmp_path, runner=None)
    with pytest.raises(RuntimeError, match="refuses to start the live host"):
        session.go(var4024())
    assert session.journal.kinds() == ["join-start", "join-error"]
    assert session.used == 1 and session.stopped == "halted"     # counted: errs safe
