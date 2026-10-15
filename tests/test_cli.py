"""The Shell, `run FILE`, and `repl` as a process. Runner, gate, journal and log reader are fakes;
the one subprocess here is m1mu2's own CLI with M1MU2_NO_LIVE set, never the host."""
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from m1mu2 import cli
from m1mu2.cli import Shell
from m1mu2.pack import prev
from m1mu2.session import DEFAULT_KEYS, Session
from m1mu2.upstream import HOST_SCRIPT, REPO_ROOT, VENV_PYTHON

FIXED = datetime(2026, 10, 15, 3, 45, 1, tzinfo=timezone.utc)
STAMP = "20261015T034501Z"
PROGRAMS = Path(__file__).parent / "fixtures" / "programs"


class FakeJournal:
    def __init__(self, path=None):
        self.path = path
        self.rows = []

    def append(self, kind, **fields):
        assert not {"seq", "utc", "kind"} & set(fields)
        self.rows.append({"seq": len(self.rows) + 1, "kind": kind, **fields})
        return len(self.rows)

    def entries(self):
        return list(self.rows)


@dataclass
class FakeOutcome:
    verdict: str
    label: str = ""
    fault_window: tuple | None = None
    evidence: tuple = ()

    @property
    def halted(self):
        return self.verdict in {"crashed", "ghost", "not-started", "no-answer"}

    def describe(self):
        return [f"{self.label}: {self.verdict}"]


def never(*args, **kwargs):
    raise AssertionError("must not be called")


def answered(join, log_path, bin_path, *, journal_seq=None):
    return FakeOutcome("answered", join.label)


def shell(tmp_path, **kwargs):
    lines = []
    kwargs.setdefault("journal", FakeJournal())
    kwargs.setdefault("captures_dir", tmp_path / "captures")
    for name in ("runner", "confirm", "load_outcome", "bisection_plan"):
        kwargs.setdefault(name, never)
    session = Session(out=lines.append, now=FIXED, **kwargs)
    return Shell(session, out=lines.append), lines


def golden(captures):
    return (f"sudo -nE {VENV_PYTHON} -u {HOST_SCRIPT} --keys {DEFAULT_KEYS} "
            "--expect-console firered --buffer-script call-chain "
            "--chain-step call:GetVarPointer,0x4024 --chain-step read16:prev "
            f"--chain-step read32:0x30042D0 --dump-file {captures}/{STAMP}-var4024.bin")


# -- definition of done -------------------------------------------------------------------------

def test_golden_var4024_dry_run(tmp_path):
    sh, lines = shell(tmp_path)
    for line in (".call GetVarPointer 0x4024", ".peek prev 2", ".peek 0x030042D0",
                 ".go var4024"):
        assert sh.execute(line)
    captures = tmp_path / "captures"
    assert sh.errors == 0 and sh.queue == []
    assert f"{golden(captures)} | tee {captures}/{STAMP}-var4024.log" in lines
    assert "export POKELDN_RADIO=esp32:/dev/cu.usbserial-0001" in lines
    check = [line for line in lines if line.startswith("host check:")]
    assert check == ["host check: the host accepts this command line "
                     "(builds: BPRF, BPGF, BPRE, BPGE)"]
    (row,) = sh.session.journal.rows
    assert row["kind"] == "dry-run" and row["label"] == "var4024"
    assert " ".join(row["command"]) == golden(captures)
    assert not captures.exists()


def test_run_fixture_dry_run(tmp_path, capsys):
    journal = tmp_path / "j.jsonl"
    made = []

    def factory(path):
        made.append(FakeJournal(path))
        return made[-1]

    status = cli.main(["run", str(PROGRAMS / "var4024.muprog"), "--dry-run",
                       "--captures", str(tmp_path), "--journal", str(journal)],
                      journal_factory=factory, now=FIXED)
    out = capsys.readouterr().out
    assert status == 0
    assert golden(tmp_path) in out
    assert "dry run" in out
    assert [m.path for m in made] == [journal]
    assert [r["kind"] for r in made[0].rows] == ["dry-run"]


# -- run FILE -----------------------------------------------------------------------------------

def test_run_implicit_go_uses_the_file_stem(tmp_path, capsys):
    program = tmp_path / "noon.muprog"
    program.write_text(".call FlagGet 0x828  # a flag\n\n.peek 0x02000000 8\n")
    made = []
    status = cli.main(["run", str(program), "--captures", str(tmp_path / "c")],
                      journal_factory=lambda p: made.append(FakeJournal(p)) or made[-1],
                      now=FIXED)
    out = capsys.readouterr().out
    assert status == 0
    assert f"{STAMP}-noon.bin" in out
    assert made[0].path == tmp_path / "c" / "journal.jsonl"
    assert made[0].rows[0]["label"] == "noon"


def test_run_error_exits_nonzero(tmp_path, capsys):
    program = tmp_path / "bad.muprog"
    program.write_text(".peek 0x02000000\n.frobnicate\n.go never\n")
    status = cli.main(["run", str(program), "--captures", str(tmp_path)],
                      journal_factory=FakeJournal)
    out = capsys.readouterr().out
    assert status == 1
    assert "unknown command '.frobnicate'" in out and "bad.muprog:2" in out
    assert "sudo -nE" not in out


def test_run_policy_refusal_exits_nonzero(tmp_path, capsys):
    program = tmp_path / "poke.muprog"
    program.write_text(".poke 0x02000000 1\n")
    status = cli.main(["run", str(program), "--captures", str(tmp_path)],
                      journal_factory=FakeJournal)
    assert status == 1
    assert "needs --allow-unsafe" in capsys.readouterr().out


def test_dry_run_flag_beats_live(tmp_path, capsys):
    status = cli.main(["run", str(PROGRAMS / "var4024.muprog"), "--live", "--dry-run",
                       "--captures", str(tmp_path)],
                      journal_factory=FakeJournal, now=FIXED, runner=never, confirm=never)
    out = capsys.readouterr().out
    assert status == 0 and "dry run" in out and "LIVE" not in out


def test_live_run_with_fakes(tmp_path, capsys):
    keys = tmp_path / "prod.keys"
    keys.write_text("not a key\n")
    made, fired = [], []
    status = cli.main(["run", str(PROGRAMS / "var4024.muprog"), "--live", "--keys", str(keys),
                       "--mac", "20:50:0d:d1:15:20", "--captures", str(tmp_path)],
                      journal_factory=lambda p: made.append(FakeJournal(p)) or made[-1],
                      now=FIXED, runner=lambda inv: fired.append(inv) or 1,
                      confirm=lambda prompt: True, load_outcome=answered)
    out = capsys.readouterr().out
    assert status == 0 and "LIVE" in out
    assert len(fired) == 1 and fired[0].keys == keys
    kinds = [r["kind"] for r in made[0].rows]
    assert kinds == ["join-start", "join-end"]
    assert made[0].rows[0]["radio_mac"] == "20:50:0d:d1:15:20"
    assert made[0].rows[1]["exit_status"] == 1 and made[0].rows[1]["verdict"] == "answered"


def test_no_sudo_drops_sudo_from_render_and_runner(tmp_path, capsys):
    keys = tmp_path / "prod.keys"
    keys.write_text("not a key\n")
    made, fired = [], []
    status = cli.main(["run", str(PROGRAMS / "var4024.muprog"), "--live", "--no-sudo",
                       "--keys", str(keys), "--captures", str(tmp_path)],
                      journal_factory=lambda p: made.append(FakeJournal(p)) or made[-1],
                      now=FIXED, runner=lambda inv: fired.append(inv) or 0,
                      confirm=lambda prompt: True, load_outcome=answered)
    out = capsys.readouterr().out
    assert status == 0 and "sudo -nE" not in out
    assert fired[0].command()[:2] == [str(VENV_PYTHON), "-u"]
    assert made[0].rows[0]["command"][0] == str(VENV_PYTHON)


def test_live_decline_stops_the_file(tmp_path, capsys):
    keys = tmp_path / "prod.keys"
    keys.write_text("not a key\n")
    status = cli.main(["run", str(PROGRAMS / "var4024.muprog"), "--live", "--keys", str(keys),
                       "--captures", str(tmp_path)],
                      journal_factory=FakeJournal, runner=never, confirm=lambda p: False)
    assert status == cli.EXIT_STOPPED
    assert "declined" in capsys.readouterr().out


# -- the Shell ----------------------------------------------------------------------------------

def test_call_args_and_prev(tmp_path):
    sh, lines = shell(tmp_path)
    sh.execute(".call GetVarPointer 0x4024")
    sh.execute(".call FlagGet prev+0x10")
    assert lines[-1] == "  2. call:FlagGet,prev+0x10"
    sh.execute(".call FlagGet 1 prev")
    assert sh.errors == 1 and "only the FIRST argument" in lines[-1]
    sh.execute(".call NoSuchFunction")
    assert sh.errors == 2 and len(sh.queue) == 2


def test_peek_lengths_and_prev(tmp_path):
    sh, _ = shell(tmp_path)
    sh.execute(".peek 0x02000000")
    sh.execute(".peek prev+0x10 8")
    sh.execute(".peek 0x02000000 3")
    assert sh.errors == 1
    from m1mu2.pack import step_text
    assert [step_text(s) for s in sh.queue] == [
        "read32:0x2000000", "read32+keep:prev+0x10", "read32+keep:prev+0x14"]


def test_svc_options(tmp_path):
    sh, _ = shell(tmp_path)
    sh.execute(".svc 0x53 0x4A args=1,0x20 hex=0aff in=r0")
    assert sh.errors == 0
    first, second = sh.queue
    assert (first.number, second.number) == (0x53, 0x4A)
    assert first.operands == second.operands == ((1, 0x20), b"\x0a\xff", "r0", False)
    sh.execute(".svc 0x53 bkpt")
    assert sh.queue[-1].bkpt
    sh.execute(".svc args=1")
    sh.execute(".svc 0x53 hex=zz")
    sh.execute(".svc 0x53 colour=red")
    assert sh.errors == 3


def test_poke_needs_allow_unsafe_and_keeps_the_queue(tmp_path):
    sh, lines = shell(tmp_path)
    sh.execute(".poke 0x02000000 0x1234 2")
    sh.execute(".go")
    assert sh.errors == 1 and "needs --allow-unsafe" in lines[-1]
    assert len(sh.queue) == 1
    sh.execute(".poke 0x02000000 1 3")
    assert sh.errors == 2


def test_poke_with_allow_unsafe_renders_write_unsafe_and_health(tmp_path):
    sh, lines = shell(tmp_path, allow_unsafe=True)
    sh.execute(".poke 0x02000000 0x1234 2")
    sh.execute(".go poke")
    assert sh.errors == 0 and sh.queue == []
    commands = [line for line in lines if line.startswith("sudo -nE")]
    assert len(commands) == 2
    assert "--chain-step write16:0x2000000,0x1234 --write-unsafe" in commands[0]
    assert "--svc-number 0x53 --svc-number 0x4A" in commands[1]


def test_steps_list_and_replace(tmp_path):
    sh, lines = shell(tmp_path)
    sh.execute(".steps")
    assert lines[-1] == "(queue empty)"
    sh.execute(".steps call:FlagGet,0x828 read32+keep:0x2000000 svc:0x53")
    assert sh.errors == 0 and len(sh.queue) == 3
    lines.clear()
    sh.execute(".steps")
    assert lines == ["  1. call:FlagGet,0x828", "  2. read32+keep:0x2000000", "  3. swi 0x53()"]
    sh.execute(".steps read16:prev+")
    assert sh.errors == 1 and len(sh.queue) == 3


def test_budget_show_set_and_overflow_keeps_queue(tmp_path):
    sh, lines = shell(tmp_path)
    sh.execute(".budget")
    assert lines[-1] == "budget 2, 0 fired, 2 left"
    sh.execute(".budget 1")
    assert sh.session.budget == 1
    sh.execute(".steps read32:0x3005008 read16:prev+0x290")
    sh.execute(".go sb")
    assert sh.errors == 1 and "budget has 1 left" in lines[-1]
    assert len(sh.queue) == 2
    sh.execute(".budget -1")
    sh.execute(".budget lots")
    assert sh.errors == 3 and sh.session.budget == 1


def test_comments_blank_unknown_clear_help_quit(tmp_path):
    sh, lines = shell(tmp_path)
    assert sh.execute("") and sh.execute("   # nothing") and sh.execute(".peek 0x2000000 # c")
    assert len(sh.queue) == 1 and sh.errors == 0
    assert sh.execute("peek 0x2000000") and sh.errors == 1
    sh.execute(".clear")
    assert sh.queue == []
    sh.execute(".help")
    assert ".peek ADDR [LEN]" in lines[-1]
    assert sh.execute(".exit") is False
    assert Shell(sh.session, out=lines.append).execute(".QUIT") is False


def test_go_with_empty_queue_is_an_error(tmp_path):
    sh, lines = shell(tmp_path)
    sh.execute(".go")
    assert sh.errors == 1 and "at least one step" in lines[-1]


def test_go_decline_keeps_queue_and_fire_clears_it(tmp_path):
    keys = tmp_path / "prod.keys"
    keys.write_text("x")
    answers = [False, True]
    sh, lines = shell(tmp_path, live=True, keys=keys, confirm=lambda p: answers.pop(0),
                      runner=lambda inv: 0, load_outcome=answered)
    sh.execute(".peek 0x02000000")
    sh.execute(".go a")
    assert len(sh.queue) == 1 and "nothing ran; the queue is kept" in lines
    sh.execute(".go a")
    assert sh.queue == [] and sh.session.used == 1


def test_prev_value_parser():
    assert cli._value("prev") == prev
    assert cli._value("PREV+0x10") == prev + 0x10
    assert cli._value("0x30042D0") == 0x030042D0
    with pytest.raises(cli.ShellError):
        cli._value("prev", allow_prev=False)
    with pytest.raises(cli.ShellError):
        cli._value("prev+x")


# -- the REPL as a process (m1mu2's own CLI; never the host) ------------------------------------

@pytest.mark.parametrize("module", ["m1mu2.cli", "m1mu2"])
def test_repl_opens(tmp_path, module):
    env = {**os.environ, "M1MU2_NO_LIVE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", module, "repl", "--captures", str(tmp_path)],
        input=".help\n.quit\n", capture_output=True, text=True, cwd=REPO_ROOT, env=env,
        timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert cli.PROMPT in proc.stdout
    assert ".call NAME [ARG ...]" in proc.stdout
    assert "dry run" in proc.stdout
    assert not list(tmp_path.iterdir())
