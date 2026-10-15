"""Joins -> frlg_mg_host.py command lines -> (only with --live, only after a typed `go`) a run.

A Session turns compiled joins (m1mu2.pack) into the exact host invocation, checks each one with
the host's own parser offline (upstream.check_host_argv), and then either prints it (dry run, the
default) or fires it, one join at a time, behind a human gate:

- Budget: at most `budget` live joins per invocation (CLAUDE.md "Join economy discipline").
- Verify-after-risk: every risky join is followed by the health pair (policy.HEALTH_PAIR), and the
  pair counts against the budget. A dry run schedules exactly what a live run would.
- Pause-confirm: before every live join the console precondition is printed and the operator
  must type `go`. Nothing fires silently.
- The host's exit status is journaled and never trusted: it is 0 only when a console joined and the
  engine succeeded, 1 with no console, 130 on Ctrl-C and 124 on --idle-timeout. The tee'd stdout
  log decides (m1mu2.result.load_outcome).
- A halting verdict stops the sequence; a crash prints a bisection plan. Bisection never spends a
  join on its own: the plan is for the operator's next invocation.

Journal, result parsing and the runner are injected; result.py and journal.py are imported lazily
so this module imports (and its tests run) without them.
"""
import functools
import os
import re
import shlex
import signal
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import pack
from .upstream import HOST_SCRIPT, REPO_ROOT, VENV_PYTHON, HostCheck, check_host_argv

CAPTURES_DIR = REPO_ROOT / "captures" / "m1mu2"
DEFAULT_KEYS = REPO_ROOT / "keys" / "prod.keys"
DEFAULT_PORT = "/dev/cu.usbserial-0001"
DEFAULT_BUDGET = 2
# Live hosting is run as root, and -E keeps POKELDN_RADIO through sudo: without it the host never
# sees the board and fails with a misleading "visible PHYs: none". -n fails instead of prompting
# for a password into a tee'd pipe; cache credentials with `sudo -v` first, in the same terminal
# (macOS sudo caches per tty). sudo=False (--no-sudo) runs the host as the operator: the host's own
# needs_root() is False whenever POKELDN_RADIO names the ESP32 board.
SUDO = ("sudo", "-nE")
PRECONDITION = ("The console must sit on Mystery Gift -> friends search/waiting screen (set it up "
                "by hand and confirm visually).")
NO_LIVE_ENV = ("PYTEST_CURRENT_TEST", "M1MU2_NO_LIVE")
STOP_REFUSED, STOP_DECLINED, STOP_HALTED = "refused", "declined", "halted"

_UNSAFE_LABEL = re.compile(r"[^A-Za-z0-9._-]")


class BudgetError(RuntimeError):
    pass


def utcstamp(now=None):
    """-> "20261015T034501Z" for `now` (a datetime; naive is taken as UTC), default the clock."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_label(label):
    """A label as a file-name part: [A-Za-z0-9._-] kept, anything else "-"."""
    return _UNSAFE_LABEL.sub("-", str(label)) or "join"


def capture_paths(captures_dir, label, stamp):
    """-> (log, bin, stderr) paths: <stamp>-<label>.log / .bin / .stderr.log in `captures_dir`."""
    base = Path(captures_dir) / f"{stamp}-{safe_label(label)}"
    return (base.with_name(base.name + ".log"), base.with_name(base.name + ".bin"),
            base.with_name(base.name + ".stderr.log"))


def _absolute(path):
    # Absolute because the host opens --dump-file relative to ITS cwd, and sudo may change that.
    return Path(path).expanduser().absolute()


@dataclass(frozen=True)
class Invocation:
    """One join as one host command line, plus where its evidence lands."""
    join: object
    keys: Path
    port: str
    log_path: Path
    bin_path: Path
    stderr_path: Path
    expect_console: str | None = "firered"
    sudo: bool = True

    def host_argv(self):
        """Everything after the script path. --expect-console makes the host refuse (send
        nothing to) a console that is not that cartridge."""
        argv = ["--keys", str(_absolute(self.keys))]
        if self.expect_console is not None:
            argv += ["--expect-console", self.expect_console]
        return argv + [*self.join.host_args(), "--dump-file", str(_absolute(self.bin_path))]

    def command(self):
        """The argv to exec. -u: unbuffered, so the tee'd log streams line by line."""
        return [*(SUDO if self.sudo else ()), str(VENV_PYTHON), "-u", str(HOST_SCRIPT),
                *self.host_argv()]

    def env(self):
        """What the command needs on top of the caller's environment: the radio board."""
        return {"POKELDN_RADIO": f"esp32:{self.port}"}

    def render(self):
        """The two shell lines an operator could paste: the export, then the tee'd command."""
        radio = self.env()["POKELDN_RADIO"]
        return (f"export POKELDN_RADIO={shlex.quote(radio)}\n"
                + shlex.join(self.command()) + " | tee " + shlex.quote(str(self.log_path)))


@dataclass(frozen=True)
class DryRun:
    """What a dry run produced for one join: the invocation and the host's verdict on it."""
    join: object
    invocation: Invocation
    check: HostCheck
    journal_seq: int | None = None
    verdict: str = "dry-run"
    fault_window: tuple | None = None

    @property
    def label(self):
        return self.join.label

    @property
    def halted(self):
        return False

    def describe(self):
        return [f"{self.label or 'join'}: dry run, {self.check.message}"]


def _ask_go(prompt):
    """The default gate: only the exact word `go` fires."""
    try:
        return input(prompt).strip() == "go"
    except EOFError:
        return False


@functools.cache
def _health_args():
    return tuple(pack.health_join().host_args())


def _is_health(join):
    """Is `join` the health pair itself (same payload, whatever its label)?"""
    return tuple(join.host_args()) == _health_args()


def run_host(inv, out=print):
    """The real runner: exec inv.command(), tee stdout to inv.log_path and `out`, stderr to
    inv.stderr_path. -> the host's exit status (recorded, never trusted).

    stderr gets its own file because the conda crash-report spam after a failure is known noise;
    runs are judged only by the stdout log. stdin is /dev/null: the host reads nothing, and the
    terminal belongs to the go/no-go prompt."""
    blocked = [name for name in NO_LIVE_ENV if os.environ.get(name)]
    if blocked:
        raise RuntimeError(f"m1mu2 refuses to start the live host while {', '.join(blocked)} is "
                           "set (tests and offline sessions never touch the radio)")
    inv.log_path.parent.mkdir(parents=True, exist_ok=True)
    inv.bin_path.parent.mkdir(parents=True, exist_ok=True)
    with open(inv.log_path, "w", encoding="utf-8") as log, \
            open(inv.stderr_path, "w", encoding="utf-8") as err:
        proc = subprocess.Popen(inv.command(), env={**os.environ, **inv.env()},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err,
                                text=True, encoding="utf-8", errors="replace", bufsize=1)
        while True:
            try:
                line = proc.stdout.readline()
                if not line:
                    break
                log.write(line)
                log.flush()
                out(line.rstrip("\n"))
            except KeyboardInterrupt:
                _interrupt(proc, out)
        while True:
            try:
                return proc.wait()
            except KeyboardInterrupt:
                _interrupt(proc, out)


def _interrupt(proc, out):
    """Ctrl-C: ask the host to wind down (it exits 130 and still writes its log), keep draining.
    From a terminal the host already got the SIGINT through the shared foreground process group;
    this forward covers a signal aimed at m1mu2 alone."""
    out("[m1mu2] interrupt: sending SIGINT to the host and draining its log")
    try:
        proc.send_signal(signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        pass


class Session:
    """Schedules joins against a budget and runs them: dry (print, check, journal) or live
    (gate, run, read the log, journal). `used` counts live joins fired this invocation;
    `stopped` says why the last go() ended early (refused / declined / halted) or is None."""

    def __init__(self, *, budget=DEFAULT_BUDGET, allow_unsafe=False, live=False, keys=DEFAULT_KEYS,
                 port=DEFAULT_PORT, captures_dir=CAPTURES_DIR, journal=None, confirm=None,
                 runner=None, load_outcome=None, bisection_plan=None, out=print,
                 radio_mac=None, expect_console="firered", sudo=True, now=None):
        self.budget = int(budget)
        self.allow_unsafe = bool(allow_unsafe)
        self.live = bool(live)
        self.keys = _absolute(keys)
        self.port = str(port)
        self.captures_dir = _absolute(captures_dir)
        self.out = out
        self.radio_mac = radio_mac
        self.expect_console = expect_console
        self.sudo = bool(sudo)
        self.confirm = confirm or _ask_go
        self.runner = runner or functools.partial(run_host, out=out)
        self._journal = journal
        self._load_outcome = load_outcome
        self._bisection_plan = bisection_plan
        self._now = now
        self._reserved = set()
        self.used = 0
        self.stopped = None

    # -- lazy collaborators ------------------------------------------------------------------

    @property
    def journal(self):
        """The injected journal; a path, or None (captures_dir/journal.jsonl), opens a Journal."""
        if self._journal is None or isinstance(self._journal, (str, os.PathLike)):
            from .journal import Journal
            path = self._journal or self.captures_dir / "journal.jsonl"
            self._journal = Journal(_absolute(path))
        return self._journal

    @property
    def load_outcome(self):
        if self._load_outcome is None:
            from .result import load_outcome
            self._load_outcome = load_outcome
        return self._load_outcome

    @property
    def bisection_plan(self):
        if self._bisection_plan is None:
            from .result import bisection_plan
            self._bisection_plan = bisection_plan
        return self._bisection_plan

    def _clock(self):
        if self._now is None:
            return None
        return self._now() if callable(self._now) else self._now

    # -- planning ----------------------------------------------------------------------------

    @property
    def remaining(self):
        return self.budget - self.used

    def schedule(self, joins):
        """-> the joins in firing order, each risky one followed by the health pair unless the
        next join already is it. Raises BudgetError if that exceeds what the budget has left."""
        joins = [joins] if isinstance(joins, pack.Join) else list(joins)
        plan = []
        for index, join in enumerate(joins):
            plan.append(join)
            following = joins[index + 1] if index + 1 < len(joins) else None
            if join.risky and not (following is not None and _is_health(following)):
                plan.append(pack.health_join(f"{join.label or 'join'}-health"))
        if len(plan) > self.remaining:
            added = len(plan) - len(joins)
            why = (f" ({added} of them the health pair that must follow a risky join)"
                   if added else "")
            raise BudgetError(
                f"this program needs {len(plan)} join(s){why} but the budget has "
                f"{self.remaining} left (budget {self.budget}, {self.used} fired this "
                f"invocation): {', '.join(j.label or 'join' for j in plan)}. Raise --budget, "
                "or split the program across invocations.")
        return plan

    def invocation(self, join, stamp=None):
        """-> the Invocation for `join`, with capture paths no other join of this session (or
        file on disk) already has."""
        return self._invocation(join, stamp, reserve=True)

    def _invocation(self, join, stamp, *, reserve):
        stamp = stamp or utcstamp(self._clock())
        label = join.label or "join"
        paths, n = capture_paths(self.captures_dir, label, stamp), 2
        while any(p in self._reserved or p.exists() for p in paths):
            paths, n = capture_paths(self.captures_dir, f"{label}-{n}", stamp), n + 1
        if reserve:
            self._reserved.update(paths)
        return Invocation(join, self.keys, self.port, *paths, expect_console=self.expect_console,
                          sudo=self.sudo)

    def _refuse(self, join, inv, message):
        self.stopped = STOP_REFUSED
        self.out(f"REFUSED {join.label or 'join'}: {message}")
        self.journal.append("plan", label=join.label, live=self.live,
                            host_args=inv.host_argv(), refused=message)

    # -- running -----------------------------------------------------------------------------

    def go(self, joins):
        """Schedule, check every join with the host's parser, then dry-run or fire them in order.
        -> list of DryRun (dry) or outcomes (live), one per join that ran."""
        self.stopped = None
        plan = self.schedule(joins)
        # Every join is checked before the first one fires: a refusal of join 2 must not cost
        # join 1. Each is checked again on its final command line below.
        for join in plan:
            draft = self._invocation(join, None, reserve=False)
            check = check_host_argv(draft.host_argv())
            if not check.ok:
                self._refuse(join, draft, check.message)
                return []
        if self.live and not self.keys.is_file():
            self._refuse(plan[0], self._invocation(plan[0], None, reserve=False),
                         f"no keys file at {self.keys}; pass --keys")
            return []
        results = []
        for index, join in enumerate(plan):
            inv = self.invocation(join)
            check = check_host_argv(inv.host_argv())
            if not check.ok:
                self._refuse(join, inv, check.message)
                break
            check_line = (f"host check: {check.message}"
                          + (f" (builds: {', '.join(check.codes)})" if check.codes else ""))
            if not self.live:
                results.append(self._dry(join, inv, check, check_line))
                continue
            outcome = self._fire(join, inv, check_line, index, plan)
            if outcome is None:
                break
            results.append(outcome)
            if outcome.halted:
                self._halt(join, outcome, plan[index + 1:])
                break
        if self.live:
            self.out(f"spent {self.used} of {self.budget} join(s) this invocation")
        return results

    def _dry(self, join, inv, check, check_line):
        for line in join.describe():
            self.out(line)
        for line in inv.render().splitlines():
            self.out(line)
        self.out(check_line)
        seq = self.journal.append(
            "dry-run", label=join.label, script=join.script, host_args=join.host_args(),
            command=inv.command(), env=inv.env(), log_path=inv.log_path, bin_path=inv.bin_path)
        return DryRun(join, inv, check, seq)

    def _fire(self, join, inv, check_line, index, plan):
        """One live join behind the gate. -> its outcome, or None if the operator declined."""
        self.out(PRECONDITION)
        if self.radio_mac is None:
            self.out("(no --mac given: the journal will not say which radio board fired)")
        for line in join.describe():
            self.out(line)
        for line in inv.render().splitlines():
            self.out(line)
        self.out(check_line)
        prompt = (f"join {index + 1}/{len(plan)} '{join.label or 'join'}' "
                  f"({self.remaining} of {self.budget} left) - type go to fire: ")
        if not self.confirm(prompt):
            self.stopped = STOP_DECLINED
            self.out("declined: nothing sent; the rest of the sequence is skipped")
            self.journal.append("decline", label=join.label, host_args=join.host_args(),
                                skipped=[j.label for j in plan[index:]])
            return None
        start_seq = self.journal.append(
            "join-start", label=join.label, script=join.script, host_args=join.host_args(),
            command=inv.command(), env=inv.env(), log_path=inv.log_path, bin_path=inv.bin_path,
            radio_mac=self.radio_mac)
        try:
            exit_status = self.runner(inv)
        except BaseException as exc:
            # Counted: the radio may have been up when it failed, and the budget errs safe.
            self.used += 1
            self.stopped = STOP_HALTED
            self.journal.append("join-error", label=join.label, start_seq=start_seq,
                                error=repr(exc))
            self.out(f"the runner failed ({exc!r}); the sequence is halted")
            raise
        self.used += 1
        # The exit status is evidence for the journal only; the log decides.
        outcome = self.load_outcome(join, inv.log_path, inv.bin_path, journal_seq=start_seq)
        self.journal.append(
            "join-end", label=join.label, start_seq=start_seq, exit_status=exit_status,
            verdict=outcome.verdict, fault_window=outcome.fault_window, log_path=inv.log_path,
            bin_path=inv.bin_path)
        for line in outcome.describe():
            self.out(line)
        return outcome

    def _halt(self, join, outcome, rest):
        self.stopped = STOP_HALTED
        self.journal.append("halt", label=join.label, verdict=outcome.verdict,
                            fault_window=outcome.fault_window, skipped=[j.label for j in rest])
        skipped = f"; skipped: {', '.join(j.label for j in rest)}" if rest else ""
        self.out(f"HALTED after {join.label or 'join'} ({outcome.verdict}){skipped}. Leave the "
                 "console to save and close normally; do not power it off mid-save.")
        if outcome.verdict == "crashed":
            plan = list(self.bisection_plan(join, outcome.fault_window))
            self.out("bisection plan (each line is a future join; none is spent automatically):")
            for line in plan:
                self.out(f"  {line}")
            self.journal.append("bisect-plan", label=join.label,
                                fault_window=outcome.fault_window, plan=plan)
