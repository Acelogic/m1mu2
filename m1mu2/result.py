"""What one join came back with, what that means, and what to run next when nothing came back.

Two kinds of evidence exist for a join: the host's tee'd log (always, if the host ran) and the
answer block it wrote to the .bin (only if the console answered). Parsing the block is upstream's
job - bs.parse_sloop_svc, bs.read_call_chain, bs.describe_call_chain - and is never re-done here.
The one byte-level read this module adds is each sloop-svc record's full thunk word, which
parse_sloop_svc narrows to its low byte: the echoed call-site word (0x4770DFnn for `swi nn`,
0x4770BEnn for `bkpt nn`) is the provenance that says which instruction actually ran.

THE ANSWER IS ALL OR NOTHING. Both step payloads point the console's outgoing message at their
result block only at .Ldone, after every step has returned [asm/sloop-svc.s, asm/call-chain.s].
A step that faults the core therefore sends back NOTHING - no partial block, no "last echoed
step" to read. A crash classifies the whole join as the fault window (1, n), and the only way to
narrow it is ACROSS joins: re-run prefixes of the program and see which one still answers.
Prefixes are valid bisection probes for call-chain too, because `prev` only ever points backwards:
the first m steps carry every dependency they need. Each probe is a live join followed by the
health pair (policy.HEALTH_PAIR), so bisection is slow on purpose: one probe per invocation at the
default budget, and the plan says how many are left.

Verdicts, from the log and the block alone (the host's exit status is never an input):
  answered     the block parsed and every step ran
  stopped      the block parsed, but the payload stopped early (an END or unknown op word)
  crashed      a console joined, nothing came back, and the link died abnormally or went idle
  ghost        no console joined: it was not on Mystery Gift -> friends search
  not-started  the log is empty: the host never ran (sudo -n with no cached credentials)
  no-answer    joined, nothing came back, no crash signature (the operator stopped it)
"""
import dataclasses
import math
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from . import pack, policy
from .upstream import bs

VERDICTS = ("answered", "stopped", "crashed", "ghost", "not-started", "no-answer")
HALTING = frozenset({"crashed", "ghost", "not-started", "no-answer"})

# The host's own messages [pokeldn/frlg/link/trade_runtime.py ConsoleLog: "[%7.1fs] " + message;
# pokeldn/ldn/transport.py; pokeldn/frlg/gift/mg_server.py; pokeldn/frlg/link/host_app.py;
# pokeldn/frlg/gift/host_mg_app.py _write_dump, a plain print]. Searched, not anchored, so a
# ConsoleLog prefix between the stamp and the message does not hide them.
_STAMP = re.compile(r"^\[\s*-?\d+(?:\.\d+)?s\]\s?")
_PATTERNS = {
    "joined": re.compile(r"A console joined the network\."),
    "dump": re.compile(r"Buffer script dump: (\d+) bytes of console memory"),
    "short-block": re.compile(r"Buffer script dump: block (\d+) came back (\d+) bytes, "
                              r"expected (\d+)"),
    "status": re.compile(r"Buffer script status: 0x([0-9A-Fa-f]{8})"),
    "close": re.compile(r"Switch sent the RFU disconnect frame \(D\) in .*: the normal close\."),
    "abnormal": re.compile(r"Switch sent the RFU disconnect frame \(D\) while the host is in "),
    "in-flight": re.compile(r"a block send was IN FLIGHT when it left: "),
    "idle": re.compile(r"No meaningful Switch traffic for \S+s; stopping host\."),
    "wrote": re.compile(r"^wrote (\d+) bytes of console memory to (.+)$"),
}
CRASH_SIGNS = ("abnormal", "in-flight", "idle")

_SWI, _BKPT = 0xDF, 0xBE        # THUMB `swi nn` / `bkpt nn` opcode bytes in the thunk word


@dataclass(frozen=True)
class Provenance:
    """Where a result came from: the capture files, the journal entry, and the log lines (1-based)
    the verdict rests on."""
    label: str
    log_path: str | None = None
    bin_path: str | None = None
    journal_seq: int | None = None
    log_lines: tuple = ()

    def describe(self):
        lines = []
        if self.log_path:
            cited = f" (lines {', '.join(map(str, self.log_lines))})" if self.log_lines else ""
            lines.append(f"log: {self.log_path}{cited}")
        elif self.log_lines:
            lines.append(f"log lines {', '.join(map(str, self.log_lines))}")
        if self.bin_path:
            lines.append(f"bin: {self.bin_path}")
        if self.journal_seq is not None:
            lines.append(f"journal seq {self.journal_seq}")
        return lines


@dataclass(frozen=True)
class SvcCall:
    """One sloop-svc record: the call-site word the console echoed and r0..r3 as the call left
    them [asm/sloop-svc.s, result block +0x10 + 20 * index]."""
    index: int                  # 1-based, in program order
    number: int
    mode: str                   # "swi" | "bkpt" | "?" from the echoed opcode byte
    call_site: int              # the full 32-bit THUMB thunk word, e.g. 0x4770DF53
    regs: tuple

    def describe(self):
        regs = " ".join(f"{v:08X}" for v in self.regs)
        return f"{self.index}. {self.mode} 0x{self.number:02X} @ 0x{self.call_site:08X}: " \
               f"r0..r3 {regs}"


@dataclass(frozen=True)
class SvcResult:
    returned: bool
    calls: tuple
    data: bytes

    def describe(self):
        lines = [f"sloop-svc: {len(self.calls)} call(s) recorded, "
                 + ("every call returned" if self.returned else "the returned marker is missing")]
        lines += [f"   {call.describe()}" for call in self.calls]
        lines.append(f"   data after the last call: {self.data!r}")
        return lines


@dataclass(frozen=True)
class ChainResult:
    calls: int
    count: int
    executed: int
    refused: int
    values: tuple
    lines: tuple                # bs.describe_call_chain(raw, join.steps)

    def describe(self):
        return list(self.lines)


@dataclass(frozen=True)
class JoinOutcome:
    verdict: str
    label: str
    result: object              # SvcResult | ChainResult | None
    fault_window: tuple | None  # (lo, hi): 1-based, inclusive steps the fault is among
    evidence: tuple
    provenance: Provenance

    @property
    def halted(self):
        return self.verdict in HALTING

    def describe(self):
        head = f"{self.label or 'join'}: {self.verdict}"
        if self.fault_window:
            lo, hi = self.fault_window
            head += f", fault in step {lo}" if lo == hi else f", fault in steps {lo}..{hi}"
        lines = [head]
        if self.result is not None:
            lines += [f"  {line}" for line in self.result.describe()]
        lines += [f"  - {line}" for line in self.evidence]
        lines += [f"  {line}" for line in self.provenance.describe()]
        return lines


def parse_answer(join, raw):
    """-> SvcResult | ChainResult from the answer block. Raises ValueError (bs.BufferScriptError
    is one) on a block upstream's parser refuses."""
    raw = bytes(raw)
    if join.script == bs.SLOOP_SVC:
        got = bs.parse_sloop_svc(raw)
        calls = []
        for index, (number, regs) in enumerate(got["calls"]):
            # The only byte-level read in m1mu2: parse_sloop_svc keeps thunk & 0xFF, and the
            # whole echoed word is the provenance [asm/sloop-svc.s, +0x10 + 20 * index].
            at = 0x10 + bs.SLOOP_RECORD_SIZE * index
            site = int.from_bytes(raw[at:at + 4], "little")
            mode = {_SWI: "swi", _BKPT: "bkpt"}.get((site >> 8) & 0xFF, "?")
            calls.append(SvcCall(index + 1, number, mode, site, tuple(regs)))
        return SvcResult(bool(got["returned"]), tuple(calls), bytes(got["data"]))
    if join.script == bs.CALL_CHAIN:
        got = bs.read_call_chain(raw)
        return ChainResult(got["calls"], got["count"], got["executed"], got["refused"],
                           tuple(got["values"]), tuple(bs.describe_call_chain(raw, join.steps)))
    raise ValueError(f"m1mu2 parses {' and '.join(pack.SCRIPTS)} answers, not {join.script!r}")


def scan_log(log_text):
    """-> {kind: [(line number, message)]} for every host message classify() reads; the message
    has its timestamp stripped. Kinds are the keys of _PATTERNS."""
    found = {kind: [] for kind in _PATTERNS}
    for number, line in enumerate((log_text or "").splitlines(), start=1):
        message = _STAMP.sub("", line.rstrip(), count=1)
        for kind, pattern in _PATTERNS.items():
            if pattern.search(message):
                found[kind].append((number, message))
    return found


def _cite(entries):
    return [f"log {number}: {message.strip()}" for number, message in entries]


def _cross_checks(join, raw, result, scan):
    """Evidence that the block is the one this join asked for. Notes, never failures."""
    notes = []
    for number, message in scan["dump"]:
        size = int(_PATTERNS["dump"].search(message).group(1))
        if size != len(raw):
            notes.append(f"log {number} says {size} bytes came back, the answer given is "
                         f"{len(raw)} bytes")
    if len(raw) != join.answer_size():
        notes.append(f"the answer is {len(raw)} bytes; this join's block is "
                     f"{join.answer_size()}")
    if isinstance(result, SvcResult):
        echoed = tuple(call.number for call in result.calls)
        if result.returned and echoed != join.numbers:
            asked = ", ".join(f"0x{n:02X}" for n in join.numbers)
            got = ", ".join(f"0x{n:02X}" for n in echoed) or "none"
            notes.append(f"the console echoed {got}; this join asked for {asked}")
        want = "bkpt" if join.steps[0].bkpt else "swi"
        odd = [call.index for call in result.calls if call.mode != want]
        if odd:
            notes.append(f"call(s) {', '.join(map(str, odd))} echoed a call site that is not "
                         f"`{want}`")
    elif result.count != len(join.steps):
        notes.append(f"the chain echoed a count of {result.count}; this join has "
                     f"{len(join.steps)} step(s)")
    return notes


def classify(join, log_text, raw=None, *, provenance=None):
    """-> JoinOutcome from the log text and the answer bytes (None when there is no .bin)."""
    provenance = provenance or Provenance(join.label)
    label = provenance.label or join.label
    n_steps = len(join.steps)
    scan = scan_log(log_text)
    cited = []

    def outcome(verdict, result=None, window=None, evidence=()):
        lines = tuple(sorted({number for number, _ in cited}))
        return JoinOutcome(verdict, label, result, window, tuple(evidence),
                           dataclasses.replace(provenance, log_lines=lines))

    if not any(line.strip() for line in (log_text or "").splitlines()):
        return outcome("not-started", evidence=(
            "the log is empty: the host never ran (no cached credentials for sudo -n, or it "
            "died before its first line)",))

    if not scan["joined"]:
        cited += scan["idle"]
        evidence = ["no 'A console joined the network.' line: nothing joined, so the console "
                    "was not on Mystery Gift -> friends search"] + _cite(scan["idle"])
        if raw:
            evidence.append("an answer file was given anyway; it cannot belong to this run")
        return outcome("ghost", evidence=evidence)

    joined = scan["joined"][:1]
    crash = sorted(entry for kind in CRASH_SIGNS for entry in scan[kind])
    result, failure = None, None
    if raw:
        try:
            result = parse_answer(join, raw)
        except ValueError as exc:
            failure = f"the answer file does not parse: {exc}"

    if result is not None:
        cited += joined + scan["status"] + scan["dump"]
        evidence = _cite(joined + scan["status"] + scan["dump"])
        evidence += _cross_checks(join, bytes(raw), result, scan)
        if crash:
            cited += crash
            evidence += ["the link died abnormally AFTER the answer arrived; the program "
                         "itself ran to the end"] + _cite(crash)
        if isinstance(result, SvcResult):
            if result.returned:
                return outcome("answered", result, None, evidence)
            lo = min(len(result.calls) + 1, n_steps)
            evidence.append(f"the returned marker is missing after {len(result.calls)} call(s)")
            return outcome("stopped", result, (lo, n_steps), evidence)
        if result.executed == result.count and not result.refused:
            return outcome("answered", result, None, evidence)
        step = min(result.executed + 1, n_steps)
        why = (f"op word 0x{result.refused:08X} is not one the payload has" if result.refused
               else "its op word was zero (END)")
        evidence.append(f"the chain ran {result.executed} of {result.count} step(s); step "
                        f"{step} did not run: {why}")
        return outcome("stopped", result, (step, step), evidence)

    answered_lines = scan["dump"] + scan["wrote"]
    if crash:
        cited += joined + crash + answered_lines
        evidence = _cite(joined + crash)
        if failure:
            evidence.append(failure)
        if answered_lines:
            # The block is only sent after the last step returned, so the program finished.
            evidence += _cite(answered_lines) + [
                "an answer arrived before the link died, so every step returned: the fault is "
                "after the program, not inside it; recover the .bin rather than bisect"]
            return outcome("crashed", None, None, evidence)
        evidence.append(f"nothing came back, and a faulting step sends nothing: the fault is "
                        f"somewhere in steps 1..{n_steps}")
        return outcome("crashed", None, (1, n_steps), evidence)

    cited += joined + scan["close"] + answered_lines + scan["short-block"]
    evidence = _cite(joined)
    if failure:
        evidence.append(failure)
    evidence.append("a console joined but nothing came back and the link did not die abnormally "
                    "(the host was stopped, e.g. Ctrl-C)")
    evidence += _cite(scan["short-block"] + scan["close"])
    if answered_lines:
        evidence += _cite(answered_lines)
        if not raw:
            evidence.append("the log shows an answer arrived, but no answer bytes were given: "
                            "the .bin is missing or empty")
    return outcome("no-answer", None, None, evidence)


def _read_text(path):
    if not path:
        return "", None
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace"), None
    except FileNotFoundError:
        return "", f"no log file at {path}"


def _read_bytes(path):
    if not path:
        return None
    try:
        return Path(path).read_bytes() or None
    except FileNotFoundError:
        return None


def load_outcome(join, log_path, bin_path, *, journal_seq=None):
    """-> classify() over the capture files. A missing log reads as "", a missing or empty .bin
    as no answer."""
    log_text, note = _read_text(log_path)
    provenance = Provenance(join.label, str(log_path) if log_path else None,
                            str(bin_path) if bin_path else None, journal_seq)
    outcome = classify(join, log_text, _read_bytes(bin_path), provenance=provenance)
    if note:
        outcome = dataclasses.replace(outcome, evidence=outcome.evidence + (note,))
    return outcome


def _check_window(n_steps, window):
    lo, hi = window
    if not 1 <= lo <= hi <= n_steps:
        raise ValueError(f"a fault window is 1 <= lo <= hi <= {n_steps}, got {window!r}")
    return lo, hi


def bisect(n_steps, crashes, lo=1):
    """-> (fault step, prefix lengths probed). `crashes(m)` answers "do the first m steps
    fault?"; the full program is known to. Pure: the live loop runs one probe per invocation."""
    lo, hi = _check_window(n_steps, (lo, n_steps))
    probed = []
    while lo < hi:
        m = (lo + hi) // 2
        probed.append(m)
        if crashes(m):
            hi = m
        else:
            lo = m + 1
    return lo, tuple(probed)


def next_probe(join, window):
    """-> the prefix Join to run next, or None once the window is one step (or there is none).
    Built with allow_unsafe because the full join already passed policy (and ran)."""
    if window is None:
        return None
    lo, hi = _check_window(len(join.steps), window)
    if lo == hi:
        return None
    m = (lo + hi) // 2
    return pack.compile_program(join.steps[:m], allow_unsafe=True,
                                label=f"{join.label or 'join'}-prefix{m}")[0]


def bisection_plan(join, window):
    """-> human lines: where the fault is, the next prefix, and what bisecting it costs."""
    if window is None:
        return ["no fault window: no step is implicated (every step returned, or nothing ran), "
                "so there is nothing to bisect"]
    lo, hi = _check_window(len(join.steps), window)
    if lo == hi:
        return [f"fault isolated to step {lo}: {pack.step_text(join.steps[lo - 1])}"]
    probe = next_probe(join, window)
    m = len(probe.steps)
    pair = " + ".join(f"0x{n:02X}" for n in policy.HEALTH_PAIR)
    worst = math.ceil(math.log2(hi - lo + 1))
    return [
        f"fault window: steps {lo}..{hi} of {len(join.steps)} in {join.label or 'join'} (a "
        "faulting join answers nothing, so the window narrows only by re-running prefixes)",
        f"next probe: the first {m} step(s) as {probe.label}: {shlex.join(probe.host_args())}",
        f"  it answers -> the fault is in {m + 1}..{hi}; it crashes -> in {lo}..{m}",
        f"each probe costs 2 joins (the probe, then the health pair {pair}), so it is one probe "
        "per invocation at the default budget",
        f"worst case {worst} more probe(s)",
    ]
