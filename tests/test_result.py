"""result: answer blocks and host logs -> verdicts, provenance and bisection. Every block and log
here is SYNTHETIC, built from the documented layouts (tests/fixtures/logs/README.txt)."""
from pathlib import Path

import pytest

from m1mu2 import policy, result
from m1mu2.pack import compile_program, health_join, join_from_host_args, prev, probe, step_text
from m1mu2.result import (HALTING, VERDICTS, ChainResult, JoinOutcome, Provenance, SvcResult,
                          bisect, bisection_plan, classify, load_outcome, next_probe,
                          parse_answer)
from m1mu2.upstream import bs

LOGS = Path(__file__).parent / "fixtures" / "logs"
VAR4024 = [probe.call("GetVarPointer", 0x4024), probe.read16(prev), probe.read32(0x030042D0)]
EIGHT = (0x49, 0x4A, 0x4B, 0x50, 0x52, 0x53, 0x54, 0x53)

JOINED = "A console joined the network."
HOSTING = "Hosting a buffer script. On the Switch choose Mystery Gift -> Wonder Cards -> Friend."
ABNORMAL = ("Switch sent the RFU disconnect frame (D) while the host is in serving; it leaves LDN "
            "next. What the host sent just before this is the cause.")
IN_FLIGHT = "  a block send was IN FLIGHT when it left: sending frag 2"
IDLE = "No meaningful Switch traffic for 30s; stopping host."
CLOSE = "Switch sent the RFU disconnect frame (D) in done: the normal close."


def log(*messages):
    """ConsoleLog lines: `[%7.1fs] message` [trade_runtime.ConsoleLog]."""
    return "".join(f"[{1.0 + i:7.1f}s] {m}\n" for i, m in enumerate(messages))


def dump_line(raw):
    return f"Buffer script dump: {len(raw)} bytes of console memory, head {raw[:16].hex()}"


def sloop_answer(calls, data=b"", *, returned=True, bkpt=False, opcode=None):
    """A sloop-svc result block [asm/sloop-svc.s]: calls = [(number, (r0, r1, r2, r3))]."""
    block = bytearray(bs.sloop_svc_answer_size(len(data)))

    def put(at, value):
        block[at:at + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    put(0x00, bs.SLOOP_REACHED)
    put(0x04, len(calls))
    put(0x08, bs.SLOOP_RETURNED if returned else 0)
    put(0x0C, len(data))
    op = opcode if opcode is not None else (0xBE if bkpt else 0xDF)
    for index, (number, regs) in enumerate(calls):
        at = 0x10 + bs.SLOOP_RECORD_SIZE * index
        put(at, 0x47700000 | op << 8 | number)
        for slot, value in enumerate(regs):
            put(at + 4 + 4 * slot, value)
    block[bs.SLOOP_HEADER_SIZE:bs.SLOOP_HEADER_SIZE + len(data)] = data
    return bytes(block)


def chain_answer(values, count, *, executed=None, refused=0, calls=1):
    """A call-chain answer [asm/call-chain.s, 0x190]: calls, count, executed, refused, values."""
    executed = len(values) if executed is None else executed
    words = [calls, count, executed, refused] + list(values) + [0] * (16 - len(values))
    return b"".join((w & 0xFFFFFFFF).to_bytes(4, "little") for w in words)


ZERO = (0, 0, 0, 0)


@pytest.fixture
def health():
    return health_join()


@pytest.fixture
def eight():
    return compile_program([probe.svc(n) for n in EIGHT], label="eight")[0]


@pytest.fixture
def var4024():
    return compile_program(VAR4024, label="var4024")[0]


# -- parse_answer ----------------------------------------------------------------------------

def test_health_pair_answer_echoes_call_sites(health):
    raw = sloop_answer([(0x53, ZERO), (0x4A, (0, 1, 2, 3))])
    got = parse_answer(health, raw)
    assert isinstance(got, SvcResult) and got.returned and got.data == b""
    assert [c.index for c in got.calls] == [1, 2]
    assert [c.number for c in got.calls] == list(policy.HEALTH_PAIR)
    assert [c.call_site for c in got.calls] == [0x4770DF53, 0x4770DF4A]
    assert [c.mode for c in got.calls] == ["swi", "swi"]
    assert got.calls[1].regs == (0, 1, 2, 3)


def test_bkpt_answer_mode():
    join = compile_program([probe.svc(0xFF, bkpt=True)], allow_unsafe=True)[0]
    got = parse_answer(join, sloop_answer([(0xFF, ZERO)], bkpt=True))
    assert got.calls[0].mode == "bkpt" and got.calls[0].call_site == 0x4770BEFF


def test_unknown_opcode_mode(health):
    got = parse_answer(health, sloop_answer([(0x53, ZERO)], opcode=0x12))
    assert got.calls[0].mode == "?"


def test_data_comes_back():
    join = compile_program([probe.svc(0x4D, data="hi", data_in="r0")])[0]
    raw = sloop_answer([(0x4D, ZERO)], data=b"hi")
    assert len(raw) == join.answer_size()
    assert parse_answer(join, raw).data == b"hi"


@pytest.mark.parametrize("raw", [b"", b"\x00" * 16, b"\x00" * bs.SLOOP_HEADER_SIZE])
def test_malformed_svc_block_raises(health, raw):
    with pytest.raises(ValueError):
        parse_answer(health, raw)


def test_short_chain_block_raises(var4024):
    with pytest.raises(ValueError):
        parse_answer(var4024, b"\x01" * 40)


def test_chain_answer_uses_upstream_lines(var4024):
    raw = chain_answer([0x02026E40, 7, 0x12345678], 3)
    got = parse_answer(var4024, raw)
    assert isinstance(got, ChainResult)
    assert (got.calls, got.count, got.executed, got.refused) == (1, 3, 3, 0)
    assert got.values[:3] == (0x02026E40, 7, 0x12345678) and len(got.values) == 16
    assert got.lines == tuple(bs.describe_call_chain(raw, var4024.steps))
    assert got.lines[0].startswith("call-chain: 3 of 3 step(s)")


# -- classify: one test per rule -------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "\n  \n\t\n"])
def test_not_started(health, text):
    out = classify(health, text)
    assert out.verdict == "not-started" and out.fault_window is None and out.halted
    assert "never ran" in out.evidence[0]


def test_ghost(health):
    text = log(HOSTING, IDLE)
    out = classify(health, text)
    assert out.verdict == "ghost" and out.fault_window is None and out.halted
    assert "friends search" in out.evidence[0]
    assert out.provenance.log_lines == (2,)


def test_answered_svc_from_fixture(tmp_path, health):
    raw = sloop_answer([(0x53, ZERO), (0x4A, ZERO)])
    bin_path = tmp_path / "health.bin"
    bin_path.write_bytes(raw)
    log_path = LOGS / "health-answered.log"
    out = load_outcome(health, log_path, bin_path, journal_seq=7)
    assert out.verdict == "answered" and not out.halted and out.fault_window is None
    assert out.label == "health"
    assert out.provenance == Provenance("health", str(log_path), str(bin_path), 7, (3, 4, 5))
    assert [c.call_site for c in out.result.calls] == [0x4770DF53, 0x4770DF4A]
    assert not any("bytes" in e and "says" in e for e in out.evidence)   # 177 == 177
    text = "\n".join(out.describe())
    assert "health: answered" in text and "0x4770DF4A" in text and "journal seq 7" in text


def test_answered_chain(var4024):
    raw = chain_answer([0x02026E40, 7, 0x12345678], 3)
    out = classify(var4024, log(HOSTING, JOINED, dump_line(raw), CLOSE), raw)
    assert out.verdict == "answered" and out.fault_window is None
    assert out.result.lines == tuple(bs.describe_call_chain(raw, var4024.steps))
    assert out.provenance.log_lines == (2, 3)
    assert any("3 of 3" in line for line in out.describe())


def test_stopped_svc_window(eight):
    raw = sloop_answer([(n, ZERO) for n in EIGHT[:3]], returned=False)
    out = classify(eight, log(JOINED, dump_line(raw)), raw)
    assert out.verdict == "stopped" and not out.halted
    assert out.fault_window == (4, 8)


def test_stopped_chain_window(var4024):
    raw = chain_answer([0x02026E40], 3, executed=1)
    out = classify(var4024, log(JOINED, dump_line(raw)), raw)
    assert out.verdict == "stopped" and out.fault_window == (2, 2)
    assert any("zero (END)" in e for e in out.evidence)
    assert bisection_plan(var4024, out.fault_window) == [
        f"fault isolated to step 2: {step_text(var4024.steps[1])}"]
    assert next_probe(var4024, out.fault_window) is None


def test_stopped_chain_refused(var4024):
    raw = chain_answer([0x02026E40, 7], 3, executed=2, refused=0x000000EE)
    out = classify(var4024, log(JOINED, dump_line(raw)), raw)
    assert out.verdict == "stopped" and out.fault_window == (3, 3)
    assert any("0x000000EE" in e for e in out.evidence)


def test_no_answer(health):
    out = classify(health, log(HOSTING, JOINED))
    assert out.verdict == "no-answer" and out.fault_window is None and out.halted
    assert any("Ctrl-C" in e for e in out.evidence)


def test_no_answer_notes_missing_bin(health):
    raw = sloop_answer([(0x53, ZERO), (0x4A, ZERO)])
    text = log(JOINED, dump_line(raw), CLOSE) + "wrote 177 bytes of console memory to x.bin\n"
    out = classify(health, text, None)
    assert out.verdict == "no-answer"
    assert any(".bin is missing" in e for e in out.evidence)
    assert out.provenance.log_lines == (1, 2, 3, 4)


def test_dump_size_mismatch_is_noted_not_fatal(health):
    raw = sloop_answer([(0x53, ZERO), (0x4A, ZERO)])
    text = log(JOINED, "Buffer script dump: 200 bytes of console memory, head 00")
    out = classify(health, text, raw)
    assert out.verdict == "answered"
    assert any("200 bytes" in e and "177 bytes" in e for e in out.evidence)


def test_echoed_numbers_cross_checked(health):
    raw = sloop_answer([(0x53, ZERO), (0x4B, ZERO)])
    out = classify(health, log(JOINED, dump_line(raw)), raw)
    assert out.verdict == "answered"
    assert any("echoed 0x53, 0x4B" in e for e in out.evidence)


def test_exit_status_is_not_an_input():
    import inspect
    assert "exit" not in " ".join(inspect.signature(classify).parameters)


def test_verdict_sets():
    assert set(HALTING) < set(VERDICTS)
    assert {"answered", "stopped"} == set(VERDICTS) - HALTING


# -- crash injection: an 8-step sloop-svc join that faults ------------------------------------

def test_crash_8svc(eight, tmp_path):
    out = load_outcome(eight, LOGS / "crash-8svc.log", tmp_path / "never-written.bin",
                       journal_seq=3)
    assert out.verdict == "crashed" and out.halted
    assert out.fault_window == (1, 8)
    assert out.result is None
    assert out.provenance.log_lines == (3, 4, 5, 6)
    assert out.provenance.journal_seq == 3
    assert any("IN FLIGHT" in e for e in out.evidence)
    assert any(e.startswith("log 4: Switch sent the RFU disconnect frame") for e in out.evidence)


@pytest.mark.parametrize("k", range(1, 9))
def test_bisect_finds_every_step(k):
    fault, probed = bisect(8, lambda m: m >= k)
    assert fault == k
    assert len(probed) <= 3 and probed[0] == 4


def test_bisect_from_a_narrowed_window():
    assert bisect(8, lambda m: m >= 6, lo=5) == (6, (6, 5))
    assert bisect(1, lambda m: True) == (1, ())
    with pytest.raises(ValueError):
        bisect(8, lambda m: True, lo=9)


def test_next_probe_is_the_4_step_prefix(eight):
    probe4 = next_probe(eight, (1, 8))
    pairs = []
    for n in EIGHT[:4]:
        pairs += ["--svc-number", f"0x{n:02X}"]
    assert probe4.host_args() == ["--buffer-script", "sloop-svc"] + pairs
    assert probe4.steps == eight.steps[:4] and probe4.label == "eight-prefix4"
    assert next_probe(eight, (5, 8)).steps == eight.steps[:6]
    assert next_probe(eight, (5, 5)) is None
    with pytest.raises(ValueError):
        next_probe(eight, (0, 8))


def test_bisection_plan(eight):
    lines = bisection_plan(eight, (1, 8))
    text = "\n".join(lines)
    assert "steps 1..8 of 8" in lines[0]
    assert " ".join(next_probe(eight, (1, 8)).host_args()) in text
    assert "2 joins" in text and "0x53 + 0x4A" in text
    assert lines[-1] == "worst case 3 more probe(s)"
    assert bisection_plan(eight, (5, 6))[-1] == "worst case 1 more probe(s)"
    assert bisection_plan(eight, (6, 6)) == ["fault isolated to step 6: swi 0x53()"]


def test_live_bisection_loop_against_a_simulated_console(eight):
    """Drive classify -> next_probe -> classify as the session would, with a console whose step 6
    faults: every probe that reaches step 6 sends nothing back."""
    crash_log = (LOGS / "crash-8svc.log").read_text()
    window = classify(eight, crash_log).fault_window
    runs = 0
    while (candidate := next_probe(eight, window)) is not None:
        runs += 1
        m = len(candidate.steps)
        if m >= 6:
            out = classify(candidate, crash_log)
        else:
            raw = sloop_answer([(n, ZERO) for n in EIGHT[:m]])
            out = classify(candidate, log(JOINED, dump_line(raw)), raw)
        lo, hi = window
        window = (lo, m) if out.verdict == "crashed" else (m + 1, hi)
    assert window == (6, 6) and runs == 3


def test_chain_crash_keeps_prev_with_its_producer(tmp_path):
    steps = [probe.call("GetVarPointer", 0x4024), probe.read16(prev),
             probe.read32(0x030042D0),
             probe.call("GetVarPointer", 0x4025), probe.read16(prev), probe.read8(0x08000000)]
    join = compile_program(steps, label="vars")[0]
    out = classify(join, (LOGS / "crash-8svc.log").read_text())
    assert out.verdict == "crashed" and out.fault_window == (1, 6)
    first = next_probe(join, out.fault_window)
    assert first.host_args() == ["--buffer-script", "call-chain",
                                 "--chain-step", "call:GetVarPointer,0x4024",
                                 "--chain-step", "read16:prev",
                                 "--chain-step", "read32:0x30042D0"]
    later = next_probe(join, (4, 6))
    assert later.steps == join.steps[:5]
    assert later.host_args()[-4:] == ["--chain-step", "call:GetVarPointer,0x4025",
                                      "--chain-step", "read16:prev"]
    narrow = next_probe(join, (2, 3))
    assert narrow.steps == join.steps[:2]
    # The prefix is a join the host would run as-is: its argv rebuilds the same steps.
    assert join_from_host_args(later.host_args()).steps == later.steps


def test_crash_after_an_answer_is_not_bisected(health):
    raw = sloop_answer([(0x53, ZERO), (0x4A, ZERO)])
    text = log(JOINED, dump_line(raw), ABNORMAL, IN_FLIGHT)
    out = classify(health, text)
    assert out.verdict == "crashed" and out.fault_window is None
    assert any("not inside it" in e for e in out.evidence)
    # The session asks for a plan on every "crashed"; a None window must not blow up.
    assert next_probe(health, out.fault_window) is None
    assert bisection_plan(health, out.fault_window)[0].startswith("no fault window")
    with_bin = classify(health, text, raw)
    assert with_bin.verdict == "answered"
    assert any("AFTER the answer" in e for e in with_bin.evidence)


def test_unparseable_bin_with_crash_signature(eight):
    out = classify(eight, log(JOINED, IDLE), b"\x00" * 40)
    assert out.verdict == "crashed" and out.fault_window == (1, 8)
    assert any("does not parse" in e for e in out.evidence)


def test_missing_log_file(health, tmp_path):
    out = load_outcome(health, tmp_path / "nope.log", None)
    assert out.verdict == "not-started"
    assert out.provenance.log_path.endswith("nope.log") and out.provenance.bin_path is None
    assert any("no log file" in e for e in out.evidence)


def test_empty_bin_reads_as_no_answer(health, tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    out = load_outcome(health, LOGS / "health-answered.log", empty)
    assert out.verdict == "no-answer"


def test_outcome_describe_shape(eight):
    out = classify(eight, (LOGS / "crash-8svc.log").read_text(),
                   provenance=Provenance("eight", "x.log", None, 2))
    lines = out.describe()
    assert lines[0] == "eight: crashed, fault in steps 1..8"
    assert "  log: x.log (lines 3, 4, 5, 6)" in lines and "  journal seq 2" in lines
    assert isinstance(out, JoinOutcome) and result.HALTING is HALTING
