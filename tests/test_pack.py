"""pack: steps -> joins -> host argv, and back. Goldens are checked against the host's own parser."""
import pytest

from m1mu2 import policy
from m1mu2.pack import (PackError, chain_step_text, compile_program, health_join,
                        join_from_host_args, parse_step, prev, probe)
from m1mu2.upstream import bs, builds, check_host_argv

VAR4024 = [probe.call("GetVarPointer", 0x4024), probe.read16(prev), probe.read32(0x030042D0)]

GOLDENS = [
    (VAR4024, {},
     ["--buffer-script", "call-chain",
      "--chain-step", "call:GetVarPointer,0x4024",
      "--chain-step", "read16:prev",
      "--chain-step", "read32:0x30042D0"]),
    ([probe.svc(0x53), probe.svc(0x4A)], {},
     ["--buffer-script", "sloop-svc", "--svc-number", "0x53", "--svc-number", "0x4A"]),
    ([probe.svc(0x4D, data="hello", data_in="r0"), probe.svc(0x54, data="hello", data_in="r0")],
     {},
     ["--buffer-script", "sloop-svc", "--svc-number", "0x4D", "--svc-number", "0x54",
      "--svc-hex", "68656c6c6f", "--svc-data-in", "r0"]),
    ([probe.svc(0x50, 1, 2, 3, 4)], {},
     ["--buffer-script", "sloop-svc", "--svc-number", "0x50", "--svc-arg", "0x1", "--svc-arg",
      "0x2", "--svc-arg", "0x3", "--svc-arg", "0x4"]),
    ([probe.read32(0x03005008), probe.read16(prev + 0x290), probe.read8(0x08000000, keep=True)],
     {},
     ["--buffer-script", "call-chain", "--chain-step", "read32:0x3005008",
      "--chain-step", "read16:prev+0x290", "--chain-step", "read8+keep:0x8000000"]),
    ([probe.svc(0xFF, bkpt=True)], {"allow_unsafe": True},
     ["--buffer-script", "sloop-svc", "--svc-number", "0xFF", "--svc-bkpt", "--write-unsafe"]),
    ([probe.call("GetVarPointer", 0x4024), probe.write16(prev, 7), probe.read16(prev)],
     {"allow_unsafe": True},
     ["--buffer-script", "call-chain", "--chain-step", "call:GetVarPointer,0x4024",
      "--chain-step", "write16:prev,0x7", "--chain-step", "read16:prev", "--write-unsafe"]),
]


@pytest.mark.parametrize("steps, kwargs, argv", GOLDENS)
def test_golden_programs_render_the_intended_argv_and_the_host_accepts_it(steps, kwargs, argv):
    joins = compile_program(steps, **kwargs)
    assert len(joins) == 1
    assert joins[0].host_args() == argv
    check = check_host_argv(["--keys", "/nonexistent/prod.keys", *argv])
    assert check.ok, check.message
    # A named call is resolved per cartridge; anything else is the same bytes for every build.
    named = any(getattr(s, "function_name", None) for s in joins[0].steps)
    assert set(check.codes) == (set(builds.GAME_CODES) if named else set())


@pytest.mark.parametrize("steps, kwargs, argv", GOLDENS)
def test_argv_decompiles_to_the_same_join(steps, kwargs, argv):
    join = compile_program(steps, **kwargs)[0]
    assert join_from_host_args(argv) == join


def test_a_chain_payload_decompiles_to_the_steps_that_built_it():
    join = compile_program(VAR4024)[0]
    built = bs.chain_parameters(join.build_code())
    assert built["count"] == 3
    assert built["steps"] == list(join.steps)
    assert join.answer_size() == bs.CHAIN_ANSWER_SIZE


def test_a_svc_payload_carries_its_numbers_and_operands():
    join = compile_program([probe.svc(0x53, 0x1234), probe.svc(0x4A, 0x1234)])[0]
    code = join.build_code()
    count = int.from_bytes(code[bs.SLOOP_COUNT_OFFSET:bs.SLOOP_COUNT_OFFSET + 4], "little")
    assert count == 2
    assert code[bs.SLOOP_NUMBERS_OFFSET:bs.SLOOP_NUMBERS_OFFSET + 2] == bytes([0x53, 0x4A])
    assert int.from_bytes(code[bs.SLOOP_REGS_OFFSET:bs.SLOOP_REGS_OFFSET + 4], "little") == 0x1234
    assert join.answer_size() == bs.sloop_svc_answer_size(0)


@pytest.mark.parametrize("text", [
    "call:GetVarPointer,0x4024", "call:FlagGet,0x828", "call:GetMoney,prev+0x290",
    "read16:prev", "read32:prev+0x10", "read8+keep:0x2000000", "write16:prev,0x7",
    "write32:0x2000000,prev", "call+keep:VarGet,0x4020", "call:0x8000001,0x1,0x2",
])
def test_step_text_round_trips_through_upstreams_parser(text):
    step = parse_step(text)
    assert chain_step_text(step) == text
    assert bs.parse_chain_step(text) == step


def test_names_resolve_case_insensitively_to_the_tables_spelling():
    assert chain_step_text(probe.call("getvarpointer", 1)) == "call:GetVarPointer,0x1"
    assert chain_step_text(parse_step("call:flagget,0x828")) == "call:FlagGet,0x828"


def test_a_mixed_program_splits_at_the_payload_change():
    joins = compile_program([probe.call("VarGet", 0x4020), probe.read32(0x03005008),
                             probe.svc(0x53)], label="mix")
    assert [(j.label, j.script, len(j.steps)) for j in joins] == [
        ("mix-1", bs.CALL_CHAIN, 2), ("mix-2", bs.SLOOP_SVC, 1)]


def test_svc_operands_and_the_eight_call_limit_split_joins():
    joins = compile_program([probe.svc(0x53, 1), probe.svc(0x4A, 2)])
    assert [j.numbers for j in joins] == [(0x53,), (0x4A,)]
    joins = compile_program([probe.svc(0x53)] * (bs.SLOOP_MAX_CALLS + 1))
    assert [len(j.steps) for j in joins] == [bs.SLOOP_MAX_CALLS, 1]


def test_prev_never_crosses_a_join_boundary():
    with pytest.raises(PackError, match="first step"):
        compile_program([probe.read16(prev)])
    steps = [probe.read32(0x03005008)] * bs.CHAIN_MAX_STEPS + [probe.read16(prev)]
    with pytest.raises(PackError, match="join boundary"):
        compile_program(steps)
    with pytest.raises(PackError, match="join boundary"):
        compile_program([probe.svc(0x53), probe.read16(prev)])


def test_the_chain_limit_is_sixteen_not_eight():
    joins = compile_program([probe.read32(0x03005008)] * bs.CHAIN_MAX_STEPS)
    assert len(joins) == 1 and len(joins[0].steps) == 16


@pytest.mark.parametrize("make, match", [
    (lambda: probe.call(prev), "computed address"),
    (lambda: probe.call("NotAFunction"), "build tables"),
    (lambda: probe.call("VarGet", 1, prev), "FIRST argument"),
    (lambda: probe.svc(0x53, data_in="r2"), "data_in"),
    (lambda: probe.peek(0x02000000, 6), "whole number of words"),
])
def test_malformed_steps_are_refused_where_they_are_written(make, match):
    with pytest.raises(PackError, match=match):
        make()


def test_peek_reads_words_and_a_prev_peek_keeps_its_base():
    assert [chain_step_text(s) for s in probe.peek(0x02024000, 8)] == [
        "read32:0x2024000", "read32:0x2024004"]
    assert [chain_step_text(s) for s in probe.peek(prev + 0x10, 8)] == [
        "read32+keep:prev+0x10", "read32+keep:prev+0x14"]
    assert [chain_step_text(s) for s in probe.peek(0x02024000, 2)] == ["read16:0x2024000"]


def test_the_hosts_own_builder_runs_on_every_join():
    # Unaligned: policy has no opinion on alignment, upstream's builder does.
    with pytest.raises(PackError, match="aligned"):
        compile_program([probe.read32(0x02000002)])


def test_an_unsafe_call_needs_our_override_but_not_the_hosts():
    """The host lets named calls out without --write-unsafe; m1mu2 does not."""
    with pytest.raises(policy.PolicyError, match="FlagSet changes game state"):
        compile_program([probe.call("FlagSet", 0x828)])
    join = compile_program([probe.call("FlagSet", 0x828)], allow_unsafe=True)[0]
    assert join.unsafe and join.risky
    assert "--write-unsafe" not in join.host_args()
    assert check_host_argv(["--keys", "/x", *join.host_args()]).ok


def test_the_host_refuses_a_write_we_render_without_its_flag():
    argv = ["--keys", "/x", "--buffer-script", "call-chain", "--chain-step",
            "write16:0x2000000,0x1"]
    check = check_host_argv(argv)
    assert not check.ok
    assert "--write-unsafe" in check.message


def test_the_health_join_is_the_configured_pair_and_needs_no_override():
    join = health_join()
    assert join.numbers == policy.HEALTH_PAIR
    assert not join.unsafe and not join.risky
    assert "--write-unsafe" not in join.host_args()
