"""policy: narrower than the host's guards, never looser."""
import pytest

from m1mu2 import policy
from m1mu2.pack import compile_program, prev, probe
from m1mu2.upstream import bs, builds


@pytest.mark.parametrize("number", sorted(policy.HARD_REFUSED_SVC))
def test_the_never_set_is_refused_even_with_the_override(number):
    with pytest.raises(policy.PolicyError, match="never issues"):
        compile_program([probe.svc(number)], allow_unsafe=True)


def test_upstream_still_lets_0x55_through_which_is_why_we_refuse_it():
    """buffer_script.py:2021-2026 says 0x55 re-points SaveBlock2 and outlives the session, yet
    its refusal set omits it. If upstream fixes that, this test says the workaround can go."""
    assert 0x55 not in bs.SLOOP_REFUSED_NUMBERS
    assert bs.build_sloop_svc([0x55], unsafe=True)
    assert 0x55 in policy.HARD_REFUSED_SVC


def test_the_default_set_is_inside_the_hosts_read_only_set():
    assert policy.DEFAULT_SAFE_SVC <= bs.SLOOP_SAFE_NUMBERS
    assert not policy.DEFAULT_SAFE_SVC & policy.HARD_REFUSED_SVC
    assert set(policy.HEALTH_PAIR) <= policy.DEFAULT_SAFE_SVC


@pytest.mark.parametrize("number, host_flag", [
    (0x51, False),      # read-and-clear: host calls it safe, we do not
    (0x58, False),      # never issued on hardware
    (0x46, False),
    (0x57, True),       # outside the host's safe set: the host needs --write-unsafe too
])
def test_numbers_outside_the_observed_set_need_the_override(number, host_flag):
    with pytest.raises(policy.PolicyError, match="allow-unsafe"):
        compile_program([probe.svc(number)])
    join = compile_program([probe.svc(number)], allow_unsafe=True)[0]
    assert join.unsafe and join.risky
    assert ("--write-unsafe" in join.host_args()) == host_flag


def test_the_bad_word_check_is_free_only_on_the_payloads_copy():
    assert not compile_program([probe.svc(0x4D, data="x", data_in="r0")])[0].unsafe
    with pytest.raises(policy.PolicyError, match="rewrites the string"):
        compile_program([probe.svc(0x4D, data="x")])


def test_every_bkpt_needs_the_override_and_0x52_never_goes():
    with pytest.raises(policy.PolicyError):
        compile_program([probe.svc(0xFF, bkpt=True)])
    with pytest.raises(policy.PolicyError, match="re-keys"):
        compile_program([probe.svc(0x52, bkpt=True)], allow_unsafe=True)


def test_pure_callees_exist_on_every_build():
    for code in builds.GAME_CODES:
        build = builds.resolve(code)
        assert policy.PURE_CALLEES <= set(build.callable), code
    assert policy.POINTER_CALLEES <= policy.PURE_CALLEES


@pytest.mark.parametrize("name", ["Random", "SeedRng", "FlagSet", "VarSet", "AddMoney",
                                  "ReadFlash", "GetSetPokedexFlag"])
def test_state_changing_callees_need_the_override(name):
    with pytest.raises(policy.PolicyError, match="allow-unsafe"):
        compile_program([probe.call(name, 0)])


def test_a_call_by_bare_address_needs_the_override():
    with pytest.raises(policy.PolicyError, match="bare address"):
        compile_program([probe.call(0x08000001)])


@pytest.mark.parametrize("address, kind", [
    (0x02000000, "read"), (0x0203FFFC, "read"), (0x03007FFC, "read"), (0x08FFFFFC, "read"),
    (0x04000000, "gated"), (0x06000000, "gated"), (0x09000000, "gated"),
    (0x02040000, "outside"), (0x00000000, "outside"), (0x0E000000, "outside"),
])
def test_read_windows(address, kind):
    assert policy.window_of(address)[0] == kind


def test_gated_reads_need_the_override_and_unmapped_reads_never_go():
    with pytest.raises(policy.PolicyError, match="I/O registers"):
        compile_program([probe.read16(0x04000130)])
    assert compile_program([probe.read16(0x04000130)], allow_unsafe=True)[0].risky
    with pytest.raises(policy.PolicyError, match="outside every mapped region"):
        compile_program([probe.read32(0x02040000)], allow_unsafe=True)


def test_prev_is_trusted_only_after_a_pointer_callee():
    trusted = compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev)])[0]
    assert not trusted.risky
    chased = compile_program([probe.read32(0x03005008), probe.read16(prev + 0x290)])[0]
    assert chased.risky
    kept = compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev, keep=True),
                            probe.read16(prev + 2)])[0]
    assert not kept.risky
    lost = compile_program([probe.call("GetVarPointer", 0x4024), probe.read16(prev),
                            probe.read16(prev)])[0]
    assert lost.risky
