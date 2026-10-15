"""What m1mu2 lets out without --allow-unsafe, and what it never lets out.

This is deliberately NARROWER than the host's own guards (buffer_script.SLOOP_SAFE_NUMBERS and
build_call_chain's checks), which it runs on top of, never instead of:

- Syscalls: only the numbers observed on hardware answering without side effects
  [pokeldn-src/docs/frlg_rom.md, "Answer-only syscalls"]. The host's safe set also holds 0x46,
  0x4E and 0x58..0x60, which the Mystery Gift client has never issued, and 0x51, which reads AND
  CLEARS the close-link flag; those need --allow-unsafe here.
- 0x55 is refused outright. The host comments say it re-points SaveBlock2 and outlives the
  session, but its refusal set is {0x48, 0x4C, 0x56} and lets 0x55 through with --write-unsafe.
- Chain calls: the host lets any named call out with no flag at all (FlagSet, AddMoney, VarSet
  build without --write-unsafe). Here only getters are free; anything else, and any call by bare
  address, needs --allow-unsafe.
- Reads: a literal target must sit in EWRAM, IWRAM or the 16 MB cartridge. The other mapped
  regions need --allow-unsafe; anything outside the host's reach is refused by the host itself.

A step that needs --allow-unsafe is also RISKY, and so is a step whose target is a pointer the
console computes from data (prev after a read32) - nothing here can check it before it runs, and a
read outside mapped memory faults the core. A risky join must be followed by the health pair.
"""
from dataclasses import dataclass

from .upstream import bs

# Never, whatever the operator passes: flash sector writes, the finished save, SaveBlock2's
# pointer hand-over and ReplaceSector [buffer_script.py:2021-2026, docs/frlg_rom.md].
HARD_REFUSED_SVC = frozenset({bs.SWI_WRITE_SECTOR, 0x4C, 0x55, bs.SWI_REPLACE_SECTOR})
# Issued from the Mystery Gift client and seen to answer only: r0 = 0 (0x49, 0x4A, 0x4B, 0x52,
# 0x53) or 1 (0x50, 0x54), r1..r3 as passed.
DEFAULT_SAFE_SVC = frozenset({0x49, 0x4A, 0x4B, 0x50, 0x52, 0x53, 0x54})
# The bad-word check rewrites the string r0 points at; safe only on the payload's own copy.
SVC_BAD_WORD_CHECK = bs.SWI_BAD_WORD_CHECK
# The verification readers that bookend a risky join (CLAUDE.md, Join economy discipline).
HEALTH_PAIR = (0x53, 0x4A)

# Named ROM functions that only compute an answer from their arguments and saved state.
PURE_CALLEES = frozenset({
    "CalcCRC16", "CheckBagHasItem", "CheckBagHasSpace", "FlagGet", "GetMoney", "GetVarPointer",
    "IsEnoughMoney", "ItemIsMail", "SpeciesToNationalPokedexNum", "StringCompare", "VarGet",
})
# Pure callees whose result is a pointer the game computed itself, so `prev` after them is
# trusted to land in mapped RAM.
POINTER_CALLEES = frozenset({"GetVarPointer"})

# Literal read targets that need no override: [start, end).
READ_WINDOWS = (
    (0x02000000, 0x02040000, "EWRAM"),
    (0x03000000, 0x03008000, "IWRAM"),
    (0x08000000, 0x09000000, "the 16 MB cartridge"),
)
# Mapped, but reading them is an experiment, not a measurement.
GATED_WINDOWS = (
    (0x04000000, 0x04000400, "the I/O registers"),
    (0x05000000, 0x05000400, "palette RAM"),
    (0x06000000, 0x06018000, "VRAM"),
    (0x07000000, 0x07000400, "OAM"),
    (0x09000000, 0x0A000000, "the cartridge window past FireRed's 16 MB"),
)
# The host's own reach for a chain read [build_call_chain]; outside it the host refuses.
HOST_REACH = (bs.SCAN_MIN_ADDRESS, bs.SCAN_MAX_ADDRESS)


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Assessment:
    """Why a step needs --allow-unsafe (`unsafe`) and why its join needs the health pair after it
    (`risky`). Every unsafe reason is also a risk."""
    unsafe: tuple = ()
    risky: tuple = ()

    def __add__(self, other):
        return Assessment(self.unsafe + other.unsafe, self.risky + other.risky)


def window_of(address):
    """-> ("read"|"gated"|"outside", name) for a literal address."""
    for start, end, name in READ_WINDOWS:
        if start <= address < end:
            return "read", name
    for start, end, name in GATED_WINDOWS:
        if start <= address < end:
            return "gated", name
    return "outside", "unmapped memory"


def assess_svc(number, *, data_in="none", bkpt=False):
    """-> Assessment for one sloop-svc number. Raises PolicyError for the never-set."""
    if bkpt:
        if number == bs.SLOOP_BKPT_RFU:
            raise PolicyError("bkpt #0x52 re-keys the wrapper's RFU hook and outlives the session")
        reason = f"bkpt #0x{number:02X} hands the CPU to the wrapper's hook table"
        return Assessment((reason,), (reason,))
    if number in HARD_REFUSED_SVC:
        raise PolicyError(
            f"swi 0x{number:02X} writes the save or re-points SaveBlock2; m1mu2 never issues it, "
            "--allow-unsafe or not")
    if number == SVC_BAD_WORD_CHECK:
        if data_in == "r0":
            return Assessment()
        reason = "swi 0x4D rewrites the string r0 points at; only the payload's copy is safe (r0)"
        return Assessment((reason,), (reason,))
    if number in DEFAULT_SAFE_SVC:
        return Assessment()
    if number in bs.SLOOP_SAFE_NUMBERS:
        reason = (f"swi 0x{number:02X} is in the host's static safe set but was never seen "
                  "answering on hardware" if number != 0x51 else
                  "swi 0x51 reads and CLEARS the close-link flag")
    else:
        reason = f"swi 0x{number:02X} takes a pointer or changes link or telemetry state"
    return Assessment((reason,), (reason,))


def _target_assessment(step, prev_trusted):
    """Reads and writes: where the target is."""
    if step.target_from_prev:
        if prev_trusted:
            return Assessment()
        return Assessment(risky=(
            f"{step.describe()}: the target is a pointer the console reads out of memory; "
            "nothing here can check it lands in mapped RAM",))
    kind, name = window_of(step.target)
    if kind == "read":
        return Assessment()
    if kind == "gated":
        reason = f"{step.describe()}: 0x{step.target:08X} is in {name}"
        return Assessment((reason,), (reason,))
    raise PolicyError(f"{step.describe()}: 0x{step.target:08X} is outside every mapped region; "
                      "a read there faults the core")


def assess_chain(steps):
    """-> Assessment for a call-chain, in order: `prev` is trusted only after a pointer callee
    or a +keep step that left a trusted prev alone."""
    total = Assessment()
    prev_trusted = False
    for step in steps:
        op = int(step.op) & 0xFF
        if op == bs.CHAIN_CALL:
            name = step.function_name
            canonical = canonical_callee(name) if name else None
            if canonical is None:
                reason = (f"{step.describe()}: a call by bare address; only named getters are "
                          "free")
                total += Assessment((reason,), (reason,))
            elif canonical not in PURE_CALLEES:
                reason = f"{step.describe()}: {canonical} changes game state"
                total += Assessment((reason,), (reason,))
            if step.arg_from_prev and not prev_trusted:
                total += Assessment(risky=(f"{step.describe()}: its pointer argument is prev, "
                                           "read out of memory",))
            produced_trusted = canonical in POINTER_CALLEES
        elif op in bs.CHAIN_READS:
            total += _target_assessment(step, prev_trusted)
            produced_trusted = False
        elif op in bs.CHAIN_WRITES:
            reason = (f"{step.describe()}: writes the console's live memory, which it commits "
                      "to flash when it saves")
            total += Assessment((reason,), (reason,)) + _target_assessment(step, prev_trusted)
            produced_trusted = False
        else:
            raise PolicyError(f"op {op} is not one the call-chain payload dispatches")
        if not step.keep_prev:
            prev_trusted = produced_trusted
    return total


def canonical_callee(name):
    """-> the build table's spelling of a callable name, or None if it names nothing."""
    from .upstream import builds
    for known in builds.DEFAULT.callable:
        if known.lower() == str(name).lower():
            return known
    return None
