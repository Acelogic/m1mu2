"""result against REAL hardware captures (tests/fixtures/real/README.txt), not the synthetic ones
test_result.py builds. The first: the health pair (swi 0x53 + 0x4A) answered by the console on
2026-10-15, run with --no-sudo; the run under sudo -nE before it wrote a byte-identical .bin."""
from pathlib import Path

from m1mu2.pack import health_join
from m1mu2.result import Provenance, SvcResult, load_outcome, scan_log

REAL = Path(__file__).parent / "fixtures" / "real"
HEALTH_LOG = REAL / "20261015T072229Z-health.log"
HEALTH_BIN = REAL / "20261015T072229Z-health.bin"


def test_first_live_health_join_answered():
    out = load_outcome(health_join(), HEALTH_LOG, HEALTH_BIN, journal_seq=7)
    assert out.verdict == "answered" and not out.halted and out.fault_window is None
    assert isinstance(out.result, SvcResult) and out.result.returned
    assert [(c.index, c.mode, c.number, c.call_site, c.regs) for c in out.result.calls] == [
        (1, "swi", 0x53, 0x4770DF53, (0, 0, 0, 0)),
        (2, "swi", 0x4A, 0x4770DF4A, (0, 0, 0, 0)),
    ]
    assert out.result.data == b""
    assert out.provenance == Provenance("health", str(HEALTH_LOG), str(HEALTH_BIN), 7, (19, 54))
    # Only the two cited lines: no cross-check note (177 bytes logged == read == expected, and
    # the console echoed exactly 0x53, 0x4A as swi).
    assert out.evidence == (
        "log 19: A console joined the network.",
        "log 54: Buffer script dump: 177 bytes of console memory, head "
        "31535653020000003253565300000000",
    )


def test_first_live_health_join_has_no_status_line():
    # The host announces "The evidence line is 'Buffer script status:'", but a sloop-svc answer
    # comes back on "Buffer script dump:" only; classify() must not depend on the status line.
    scan = scan_log(HEALTH_LOG.read_text())
    assert scan["status"] == [] and [n for n, _ in scan["dump"]] == [54]
    assert [n for n, _ in scan["close"]] == [69] and not scan["abnormal"] and not scan["idle"]
