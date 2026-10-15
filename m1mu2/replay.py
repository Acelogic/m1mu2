"""python -m m1mu2.replay [JOURNAL]: re-read every finished join a journal recorded, offline.

Each join-end points at its join-start (start_seq); the start holds the buffer-script argv, which
rebuilds the exact Join (pack.join_from_host_args), and the end holds the capture paths. The
capture files are re-classified with today's result.py, so a parser fix re-reads old evidence, and
a verdict that no longer matches what the journal recorded is called out. Nothing here builds a
transport, opens a port or starts the host: replay reads files and prints.
"""
import argparse
import sys
from pathlib import Path

from . import pack, policy
from .journal import DEFAULT_JOURNAL, Journal
from .result import load_outcome
from .upstream import REPO_ROOT


def _locate(path, journal_path):
    """A capture path as the journal spelled it: absolute, or relative to the working directory,
    the repo root or the journal's own directory - whichever exists, else as spelled."""
    if not path:
        return None
    path = Path(path)
    if path.is_absolute():
        return path
    for base in (Path.cwd(), REPO_ROOT, journal_path.parent):
        if (base / path).exists():
            return base / path
    return path


def replay_entries(entries, journal_path, out=print):
    """Print every finished join in `entries`. -> how many were replayed."""
    starts = {e.get("seq"): e for e in entries if e.get("kind") == "join-start"}
    ended = set()
    replayed = 0
    for error in (e for e in entries if e.get("kind") == "join-error"):
        ended.add(error.get("start_seq"))
        out(f"seq {error.get('start_seq')}: join {error.get('label', '')!r} never finished: the "
            f"runner failed ({error.get('error', 'no error recorded')}); nothing to replay")
    for end in (e for e in entries if e.get("kind") == "join-end"):
        start_seq = end.get("start_seq")
        ended.add(start_seq)
        start = starts.get(start_seq)
        if start is None:
            out(f"seq {end.get('seq')}: join-end {end.get('label', '')!r} points at join-start "
                f"seq {start_seq}, which the journal does not have; skipped")
            continue
        label = start.get("label", "")
        try:
            join = pack.join_from_host_args(start.get("host_args") or [], label=label)
        except (pack.PackError, policy.PolicyError, ValueError) as exc:
            out(f"seq {start_seq}: cannot rebuild {label or 'the join'} from its host_args: {exc}")
            continue
        log_path = _locate(end.get("log_path") or start.get("log_path"), journal_path)
        bin_path = _locate(end.get("bin_path") or start.get("bin_path"), journal_path)
        head = f"== seq {start_seq}..{end.get('seq')}"
        head += f" {start.get('utc', '')}" if start.get("utc") else ""
        head += f" radio {start['radio_mac']}" if start.get("radio_mac") else ""
        head += f" exit {end['exit_status']}" if "exit_status" in end else ""
        out(head)
        for line in join.describe():
            out(line)
        if log_path is None or not log_path.exists():
            out(f"  note: the log {log_path or '(none recorded)'} is missing; classifying "
                "without it")
        if bin_path is not None and not bin_path.exists():
            out(f"  note: no answer file at {bin_path} (normal when nothing came back)")
        outcome = load_outcome(join, log_path, bin_path, journal_seq=start_seq)
        for line in outcome.describe():
            out(line)
        recorded = end.get("verdict")
        if recorded and recorded != outcome.verdict:
            out(f"  note: the journal recorded {recorded!r}; replay classifies it "
                f"{outcome.verdict!r}")
        replayed += 1
    for seq, start in starts.items():
        if seq not in ended:
            out(f"seq {seq}: join-start {start.get('label', '')!r} has no join-end (the bench "
                "process stopped mid-join); its log, if any: " + str(start.get("log_path")))
    return replayed


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m m1mu2.replay",
        description="Re-classify every join a journal recorded from its capture files. Offline.")
    parser.add_argument("journal", nargs="?", default=str(DEFAULT_JOURNAL),
                        help=f"the journal to replay (default {DEFAULT_JOURNAL})")
    args = parser.parse_args(argv)
    path = Path(args.journal)
    if not path.exists():
        print(f"no journal at {path}")
        return 1
    entries = Journal(path).entries()
    replayed = replay_entries(entries, path)
    print(f"{replayed} join(s) replayed from {path} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
