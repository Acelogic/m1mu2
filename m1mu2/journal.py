"""The bench journal: one JSON object per line, appended, never rewritten.

A capture file says what the console sent back; only the journal says which argv produced it, on
which radio, after which confirmation, and what m1mu2 concluded. That is what makes a session
replayable offline (python -m m1mu2.replay) and auditable afterwards, so the file is append-only:

- every entry carries `seq` (1-based, continuing across processes: the last seq in the file + 1),
  `utc` (ISO-8601, Z) and `kind`, then the caller's fields;
- each append is one write under an exclusive lock, flushed and fsync'd before it returns, so a
  bench process killed mid-join loses at most the entry it was writing;
- a write torn by a crash leaves a partial last line; the next append starts on a fresh line and
  entries() skips the fragment. Nothing is ever truncated to "repair" it.

Kinds the session writes: dry-run, plan, confirm, decline, join-start, join-end, halt, bisect-plan.
join-end points back at its join-start through `start_seq`.
"""
import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .upstream import REPO_ROOT

DEFAULT_JOURNAL = REPO_ROOT / "captures" / "m1mu2" / "journal.jsonl"
RESERVED = ("seq", "utc", "kind")


def jsonable(value):
    """-> `value` with Path as str, bytes as hex and tuples (and sets) as lists, recursively.
    Anything else json cannot write raises TypeError at append, before a byte is written."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((jsonable(v) for v in value), key=repr)
    return value


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(lines):
    """Complete JSON objects from raw lines; a torn or blank line is skipped, not fatal."""
    entries = []
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _last_seq(entries):
    for entry in reversed(entries):
        if isinstance(entry.get("seq"), int):
            return entry["seq"]
    return 0


class Journal:
    """Append-only JSONL at `path`. The parent directory is created on the first append."""

    def __init__(self, path=DEFAULT_JOURNAL):
        self.path = Path(path)

    def append(self, kind, **fields):
        """-> the new entry's seq. One line, one write, flushed and fsync'd."""
        clash = [name for name in RESERVED if name in fields]
        if clash:
            raise ValueError(f"{', '.join(clash)} is set by the journal, not by the caller")
        body = jsonable(fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+b") as handle:
            # The lock makes read-last-seq-then-append one step for every process on this file.
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                handle.seek(0)
                existing = handle.read()
                seq = _last_seq(_parse(existing.splitlines())) + 1
                entry = {"seq": seq, "utc": utc_now(), "kind": str(kind), **body}
                line = json.dumps(entry, allow_nan=False).encode("utf-8") + b"\n"
                if existing and not existing.endswith(b"\n"):
                    line = b"\n" + line         # a torn last line stays its own (skipped) line
                handle.write(line)              # "a" mode: always at the end, never in place
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        return seq

    def entries(self):
        """-> every complete entry, in file order; [] if there is no journal yet."""
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return []
        return _parse(data.splitlines())

    def find(self, seq):
        """-> the entry with this seq, or None."""
        for entry in self.entries():
            if entry.get("seq") == seq:
                return entry
        return None
