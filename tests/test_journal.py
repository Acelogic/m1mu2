"""journal: append-only JSONL, seq continuity across processes, torn-line tolerance."""
import json
from datetime import datetime
from pathlib import Path

import pytest

from m1mu2.journal import DEFAULT_JOURNAL, Journal
from m1mu2.upstream import REPO_ROOT


def test_default_path():
    assert DEFAULT_JOURNAL == REPO_ROOT / "captures" / "m1mu2" / "journal.jsonl"
    assert Journal().path == DEFAULT_JOURNAL


def test_parent_dirs_created_lazily(tmp_path):
    path = tmp_path / "a" / "b" / "journal.jsonl"
    journal = Journal(path)
    assert journal.entries() == [] and not path.parent.exists()
    assert journal.append("plan", label="x") == 1
    assert path.exists()


def test_seq_continues_across_instances(tmp_path):
    path = tmp_path / "journal.jsonl"
    first = Journal(path)
    assert [first.append("plan"), first.append("confirm")] == [1, 2]
    second = Journal(str(path))
    assert second.append("join-start", label="health") == 3
    assert first.append("join-end", start_seq=3) == 4
    entries = second.entries()
    assert [e["seq"] for e in entries] == [1, 2, 3, 4]
    assert [e["kind"] for e in entries] == ["plan", "confirm", "join-start", "join-end"]
    assert first.find(3)["label"] == "health" and first.find(99) is None


def test_one_object_per_line_with_seq_utc_kind_first(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    journal.append("dry-run", label="var4024", host_args=["--buffer-script", "call-chain"])
    lines = journal.path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert list(entry)[:3] == ["seq", "utc", "kind"]
    assert entry["utc"].endswith("Z")
    assert datetime.fromisoformat(entry["utc"].replace("Z", "+00:00")).utcoffset().seconds == 0
    assert entry["host_args"] == ["--buffer-script", "call-chain"]


def test_append_only(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    journal.append("plan", label="a")
    journal.append("confirm", label="a")
    before = journal.path.read_bytes()
    journal.append("join-start", label="a")
    journal.append("join-end", label="a", start_seq=3)
    after = journal.path.read_bytes()
    assert after.startswith(before) and len(after.splitlines()) == 4


def test_torn_last_line_is_skipped_and_never_repaired(tmp_path):
    path = tmp_path / "j.jsonl"
    journal = Journal(path)
    journal.append("plan")
    journal.append("confirm")
    torn = b'{"seq": 3, "utc": "2026-10-15T00:00:00.000Z", "ki'
    with open(path, "ab") as handle:
        handle.write(torn)
    before = path.read_bytes()
    assert [e["seq"] for e in journal.entries()] == [1, 2]
    assert journal.append("halt", reason="crashed") == 3
    after = path.read_bytes()
    assert after.startswith(before)                     # the fragment is kept, not rewritten
    entries = journal.entries()
    assert [e["seq"] for e in entries] == [1, 2, 3] and entries[-1]["kind"] == "halt"


def test_blank_lines_are_skipped(tmp_path):
    path = tmp_path / "j.jsonl"
    Journal(path).append("plan")
    with open(path, "ab") as handle:
        handle.write(b"\n   \n")
    journal = Journal(path)
    assert len(journal.entries()) == 1 and journal.append("plan") == 2


def test_serialization(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    journal.append("join-start", log_path=Path("/x/y.log"), raw=b"\x01\xff", window=(1, (2, 3)),
                   env={"POKELDN_RADIO": "esp32:/dev/null", "where": Path("z")},
                   numbers=frozenset({0x4A, 0x53}), none=None)
    entry = journal.entries()[0]
    assert entry["log_path"] == "/x/y.log"
    assert entry["raw"] == "01ff"
    assert entry["window"] == [1, [2, 3]]
    assert entry["env"] == {"POKELDN_RADIO": "esp32:/dev/null", "where": "z"}
    assert entry["numbers"] == [0x4A, 0x53] and entry["none"] is None


def test_reserved_fields_and_unserializable_values_write_nothing(tmp_path):
    journal = Journal(tmp_path / "j.jsonl")
    journal.append("plan")
    before = journal.path.read_bytes()
    with pytest.raises(ValueError):
        journal.append("plan", seq=9)
    with pytest.raises(TypeError):
        journal.append("plan", thing=object())
    assert journal.path.read_bytes() == before
    assert journal.append("plan") == 2
