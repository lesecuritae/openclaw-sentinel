"""Tests for core.bounded_reader: bounded binary readline + byte tracking."""

import os
import tempfile
from pathlib import Path

from core.bounded_reader import BoundedLogReader


def test_5_lines_max_lines_2_yields_2_2_1():
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"line1\nline2\nline3\nline4\nline5\n")
        path = f.name
    try:
        reader = BoundedLogReader([Path(path)], max_lines=2, max_bytes=1024, size_limit=1024)
        assert reader.read_incremental() == ["line1", "line2"]
        assert reader.read_incremental() == ["line3", "line4"]
        assert reader.read_incremental() == ["line5"]
        assert reader.read_incremental() == []
    finally:
        os.unlink(path)


def test_identical_lines_all_retained():
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"dup\ndup\ndup\n")
        path = f.name
    try:
        reader = BoundedLogReader([Path(path)], max_lines=10, max_bytes=1024, size_limit=1024)
        result = reader.read_incremental()
        assert result == ["dup", "dup", "dup"]
        # Repeated equal lines are distinct events; never deduplicate
        assert len(result) == 3
    finally:
        os.unlink(path)


def test_multiple_paths_no_loss():
    with (
        tempfile.NamedTemporaryFile(delete=False, mode="wb") as f1,
        tempfile.NamedTemporaryFile(delete=False, mode="wb") as f2,
    ):
        f1.write(b"a\nb\n")
        f2.write(b"c\n")
        p1 = f1.name
        p2 = f2.name
    try:
        reader = BoundedLogReader(
            [Path(p1), Path(p2)], max_lines=10, max_bytes=1024, size_limit=1024
        )
        # Round robin fairness: first pass p1 gets a,b then p2 gets c
        result = reader.read_incremental()
        assert result == ["a", "b", "c"]
    finally:
        os.unlink(p1)
        os.unlink(p2)


def test_partial_lines():
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"partial")
        path = f.name
    try:
        reader = BoundedLogReader([Path(path)], max_lines=10, max_bytes=1024, size_limit=1024)
        # No newline yet: partial preserved, nothing emitted
        assert reader.read_incremental() == []
        # Append newline
        with open(path, "ab") as f:
            f.write(b" line\n")
        assert reader.read_incremental() == ["partial line"]
        assert reader.read_incremental() == []
    finally:
        os.unlink(path)


def test_inode_replacement_and_truncate():
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        f.write(b"old\n")
        path = f.name
    try:
        reader = BoundedLogReader([Path(path)], max_lines=10, max_bytes=1024, size_limit=1024)
        assert reader.read_incremental() == ["old"]
        # Truncate to smaller: reset partial state; unrelated lines must not concatenate
        with open(path, "wb") as f:
            f.write(b"n\n")  # shorter -> truncation
        # The file was truncated; previous partial (none) should reset; new line emitted
        assert reader.read_incremental() == ["n"]
    finally:
        os.unlink(path)


def test_oversized_lines_bounded():
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
        # Write a very long line that exceeds a small size_limit (10 bytes)
        f.write(b"a" * 50 + b"\nshort\n")
        path = f.name
    try:
        reader = BoundedLogReader([Path(path)], max_lines=10, max_bytes=1024, size_limit=10)
        # Oversized line explicitly discarded; bounded discard state used
        # After discard completes, "short" is emitted
        result = reader.read_incremental()
        assert result == ["short"]
        assert reader.read_incremental() == []
    finally:
        os.unlink(path)


def test_partial_across_three_appends_and_byte_budget(tmp_path):
    path = tmp_path / "log"
    path.write_bytes(b"first")
    reader = BoundedLogReader([path], max_bytes=2, size_limit=100)
    assert reader.read_incremental() == []
    assert reader._state[str(path.absolute())]["offset"] == 2
    for fragment in (b"second", b"\n"):
        with path.open("ab") as stream:
            stream.write(fragment)
        assert reader.read_incremental() == []
    result = []
    for _ in range(5):
        result.extend(reader.read_incremental())
    assert result == ["firstsecond"]


def test_round_robin_does_not_starve_second_file(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_text("a\n" * 20)
    second.write_text("b\n")
    reader = BoundedLogReader([first, second], max_lines=1)
    assert reader.read_incremental() == ["a"]
    assert reader.read_incremental() == ["b"]
    assert reader.read_incremental() == ["a"]


def test_replacement_does_not_join_old_partial(tmp_path):
    path, replacement = tmp_path / "log", tmp_path / "new"
    path.write_text("old partial")
    reader = BoundedLogReader([path])
    assert reader.read_incremental() == []
    replacement.write_text("new complete line\n")
    replacement.replace(path)
    assert reader.read_incremental() == ["new complete line"]


def test_oversized_line_appended_in_small_chunks(tmp_path):
    path = tmp_path / "log"
    path.touch()
    reader = BoundedLogReader([path], max_bytes=3, size_limit=8)
    for _ in range(8):
        with path.open("ab") as stream:
            stream.write(b"abc")
        assert reader.read_incremental() == []
        assert len(reader._state[str(path.absolute())]["partial_bytes"]) <= 8
    with path.open("ab") as stream:
        stream.write(b"\nok\n")
    result = []
    for _ in range(3):
        result.extend(reader.read_incremental())
    assert result == ["ok"]
    assert reader.discarded_lines == 1


def test_fifo_is_skipped_without_blocking(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    assert BoundedLogReader([path]).read_incremental() == []
