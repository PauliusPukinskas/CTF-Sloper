from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "artifact_inventory.py"
SPEC = importlib.util.spec_from_file_location("artifact_inventory", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
artifact_inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = artifact_inventory
SPEC.loader.exec_module(artifact_inventory)


def test_detects_png_and_hashes_complete_file(tmp_path: Path) -> None:
    payload = b"\x89PNG\r\n\x1a\n" + b"A" * 64
    target = tmp_path / "image.bin"
    target.write_bytes(payload)

    record = artifact_inventory.inspect_file(target, sample_bytes=16)

    assert record.kind == "png"
    assert record.size == len(payload)
    assert record.sha256 == hashlib.sha256(payload).hexdigest()
    assert record.sampled_bytes == 16
    assert record.truncated_sample is True


def test_text_metrics_are_bounded_and_readable(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("flag{example}\nplain text\n", encoding="utf-8")

    record = artifact_inventory.inspect_file(target, sample_bytes=1024)

    assert record.kind == "text"
    assert record.extension == ".txt"
    assert record.printable_ratio == 1.0
    assert 0.0 < record.entropy < 8.0
    assert record.truncated_sample is False


def test_iter_files_is_stable_and_skips_symlinks(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "b.txt").write_text("b", encoding="utf-8")
    (nested / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(nested / "a.txt")

    paths = list(artifact_inventory.iter_files([tmp_path], max_files=10))

    assert [path.name for path in paths] == ["a.txt", "b.txt"]


def test_file_limit_stops_unbounded_walk(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text(str(index), encoding="utf-8")

    try:
        list(artifact_inventory.iter_files([tmp_path], max_files=2))
    except RuntimeError as exc:
        assert "file limit exceeded" in str(exc)
    else:
        raise AssertionError("expected file limit failure")


def test_riff_subtype_detection() -> None:
    sample = b"RIFF" + (12).to_bytes(4, "little") + b"WAVE" + b"fmt "
    assert artifact_inventory.detect_kind(sample) == "wav"
