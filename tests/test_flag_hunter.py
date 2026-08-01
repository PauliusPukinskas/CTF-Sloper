from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "flag_hunter.py"
SPEC = importlib.util.spec_from_file_location("flag_hunter", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
flag_hunter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = flag_hunter
SPEC.loader.exec_module(flag_hunter)


def test_finds_default_flag_formats_in_binary_data(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    target.write_bytes(b"\x00\xffnoise ctf_cs{real_candidate} tail")

    matches = flag_hunter.scan_file(
        target,
        patterns=flag_hunter.compile_patterns(None),
        max_bytes=1024,
        context_bytes=8,
    )

    assert [item.candidate for item in matches] == ["ctf_cs{real_candidate}"]
    assert matches[0].offset == 8
    assert "\x00" not in matches[0].context


def test_custom_regex_replaces_default_patterns(tmp_path: Path) -> None:
    target = tmp_path / "answer.txt"
    target.write_text("FLAG-ABC-123 flag{ignored}", encoding="utf-8")

    patterns = flag_hunter.compile_patterns([r"FLAG-[A-Z]{3}-\d{3}"])
    matches = flag_hunter.scan_file(
        target,
        patterns=patterns,
        max_bytes=1024,
        context_bytes=4,
    )

    assert [item.candidate for item in matches] == ["FLAG-ABC-123"]


def test_duplicate_pattern_hits_are_deduplicated(tmp_path: Path) -> None:
    target = tmp_path / "answer.txt"
    target.write_text("flag{same}", encoding="utf-8")
    patterns = [re.compile(r"flag\{[^}]+\}"), re.compile(r"flag\{same\}")]

    matches = flag_hunter.scan_file(
        target,
        patterns=patterns,
        max_bytes=1024,
        context_bytes=0,
    )

    assert len(matches) == 1


def test_scan_marks_truncated_files(tmp_path: Path) -> None:
    target = tmp_path / "large.txt"
    target.write_text("flag{early}" + "A" * 200, encoding="utf-8")

    matches = flag_hunter.scan_file(
        target,
        patterns=flag_hunter.compile_patterns(None),
        max_bytes=32,
        context_bytes=0,
    )

    assert len(matches) == 1
    assert matches[0].truncated_file is True


def test_invalid_custom_regex_has_clear_error() -> None:
    try:
        flag_hunter.compile_patterns(["("])
    except ValueError as exc:
        assert "invalid regex" in str(exc)
    else:
        raise AssertionError("expected invalid regex failure")


def test_recursive_scan_order_is_stable(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "b.txt").write_text("flag{b}", encoding="utf-8")
    (nested / "a.txt").write_text("flag{a}", encoding="utf-8")

    matches = flag_hunter.scan_paths(
        [tmp_path],
        patterns=flag_hunter.compile_patterns(None),
        max_bytes=1024,
        max_files=10,
        context_bytes=0,
    )

    assert [Path(item.path).name for item in matches] == ["a.txt", "b.txt"]
