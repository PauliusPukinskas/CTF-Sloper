from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "hash_identifier.py"
SPEC = importlib.util.spec_from_file_location("hash_identifier", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
hash_identifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hash_identifier
SPEC.loader.exec_module(hash_identifier)


def test_identifies_ambiguous_32_character_hex_digest() -> None:
    guess = hash_identifier.identify_hash("5d41402abc4b2a76b9719d911017c592")

    assert guess.encoding == "hex"
    assert guess.normalized == "5d41402abc4b2a76b9719d911017c592"
    assert "MD5" in guess.algorithms
    assert "NTLM" in guess.algorithms
    assert guess.confidence == "low"


def test_identifies_bcrypt_from_format_marker() -> None:
    value = "$2b$12$abcdefghijklmnopqrstuuBqP9h55QQb9xv0aFZBmm7jyV8J5QAmA"
    guess = hash_identifier.identify_hash(value)

    assert guess.algorithms == ("bcrypt",)
    assert guess.encoding == "modular-crypt"
    assert guess.confidence == "high"


def test_mysql_star_prefix_is_classified_before_generic_hex() -> None:
    guess = hash_identifier.identify_hash("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19")

    assert guess.algorithms == ("MySQL 4.1+",)
    assert guess.confidence == "high"


def test_unknown_text_is_not_forced_into_hash_family() -> None:
    guess = hash_identifier.identify_hash("not-a-hash")

    assert guess.encoding == "unknown"
    assert guess.algorithms == ()
    assert guess.confidence == "none"


def test_base64_detection_is_opt_in() -> None:
    value = "XUFAKrxLKna5cZ2REBfFkg=="

    disabled = hash_identifier.identify_hash(value)
    enabled = hash_identifier.identify_hash(value, allow_base64=True)

    assert disabled.encoding == "unknown"
    assert enabled.encoding == "base64"
    assert enabled.length == 16
    assert "MD5" in enabled.algorithms
    assert enabled.confidence == "low"


def test_collect_values_ignores_blank_lines_and_comments(tmp_path: Path) -> None:
    source = tmp_path / "hashes.txt"
    source.write_text("# exported values\n\nabc\ndef\n", encoding="utf-8")

    values = hash_identifier.collect_values(["123"], files=[source])

    assert values == ["123", "abc", "def"]


def test_render_text_reports_unknown_candidates() -> None:
    guess = hash_identifier.identify_hash("xyz")

    output = hash_identifier.render_text([guess])

    assert "possible: unknown" in output
    assert "confidence: none" in output
