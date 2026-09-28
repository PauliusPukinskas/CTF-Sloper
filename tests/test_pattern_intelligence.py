from pathlib import Path

from sloper.pattern_intelligence import _safe_name, _signals, _strings, score_pattern


def test_safe_name_normalizes_untrusted_artifact_names():
    assert _safe_name("../../weird challenge?.png") == ".._.._weird_challenge_.png"
    assert _safe_name("") == "pattern"
    assert len(_safe_name("x" * 300)) == 140


def test_strings_extracts_printable_runs_and_ignores_short_noise():
    raw = b"\x00\x01abc\x02flag{demo}\nhello world\x00zz\x03"
    text = _strings(raw)

    assert "flag{demo}" in text
    assert "hello world" in text
    assert "abc" not in text
    assert "zz" not in text


def test_signals_detects_png_metadata_tail_and_flag_shape():
    raw = b"\x89PNG\r\n\x1a\n" + b"tEXt" + b"note CTF{demo_flag}" + b"IEND" + b"hidden-tail"
    text = "note CTF{demo_flag}"

    signals = _signals(Path("challenge.png"), raw, text)

    assert "PNG magic" in signals
    assert "ancillary chunk names" in signals
    assert "tEXt" in signals
    assert "bytes after IEND" in signals
    assert "high entropy tail" in signals
    assert "exact flag regex" in signals
    assert "forensics/image/png" in signals


def test_score_pattern_rewards_exact_and_category_matches():
    image_pattern = {
        "category": "forensics/image/png",
        "trigger_signals": ["PNG magic", "bytes after IEND"],
    }
    unrelated_pattern = {
        "category": "crypto/encodings_classical",
        "trigger_signals": ["base64"],
    }
    signals = {"PNG magic", "bytes after IEND", "image", "forensics/image/png"}

    image_score = score_pattern(image_pattern, signals, ".png")
    unrelated_score = score_pattern(unrelated_pattern, signals, ".png")

    assert image_score > unrelated_score
    assert image_score >= 100


def test_score_pattern_accepts_useful_fuzzy_trigger_matches():
    pattern = {"category": "", "trigger_signals": ["png"]}

    assert score_pattern(pattern, {"PNG magic"}) > 0
