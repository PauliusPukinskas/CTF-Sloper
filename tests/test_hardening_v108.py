from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hardening_module_exists():
    text = (ROOT / "sloper_v72/hardening_v108.py").read_text(encoding="utf-8")
    assert "def apply(mod)" in text
    assert "safe_source_path" in text
    assert "v109_safe_manual" in text
    assert "base64" in text


def test_bootstrap_loads_hardening():
    text = (ROOT / "sloper_v72/bootstrap.py").read_text(encoding="utf-8")
    assert "hardening_v108" in text
    assert "sl108_postprocess_report_file" in text
