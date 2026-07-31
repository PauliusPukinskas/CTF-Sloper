from __future__ import annotations

import importlib.util
from pathlib import Path


DOCTOR_PATH = Path(__file__).resolve().parents[1] / "scripts" / "doctor.py"
SPEC = importlib.util.spec_from_file_location("ctf_sloper_doctor", DOCTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
DOCTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCTOR)


def test_summarize_reports_required_and_optional_failures() -> None:
    checks = [
        DOCTOR.Check("required-ok", True, True, "ok"),
        DOCTOR.Check("required-missing", False, True, "missing"),
        DOCTOR.Check("optional-missing", False, False, "missing"),
    ]

    assert DOCTOR.summarize(checks) == {
        "ready": False,
        "checks": 3,
        "required_failures": 1,
        "optional_missing": 1,
    }


def test_render_text_distinguishes_failures_from_optional_tools() -> None:
    output = DOCTOR.render_text(
        [
            DOCTOR.Check("python", True, True, "3.12"),
            DOCTOR.Check("command:file", False, True, "not found on PATH"),
            DOCTOR.Check("command:binwalk", False, False, "not found on PATH"),
        ]
    )

    assert "[OK  ] python" in output
    assert "[FAIL] command:file" in output
    assert "[MISS] command:binwalk" in output
    assert "NOT READY" in output
    assert "required failures: 1" in output
    assert "optional tools missing: 1" in output


def test_module_check_uses_import_name(monkeypatch) -> None:
    requested: list[str] = []

    def fake_find_spec(name: str):
        requested.append(name)
        return object()

    monkeypatch.setattr(DOCTOR.importlib.util, "find_spec", fake_find_spec)

    check = DOCTOR.module_check("Pillow", "PIL")

    assert requested == ["PIL"]
    assert check.ok is True
    assert check.name == "python:Pillow"


def test_strict_mode_fails_when_only_optional_tooling_is_missing(monkeypatch) -> None:
    checks = [DOCTOR.Check("command:binwalk", False, False, "not found")]
    monkeypatch.setattr(DOCTOR, "collect_checks", lambda: checks)

    assert DOCTOR.main([]) == 0
    assert DOCTOR.main(["--strict"]) == 1
