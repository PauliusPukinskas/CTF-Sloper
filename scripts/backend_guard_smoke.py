#!/usr/bin/env python3
"""Backend-only guard regression checks.

These checks exercise the late backend guard without touching static frontend
files.  They focus on the failure modes from the May 2026 backend audit:
path containment, project-id validation, upload route health, log tailing,
custom regex sanitation, and blocking automatic uploaded-binary execution.
"""
from __future__ import annotations

import tempfile
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as sloper


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> None:
    client = TestClient(sloper.app)

    # raw_info must not act as a filesystem oracle for paths outside projects.
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(b"outside")
        outside = Path(fh.name)
    try:
        r = client.get("/api/raw_info", params={"path": str(outside)})
        assert_true(r.status_code == 200, f"raw_info outside status {r.status_code}")
        js = r.json()
        assert_true(js.get("exists") is False and not js.get("url"), "raw_info leaked outside path")
    finally:
        outside.unlink(missing_ok=True)

    # Upload route must work and create a project without auto-start.
    r = client.post(
        "/api/projects",
        data={"title": "", "auto_start": "false", "custom_flag_regex": "(a+)+"},
        files={"files": ("sample with spaces.txt", b"ctf_cs{backend_guard_upload_ok}\n", "text/plain")},
    )
    assert_true(r.status_code == 200, f"upload status {r.status_code}: {r.text[:200]}")
    js = r.json()
    assert_true(js.get("ok") is True and js.get("id"), "upload did not create project")
    pid = js["id"]
    assert_true(js.get("settings", {}).get("custom_flag_regex", "") == "", "dangerous custom regex was not sanitized")

    root = sloper.PROJECTS / pid
    inside = root / "files" / "sample with spaces.txt"
    assert_true(inside.exists(), "uploaded file missing")

    r = client.get("/api/raw_info", params={"path": str(inside)})
    assert_true(r.status_code == 200 and r.json().get("exists") is True, "raw_info failed for project file")
    r = client.get("/api/raw", params={"path": str(inside)})
    assert_true(r.status_code == 200 and b"backend_guard_upload_ok" in r.content, "raw failed for project file")

    # Invalid project ids must be rejected before legacy path construction.
    r = client.get("/api/projects/..%2Fescape/compact")
    assert_true(r.status_code == 400, f"invalid pid was not rejected: {r.status_code}")

    # Log endpoint must read events.log.
    sloper.log(pid, "backend guard log smoke")
    r = client.get(f"/api/projects/{pid}/log")
    assert_true(r.status_code == 200 and "backend guard log smoke" in r.json().get("tail", ""), "events.log tail missing")

    # Automatic local executable smoke-run must be blocked.
    report = {"name": "fake.elf", "rel": "files/fake.elf", "path": str(root / "files" / "fake.elf"), "artifacts": [], "next_steps": []}
    out = sloper.v99_local_binary_smoke_agent(root, report, b"\x7fELF" + b"Password" + b"\0" * 2000)
    assert_true(out and "execution_blocked" in out[0].get("name", ""), "local binary execution was not blocked")

    # Final ranking must also update stale older triage headlines.
    summary = sloper.sloper_clean_rerank_summary({
        "user_preferences": {"flag_format": "ctf_cs"},
        "flags": [
            {"flag": "ctf_cs{Category}", "source": "README metadata", "score": 99999},
            {
                "flag": "ctf_cs{caesar_shift_ok}",
                "source": "classic_crypto:caesar_7",
                "artifact": str(inside),
                "why": "deterministic transform artifact",
                "score": 10,
            },
        ],
        "v117_triage": {"best_flag": "ctf_cs{Category}", "best_score": 99999},
    })
    assert_true(summary["flags"][0]["flag"] == "ctf_cs{caesar_shift_ok}", "clean ranking did not promote transform proof")
    assert_true(summary["v117_triage"]["best_flag"] == "ctf_cs{caesar_shift_ok}", "stale triage best flag was not synchronized")

    print({
        "ok": True,
        "pid": pid,
        "checks": [
            "raw_info_no_oracle",
            "streaming_upload_route",
            "custom_regex_sanitized",
            "raw_project_file",
            "invalid_pid_rejected",
            "events_log_tail",
            "binary_auto_execution_blocked",
            "ranking_triage_sync",
        ],
    })


if __name__ == "__main__":
    main()
