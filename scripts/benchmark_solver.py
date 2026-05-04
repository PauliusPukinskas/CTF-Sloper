#!/usr/bin/env python3
"""Local regression benchmark for CTF SLOPER.

v112 checks custom flag formats, project settings, recursive decoding, and
bounded runtime.  It does not execute challenge binaries or touch the network.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

os.environ.setdefault("SLOPER_ENABLE_LEGACY_DEEP", "0")
os.environ.setdefault("SLOPER_ENABLE_LEGACY_SUMMARY", "0")
os.environ.setdefault("SLOPER_MAX_TOOL_TIMEOUT", "2")

import app  # noqa: E402,F401
import sloper_legacy as sloper  # noqa: E402


def b64(x: bytes) -> bytes:
    return base64.b64encode(x)


def rot13_text(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

CASES = [
    {"case": "plain_ctf_cs", "data": b"notes: ctf_cs{bench_plain_01}\n", "expected": "ctf_cs{bench_plain_01}", "settings": {"flag_format": "ctf_cs", "attack_preset": "quick", "difficulty": "easy", "max_depth": 1}},
    {"case": "base64_ctf_cs", "data": b64(b"ctf_cs{bench_base64_02}"), "expected": "ctf_cs{bench_base64_02}", "settings": {"flag_format": "ctf_cs", "attack_preset": "balanced", "difficulty": "medium", "max_depth": 2}},
    {"case": "hex_ctf_cs", "data": b"prefix " + b"ctf_cs{bench_hex_03}".hex().encode(), "expected": "ctf_cs{bench_hex_03}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "url_ctf_cs", "data": b"%63%74%66%5F%63%73%7Bbench_url_04%7D", "expected": "ctf_cs{bench_url_04}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "rot13_ctf_cs", "data": b"pgs_pf{orapu_ebg13_05}", "expected": "ctf_cs{bench_rot13_05}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "ctf_cm_selected", "data": b"answer: ctf_cm{bench_custom_prefix_06}", "expected": "ctf_cm{bench_custom_prefix_06}", "settings": {"flag_format": "ctf_cm", "flag_prefix": "ctf_cm"}},
    {"case": "flag_selected", "data": b"flag{bench_flag_prefix_07}", "expected": "flag{bench_flag_prefix_07}", "settings": {"flag_format": "flag", "flag_prefix": "flag"}},
    {"case": "braces_only_selected", "data": b"hidden {bench_bare_braces_08}", "expected": "{bench_bare_braces_08}", "settings": {"flag_format": "braces_only"}},
    {"case": "custom_regex_selected", "data": b"ticket KEY-BENCH-09 accepted", "expected": "KEY-BENCH-09", "settings": {"flag_format": "custom_regex", "custom_flag_regex": r"KEY-[A-Z0-9-]+"}},
    {"case": "multistep_base64_rot13", "data": b64(rot13_text("ctf_cs{multi_step_10}").encode()), "expected": "ctf_cs{multi_step_10}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 4, "max_artifacts": 2500}},
    {"case": "multistep_base64_hex", "data": b64(b"ctf_cs{hex_inside_11}".hex().encode()), "expected": "ctf_cs{hex_inside_11}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 4}},
    {"case": "url_base64_rot13", "data": quote(base64.b64encode(rot13_text("ctf_cs{url_b64_rot_12}").encode()).decode()).encode(), "expected": "ctf_cs{url_b64_rot_12}", "settings": {"flag_format": "ctf_cs", "max_depth": 4}},
    {"case": "gzip_base64", "data": b64(gzip.compress(b"ctf_cs{gzip_b64_13}")), "expected": "ctf_cs{gzip_b64_13}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "max_depth": 4}},
    {"case": "single_byte_xor", "data": xor(b"ctf_cs{xor_42_14}", 42), "expected": "ctf_cs{xor_42_14}", "settings": {"flag_format": "ctf_cs", "attack_preset": "balanced", "max_depth": 2}},
    {"case": "base32", "data": base64.b32encode(b"ctf_cs{base32_15}"), "expected": "ctf_cs{base32_15}", "settings": {"flag_format": "ctf_cs", "max_depth": 2}},
]


def set_settings(settings: dict) -> None:
    if hasattr(sloper, "sl111_write_settings"):
        sloper.sl111_write_settings(settings)


def run_case(case: dict) -> dict:
    set_settings(case.get("settings", {}))
    with tempfile.TemporaryDirectory(prefix="sloper_bench_") as td:
        root = Path(td)
        files = root / "files"
        files.mkdir()
        path = files / f"{case['case']}.bin"
        path.write_bytes(case["data"])
        meta = {"id": "bench", "title": "benchmark", "solver_settings": case.get("settings", {})}
        start = time.perf_counter()
        report = sloper.analyze_file("bench", path, root, 1, 1)
        summary = sloper.project_summary([report], meta)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        found = [item.get("flag") if isinstance(item, dict) else str(item) for item in summary.get("flags", []) or []]
        preferred = [item.get("preferred_flag") or item.get("flag") if isinstance(item, dict) else str(item) for item in summary.get("preferred_flags", []) or []]
        ok = case["expected"] in found or case["expected"] in preferred
        return {
            "case": case["case"],
            "expected": case["expected"],
            "ok": ok,
            "elapsed_ms": elapsed_ms,
            "settings": case.get("settings", {}),
            "top_flags": found[:8],
            "preferred": preferred[:8],
            "fast_lane": report.get("v110_fast_lane", {}),
            "control_plane": summary.get("v111_control_plane", {}),
        }


def main() -> int:
    results = [run_case(case) for case in CASES]
    ok = sum(1 for r in results if r["ok"])
    max_ms = max((r["elapsed_ms"] for r in results), default=0)
    out = {"ok": ok == len(results), "passed": ok, "total": len(results), "max_elapsed_ms": max_ms, "results": results}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    Path("docs/BENCHMARK_RESULTS_v112.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
