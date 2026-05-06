#!/usr/bin/env python3
"""Benchmark CTF SLOPER against a local CTF writeup/challenge repository.

Usage:
  python3 scripts/benchmark_writeup_repo.py /path/to/ShundaZhang-CTF

The benchmark is intentionally fairer than a simple grep:
- expected flags are mined from writeups / README / solution notes;
- solver input excludes obvious writeup/solution files by default;
- results are classified as solved_asset_only, leaked_by_writeup_only, or unresolved.

This lets you use public writeup repos as regression corpora without fooling
SLOPER by feeding it the answer page as the challenge file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

os.environ.setdefault("SLOPER_ENABLE_LEGACY_DEEP", "0")
os.environ.setdefault("SLOPER_ENABLE_LEGACY_SUMMARY", "0")
os.environ.setdefault("SLOPER_MAX_TOOL_TIMEOUT", "2")

import app  # noqa: E402,F401
import sloper_legacy as sloper  # noqa: E402

FLAG_PATTERNS = [
    re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}"),
    re.compile(r"(?is)(?<![A-Za-z0-9_])\{[^{}\r\n]{5,220}\}"),
]
WRITEUP_HINTS = re.compile(r"(?i)(readme|writeup|solution|solve|flag|walkthrough|wp|notes?)")
ASSET_SKIP = re.compile(r"(?i)(^readme\.md$|writeup|solution|walkthrough|solve\.(py|sage|js|sh|txt|md)$|flag\.txt$|\.git/|__pycache__|\.DS_Store)")
MAX_FILE_BYTES = 8_000_000


def safe_read(path: Path, limit: int = 1_000_000) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_flags_from_text(text: str) -> list[str]:
    out, seen = [], set()
    for rx in FLAG_PATTERNS:
        for m in rx.finditer(text or ""):
            f = m.group(0).strip()
            low = f.lower()
            if any(x in low for x in ["your_flag", "flag_here", "example", "placeholder", "fake", "not_the_flag"]):
                continue
            if low not in seen:
                seen.add(low)
                out.append(f)
    return out


def is_binary_asset(path: Path) -> bool:
    if not path.is_file():
        return False
    rel = str(path).replace("\\", "/")
    if ASSET_SKIP.search(path.name) or ASSET_SKIP.search(rel):
        return False
    try:
        if path.stat().st_size <= 0 or path.stat().st_size > MAX_FILE_BYTES:
            return False
    except Exception:
        return False
    return True


def candidate_challenge_dirs(repo: Path) -> list[Path]:
    dirs = set()
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if WRITEUP_HINTS.search(p.name):
            flags = extract_flags_from_text(safe_read(p))
            if flags:
                dirs.add(p.parent)
    return sorted(dirs)


def analyze_dir_assets(chal: Path) -> tuple[list[str], list[dict[str, Any]]]:
    found, seen = [], set()
    reports = []
    with tempfile.TemporaryDirectory(prefix="sloper_repo_bench_") as td:
        root = Path(td)
        fdir = root / "files"
        fdir.mkdir()
        assets = [p for p in chal.rglob("*") if is_binary_asset(p)][:60]
        # Copy into a project-like files/ dir so sandbox assumptions hold.
        copied = []
        for p in assets:
            rel = p.relative_to(chal)
            dest = fdir / str(rel).replace("/", "__")
            try:
                dest.write_bytes(p.read_bytes())
                copied.append(dest)
            except Exception:
                pass
        for i, p in enumerate(copied, 1):
            try:
                rep = sloper.analyze_file("repo-bench", p, root, i, len(copied))
                reports.append(rep)
            except Exception as e:
                reports.append({"name": p.name, "error": str(e), "flags": []})
        try:
            summary = sloper.project_summary(reports, {"id": "repo-bench", "title": chal.name})
        except Exception:
            summary = {"flags": []}
        for item in summary.get("flags", []) or []:
            f = item.get("flag") if isinstance(item, dict) else str(item)
            if f and f.lower() not in seen:
                seen.add(f.lower())
                found.append(f)
    return found, reports


def benchmark_repo(repo: Path, limit: int = 200) -> dict[str, Any]:
    if not repo.exists() or not repo.is_dir():
        return {"ok": False, "error": f"repo path not found: {repo}"}
    if hasattr(sloper, "sl111_write_settings"):
        sloper.sl111_write_settings({"flag_format": "any_prefix", "attack_preset": "balanced", "difficulty": "medium"})
    dirs = candidate_challenge_dirs(repo)[:limit]
    results = []
    started = time.perf_counter()
    for chal in dirs:
        expected = []
        writeup_files = [p for p in chal.rglob("*") if p.is_file() and WRITEUP_HINTS.search(p.name)][:20]
        for wf in writeup_files:
            for f in extract_flags_from_text(safe_read(wf)):
                if f.lower() not in {x.lower() for x in expected}:
                    expected.append(f)
        if not expected:
            continue
        t0 = time.perf_counter()
        found, reports = analyze_dir_assets(chal)
        exp_low = {x.lower() for x in expected}
        found_low = {x.lower() for x in found}
        solved = bool(exp_low & found_low)
        results.append({
            "challenge_dir": str(chal.relative_to(repo)),
            "expected": expected[:10],
            "found_asset_only": found[:10],
            "status": "solved_asset_only" if solved else "unresolved_asset_only",
            "files_analyzed": len(reports),
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        })
    solved = sum(1 for r in results if r["status"] == "solved_asset_only")
    out = {
        "ok": True,
        "repo": str(repo),
        "challenge_dirs_with_expected_flags": len(results),
        "solved_asset_only": solved,
        "unresolved_asset_only": len(results) - solved,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "results": results,
        "notes": [
            "Expected flags are mined from local writeups; obvious writeup/solution files are excluded from solver input.",
            "If a challenge only contains the writeup and not original assets, it will show unresolved_asset_only.",
        ],
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", type=Path, help="local path to a CTF repository clone")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--out", type=Path, default=Path("docs/SHUNDAZHANG_CTF_BENCHMARK_RESULTS_v111.json"))
    args = ap.parse_args()
    out = benchmark_repo(args.repo, args.limit)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
