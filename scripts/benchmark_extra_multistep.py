#!/usr/bin/env python3
"""Run the supplied extra multistep regression pack through the safe pack runner."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

DEFAULT_PACKS = [
    Path(r"P:\Users\User\Downloads\sloper_extra_multistep_regression_tasks.zip"),
    ROOT / "sloper_extra_multistep_regression_tasks.zip",
]


def _default_pack() -> Path:
    for path in DEFAULT_PACKS:
        if path.exists():
            return path
    raise SystemExit("extra multistep pack not found; pass zip/folder path as the first argument")


def _extract_if_zip(path: Path, tmp: Path) -> Path:
    if path.is_dir():
        return path
    if not zipfile.is_zipfile(path):
        return path
    out = tmp / "extra_multistep_pack"
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        for member in zf.infolist():
            dest = (out / member.filename).resolve()
            if not str(dest).startswith(str(out.resolve())):
                continue
            if member.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, dest.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
    children = [p for p in out.iterdir() if p.name not in {"__MACOSX"}]
    return children[0] if len(children) == 1 and children[0].is_dir() else out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pack", nargs="?", type=Path)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--out", type=Path, default=Path("docs/EXTRA_MULTISTEP_BENCHMARK.json"))
    ap.add_argument("--html-out", type=Path, default=Path("docs/EXTRA_MULTISTEP_BENCHMARK.html"))
    ap.add_argument("--progress-out", type=Path, default=Path("docs/EXTRA_MULTISTEP_PROGRESS.json"))
    args = ap.parse_args()
    pack = (args.pack or _default_pack()).expanduser().resolve()
    if not pack.exists():
        raise SystemExit(f"pack not found: {pack}")
    with tempfile.TemporaryDirectory(prefix="sloper_extra_multistep_") as td:
        root = _extract_if_zip(pack, Path(td))
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "benchmark_challenge_pack.py"),
            str(root),
            "--recursive-leaves",
            "--per-challenge-timeout",
            str(args.timeout),
            "--out",
            str(args.out),
            "--html-out",
            str(args.html_out),
            "--progress-out",
            str(args.progress_out),
            "--attack-preset",
            "deep",
            "--difficulty",
            "multi_step",
            "--max-depth",
            "6",
            "--max-artifacts",
            "3500",
        ]
        proc = subprocess.run(cmd, cwd=str(ROOT), text=True)
    if args.out.exists():
        data = json.loads(args.out.read_text(encoding="utf-8", errors="replace"))
        print(json.dumps(data, indent=2, ensure_ascii=False))
        known = [r for r in data.get("results", []) if r.get("expected")]
        solved = [r for r in known if r.get("solved")]
        return 0 if known and len(solved) == len(known) and proc.returncode == 0 else 1
    return proc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
