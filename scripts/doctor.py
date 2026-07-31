#!/usr/bin/env python3
"""Report whether the local machine is ready to run CTF Sloper.

The diagnostic is intentionally read-only. It checks the Python runtime,
required Python modules, important repository paths, and optional external
CTF tools without executing challenge files.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
MIN_PYTHON = (3, 10)

PYTHON_MODULES: tuple[tuple[str, str], ...] = (
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("python-multipart", "multipart"),
    ("requests", "requests"),
    ("Pillow", "PIL"),
    ("numpy", "numpy"),
    ("PyJWT", "jwt"),
    ("base58", "base58"),
    ("pyzipper", "pyzipper"),
    ("rarfile", "rarfile"),
)

CORE_COMMANDS: tuple[str, ...] = (
    "file",
    "strings",
    "xxd",
    "unzip",
)

OPTIONAL_COMMANDS: tuple[str, ...] = (
    "binwalk",
    "exiftool",
    "steghide",
    "zsteg",
    "tshark",
    "qpdf",
    "gdb",
    "jadx",
)

REQUIRED_PATHS: tuple[str, ...] = (
    "app.py",
    "requirements.txt",
    "static/index.html",
    "sloper_v72/bootstrap.py",
    "sloper_v72/final_engine.py",
    "projects",
)


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    required: bool
    detail: str


def python_check() -> Check:
    current = sys.version_info[:3]
    ok = current >= MIN_PYTHON
    return Check(
        name="python",
        ok=ok,
        required=True,
        detail=(
            f"{platform.python_version()} at {sys.executable} "
            f"(requires >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"
        ),
    )


def module_check(package_name: str, import_name: str) -> Check:
    available = importlib.util.find_spec(import_name) is not None
    return Check(
        name=f"python:{package_name}",
        ok=available,
        required=True,
        detail=f"import {import_name}",
    )


def command_check(command: str, *, required: bool) -> Check:
    resolved = shutil.which(command)
    return Check(
        name=f"command:{command}",
        ok=resolved is not None,
        required=required,
        detail=resolved or "not found on PATH",
    )


def path_check(relative_path: str) -> Check:
    target = ROOT / relative_path
    return Check(
        name=f"path:{relative_path}",
        ok=target.exists(),
        required=True,
        detail=str(target),
    )


def collect_checks() -> list[Check]:
    checks = [python_check()]
    checks.extend(module_check(package, module) for package, module in PYTHON_MODULES)
    checks.extend(path_check(path) for path in REQUIRED_PATHS)
    checks.extend(command_check(command, required=True) for command in CORE_COMMANDS)
    checks.extend(command_check(command, required=False) for command in OPTIONAL_COMMANDS)
    return checks


def summarize(checks: Iterable[Check]) -> dict[str, int | bool]:
    items = list(checks)
    required_failures = sum(1 for item in items if item.required and not item.ok)
    optional_missing = sum(1 for item in items if not item.required and not item.ok)
    return {
        "ready": required_failures == 0,
        "checks": len(items),
        "required_failures": required_failures,
        "optional_missing": optional_missing,
    }


def render_text(checks: Iterable[Check]) -> str:
    items = list(checks)
    lines = ["CTF Sloper environment diagnostic", ""]
    for item in items:
        marker = "OK" if item.ok else ("FAIL" if item.required else "MISS")
        requirement = "required" if item.required else "optional"
        lines.append(f"[{marker:4}] {item.name:<30} {requirement:<8} {item.detail}")

    summary = summarize(items)
    lines.extend(
        [
            "",
            ("READY" if summary["ready"] else "NOT READY")
            + f" | required failures: {summary['required_failures']}"
            + f" | optional tools missing: {summary['optional_missing']}",
        ]
    )
    if summary["required_failures"]:
        lines.append("Install Python dependencies with: pip install -r requirements.txt")
    if summary["optional_missing"]:
        lines.append("Install the full external toolset with: bash FULL_INSTALL.sh")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check whether this machine is ready to run CTF Sloper."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when optional external tools are missing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checks = collect_checks()
    summary = summarize(checks)

    if args.json:
        payload = {
            "summary": summary,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "checks": [asdict(item) for item in checks],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(checks))

    optional_failure = args.strict and bool(summary["optional_missing"])
    return 1 if (not summary["ready"] or optional_failure) else 0


if __name__ == "__main__":
    raise SystemExit(main())
