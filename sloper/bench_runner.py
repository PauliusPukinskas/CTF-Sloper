"""Robust local benchmark process helpers."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def run_json_file_worker(cmd: list[str], cwd: Path, timeout: int, output_path: Path) -> tuple[bool, Any, str]:
    """Run a Python worker that writes JSON to output_path.

    stdout/stderr are redirected to files so inherited helper subprocesses cannot
    keep a pipe open and stall the parent benchmark.
    """
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sloper_worker_") as td:
        td_path = Path(td)
        stdoutp = td_path / "stdout.log"
        stderrp = td_path / "stderr.log"
        env = dict(os.environ)
        env.setdefault("PYTHONIOENCODING", "utf-8")
        env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
        with stdoutp.open("w", encoding="utf-8", errors="replace") as so, stderrp.open("w", encoding="utf-8", errors="replace") as se:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                env=env,
                stdout=so,
                stderr=se,
                text=True,
                start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=max(1, int(timeout or 1)))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
                return False, None, f"timed out after {timeout}s"
        if output_path.exists():
            try:
                return rc == 0, json.loads(output_path.read_text(encoding="utf-8", errors="replace")), ""
            except Exception as exc:
                err = f"worker JSON parse failed: {exc}"
        else:
            err = f"worker exited {rc} without JSON output"
        try:
            err += "\nSTDERR:\n" + stderrp.read_text(encoding="utf-8", errors="replace")[-3000:]
        except Exception:
            pass
        try:
            err += "\nSTDOUT:\n" + stdoutp.read_text(encoding="utf-8", errors="replace")[-1200:]
        except Exception:
            pass
        err += f"\nelapsed_ms={int((time.perf_counter() - started) * 1000)}"
        return False, None, err


def python_cmd(script: Path, *args: str) -> list[str]:
    return [sys.executable, str(script), *map(str, args)]
