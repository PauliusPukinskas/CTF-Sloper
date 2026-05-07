#!/usr/bin/env python3
"""Benchmark Sloper on a real local challenge pack.

Expected layout is flexible:
  pack/
    challenge-a/
      files...
      flag.txt              # optional expected flag
      challenge.json        # optional: {"flag": "ctf_cs{...}", "category": "stego"}
    challenge-b.zip         # also accepted as one challenge file

The script never contacts the network and never executes submitted binaries.
It writes JSON plus a readable HTML operator report for fast live triage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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
os.environ.setdefault("SLOPER_V116_FAST_ONLY", "1")

import app  # noqa: E402,F401
import sloper_legacy as sloper  # noqa: E402
from sloper.bench_runner import python_cmd, run_json_file_worker, write_json  # noqa: E402

FLAG_RE = re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}|\{[^{}\r\n]{3,220}\}")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", "venv", ".venv", "dist", "build", "artifacts", "artifacts_v113", "artifacts_v114", "artifacts_v115", "artifacts_v116", "artifacts_v117", "projects", "ANSWERS_DO_NOT_UPLOAD", "answers", "solutions"}


def read_expected(chal: Path) -> str:
    if chal.is_file():
        sidecars = [chal.with_suffix(chal.suffix + ".flag"), chal.with_suffix(".flag"), chal.with_name(chal.stem + "_flag.txt")]
    else:
        sidecars = [chal / "flag.txt", chal / "expected.txt", chal / "solution.txt", chal / "challenge.json", chal / "metadata.json"]
    for p in sidecars:
        if not p.exists() or not p.is_file():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if p.suffix == ".json":
            try:
                data = json.loads(txt)
                for key in ("flag", "expected", "answer"):
                    if isinstance(data, dict) and isinstance(data.get(key), str):
                        return data[key].strip()
            except Exception:
                pass
        m = FLAG_RE.search(txt)
        if m:
            return m.group(0).strip()
        if txt.strip() and len(txt.strip()) < 240:
            return txt.strip()
    return ""


def iter_challenges(pack: Path) -> list[Path]:
    if pack.is_file():
        return [pack]
    children = [p for p in sorted(pack.iterdir()) if p.name not in SKIP_DIRS and not p.name.startswith(".")]
    dirs = [p for p in children if p.is_dir()]
    files = [p for p in children if p.is_file() and p.name not in {"flag.txt", "expected.txt", "solution.txt", "metadata.json", "challenge.json"}]
    # If the supplied folder itself looks like one challenge, benchmark it as
    # one challenge rather than treating every contained file as a separate task.
    if any((pack / n).exists() for n in ("flag.txt", "expected.txt", "solution.txt", "metadata.json", "challenge.json")):
        return [pack]
    if not dirs and files:
        return [pack]
    return dirs or files



def iter_leaf_challenges(pack: Path) -> list[Path]:
    """Find challenge leaf folders recursively.

    A leaf is a folder with at least one task .txt/README-like file and at least
    one non-solution artifact, or a folder with files and no child dirs. This is
    better for CTF archives arranged as Category/Challenge/files.
    """
    if pack.is_file():
        return [pack]
    leaves: list[Path] = []
    for d in sorted([x for x in pack.rglob("*") if x.is_dir() and not any(part in SKIP_DIRS for part in x.parts)]):
        files=[p for p in d.iterdir() if p.is_file() and not p.name.startswith(".")]
        dirs=[p for p in d.iterdir() if p.is_dir() and not p.name.startswith(".")]
        if not files:
            continue
        non_meta=[p for p in files if p.name not in {"flag.txt", "expected.txt", "solution.txt", "metadata.json", "challenge.json"}]
        task_txt=[p for p in files if p.suffix.lower()==".txt" and p.name not in {"flag.txt", "expected.txt", "solution.txt"}]
        has_artifact=any(p.suffix.lower() not in {".txt", ".md"} or p.name.lower() in {"system.log", "artifact.log"} for p in non_meta)
        if (task_txt and has_artifact) or (files and not dirs):
            leaves.append(d)
    # fallback to old behavior if heuristic finds nothing
    return leaves or iter_challenges(pack)

def challenge_files(chal: Path, max_files: int = 120) -> list[Path]:
    if chal.is_file():
        return [chal]
    out: list[Path] = []
    for p in chal.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        if p.name in {"flag.txt", "expected.txt", "solution.txt", "metadata.json", "challenge.json"}:
            continue
        out.append(p)
        if len(out) >= max_files:
            break
    return out


def write_settings(settings: dict[str, Any]) -> None:
    if hasattr(sloper, "sl111_write_settings"):
        sloper.sl111_write_settings(settings)


def _run_one_inner(chal: Path, args: argparse.Namespace) -> dict[str, Any]:
    expected = read_expected(chal)
    settings = {
        "flag_format": args.flag_format,
        "custom_flag_regex": args.custom_regex or "",
        "attack_preset": args.attack_preset,
        "difficulty": args.difficulty,
        "max_depth": args.max_depth,
        "max_artifacts": args.max_artifacts,
    }
    write_settings(settings)
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sloper_pack_") as td:
        root = Path(td)
        files_dir = root / "files"
        files_dir.mkdir(parents=True)
        src_files = challenge_files(chal, args.max_files)
        copied: list[Path] = []
        for src in src_files:
            dst = files_dir / (src.name if chal.is_file() else str(src.relative_to(chal)).replace(os.sep, "__"))
            try:
                shutil.copy2(src, dst)
                copied.append(dst)
            except Exception:
                continue
        reports = []
        total = max(1, len(copied))
        for i, p in enumerate(copied, 1):
            try:
                reports.append(sloper.analyze_file(chal.stem if chal.is_file() else chal.name, p, root, i, total))
            except Exception as e:
                reports.append({"name": p.name, "error": repr(e), "flags": [], "artifacts": []})
        meta = {"id": chal.stem if chal.is_file() else chal.name, "title": chal.name, "solver_settings": settings}
        summary = sloper.project_summary(reports, meta)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    flags = [x.get("preferred_flag") or x.get("flag") if isinstance(x, dict) else str(x) for x in summary.get("flags", []) or []]
    raw_flags = [x.get("flag") if isinstance(x, dict) else str(x) for x in summary.get("flags", []) or []]
    solved = bool(expected and (expected in flags or expected in raw_flags))
    return {
        "challenge": chal.name,
        "path": str(chal),
        "files": len(challenge_files(chal, args.max_files)),
        "expected": expected,
        "solved": solved if expected else None,
        "elapsed_ms": elapsed_ms,
        "top_flags": flags[:10],
        "raw_top_flags": raw_flags[:10],
        "evidence": summary.get("v113_evidence", {}),
        "triage": summary.get("v117_triage", {}) or summary.get("v116_triage", {}) or summary.get("v115_triage", {}) or summary.get("v114_triage", {}),
        "artifact_count": len(summary.get("artifacts", []) or []),
    }



def _run_one_child(q, chal_s: str, args_dict: dict[str, Any]) -> None:
    try:
        ns = argparse.Namespace(**args_dict)
        q.put(_run_one_inner(Path(chal_s), ns))
    except BaseException as e:
        q.put({"challenge": Path(chal_s).name, "path": chal_s, "files": 0, "expected": "", "solved": None, "elapsed_ms": 0, "top_flags": [], "raw_top_flags": [], "evidence": {}, "triage": {}, "artifact_count": 0, "error": repr(e)})


def run_one(chal: Path, args: argparse.Namespace) -> dict[str, Any]:
    """Run one challenge in a fresh Python subprocess with hard timeout.

    This uses the shared file-output worker helper, so benchmark stdout/stderr
    cannot deadlock on inherited pipes and undecodable bytes are replaced.
    """
    timeout = int(getattr(args, "per_challenge_timeout", 0) or 0)
    if timeout <= 0 or getattr(args, "single", False):
        return _run_one_inner(chal, args)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="sloper_one_") as td:
        td_path = Path(td)
        outp = td_path / "result.json"
        cmd = python_cmd(
            Path(__file__).resolve(), str(chal),
            "--single",
            "--flag-format", str(args.flag_format),
            "--custom-regex", str(args.custom_regex or ""),
            "--attack-preset", str(args.attack_preset),
            "--difficulty", str(args.difficulty),
            "--max-depth", str(args.max_depth),
            "--max-artifacts", str(args.max_artifacts),
            "--max-files", str(args.max_files),
            "--per-challenge-timeout", "0",
            "--out", str(outp),
            "--html-out", str(td_path / "single.html"),
        )
        ok, data, err = run_json_file_worker(cmd, ROOT, timeout, outp)
        if ok and isinstance(data, dict):
            data.setdefault("triage", {})
            if isinstance(data["triage"], dict):
                data["triage"].setdefault("isolation", "file-output-worker")
            return data
        expected = read_expected(chal)
        return {
            "challenge": chal.name,
            "path": str(chal),
            "files": len(challenge_files(chal, getattr(args, "max_files", 120))),
            "expected": expected,
            "solved": False if expected else None,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "top_flags": [],
            "raw_top_flags": [],
            "evidence": {},
            "triage": {"isolation": "file-output-worker", "timed_out": "timed out" in (err or "").lower(), "timeout_seconds": timeout},
            "artifact_count": 0,
            "error": err or "child exited without result",
        }



def html_escape(x: Any) -> str:
    return str(x if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def write_html_report(out: dict[str, Any], path: Path) -> None:
    rows = []
    for r in out.get("results", []):
        solved = r.get("solved")
        badge = "unknown" if solved is None else ("solved" if solved else "missed")
        flags = "<br>".join(html_escape(x) for x in (r.get("top_flags") or [])[:8]) or "—"
        tri = r.get("triage") or {}
        rows.append(f"""
        <tr class="{badge}">
          <td>{html_escape(r.get('challenge'))}</td>
          <td>{badge}</td>
          <td>{html_escape(r.get('expected') or '')}</td>
          <td>{flags}</td>
          <td>{html_escape(tri.get('best_confidence', ''))}</td>
          <td>{html_escape(r.get('artifact_count'))}</td>
          <td>{html_escape(r.get('elapsed_ms'))} ms</td>
        </tr>""")
    html = f"""<!doctype html><meta charset='utf-8'><title>CTF Sloper Challenge Pack Benchmark</title>
<style>body{{font:14px system-ui,Segoe UI,Arial;background:#07130d;color:#eafff2;padding:24px}}table{{border-collapse:collapse;width:100%;background:#0b1e14}}td,th{{border:1px solid #245b3d;padding:8px;vertical-align:top}}th{{background:#11351f}}.solved td{{background:#082417}}.missed td{{background:#2b1111}}.unknown td{{background:#1c1a0b}}code{{color:#8ff0b3}}</style>
<h1>CTF Sloper Challenge Pack Benchmark</h1>
<p>Pack: <code>{html_escape(out.get('pack'))}</code></p>
<p>Total: <b>{html_escape(out.get('total_challenges'))}</b> · Known expected: <b>{html_escape(out.get('known_expected'))}</b> · Solved: <b>{html_escape(out.get('solved'))}</b></p>
<table><thead><tr><th>Challenge</th><th>Status</th><th>Expected</th><th>Top flags</th><th>Best confidence</th><th>Artifacts</th><th>Time</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<pre>{html_escape(json.dumps(out.get('settings', {}), indent=2, ensure_ascii=False))}</pre>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pack", type=Path, help="folder or single file to benchmark")
    ap.add_argument("--flag-format", default="ctf_cs")
    ap.add_argument("--custom-regex", default="")
    ap.add_argument("--attack-preset", default="deep")
    ap.add_argument("--difficulty", default="multi_step")
    ap.add_argument("--max-depth", type=int, default=5)
    ap.add_argument("--max-artifacts", type=int, default=3000)
    ap.add_argument("--max-files", type=int, default=120)
    ap.add_argument("--per-challenge-timeout", type=int, default=45, help="kill one challenge analysis after this many seconds; 0 disables timeout")
    ap.add_argument("--recursive-leaves", action="store_true", help="benchmark recursive challenge leaf folders instead of only one directory level")
    ap.add_argument("--out", type=Path, default=Path("docs/CHALLENGE_PACK_BENCHMARK_v117.json"))
    ap.add_argument("--html-out", type=Path, default=Path("docs/CHALLENGE_PACK_BENCHMARK_v117.html"))
    ap.add_argument("--progress-out", type=Path, default=Path("docs/CHALLENGE_PACK_PROGRESS.json"))
    ap.add_argument("--single", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--offset", type=int, default=0, help="skip this many discovered challenges; useful for chunked real-pack benchmarking")
    ap.add_argument("--limit", type=int, default=0, help="benchmark at most this many discovered challenges; 0 means no limit")
    ap.add_argument("--only-regex", default="", help="only benchmark challenges whose path/name matches this regex")
    ap.add_argument("--merge-existing", action="store_true", help="merge with an existing JSON report at --out, replacing same-path rows")
    args = ap.parse_args()
    pack = args.pack.expanduser().resolve()
    if not pack.exists():
        raise SystemExit(f"pack not found: {pack}")
    if args.single:
        res = _run_one_inner(pack, args)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    all_challenges = iter_leaf_challenges(pack) if args.recursive_leaves else iter_challenges(pack)
    if args.only_regex:
        rx = re.compile(args.only_regex, re.I)
        all_challenges = [c for c in all_challenges if rx.search(str(c)) or rx.search(c.name)]
    start_i = max(0, int(args.offset or 0))
    end_i = None if int(args.limit or 0) <= 0 else start_i + int(args.limit)
    challenges = all_challenges[start_i:end_i]
    results = []
    for idx, chal in enumerate(challenges, 1):
        print(f"[{idx}/{len(challenges)} | global {start_i+idx}/{len(all_challenges)}] {chal}", flush=True)
        results.append(run_one(chal, args))
        known_so_far = [r for r in results if r.get("expected")]
        solved_so_far = [r for r in known_so_far if r.get("solved")]
        write_json(args.progress_out, {
            "pack": str(pack),
            "done": idx,
            "total": len(challenges),
            "global_done": start_i + idx,
            "discovered_challenges": len(all_challenges),
            "last_challenge": str(chal),
            "known_expected": len(known_so_far),
            "solved": len(solved_so_far),
            "results": results,
        })
    if args.merge_existing and args.out.exists():
        try:
            old = json.loads(args.out.read_text(encoding="utf-8"))
            old_rows = [r for r in old.get("results", []) if isinstance(r, dict)]
            by_path = {r.get("path"): r for r in old_rows if r.get("path")}
            for r in results:
                by_path[r.get("path")] = r
            results = list(by_path.values())
        except Exception:
            pass
    known = [r for r in results if r["expected"]]
    solved = [r for r in known if r["solved"]]
    out = {
        "ok": len(solved) == len(known) if known else True,
        "pack": str(pack),
        "total_challenges": len(results),
        "discovered_challenges": len(all_challenges),
        "chunk_offset": start_i,
        "chunk_limit": int(args.limit or 0),
        "known_expected": len(known),
        "solved": len(solved),
        "settings": {"flag_format": args.flag_format, "attack_preset": args.attack_preset, "difficulty": args.difficulty, "max_depth": args.max_depth, "max_artifacts": args.max_artifacts},
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    write_html_report(out, args.html_out)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"HTML report: {args.html_out}")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
