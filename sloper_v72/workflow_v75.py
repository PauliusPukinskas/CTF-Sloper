
"""CTF SLOPER v75 logic/router layer.

Adds:
- route/columnar transposition solver
- cleaner evidence-first promotion policy
- agent routing by file type and statement hints
- project cancel/timer endpoints
- first-file project title helper
"""
from __future__ import annotations

import itertools
import json
import math
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .health import AGENT_HEALTH, agent_crash

try:
    from . import workflow_v74 as v74
except Exception:  # pragma: no cover
    v74 = None

V75_JOBS: Dict[str, Dict[str, Any]] = {}
V75_CANCEL: set[str] = set()

FLAG_RE = re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,140}\}")
DECOY_WORDS = {
    "example","test","flag","placeholder","answer","answer_here",
    "vietos_pavadinimas","rastas_tekstas","your_flag_here","todo","dummy",
    "sample","fake","lorem","ipsum"
}

def now() -> float:
    return time.time()

def mark_job(pid: str, status: str, **extra) -> None:
    job = V75_JOBS.setdefault(pid, {"pid": pid, "created": now(), "started": None, "ended": None, "status": "created", "events": []})
    if status == "running" and not job.get("started"):
        job["started"] = now()
    if status in {"done", "error", "cancelled"}:
        job["ended"] = now()
    job["status"] = status
    job.update(extra)
    job["elapsed"] = round((job.get("ended") or now()) - (job.get("started") or job.get("created") or now()), 3)

def add_event(pid: str, message: str, **extra) -> None:
    job = V75_JOBS.setdefault(pid, {"pid": pid, "created": now(), "events": []})
    ev = {"t": round(now(), 3), "message": str(message)[:500]}
    ev.update(extra)
    job.setdefault("events", []).append(ev)
    if len(job["events"]) > 500:
        del job["events"][:-500]

def cancel_project(pid: str) -> None:
    V75_CANCEL.add(pid)
    mark_job(pid, "cancelled", cancel_requested=True)
    add_event(pid, "Cancel requested")

def cancelled(pid: str | None) -> bool:
    return bool(pid and pid in V75_CANCEL)

def clean_flag(flag: str) -> str | None:
    m = re.fullmatch(r"ctf_cs\{([^{}]+)\}", str(flag or ""))
    if not m:
        return None
    body = m.group(1).strip()
    low = body.lower()
    if low in DECOY_WORDS or len(body) < 3:
        return None
    if re.fullmatch(r"[_xX0-9-]+", body):
        return None
    # reject bodies with extremely low variety unless they are meaningful leet words
    if len(set(low)) <= 2 and len(low) > 6:
        return None
    return f"ctf_cs{{{body}}}"

def ensure(report: dict) -> None:
    report.setdefault("flags", [])
    report.setdefault("artifacts", [])
    report.setdefault("transformations", [])
    report.setdefault("workflow_evidence", [])
    report.setdefault("candidate_flags", [])
    report.setdefault("next_steps", [])

def promote(report: dict, flag: str, source: str, artifact: str | None, why: str, score: int = 700) -> None:
    ensure(report)
    flag = clean_flag(flag)
    if not flag:
        return
    # Store as string in legacy-compatible report flags.
    if flag not in report["flags"]:
        report["flags"].append(flag)
    ev = {"flag": flag, "source": source, "artifact": artifact or "", "why": why, "score": score}
    if ev not in report["workflow_evidence"]:
        report["workflow_evidence"].append(ev)

def scan(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 700) -> List[str]:
    out = []
    for m in FLAG_RE.finditer(str(text or "")):
        flag = clean_flag(m.group(0))
        if flag:
            promote(report, flag, source, artifact, why, score)
            out.append(flag)
    return list(dict.fromkeys(out))

def safe_name(name: str) -> str:
    if v74 and hasattr(v74, "safe_name"):
        return v74.safe_name(name)
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "file"))[:160] or "file"

def artifact(root: Path, report: dict, name: str, content, kind: str, note: str, score: int = 400) -> dict | None:
    ensure(report)
    try:
        root = Path(root)
        outdir = root / "generated" / "sloper75" / safe_name(report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / safe_name(name)
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(content)
            text = bytes(content[:1_000_000]).decode("utf-8", "ignore")
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
            text = str(content)
        art = {
            "kind": kind,
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v75",
            "score": int(score),
            "note": note,
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report["artifacts"].append(art)
        report["transformations"].append(art)
        scan(report, text, "SLOPER v75 artifact", str(p), "Strict flag found inside v75 generated evidence artifact.", score + 100)
        return art
    except Exception as e:
        agent_crash("v75 artifact", e, report)
        return None

def score_text(text: str) -> int:
    text = str(text or "")
    if not text:
        return 0
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t") / max(1, len(text))
    score = int(printable * 100)
    low = text.lower()
    for w in ["ctf_cs{", "flag{", "secret", "password", "token", "cyber", "sprint", "raktas", "slapta", "lab", "admin"]:
        if w in low:
            score += 140
    if "{" in text and "}" in text:
        score += 80
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}", low):
        score += 55
    return score

# ---------------- route / transposition ----------------

def factors(n: int) -> List[Tuple[int, int]]:
    out = []
    for r in range(2, int(math.sqrt(n)) + 1):
        if n % r == 0:
            out.append((r, n // r))
            out.append((n // r, r))
    # useful small row counts even if very rectangular
    return sorted(set(out), key=lambda x: (abs(x[0] - x[1]), x[0]))

def read_rows_write_cols(s: str, rows: int, cols: int) -> str:
    grid = [s[i*cols:(i+1)*cols] for i in range(rows)]
    return "".join(grid[r][c] for c in range(cols) for r in range(rows))

def read_cols_write_rows(s: str, rows: int, cols: int) -> str:
    grid = [[""] * cols for _ in range(rows)]
    i = 0
    for c in range(cols):
        for r in range(rows):
            if i < len(s):
                grid[r][c] = s[i]
                i += 1
    return "".join("".join(row) for row in grid)

def snake_rows(s: str, rows: int, cols: int) -> str:
    grid = []
    for r in range(rows):
        row = s[r*cols:(r+1)*cols]
        if r % 2:
            row = row[::-1]
        grid.append(row)
    return "".join(grid[r][c] for c in range(cols) for r in range(rows))

def snake_cols(s: str, rows: int, cols: int) -> str:
    grid = [[""] * cols for _ in range(rows)]
    i = 0
    for c in range(cols):
        rr = range(rows) if c % 2 == 0 else range(rows-1, -1, -1)
        for r in rr:
            if i < len(s):
                grid[r][c] = s[i]
                i += 1
    return "".join("".join(row) for row in grid)

def route_transposition_candidates(s: str) -> List[Dict[str, Any]]:
    s = str(s or "").strip()
    if not (16 <= len(s) <= 5000):
        return []
    if any(ch.isspace() for ch in s) and len(s) > 1000:
        return []
    cand = []
    dims = factors(len(s))
    # prioritize small row/col counts common in CTF route transposition
    dims += [(r, len(s)//r) for r in range(2, 21) if len(s) % r == 0]
    seen_dims = []
    for d in dims:
        if d not in seen_dims:
            seen_dims.append(d)
    for rows, cols in seen_dims[:80]:
        variants = [
            ("rows_then_cols", read_rows_write_cols(s, rows, cols)),
            ("cols_then_rows", read_cols_write_rows(s, rows, cols)),
            ("rows_then_cols_reversed", read_rows_write_cols(s[::-1], rows, cols)),
            ("snake_rows", snake_rows(s, rows, cols)),
            ("snake_cols", snake_cols(s, rows, cols)),
        ]
        for method, text in variants:
            sc = score_text(text)
            if FLAG_RE.search(text) or sc >= 185 or re.search(r"\{[^{}]{6,120}\}", text):
                cand.append({
                    "method": method,
                    "rows": rows,
                    "cols": cols,
                    "score": sc,
                    "preview": text[:4000],
                    "brace_candidates": re.findall(r"\{[^{}]{3,140}\}", text)[:20],
                })
    # dedupe
    out = []
    seen = set()
    for c in sorted(cand, key=lambda x: x["score"], reverse=True):
        sig = (c["method"], c["rows"], c["cols"], c["preview"][:120])
        if sig not in seen:
            out.append(c); seen.add(sig)
        if len(out) >= 120:
            break
    return out

def route_transposition_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:1_000_000].decode("utf-8", "ignore")
    chunks = []
    for tok in re.findall(r"[!-~]{16,5000}", text):
        # avoid ordinary long prose; route strings tend to be dense symbols
        if len(tok) >= 16 and (sum(ch in "{}_[]-=+!@#$%^&*(),.;:" for ch in tok) >= 2 or len(set(tok)) > 10):
            chunks.append(tok)
    if not chunks and 16 <= len(text.strip()) <= 5000:
        chunks.append(text.strip())
    allc = []
    for chunk in chunks[:100]:
        for c in route_transposition_candidates(chunk):
            allc.append(c)
            scan(report, c["preview"], "SLOPER v75 route transposition", None, "Route/columnar transposition produced strict flag.", 760)
            # If no prefix but a clean {body} appears, keep as candidate only.
            for br in c.get("brace_candidates", []):
                body = br.strip("{}")
                if re.fullmatch(r"[A-Za-z0-9_+\-:.]{5,120}", body):
                    report.setdefault("candidate_flags", []).append({
                        "candidate": "ctf_cs{" + body + "}",
                        "source": "SLOPER v75 route transposition wrapper candidate",
                        "why": "Route decode produced a clean {...} body but not full ctf_cs prefix.",
                        "score": c["score"],
                    })
    if not allc:
        return []
    a = artifact(root, report, "route_transposition_candidates.json", json.dumps(allc[:160], indent=2, ensure_ascii=False), "sloper75_route_transposition", "Route/columnar transposition candidates with dimensions and method.", 500)
    return [a] if a else []

# ---------------- routing / less random hunting ----------------

def classify(report: dict, data: bytes) -> Dict[str, Any]:
    name = str(report.get("name", "")).lower()
    rel = str(report.get("rel", "")).lower()
    stmt = str(report.get("statement", "")).lower()
    path = Path(str(report.get("path", "")))
    ext = path.suffix.lower()
    head = data[:64]
    text = data[:4096].decode("utf-8", "ignore")
    hints = set()
    if ext in {".png",".jpg",".jpeg",".bmp",".gif",".webp"} or head.startswith(b"\x89PNG") or head[:3] == b"\xff\xd8\xff":
        hints.add("image")
    if ext in {".zip",".jar",".apk",".docx",".pptx",".xlsx"} or head.startswith(b"PK\x03\x04"):
        hints.add("archive")
    if ext in {".gz",".tgz",".tar",".bz2",".xz",".7z",".rar"} or head.startswith(b"\x1f\x8b"):
        hints.add("archive")
    if ext in {".pcap",".pcapng"} or head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        hints.add("pcap")
    if ext in {".wav"} or b"WAVE" in head:
        hints.add("audio")
    if ext in {".pdf"} or head.startswith(b"%PDF"):
        hints.add("document")
    if head.startswith(b"SQLite format 3\x00") or ext in {".sqlite",".db",".sqlite3"}:
        hints.add("sqlite")
    if ext in {".py",".js",".php",".c",".cpp",".h",".java",".go",".rs",".cs",".txt",".md",".json",".log",".csv",".dat",".enc",".bin",""}:
        hints.add("text_or_binary")
    if any(w in stmt + " " + name + " " + rel for w in ["xor","encoded","decode","cipher","crypto","transposition","route","stulp","lentel","column","row"]):
        hints.add("crypto_decode")
    if any(w in stmt + " " + name for w in ["revers", "byte", "array", "xor", "elf", "program", "binary"]):
        hints.add("reversing")
    if any(w in stmt + " " + name for w in ["stego", "image", "png", "lsb", "alpha", "palette", "bitplane"]):
        hints.add("image")
    return {"ext": ext, "hints": sorted(hints), "textiness": score_text(text)}

def run_routed_workflows(mod, report: dict, root: Path, data: bytes) -> List[dict]:
    ensure(report)
    info = classify(report, data)
    report["v75_classification"] = info
    hints = set(info["hints"])
    arts: List[dict] = []

    def run(fn, name):
        try:
            res = fn(report, root, data)
            if res: arts.extend(res)
        except Exception as e:
            agent_crash("v75 routed " + name, e, report)

    # Always low-cost, evidence-producing text transforms
    run(route_transposition_agent, "route_transposition")

    if v74:
        # Better targeted execution than blind all-agents. Still runs decode for text/binary.
        if "text_or_binary" in hints or "crypto_decode" in hints or len(data) < 2_000_000:
            run(v74.decode_graph_agent, "decode_graph")
            run(v74.jwt_agent, "jwt")
            run(v74.log_lowbyte_agent, "log_lowbyte")
            run(v74.classic_crypto_agent, "classic_crypto")
        if "crypto_decode" in hints or "reversing" in hints or len(data) < 1_000_000:
            run(v74.xor_agent, "xor")
            run(v74.known_prefix_xor_agent, "known_prefix_xor")
            run(v74.array_transform_agent, "array_transform")
        if "archive" in hints:
            run(v74.archive_agent, "archive")
            run(v74.magic_carve_agent, "magic_carve")
        else:
            # magic carve is useful, but expensive/noisy; run only for blobs or suspicious data
            if len(data) < 20_000_000 and (data.find(b"PK\x03\x04", 1) >= 0 or data.find(b"\x1f\x8b\x08", 1) >= 0 or data.find(b"%PDF", 1) >= 0):
                run(v74.magic_carve_agent, "magic_carve_suspicious")
        if "sqlite" in hints:
            run(v74.sqlite_agent, "sqlite")
        if "document" in hints:
            run(v74.pdf_agent, "pdf")
        if "pcap" in hints:
            run(v74.pcap_agent, "pcap")
        if "audio" in hints:
            run(v74.wav_lsb_agent, "wav_lsb")
        if "image" in hints:
            run(v74.image_agent, "image")
    if arts:
        report.setdefault("next_steps", []).insert(0, {"priority": 100, "step": "Review v75 routed workflow evidence first.", "why": "v75 selected agents by file type and task hints, reducing random flag hunting."})
    return arts

def install(mod):
    old_run = getattr(mod, "sl_run_agents", None)
    def sl_run_agents(report, root, data):
        arts = []
        # Legacy still runs to preserve old behavior, but v75 evidence/routing is now the first-class layer.
        try:
            arts += run_routed_workflows(mod, report, Path(root), bytes(data or b"")) or []
        except Exception as e:
            agent_crash("v75 run_routed_workflows", e, report)
        # Run legacy after, but do not let it crash/kill project.
        if old_run:
            try:
                prev = old_run(report, root, data)
                if prev: arts += prev
            except Exception as e:
                agent_crash("legacy sl_run_agents after v75", e, report)
        try:
            if hasattr(mod, "sl_finalize_report"):
                mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash("v75 sl_finalize_report", e, report)
        return arts
    mod.sl_run_agents = sl_run_agents

    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        artifacts = summary.get("artifacts", []) or []
        lane = summary.get("sloper74_review_lanes", {}) or summary.get("sloper72_review_lanes", {}) or {}
        lane["v75_route_transposition"] = len([a for a in artifacts if "route_transposition" in (a.get("kind","") + a.get("name",""))])
        lane["v75_workflow_artifacts"] = len([a for a in artifacts if "sloper75" in (a.get("kind","") + a.get("source","")).lower()])
        summary["sloper75_review_lanes"] = lane
        def pri(a):
            s = int(a.get("score", 0) or 0)
            txt = (a.get("source","") + " " + a.get("kind","") + " " + a.get("name","")).lower()
            if "sloper75" in txt: s += 30000
            if "route_transposition" in txt: s += 4000
            if "sloper74" in txt: s += 15000
            return (bool(a.get("exists", False)), s, int(a.get("size", 0) or 0))
        summary["artifacts"] = sorted(artifacts, key=pri, reverse=True)[:9000]
        # Compact action queue
        actions = []
        if lane.get("v75_route_transposition"):
            actions.append({"priority":100,"step":"Open route_transposition_candidates.json.","why":"v75 found route/columnar transposition evidence."})
        if lane.get("v75_workflow_artifacts"):
            actions.append({"priority":98,"step":"Open v75/v74 workflow artifacts in Artifact Hub.","why":"Routed workflows produced evidence artifacts."})
        summary["sloper75_next_actions"] = actions + summary.get("sloper72_next_actions", [])[:20] + summary.get("workflow_steps", [])[:10]
        try:
            from .artifact_hub import compact_hub
            summary["sloper75_artifact_hub"] = compact_hub(summary)
        except Exception:
            pass
        return summary
    mod.project_summary = project_summary

    old_progress = getattr(mod, "progress", None)
    def progress(pid, pct, stage):
        mark_job(pid, "running", progress=pct, stage=stage)
        add_event(pid, str(stage), progress=pct)
        if cancelled(pid):
            mark_job(pid, "cancelled", progress=pct, stage="Cancelled")
            raise RuntimeError("project cancelled by user")
        if old_progress:
            return old_progress(pid, pct, stage)
    mod.progress = progress

    old_analyze = getattr(mod, "analyze_project", None)
    def analyze_project(pid):
        mark_job(pid, "running", progress=0, stage="Starting")
        add_event(pid, "Analysis started")
        try:
            if old_analyze:
                res = old_analyze(pid)
            else:
                res = None
            if cancelled(pid):
                mark_job(pid, "cancelled", stage="Cancelled")
            else:
                mark_job(pid, "done", progress=100, stage="Done")
            return res
        except RuntimeError as e:
            if "cancelled" in str(e).lower():
                mark_job(pid, "cancelled", stage="Cancelled")
                return None
            mark_job(pid, "error", stage=str(e)[:180])
            raise
        except Exception as e:
            mark_job(pid, "error", stage=str(e)[:180])
            agent_crash("v75 analyze_project wrapper", e, None)
            raise
    mod.analyze_project = analyze_project

    # endpoints for timer/cancel/status
    try:
        @mod.app.post("/api/v75/cancel/{pid}")
        def api_v75_cancel(pid: str):
            cancel_project(pid)
            return {"ok": True, "pid": pid, "status": "cancelled"}

        @mod.app.get("/api/v75/status/{pid}")
        def api_v75_status(pid: str):
            job = V75_JOBS.get(pid, {"pid": pid, "status": "unknown"})
            if job.get("started") and not job.get("ended"):
                job = dict(job)
                job["elapsed"] = round(now() - job["started"], 3)
            return job

        @mod.app.post("/api/projects/{pid}/stop")
        def api_project_stop(pid: str):
            cancel_project(pid)
            return {"ok": True, "pid": pid, "status": "cancelled"}

        @mod.app.get("/api/projects/{pid}/status")
        def api_project_status(pid: str):
            job = V75_JOBS.get(pid, {"pid": pid, "status": "unknown"})
            if job.get("started") and not job.get("ended"):
                job = dict(job)
                job["elapsed"] = round(now() - job["started"], 3)
            return job
    except Exception as e:
        agent_crash("install v75 endpoints", e, None)

    mod.sl75_run_routed_workflows = run_routed_workflows
    mod.sl75_route_transposition_agent = route_transposition_agent
    mod.sl75_jobs = V75_JOBS
    mod.sl75_cancel = cancel_project
    return mod
