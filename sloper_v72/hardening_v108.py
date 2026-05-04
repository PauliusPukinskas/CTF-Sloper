"""Runtime hardening patch for the public GitHub package.

This is intentionally additive: it monkey-patches the legacy module after import
instead of rewriting the large compatibility file.  The goals are safe local
operation, bounded manual endpoints, and exact flag preservation.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import time
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, Form, UploadFile, File
from typing import List

STRICT_FLAG_RE = re.compile(r"\bctf_cs\{[^}\r\n]{1,220}\}", re.I)
MAX_UPLOAD_BYTES = int(os.environ.get("SLOPER_MAX_UPLOAD_BYTES", "80000000"))
MAX_MANUAL_BYTES = int(os.environ.get("SLOPER_MAX_MANUAL_BYTES", "60000000"))


def apply(mod):
    """Apply v108/v109 hardening to the imported legacy module."""

    def norm(p):
        try:
            return Path(p).expanduser().resolve()
        except Exception:
            return Path(str(p)).resolve()

    def under(child, parent):
        try:
            c = norm(child); p = norm(parent)
            return c == p or p in c.parents
        except Exception:
            return False

    def project_root_for(path):
        p = norm(path); projects = norm(mod.PROJECTS)
        if not under(p, projects):
            return None
        for parent in [p] + list(p.parents):
            try:
                if parent.parent == projects and (parent / "project.json").exists():
                    return parent
            except Exception:
                pass
        return None

    def safe_source_path(path):
        p = norm(path)
        if not p.exists() or not p.is_file():
            return None, None, {"ok": False, "error": "file not found"}
        root = project_root_for(p)
        if root is None:
            return None, None, {"ok": False, "error": "blocked: path must be inside projects/<pid>/files"}
        if not under(p, root / "files"):
            return None, root, {"ok": False, "error": "blocked: only uploaded files/ are accepted as solver input by default"}
        if any(x in p.parts for x in ["generated", "artifacts", "cache", "__pycache__", ".git", ".pytest_cache"]):
            return None, root, {"ok": False, "error": "blocked: generated/cache/internal paths are not analyzed by default"}
        try:
            if p.stat().st_size > MAX_MANUAL_BYTES:
                return None, root, {"ok": False, "error": f"file too large for manual endpoint; limit={MAX_MANUAL_BYTES} bytes"}
        except Exception:
            pass
        return p, root, None

    def exact_tokens(text, limit=100):
        text = str(text or "")[:250000]
        out, seen = [], set()
        for m in STRICT_FLAG_RE.finditer(text):
            cand = m.group(0)
            inner = cand[cand.find("{") + 1:-1].lower()
            if inner in {"flag", "your_flag", "flag_here", "example", "test"}:
                continue
            if any(x in inner for x in ["placeholder", "not_the_flag", "fake_flag", "insert_flag", "change_me"]):
                continue
            key = cand.lower()
            if key not in seen:
                seen.add(key); out.append(cand)
                if len(out) >= limit: break
        return out

    def add_flag(bucket, flag, source, file_rel="?"):
        key = str(flag).lower()
        if key not in bucket:
            bucket[key] = {"flag": str(flag), "file": file_rel, "score": 1000, "status": "confirmed", "why": "exact ctf_cs token copied byte-for-byte from evidence", "source": source, "sources": [source]}
        elif source not in bucket[key].setdefault("sources", []):
            bucket[key]["sources"].append(source)

    def scan_text(bucket, text, source, file_rel="?"):
        for f in exact_tokens(text):
            add_flag(bucket, f, source, file_rel)
        for tok in re.findall(r"[A-Za-z0-9+/=_-]{12,}|[0-9A-Fa-f]{8,}", str(text or "")[:80000])[:400]:
            blobs = []
            if re.fullmatch(r"[0-9A-Fa-f]{8,}", tok) and len(tok) % 2 == 0:
                try: blobs.append(("hex", bytes.fromhex(tok)))
                except Exception: pass
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", tok):
                try: blobs.append(("base64", base64.b64decode(tok + "="*((4-len(tok)%4)%4), altchars=b"-_", validate=True)))
                except Exception: pass
            for label, raw in blobs[:3]:
                for enc in ["utf-8", "utf-16le", "latin1"]:
                    try: decoded = raw.decode(enc, errors="ignore")
                    except Exception: continue
                    for f in exact_tokens(decoded):
                        add_flag(bucket, f, f"{source}:{label}:{enc}", file_rel)

    def scan_obj(bucket, obj, source="object", file_rel="?", depth=0, budget=None):
        if budget is None: budget = {"n": 0}
        if budget["n"] > 1400 or depth > 6: return
        budget["n"] += 1
        try:
            if isinstance(obj, str):
                scan_text(bucket, obj, source, file_rel)
            elif isinstance(obj, dict):
                rel = obj.get("file") or obj.get("rel") or file_rel
                noisy = {"flags", "candidate_flags", "answer_candidates", "verified_flags", "unconfirmed_evidence", "flag_wrapping_helpers", "raw_answer_candidates"}
                priority = ["preview", "output", "out", "value", "note", "why", "source", "name"]
                if "flag" in obj and not any(k in source.lower() for k in ["candidate", "answer", "verified", "summary"]):
                    priority.append("flag")
                for key in priority:
                    if key in obj and key not in noisy:
                        scan_obj(bucket, obj.get(key), f"{source}.{key}", rel, depth+1, budget)
                for key, val in list(obj.items())[:120]:
                    if key in noisy or key in set(priority):
                        continue
                    scan_obj(bucket, val, f"{source}.{key}", rel, depth+1, budget)
                p = obj.get("path")
                if p:
                    try:
                        pp = Path(p)
                        if pp.exists() and pp.is_file() and project_root_for(pp) and pp.stat().st_size <= 2_000_000:
                            raw = pp.read_bytes()
                            for enc in ["utf-8", "latin1", "utf-16le"]:
                                try: scan_text(bucket, raw.decode(enc, errors="ignore"), f"artifact_file:{pp.name}:{enc}", rel)
                                except Exception: pass
                    except Exception:
                        pass
            elif isinstance(obj, (list, tuple, set)):
                for i, val in enumerate(list(obj)[:300]):
                    scan_obj(bucket, val, f"{source}[{i}]", file_rel, depth+1, budget)
        except Exception:
            pass

    def promote_exact(summary, reports):
        if not isinstance(summary, dict): summary = {}
        bucket = {}
        for r in list(reports or [])[:200]:
            rel = (r.get("rel") or r.get("name") or "?") if isinstance(r, dict) else "?"
            scan_obj(bucket, r, "report", rel)
        exact = list(bucket.values())
        def compact(flag): return re.sub(r"[^a-z0-9]", "", str(flag).lower())
        def rich(item):
            f = str(item.get("flag", "")); inner = f[f.find("{")+1:-1] if "{" in f and f.endswith("}") else f
            return (inner.count("_")*8 + sum(1 for c in inner if not c.isalnum())*4 + len(inner), len(item.get("sources", [])))
        exact = sorted(exact, key=rich, reverse=True)
        exact_unique, seen, seen_compact = [], set(), set()
        for item in exact:
            f = item.get("flag", ""); k = f.lower(); ck = compact(f)
            if not f or k in seen or ck in seen_compact: continue
            seen.add(k); seen_compact.add(ck); exact_unique.append(item)
        old = list(summary.get("flags", []) or [])
        merged = list(exact_unique); old_seen = {x.get("flag", "").lower() for x in exact_unique}; old_compacts = {compact(x.get("flag", "")) for x in exact_unique}
        for item in old:
            f = item.get("flag") if isinstance(item, dict) else str(item)
            if not f or f.lower() in old_seen: continue
            inner = f[f.find("{")+1:-1] if "{" in f and f.endswith("}") else f
            if compact(f) in old_compacts and "_" not in inner: continue
            old_seen.add(f.lower()); merged.append(item if isinstance(item, dict) else {"flag": f, "file": "?", "score": 0})
        summary["flags"] = merged[:100]
        summary["exact_flags"] = exact_unique[:100]
        summary["v108_benchmark_hardening"] = {"enabled": True, "exact_count": len(exact_unique), "fixes": ["manual endpoints sandboxed to uploaded files", "generated/cache paths blocked as solver input", "exact ctf_cs evidence promoted above normalized guesses", "base64/hex evidence decoded without removing underscores"]}
        return summary

    def postprocess_report_file(pid):
        try:
            rep = mod.jread(mod.report_path(pid), {})
            if isinstance(rep, dict) and rep:
                rep["summary"] = promote_exact(rep.get("summary", {}) or {}, rep.get("files", []) or [])
                rep["v108_postprocessed"] = True
                mod.jwrite(mod.report_path(pid), rep)
            return rep
        except Exception:
            try: return mod.jread(mod.report_path(pid), {})
            except Exception: return {}

    # Expose helpers for bootstrap/tests.
    mod.sl108_safe_source_path = safe_source_path
    mod.sl108_promote_exact = promote_exact
    mod.sl108_postprocess_report_file = postprocess_report_file

    old_project_summary = mod.project_summary
    def project_summary(reports, meta):
        return promote_exact(old_project_summary(reports, meta), reports)
    mod.project_summary = project_summary

    old_run = mod.run
    def run(cmd, timeout=60, maxchars=120000):
        timeout = max(1, min(int(timeout or 60), int(os.environ.get("SLOPER_MAX_TOOL_TIMEOUT", "45"))))
        maxchars = max(1000, min(int(maxchars or 120000), int(os.environ.get("SLOPER_MAX_TOOL_OUTPUT", "160000"))))
        return old_run(cmd, timeout=timeout, maxchars=maxchars)
    mod.run = run

    def manual_report(p, root, data, kind, fileout):
        ss = mod.py_strings(data)
        try: rel = str(norm(p).relative_to(norm(root)))
        except Exception: rel = p.name
        return {"id": "manual", "name": p.name, "path": str(p), "rel": rel, "size": p.stat().st_size, "entropy": mod.entropy(data[:2_000_000]), "kind": kind, "file": fileout, "fingerprint": {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()}, "flags": list(dict.fromkeys(x.decode("utf-8", "replace") for x in mod.FLAG_BYTES_RE.findall(data))), "strings": ss[:1200], "outputs": [], "previews": [], "commands": [], "extracted": [], "expert_contexts": [], "decoders": [], "chain_results": [], "intermediate_files": [], "findings": [], "next_steps": [], "hypotheses": [], "structured_clues": [], "agent_runs": [], "agent_files": [], "transformations": [], "verifyloop": {}, "verified_flags": [], "promoted_children": [], "artifacts": []}

    async def run_tool_endpoint(path: str = Form(...), toolname: str = Form(...)):
        p, root, err = safe_source_path(path)
        if err: return err
        return mod.run_tool_local(p, toolname, 45)

    async def run_tool_suite(path: str = Form(...), suite: str = Form("quick")):
        p, root, err = safe_source_path(path)
        if err: return err
        k, tools = mod.suite_for_path(p, suite)
        results = [mod.run_tool_local(p, t, 45) for t in tools[:30]]
        return {"ok": True, "kind": k, "suite": suite, "tools": tools[:30], "results": results, "derived": mod.summarize_suite(results), "v108_bounded": True}

    async def run_verifyloop_endpoint(path: str = Form(...)):
        p, root, err = safe_source_path(path)
        if err: return err
        data = mod.readbytes(p, MAX_MANUAL_BYTES)
        fileout = mod.run(["file", str(p)], 10).get("out", "") if mod.exists("file") else ""
        kind = mod.detect_kind(p, fileout)
        temp = manual_report(p, root, data, kind, fileout)
        text = "\n".join(temp.get("strings", [])[:1200])
        temp["decoders"] = mod.decode_candidates(text, data)[:120]
        temp["chain_results"] = mod.chain_decode_report(temp, data)[:120] if hasattr(mod, "chain_decode_report") else temp["decoders"]
        summary = promote_exact({"flags": [{"flag": f} for f in temp.get("flags", [])]}, [temp])
        return {"ok": True, "kind": kind, "verifyloop": {}, "findings": mod.rank_findings(temp)[:80], "flags": [x.get("flag") for x in summary.get("flags", []) if isinstance(x, dict)][:80], "chain_results": temp.get("chain_results", [])[:80], "transformations": [], "agents": [], "previews": [], "v109_safe_manual": True}

    async def run_agents_endpoint(path: str = Form(...)):
        p, root, err = safe_source_path(path)
        if err: return err
        data = mod.readbytes(p, MAX_MANUAL_BYTES)
        fileout = mod.run(["file", str(p)], 10).get("out", "") if mod.exists("file") else ""
        kind = mod.detect_kind(p, fileout)
        temp = manual_report(p, root, data, kind, fileout)
        text = "\n".join(temp.get("strings", [])[:1200])
        temp["decoders"] = mod.decode_candidates(text, data)[:120]
        temp["chain_results"] = mod.chain_decode_report(temp, data)[:120] if hasattr(mod, "chain_decode_report") else temp["decoders"]
        summary = promote_exact({}, [temp])
        return {"ok": True, "kind": kind, "agents": [{"name": "safe_manual_decode", "status": "completed", "note": "Recursive legacy agent scan skipped for manual endpoint; use project Start for full run."}], "agent_files": [], "flags": [x.get("flag") for x in summary.get("flags", []) if isinstance(x, dict)], "findings": mod.rank_findings(temp)[:80], "v109_safe_manual": True}

    async def create_project(background_tasks: BackgroundTasks, title: str = Form(""), statement: str = Form(""), category: str = Form("auto"), auto_start: str = Form("true"), files: List[UploadFile] = File(...)):
        pid = uuid.uuid4().hex[:12]; root = mod.pdir(pid); fdir = root / "files"; fdir.mkdir(parents=True, exist_ok=True); clean = []
        for f in files:
            name = mod.safe(getattr(f, "filename", "file") or "file")
            if name.lower() in {"generated", "artifacts", "cache", "project.json", "report.json"}: name = "uploaded_" + name
            content = await f.read()
            if len(content) > MAX_UPLOAD_BYTES:
                return {"ok": False, "error": f"upload too large: {name}; limit={MAX_UPLOAD_BYTES} bytes"}
            (fdir / name).write_bytes(content); clean.append(name)
        auto_title = (title or "").strip() or (clean[0] if clean else "Untitled challenge")
        meta = {"id": pid, "title": auto_title, "statement": statement, "category": category, "created": mod.now(), "file_count": len(clean), "workspace_model": "v108: uploaded files in files/, generated artifacts separated"}
        mod.jwrite(mod.meta_path(pid), meta)
        with mod.LOCK:
            mod.JOBS[pid] = {"status": "created", "progress": 0, "stage": "Created", "updated": time.time(), "color": "gray"}
        mod.log(pid, f"Project created: {auto_title}")
        if auto_start.lower() == "true":
            with mod.LOCK: mod.JOBS[pid].update({"status": "running", "color": "yellow", "stage": "Queued", "updated": time.time()})
            background_tasks.add_task(mod.analyze_project, pid)
        return {"id": pid, "project": meta, "ok": True}

    def tool_status():
        items=[]; dummy=mod.PROJECTS/".tool_status_dummy"
        try: dummy.write_text("dummy", encoding="utf-8")
        except Exception: pass
        for name in sorted(mod.TOOL_COMMANDS.keys()):
            try: cmd=mod.TOOL_COMMANDS[name](dummy); build_error=""
            except Exception as e: cmd=None; build_error=str(e)
            try: deps=list(mod.deps_for(name, cmd) or [])
            except Exception: deps=list(mod.TOOL_DEPS.get(name, []) if hasattr(mod, "TOOL_DEPS") else [])
            try:
                if cmd and cmd[0] not in ["bash", "sh"] and cmd[0] not in deps: deps.append(cmd[0])
                if cmd and cmd[0] in ["bash", "sh"] and cmd[0] not in deps: deps.append(cmd[0])
            except Exception: pass
            deps=list(dict.fromkeys([str(d) for d in deps if str(d)])); missing=[d for d in deps if not mod.exists(d)]
            items.append({"name": name, "deps": deps, "installed": bool(cmd) and not missing and not build_error, "missing": missing, "cmd_probe": " ".join(map(str, cmd))[:240] if cmd else "", "build_error": build_error})
        try: dummy.unlink(missing_ok=True)
        except Exception: pass
        return {"tools": items, "virtual_profiles": mod.jread(mod.BASE/"data/tool_catalog_v20.json", {}).get("virtual_profiles", [])[:1000], "v108_tool_status": True}

    try:
        mod.sl103_rebind_route("/api/projects", ["POST"], create_project)
        mod.sl103_rebind_route("/api/tool_status", ["GET"], tool_status)
        mod.sl103_rebind_route("/api/run_tool", ["POST"], run_tool_endpoint)
        mod.sl103_rebind_route("/api/run_tool_suite", ["POST"], run_tool_suite)
        mod.sl103_rebind_route("/api/run_verifyloop", ["POST"], run_verifyloop_endpoint)
        mod.sl103_rebind_route("/api/run_agents", ["POST"], run_agents_endpoint)
    except Exception:
        pass

    mod.APP_TITLE = "CTF SLOPER v109 GitHub Benchmark Hardened"
    mod.SL108_VERSION = "v108-github-benchmark-hardening"
    mod.SL109_VERSION = "v109-safe-manual-endpoints"
