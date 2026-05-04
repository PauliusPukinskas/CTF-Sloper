
"""CTF SLOPER v72 bootstrap.

Loads legacy app, installs v72 wrappers/endpoints, and exposes the legacy FastAPI app.
"""
from __future__ import annotations
import importlib
import json
import mimetypes
import re
from pathlib import Path
from fastapi import Body
from .health import AGENT_HEALTH, agent_crash, install_health_endpoint
from .hidden_bits import decode_zero_width, zero_width_whitespace_agent, write_artifact, scan_flags
from .artifact_hub import compact_hub

def install(mod):
    mod.SL72_AGENT_HEALTH = AGENT_HEALTH
    mod.sl72_agent_crash = agent_crash

    install_health_endpoint(mod.app)

    old_zero = getattr(mod, "sl43_zero_width_decode", None)
    def sl43_zero_width_decode(*args, **kwargs):
        try:
            if args and isinstance(args[0], dict):
                report = args[0]
                root = args[1] if len(args) > 1 else Path(".")
                data = args[2] if len(args) > 2 else ""
                text = data.decode("utf-8", "ignore") if isinstance(data, bytes) else str(data)
                res = decode_zero_width(text)
                if res:
                    art = write_artifact(mod, root, report, "zero_width_decode_candidates.json", mod.json.dumps(res, indent=2, ensure_ascii=False), "sloper72_zero_width_decode", 430, "Compatibility zero-width decode artifact.")
                    for item in res[:20]:
                        scan_flags(mod, report, item.get("text", ""), "SLOPER v72 zero-width compat", art.get("path") if art else None, 420)
                return res
            if old_zero:
                return old_zero(*args, **kwargs)
            return decode_zero_width(args[0] if args else kwargs.get("text", ""))
        except Exception as e:
            agent_crash("sl43_zero_width_decode wrapper", e, args[0] if args and isinstance(args[0], dict) else None)
            return []
    mod.sl43_zero_width_decode = sl43_zero_width_decode

    old_chain = getattr(mod, "sl43_decode_chain_agent", None)
    def sl43_decode_chain_agent(*args, **kwargs):
        try:
            if old_chain:
                old_res = old_chain(*args, **kwargs)
            else:
                old_res = []
        except Exception as e:
            agent_crash("legacy sl43_decode_chain_agent", e, args[0] if args and isinstance(args[0], dict) else None)
            old_res = []
        try:
            if args and isinstance(args[0], dict):
                report = args[0]
                root = args[1] if len(args) > 1 else Path(".")
                data = args[2] if len(args) > 2 else b""
                new_res = zero_width_whitespace_agent(mod, report, root, data)
                if old_res and isinstance(old_res, list):
                    return old_res + new_res
                return new_res or old_res
        except Exception as e:
            agent_crash("v72 sl43_decode_chain_agent wrapper", e, args[0] if args and isinstance(args[0], dict) else None)
        return old_res
    mod.sl43_decode_chain_agent = sl43_decode_chain_agent

    old_run = getattr(mod, "sl_run_agents", None)
    def sl_run_agents(report, root, data):
        arts = []
        if old_run:
            try:
                old_arts = old_run(report, root, data)
                if old_arts:
                    arts += old_arts
            except Exception as e:
                agent_crash("legacy sl_run_agents", e, report)
        try:
            new_arts = zero_width_whitespace_agent(mod, report, root, data)
            if new_arts:
                arts += new_arts
        except Exception as e:
            agent_crash("v72 zero_width_whitespace_agent", e, report)
        try:
            if hasattr(mod, "sl_finalize_report"):
                mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash("legacy sl_finalize_report", e, report)
        return arts
    mod.sl_run_agents = sl_run_agents

    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        artifacts = summary.get("artifacts", []) or []
        lane = summary.get("sloper57_review_lanes", {}) or summary.get("sloper56_review_lanes", {}) or summary.get("sloper55_review_lanes", {}) or {}
        lane["v72_zero_width"] = len([a for a in artifacts if "zero_width" in a.get("name", "") or "zero_width" in a.get("kind", "")])
        lane["v72_whitespace_bits"] = len([a for a in artifacts if "whitespace_bits" in a.get("name", "") or "whitespace_bits" in a.get("kind", "")])
        lane["v72_agent_crashes"] = len(AGENT_HEALTH)
        summary["sloper72_review_lanes"] = lane
        summary["sloper72_agent_health"] = list(AGENT_HEALTH)[-100:]
        summary["sloper72_artifact_hub"] = compact_hub(summary)
        def pri(a):
            s = int(a.get("score", 0) or 0)
            text = (str(a.get("source", "")) + " " + str(a.get("kind", "")) + " " + str(a.get("name", ""))).lower()
            if "sloper72" in text or "v72" in text:
                s += 16000
            if "zero_width" in text or "whitespace_bits" in text:
                s += 2500
            return (bool(a.get("exists", False)), s, int(a.get("size", 0) or 0))
        summary["artifacts"] = sorted(artifacts, key=pri, reverse=True)[:8000]
        return summary
    mod.project_summary = project_summary

    try:
        @mod.app.get("/api/artifact_hub/{pid}")
        def artifact_hub(pid: str):
            rep = mod.jread(mod.report_path(pid), {})
            return compact_hub(rep.get("summary", {}))
    except Exception:
        pass

    def _inside_dir(path: Path, base: Path) -> bool:
        try:
            base = Path(base).resolve()
            raw = Path(path)
            raw_abs = raw if raw.is_absolute() else (Path.cwd() / raw)
            raw_abs = raw_abs.absolute()
            resolved = raw.resolve()
            raw_ok = raw_abs == base or base in raw_abs.parents
            resolved_ok = resolved == base or base in resolved.parents
            return raw_ok and resolved_ok
        except Exception:
            return False

    def _inside_projects(path: Path) -> bool:
        return _inside_dir(path, Path(getattr(mod, "PROJECTS", Path("."))))

    def _inside_project(pid: str, path: Path) -> bool:
        return _inside_dir(path, mod.pdir(pid))

    def _inside_base(path: Path) -> bool:
        return _inside_projects(path)

    def _report(pid: str):
        try:
            return mod.jread(mod.report_path(pid), {}) or {}
        except Exception:
            return {}

    def _compact_report(pid: str):
        root = mod.pdir(pid)
        meta = mod.jread(mod.meta_path(pid), {}) if root.exists() else {"id": pid, "title": pid}
        rep = _report(pid)
        summary = dict(rep.get("summary", {}) or {})
        artifacts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
        priority = [a for a in (summary.get("final_open_queue") or summary.get("priority_artifacts") or []) if isinstance(a, dict)]
        summary["artifact_count"] = len(artifacts)
        summary["artifacts"] = artifacts[:80]
        summary["final_open_queue"] = priority[:80]
        summary["priority_artifacts"] = priority[:80]
        files = []
        for r in rep.get("files", []) or []:
            if not isinstance(r, dict):
                continue
            files.append({
                "name": r.get("name"),
                "rel": r.get("rel"),
                "path": r.get("path"),
                "kind": r.get("kind"),
                "size": r.get("size"),
                "flags": r.get("flags", [])[:8] if isinstance(r.get("flags", []), list) else [],
                "artifact_count": len(r.get("artifacts", []) or []) + len(r.get("transformations", []) or []),
                "error": r.get("error"),
            })
        try:
            job = dict(mod.JOBS.get(pid, {}))
        except Exception:
            job = {}
        return {"project": meta, "job": job, "report": {"summary": summary, "files": files, "updated": rep.get("updated")}}

    try:
        @mod.app.get("/api/projects_compact")
        def projects_compact():
            items = []
            for p in sorted(mod.PROJECTS.iterdir(), key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True):
                if not p.is_dir():
                    continue
                meta = mod.jread(mod.meta_path(p.name), {}) or {"id": p.name, "title": p.name}
                rep = _report(p.name)
                summary = rep.get("summary", {}) or {}
                items.append({
                    "id": p.name,
                    "title": meta.get("title") or meta.get("name") or p.name,
                    "category": meta.get("category", ""),
                    "status": (mod.JOBS.get(p.name, {}) or {}).get("status", "idle") if hasattr(mod, "JOBS") else "idle",
                    "flags": len(summary.get("flags", []) or []),
                    "artifacts": len(summary.get("artifacts", []) or []),
                    "files": len(rep.get("files", []) or []),
                    "updated": rep.get("updated") or meta.get("created"),
                })
            return {"projects": items}

        @mod.app.get("/api/projects/{pid}/compact")
        def project_compact(pid: str):
            return _compact_report(pid)

        @mod.app.get("/api/projects/{pid}/artifacts")
        def project_artifacts(pid: str, offset: int = 0, limit: int = 100, query: str = "", family: str = "", file: str = "", kind: str = "", sort: str = "score"):
            rep = _report(pid)
            summary = rep.get("summary", {}) or {}
            arts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
            q = (query or "").lower()
            def match(a):
                blob = (str(a.get("name", "")) + " " + str(a.get("kind", "")) + " " + str(a.get("note", "")) + " " + str(a.get("file", ""))).lower()
                return (not q or q in blob) and (not family or family.lower() in blob) and (not file or file.lower() in str(a.get("file", "")).lower()) and (not kind or kind.lower() in str(a.get("kind", "")).lower())
            arts = [a for a in arts if match(a)]
            if sort == "size":
                arts.sort(key=lambda a: int(a.get("size", 0) or 0), reverse=True)
            elif sort == "name":
                arts.sort(key=lambda a: str(a.get("name", "")).lower())
            else:
                arts.sort(key=lambda a: int(a.get("score", 0) or 0), reverse=True)
            offset = max(0, int(offset or 0)); limit = max(1, min(500, int(limit or 100)))
            return {"total": len(arts), "offset": offset, "limit": limit, "artifacts": arts[offset:offset + limit]}

        @mod.app.get("/api/projects/{pid}/files")
        def project_files(pid: str, offset: int = 0, limit: int = 500):
            root = mod.pdir(pid)
            uploaded = []
            try:
                for p in (root / "files").rglob("*"):
                    if p.is_file():
                        uploaded.append({"name": p.name, "path": str(p), "rel": str(p.relative_to(root)), "size": p.stat().st_size, "kind": "file"})
            except Exception:
                pass
            offset = max(0, int(offset or 0)); limit = max(1, min(2000, int(limit or 500)))
            return {"total": len(uploaded), "offset": offset, "limit": limit, "files": uploaded[offset:offset + limit]}

        @mod.app.get("/api/projects/{pid}/log")
        def project_log(pid: str, tail: int = 30000):
            root = mod.pdir(pid)
            candidates = [root / "project.log", root / "log.txt", root / "autosolve.log"]
            text = ""
            for p in candidates:
                if p.exists():
                    text = p.read_text(encoding="utf-8", errors="replace")
                    break
            return {"tail": text[-max(1000, min(200000, int(tail or 30000))):], "size": len(text)}

        @mod.app.get("/api/raw_info")
        def raw_info(path: str):
            p = Path(path)
            ok = p.exists() and p.is_file() and _inside_base(p)
            mime, _enc = mimetypes.guess_type(str(p))
            return {"exists": bool(ok), "size": p.stat().st_size if ok else 0, "mime": mime or "application/octet-stream", "kind": (mime or "binary").split("/", 1)[0], "basename": p.name, "url": "/api/raw?path=" + str(p) if ok else ""}

        @mod.app.get("/api/projects/{pid}/artifact_preview")
        def artifact_preview(pid: str, path: str):
            p = Path(path)
            if not (p.exists() and p.is_file() and _inside_project(pid, p)):
                return {"ok": False, "error": "missing or outside project", "path": path}
            data = p.read_bytes()[:65536]
            mime, _enc = mimetypes.guess_type(str(p))
            info = {"ok": True, "path": str(p), "name": p.name, "size": p.stat().st_size, "mime": mime or "application/octet-stream", "raw_url": "/api/raw?path=" + str(p)}
            if (mime or "").startswith("image/"):
                info["kind"] = "image"
            else:
                txt = data.decode("utf-8", "replace")
                info["kind"] = "text" if "\x00" not in txt[:1000] else "binary"
                info["text"] = txt[:20000]
                info["hex_head"] = data[:256].hex(" ")
            return info

        @mod.app.get("/api/projects/{pid}/file_preview")
        def file_preview(pid: str, path: str):
            return artifact_preview(pid, path)
    except Exception as e:
        agent_crash("install compact/raw endpoints", e, None)

    try:
        @mod.app.post("/api/projects/{pid}/stop")
        def stop_project(pid: str):
            try:
                with mod.LOCK:
                    job = mod.JOBS.setdefault(pid, {})
                    job["cancel_requested"] = True
                    job["status"] = "cancelled"
                    job["stage"] = "Stop requested"
                    job["updated"] = mod.time.time()
                try:
                    mod.log(pid, "Stop requested by user")
                except Exception:
                    pass
                return {"ok": True, "status": "cancelled", "pid": pid}
            except Exception as e:
                agent_crash("api stop_project", e, None)
                return {"ok": False, "error": repr(e), "pid": pid}
    except Exception:
        pass

    try:
        from .workflow_v74 import install as install_v74_workflow
        install_v74_workflow(mod)
    except Exception as e:
        agent_crash('install_v74_workflow', e, None)
    try:
        from .workflow_v75 import install as install_v75_logic
        install_v75_logic(mod)
    except Exception as e:
        agent_crash('install_v75_logic', e, None)
    try:
        from .semantic_v76 import install as install_v76_semantic
        install_v76_semantic(mod)
    except Exception as e:
        agent_crash('install_v76_semantic', e, None)
    try:
        from .strict_wraps_v77 import install as install_v77_strict_wraps
        install_v77_strict_wraps(mod)
    except Exception as e:
        agent_crash('install_v77_strict_wraps', e, None)

    try:
        from .universal_v89 import install as install_v89_universal
        install_v89_universal(mod)
    except Exception as e:
        agent_crash('install_v89_universal', e, None)
    try:
        from .v93_reasoned import install as install_v93_reasoned
        install_v93_reasoned(mod)
    except Exception as e:
        agent_crash('install_v93_reasoned', e, None)
    try:
        from .v100_ctf_player import install as install_v100_ctf_player
        install_v100_ctf_player(mod)
    except Exception as e:
        agent_crash('install_v100_ctf_player', e, None)
    try:
        from .final_engine import install as install_final_engine
        install_final_engine(mod)
    except Exception as e:
        agent_crash('install_final_engine', e, None)
    try:
        _install_final_runtime_fixes(mod, _inside_projects, _inside_project)
    except Exception as e:
        agent_crash('install_final_runtime_fixes', e, None)
    try:
        _install_profile_preferences(mod)
    except Exception as e:
        agent_crash('install_profile_preferences', e, None)
    return mod

def _install_final_runtime_fixes(mod, inside_projects, inside_project) -> None:
    dangerous_tools = {"ltrace_short", "strace_short"}

    def safe(name):
        s = re.sub(r"[^A-Za-z0-9._ -]+", "_", name or "file").strip()
        s = s.replace("\\", "_").replace("/", "_").lstrip(".")
        return s[:180] or "file"
    mod.safe = safe

    if hasattr(mod, "DEEP_EXTRA"):
        for key, tools in list(mod.DEEP_EXTRA.items()):
            mod.DEEP_EXTRA[key] = [t for t in tools if t not in dangerous_tools]

    old_run_tool_local = getattr(mod, "run_tool_local", None)
    if old_run_tool_local:
        def run_tool_local(path, toolname, timeout=180, allow_dangerous=False):
            if toolname in dangerous_tools and not allow_dangerous:
                return {
                    "tool": toolname,
                    "ok": False,
                    "cmd": "",
                    "out": "BLOCKED: this tool executes the analyzed binary. Run it manually in a sandbox if you really need it.",
                    "missing": [],
                    "install_hint": "",
                    "evidence": [],
                    "decoders": [],
                    "dangerous": True,
                }
            return old_run_tool_local(path, toolname, timeout)
        mod.run_tool_local = run_tool_local

    old_detect_kind = getattr(mod, "detect_kind", None)
    if old_detect_kind:
        def detect_kind(path, fileout):
            n = Path(path).name.lower()
            f = (fileout or "").lower()
            if any(n.endswith(e) for e in [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"]):
                return "office"
            if "sqlite" in f:
                return "sqlite"
            if "luks" in f:
                return "encrypted"
            if any(x in f for x in ["filesystem", "boot sector", "mbr", "partition table", "ext2", "ext3", "ext4", "fat", "ntfs"]):
                return "disk_image"
            if any(n.endswith(e) for e in [".img", ".raw", ".dd", ".dmp", ".mem"]):
                if any(x in f for x in ["filesystem", "boot sector", "partition", "data", "dos/mbr"]):
                    return "disk_image"
            return old_detect_kind(path, fileout)
        mod.detect_kind = detect_kind

    def _job_copy(pid: str):
        try:
            with mod.LOCK:
                return dict(mod.JOBS.get(pid, {}) or {})
        except Exception:
            return {}

    def raw(path: str):
        p = Path(path)
        if not (p.exists() and p.is_file() and inside_projects(p)):
            return mod.JSONResponse({"error": "blocked: raw access is limited to project files and generated artifacts"}, status_code=403)
        return mod.FileResponse(str(p.resolve()))

    def list_projects():
        arr = []
        for d in sorted([x for x in mod.PROJECTS.iterdir() if x.is_dir()], key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True):
            meta = mod.jread(d / "project.json", {}) or {"id": d.name, "title": d.name}
            pid = meta.get("id") or d.name
            if hasattr(mod, "sl108_postprocess_report_file") and (d / "report.json").exists():
                rep = mod.sl108_postprocess_report_file(pid)
            else:
                rep = mod.jread(d / "report.json", {})
            job = _job_copy(pid)
            meta.update({
                "progress": job.get("progress", 100 if rep else 0),
                "stage": job.get("stage", "Done" if rep else "idle"),
                "runtime_status": job.get("status", "done" if rep else "idle"),
                "summary": rep.get("summary", {}),
            })
            arr.append(meta)
        return {"projects": arr}

    def get_project(pid: str):
        root = mod.pdir(pid)
        log_path = root / "events.log"
        if hasattr(mod, "sl108_postprocess_report_file"):
            rep = mod.sl108_postprocess_report_file(pid)
        else:
            rep = mod.jread(mod.report_path(pid), {})
        return {
            "project": mod.jread(mod.meta_path(pid), {}),
            "report": rep,
            "job": _job_copy(pid),
            "log": log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else "",
        }

    try:
        if hasattr(mod, "sl103_rebind_route"):
            mod.sl103_rebind_route("/api/raw", ["GET"], raw)
            mod.sl103_rebind_route("/api/projects", ["GET"], list_projects)
            mod.sl103_rebind_route("/api/projects/{pid}", ["GET"], get_project)
    except Exception:
        pass


def _install_profile_preferences(mod) -> None:
    defaults = {
        "profile_name": "Operator",
        "theme": "dark",
        "accent_color": "#35d07f",
        "tool_color": "#35d07f",
        "flag_prefix": "ctf_cs",
        "show_project_counter": True,
    }
    pref_path = Path(getattr(mod, "BASE", Path("."))) / "data" / "user_preferences.json"

    def clean_prefix(value) -> str:
        s = re.sub(r"[^A-Za-z0-9_]+", "", str(value or "")).strip("_")
        return (s[:32] or defaults["flag_prefix"])

    def clean_color(value, fallback) -> str:
        s = str(value or "").strip()
        return s if re.fullmatch(r"#[0-9A-Fa-f]{6}", s) else fallback

    def read_preferences() -> dict:
        data = {}
        try:
            data = json.loads(pref_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        prefs = dict(defaults)
        if isinstance(data, dict):
            prefs.update(data)
        prefs["profile_name"] = str(prefs.get("profile_name") or defaults["profile_name"])[:80]
        prefs["theme"] = prefs.get("theme") if prefs.get("theme") in {"dark", "light", "system"} else defaults["theme"]
        prefs["accent_color"] = clean_color(prefs.get("accent_color"), defaults["accent_color"])
        prefs["tool_color"] = clean_color(prefs.get("tool_color"), defaults["tool_color"])
        prefs["flag_prefix"] = clean_prefix(prefs.get("flag_prefix"))
        prefs["show_project_counter"] = bool(prefs.get("show_project_counter", True))
        return prefs

    def write_preferences(payload: dict) -> dict:
        prefs = read_preferences()
        for key in defaults:
            if key in payload:
                prefs[key] = payload[key]
        prefs["profile_name"] = str(prefs.get("profile_name") or defaults["profile_name"])[:80]
        prefs["theme"] = prefs.get("theme") if prefs.get("theme") in {"dark", "light", "system"} else defaults["theme"]
        prefs["accent_color"] = clean_color(prefs.get("accent_color"), defaults["accent_color"])
        prefs["tool_color"] = clean_color(prefs.get("tool_color"), defaults["tool_color"])
        prefs["flag_prefix"] = clean_prefix(prefs.get("flag_prefix"))
        prefs["show_project_counter"] = bool(prefs.get("show_project_counter", True))
        pref_path.parent.mkdir(parents=True, exist_ok=True)
        pref_path.write_text(json.dumps(prefs, ensure_ascii=False, indent=2), encoding="utf-8")
        return prefs

    def preferred_flag(value, prefix: str) -> str:
        s = str(value or "").strip()
        if not s:
            return ""
        m = re.match(r"(?is)^([A-Za-z0-9_]{1,32})\{(.+)\}$", s)
        if m:
            return f"{prefix}{{{m.group(2).strip()}}}"
        if s.startswith("{") and s.endswith("}") and len(s) > 2:
            return f"{prefix}{{{s[1:-1].strip()}}}"
        return f"{prefix}{{{s}}}"

    @mod.app.get("/api/preferences")
    def get_preferences():
        prefs = read_preferences()
        try:
            projects = [p for p in mod.PROJECTS.iterdir() if p.is_dir()]
        except Exception:
            projects = []
        return {
            "preferences": prefs,
            "project_counter": {"total": len(projects)},
            "defaults": defaults,
        }

    @mod.app.post("/api/preferences")
    def save_preferences(payload: dict = Body(...)):
        prefs = write_preferences(payload if isinstance(payload, dict) else {})
        return {"ok": True, "preferences": prefs}

    old_project_summary = getattr(mod, "project_summary", None)
    if old_project_summary:
        def project_summary(reports, meta):
            summary = old_project_summary(reports, meta)
            prefs = read_preferences()
            prefix = prefs["flag_prefix"]
            preferred = []
            seen = set()
            for item in summary.get("flags", []) or []:
                raw = item.get("flag") if isinstance(item, dict) else str(item)
                converted = preferred_flag(raw, prefix)
                if converted and converted.lower() not in seen:
                    seen.add(converted.lower())
                    row = dict(item) if isinstance(item, dict) else {"flag": raw}
                    row["preferred_flag"] = converted
                    row["preferred_prefix"] = prefix
                    preferred.append(row)
            summary["preferred_flag_format"] = f"{prefix}" + "{...}"
            summary["preferred_flags"] = preferred[:80]
            summary["user_preferences"] = {
                "profile_name": prefs["profile_name"],
                "theme": prefs["theme"],
                "accent_color": prefs["accent_color"],
                "tool_color": prefs["tool_color"],
                "flag_prefix": prefix,
                "show_project_counter": prefs["show_project_counter"],
            }
            return summary
        mod.project_summary = project_summary

def boot():
    legacy = importlib.import_module("sloper_legacy")
    install(legacy)
    try:
        from .hardening_v108 import apply as _apply_hardening_v108
        _apply_hardening_v108(legacy)
    except Exception as e:
        print("warning: hardening_v108 failed:", e)
    return legacy
