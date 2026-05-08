"""Late backend safety and reliability guard for CTF SLOPER.

This module does not replace solver logic and does not touch the frontend.  It
wraps the risky edges left by legacy layers: upload streaming, project-id/path
validation, raw artifact serving, log tailing, report writes, archive caps,
custom regex hygiene, and accidental execution of uploaded binaries.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import tempfile
import threading
import time
import traceback
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from fastapi import BackgroundTasks, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from sloper_v72.health import agent_crash


PID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
UPLOAD_CHUNK = int(os.environ.get("SLOPER_UPLOAD_CHUNK_BYTES", "1048576"))
MAX_ZIP_MEMBER_BYTES = int(os.environ.get("SLOPER_MAX_ZIP_MEMBER_BYTES", "25000000"))
MAX_ZIP_TOTAL_BYTES = int(os.environ.get("SLOPER_MAX_ZIP_TOTAL_BYTES", "160000000"))
_WRITE_LOCK = threading.RLock()
_JOB_LOCKS: dict[str, threading.Lock] = {}
_JOB_LOCKS_GUARD = threading.Lock()


def _rebind(mod: Any, path: str, methods: list[str], endpoint: Any) -> None:
    method_set = {m.upper() for m in methods}
    keep = []
    for route in list(mod.app.router.routes):
        route_methods = set(getattr(route, "methods", []) or [])
        if getattr(route, "path", None) == path and route_methods.intersection(method_set):
            continue
        keep.append(route)
    mod.app.router.routes = keep
    mod.app.add_api_route(path, endpoint, methods=sorted(method_set))


def _safe_name(mod: Any, name: str) -> str:
    try:
        return mod.safe(name)
    except Exception:
        clean = re.sub(r"[^A-Za-z0-9_. -]+", "_", str(name or "file")).strip(" .")
        return clean[:180] or "file"


def _valid_pid(pid: str) -> bool:
    return bool(PID_RE.fullmatch(str(pid or "")))


def _project_root(mod: Any, pid: str) -> Path:
    if not _valid_pid(pid):
        raise ValueError("invalid project id")
    root = (Path(getattr(mod, "PROJECTS")).resolve() / pid).resolve()
    base = Path(getattr(mod, "PROJECTS")).resolve()
    if root != base and base not in root.parents:
        raise ValueError("project path escaped workspace")
    return root


def _inside(path: Path, base: Path) -> bool:
    try:
        base_r = Path(base).resolve()
        path_r = Path(path).expanduser().resolve()
        return path_r == base_r or base_r in path_r.parents
    except Exception:
        return False


def _inside_projects(mod: Any, path: Path) -> bool:
    return _inside(path, Path(getattr(mod, "PROJECTS")))


def _inside_project(mod: Any, pid: str, path: Path) -> bool:
    try:
        return _inside(path, _project_root(mod, pid))
    except Exception:
        return False


def _safe_path_from_query(raw: str) -> Path:
    return Path(unquote(str(raw or "")))


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _job_update(mod: Any, pid: str, **updates: Any) -> None:
    try:
        with mod.LOCK:
            job = mod.JOBS.setdefault(pid, {})
            job.update(updates)
            job["updated"] = time.time()
    except Exception:
        pass


def _job_copy(mod: Any, pid: str) -> dict[str, Any]:
    try:
        with mod.LOCK:
            return dict(mod.JOBS.get(pid, {}) or {})
    except Exception:
        return {}


def _lock_for_pid(pid: str) -> threading.Lock:
    with _JOB_LOCKS_GUARD:
        return _JOB_LOCKS.setdefault(pid, threading.Lock())


def _atomic_jwrite(mod: Any) -> None:
    old_jwrite = getattr(mod, "jwrite", None)

    def jwrite(path: Any, obj: Any) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(obj, ensure_ascii=False, indent=2)
        with _WRITE_LOCK:
            fd, tmp_name = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=str(p.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp_name, p)
            finally:
                try:
                    if os.path.exists(tmp_name):
                        os.unlink(tmp_name)
                except Exception:
                    pass

    if old_jwrite:
        mod.sloper_previous_jwrite = old_jwrite
    mod.jwrite = jwrite


def _safe_regex_value(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) > 220:
        return ""
    # Reject common catastrophic-backtracking shapes and advanced constructs.
    dangerous = [
        r"\([^)]*[+*][^)]*\)[+*{]",
        r"\([^)]*\{[^}]+,[^}]*\}[^)]*\)[+*{]",
        r"\(\?([=!<]|P|#)",
        r"\\[1-9]",
        r"\.\*.*\.\*.*\.\*",
    ]
    if any(re.search(pat, s) for pat in dangerous):
        return ""
    try:
        re.compile(s)
    except Exception:
        return ""
    return s


def _patch_settings(mod: Any) -> None:
    old_norm = getattr(mod, "sl111_normalize_settings", None)
    if old_norm:
        def normalize_settings(data: dict[str, Any] | None) -> dict[str, Any]:
            src = dict(data or {})
            if src.get("custom_flag_regex"):
                src["custom_flag_regex"] = _safe_regex_value(src.get("custom_flag_regex"))
            prefs = old_norm(src)
            if isinstance(prefs, dict):
                prefs["custom_flag_regex"] = _safe_regex_value(prefs.get("custom_flag_regex"))
                if prefs.get("flag_format") == "custom_regex" and not prefs.get("custom_flag_regex"):
                    prefs["flag_format"] = "any_prefix"
                    prefs["flag_regex"] = r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}"
                    prefs["flag_label"] = "anyPrefix{...}"
            return prefs
        mod.sl111_normalize_settings = normalize_settings

    old_compile = getattr(mod, "sl111_compile_flag_patterns", None)
    if old_compile:
        def compile_flag_patterns(prefs: dict[str, Any]) -> list[re.Pattern[str]]:
            prefs = dict(prefs or {})
            prefs["custom_flag_regex"] = _safe_regex_value(prefs.get("custom_flag_regex"))
            return old_compile(prefs)
        mod.sl111_compile_flag_patterns = compile_flag_patterns


def _patch_zip_limits(mod: Any) -> None:
    if getattr(zipfile.ZipFile, "_sloper_guarded", False):
        return
    old_read = zipfile.ZipFile.read
    old_extract = zipfile.ZipFile.extract
    old_extractall = zipfile.ZipFile.extractall

    def _member_info(zf: zipfile.ZipFile, name: Any) -> zipfile.ZipInfo:
        return name if isinstance(name, zipfile.ZipInfo) else zf.getinfo(str(name))

    def read(self: zipfile.ZipFile, name: Any, pwd: bytes | None = None) -> bytes:
        info = _member_info(self, name)
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise RuntimeError(f"blocked oversized zip member: {info.filename} ({info.file_size} bytes)")
        return old_read(self, name, pwd=pwd)

    def extract(self: zipfile.ZipFile, member: Any, path: Any = None, pwd: bytes | None = None) -> str:
        info = _member_info(self, member)
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise RuntimeError(f"blocked oversized zip member: {info.filename} ({info.file_size} bytes)")
        return old_extract(self, member, path=path, pwd=pwd)

    def extractall(self: zipfile.ZipFile, path: Any = None, members: Any = None, pwd: bytes | None = None) -> None:
        infos = list(members) if members is not None else self.infolist()
        total = 0
        for item in infos:
            info = _member_info(self, item)
            total += int(info.file_size or 0)
            if info.file_size > MAX_ZIP_MEMBER_BYTES or total > MAX_ZIP_TOTAL_BYTES:
                raise RuntimeError("blocked oversized zip extraction")
        return old_extractall(self, path=path, members=infos, pwd=pwd)

    zipfile.ZipFile.read = read
    zipfile.ZipFile.extract = extract
    zipfile.ZipFile.extractall = extractall
    zipfile.ZipFile._sloper_guarded = True
    mod.SLOPER_ZIP_LIMITS = {"member": MAX_ZIP_MEMBER_BYTES, "total": MAX_ZIP_TOTAL_BYTES}


def _patch_dangerous_execution(mod: Any) -> None:
    def blocked_local_binary(root: Path, report: dict[str, Any], data: bytes) -> list[dict[str, Any]]:
        if not data.startswith((b"\x7fELF", b"MZ")):
            return []
        note = {
            "name": "local_binary_execution_blocked.txt",
            "kind": "safety_note",
            "source": "backend_guard",
            "file": report.get("rel") or report.get("name"),
            "score": 420,
            "size": 0,
            "exists": False,
            "note": "Uploaded executable was not run automatically. Use static strings/imports/sections first; run manually in a sandbox if needed.",
        }
        report.setdefault("artifacts", []).append(note)
        report.setdefault("next_steps", []).insert(0, {
            "priority": 95,
            "step": "Review static binary artifacts before executing anything.",
            "why": "Backend guard blocks automatic execution of uploaded ELF/PE files.",
        })
        return [note]

    mod.v99_local_binary_smoke_agent = blocked_local_binary

    old_run_tool_local = getattr(mod, "run_tool_local", None)
    dangerous = {"ltrace_short", "strace_short", "local_binary_smoke"}
    if old_run_tool_local:
        def run_tool_local(path: Any, toolname: str, timeout: int = 180, allow_dangerous: bool = False):
            if str(toolname) in dangerous and not allow_dangerous:
                return {
                    "tool": toolname,
                    "ok": False,
                    "cmd": "",
                    "out": "BLOCKED: automatic execution/tracing of uploaded binaries is disabled. Run manually in a sandbox if required.",
                    "missing": [],
                    "dangerous": True,
                }
            return old_run_tool_local(path, toolname, min(int(timeout or 180), 180))
        mod.run_tool_local = run_tool_local


def _patch_pyc_extractors(mod: Any) -> None:
    def safe_pyc_notice(report: dict[str, Any], root: Path, data: bytes) -> list[dict[str, Any]]:
        p = Path(str(report.get("path", "")))
        if p.suffix.lower() != ".pyc":
            return []
        strings = re.findall(rb"[\x20-\x7e]{4,}", bytes(data or b"")[:2_000_000])
        text = "\n".join(s.decode("utf-8", "replace") for s in strings[:1000])
        outdir = Path(root) / "generated" / "pyc_safe_static" / _safe_name(mod, p.name)
        outdir.mkdir(parents=True, exist_ok=True)
        art_path = outdir / "pyc_strings_no_marshal.txt"
        art_path.write_text(text, encoding="utf-8", errors="replace")
        art = {
            "name": art_path.name,
            "kind": "pyc_safe_strings",
            "source": "backend_guard",
            "file": report.get("rel") or report.get("name"),
            "path": str(art_path),
            "url": "/api/raw?path=" + str(art_path),
            "score": 520,
            "size": art_path.stat().st_size,
            "exists": True,
            "note": "PYC reviewed via raw strings only; marshal parsing is disabled for uploaded bytecode.",
        }
        report.setdefault("artifacts", []).append(art)
        report.setdefault("transformations", []).append(art)
        return [art]

    for name in ("v95_pyc_static_agent", "sl_pyc_constants_agent"):
        if hasattr(mod, name):
            setattr(mod, name, safe_pyc_notice)

    try:
        import sloper_v72.competition_v116 as v116
        def safe_v116_pyc(raw: bytes) -> list[tuple[str, str]]:
            if bytes(raw or b"")[:4]:
                strings = re.findall(rb"[\x20-\x7e]{4,}", bytes(raw or b"")[:2_000_000])
                text = "\n".join(s.decode("utf-8", "replace") for s in strings[:1000])
                return [("pyc_strings_no_marshal", text)] if text else []
            return []
        v116._pyc_extract = safe_v116_pyc
    except Exception as exc:
        agent_crash("backend_guard patch v116 pyc", exc, None)


def _safe_analyze(mod: Any, pid: str) -> None:
    lock = _lock_for_pid(pid)
    if not lock.acquire(blocking=False):
        _job_update(mod, pid, status="running", color="yellow", stage="Already running")
        return
    try:
        _job_update(mod, pid, status="running", color="yellow", stage="Analyzing", started=time.time())
        mod.analyze_project(pid)
        job = _job_copy(mod, pid)
        if not job.get("cancel_requested"):
            _job_update(mod, pid, status="done", color="green", progress=100, stage="Done", finished=time.time())
    except Exception as exc:
        agent_crash("backend_guard safe analyze_project", exc, None)
        try:
            root = _project_root(mod, pid)
            root.mkdir(parents=True, exist_ok=True)
            rep_path = root / "report.json"
            rep = _read_json(rep_path, {})
            rep.setdefault("summary", {}).setdefault("warnings", []).append(
                "Analysis crashed; backend guard preserved partial report and logs."
            )
            rep.setdefault("agent_health", []).append({
                "agent": "backend_guard safe analyze_project",
                "error": repr(exc),
                "traceback": traceback.format_exc()[-8000:],
                "time": time.time(),
            })
            mod.jwrite(rep_path, rep)
        except Exception:
            pass
        _job_update(mod, pid, status="failed", color="red", progress=100, stage="Analysis crashed", finished=time.time())
    finally:
        lock.release()


def _install_routes(mod: Any) -> None:
    max_upload = int(getattr(mod, "MAX_UPLOAD_BYTES", os.environ.get("SLOPER_MAX_UPLOAD_BYTES", "80000000")))

    async def create_project(
        background_tasks: BackgroundTasks,
        title: str = Form(""),
        statement: str = Form(""),
        category: str = Form("auto"),
        auto_start: str = Form("true"),
        flag_format: str = Form(""),
        flag_prefix: str = Form(""),
        custom_flag_regex: str = Form(""),
        attack_preset: str = Form(""),
        difficulty: str = Form(""),
        max_depth: str = Form(""),
        max_artifacts: str = Form(""),
        max_runtime_seconds: str = Form(""),
        enabled_categories: str = Form(""),
        files: list[UploadFile] = File(...),
    ):
        if not files:
            return {"ok": False, "error": "no files uploaded"}
        import uuid
        pid = uuid.uuid4().hex[:12]
        root = _project_root(mod, pid)
        fdir = root / "files"
        fdir.mkdir(parents=True, exist_ok=True)
        clean: list[str] = []
        total = 0
        for upload in files:
            raw_name = getattr(upload, "filename", "") or "file"
            name = _safe_name(mod, raw_name)
            if name.lower() in {"generated", "artifacts", "cache", "project.json", "report.json"}:
                name = "uploaded_" + name
            target = fdir / name
            if target.exists():
                stem, suffix = target.stem, target.suffix
                i = 2
                while target.exists():
                    target = fdir / f"{stem}_{i}{suffix}"
                    i += 1
            tmp = target.with_suffix(target.suffix + ".uploading")
            size = 0
            try:
                with tmp.open("wb") as fh:
                    while True:
                        chunk = await upload.read(UPLOAD_CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        total += len(chunk)
                        if size > max_upload or total > max_upload * max(1, min(len(files), 8)):
                            raise ValueError(f"upload too large: {name}; limit={max_upload} bytes per file")
                        fh.write(chunk)
                os.replace(tmp, target)
            except Exception as exc:
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
                return {"ok": False, "error": str(exc)}
            clean.append(target.name)

        cleaned_custom_regex = _safe_regex_value(custom_flag_regex)
        payload = {
            "flag_format": flag_format,
            "flag_prefix": flag_prefix,
            "custom_flag_regex": cleaned_custom_regex,
            "attack_preset": attack_preset,
            "difficulty": difficulty,
            "max_depth": max_depth,
            "max_artifacts": max_artifacts,
            "max_runtime_seconds": max_runtime_seconds,
        }
        payload = {k: v for k, v in payload.items() if str(v or "").strip()}
        if str(custom_flag_regex or "").strip() and not cleaned_custom_regex:
            payload["custom_flag_regex"] = ""
        if enabled_categories:
            cats = {c.strip() for c in enabled_categories.split(",") if c.strip()}
            payload["enabled_categories"] = {c: c in cats for c in getattr(mod, "sl111_CATEGORIES", [])}
        try:
            base = mod.sl111_read_settings() if hasattr(mod, "sl111_read_settings") else {}
            settings = mod.sl111_normalize_settings({**base, **payload}) if hasattr(mod, "sl111_normalize_settings") else {**base, **payload}
        except Exception as exc:
            agent_crash("backend_guard upload settings", exc, None)
            settings = payload
        auto_title = (title or "").strip() or (clean[0] if clean else "Untitled challenge")
        meta = {
            "id": pid,
            "title": auto_title,
            "statement": statement,
            "category": category or "auto",
            "created": mod.now() if hasattr(mod, "now") else time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_count": len(clean),
            "uploaded_files": clean,
            "workspace_model": "backend_guard: streaming upload, files/ inputs, generated/ outputs",
            "solver_settings": settings,
        }
        mod.jwrite(root / "project.json", meta)
        _job_update(mod, pid, status="created", color="gray", progress=0, stage=f"Created {len(clean)} file(s)", settings=settings)
        try:
            mod.log(pid, f"Project created: {auto_title} ({len(clean)} files)")
        except Exception:
            pass
        if str(auto_start).lower() in {"1", "true", "yes", "on"}:
            _job_update(mod, pid, status="queued", color="yellow", progress=1, stage="Queued")
            background_tasks.add_task(_safe_analyze, mod, pid)
        return {"ok": True, "id": pid, "project": meta, "settings": settings}

    def start_project(pid: str, background_tasks: BackgroundTasks):
        try:
            root = _project_root(mod, pid)
        except Exception:
            return JSONResponse({"ok": False, "error": "invalid project id"}, status_code=400)
        if not root.exists():
            return JSONResponse({"ok": False, "error": "project not found"}, status_code=404)
        if _job_copy(mod, pid).get("status") == "running":
            return {"ok": True, "id": pid, "status": "running", "note": "already running"}
        _job_update(mod, pid, status="queued", color="yellow", progress=1, stage="Queued")
        background_tasks.add_task(_safe_analyze, mod, pid)
        return {"ok": True, "id": pid, "status": "queued"}

    def stop_project(pid: str):
        if not _valid_pid(pid):
            return JSONResponse({"ok": False, "error": "invalid project id"}, status_code=400)
        _job_update(mod, pid, cancel_requested=True, status="cancelled", color="red", stage="Stop requested", finished=time.time())
        try:
            mod.log(pid, "Stop requested by user")
        except Exception:
            pass
        return {"ok": True, "status": "cancelled", "pid": pid}

    def _report(pid: str) -> dict[str, Any]:
        try:
            return _read_json(_project_root(mod, pid) / "report.json", {}) or {}
        except Exception:
            return {}

    def project_compact(pid: str):
        try:
            root = _project_root(mod, pid)
        except Exception:
            return JSONResponse({"error": "invalid project id"}, status_code=400)
        meta = _read_json(root / "project.json", {"id": pid, "title": pid}) if root.exists() else {"id": pid, "title": pid}
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
            if isinstance(r, dict):
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
        return {"project": meta, "job": _job_copy(mod, pid), "report": {"summary": summary, "files": files, "updated": rep.get("updated")}}

    def project_artifacts(pid: str, offset: int = 0, limit: int = 100, query: str = "", family: str = "", file: str = "", kind: str = "", sort: str = "score"):
        if not _valid_pid(pid):
            return JSONResponse({"error": "invalid project id"}, status_code=400)
        summary = (_report(pid).get("summary", {}) or {})
        arts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
        q = (query or "").lower()
        def match(a: dict[str, Any]) -> bool:
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

    def project_files(pid: str, offset: int = 0, limit: int = 500):
        try:
            root = _project_root(mod, pid)
        except Exception:
            return JSONResponse({"error": "invalid project id"}, status_code=400)
        uploaded = []
        try:
            for p in (root / "files").rglob("*"):
                if p.is_file() and _inside_project(mod, pid, p):
                    uploaded.append({"name": p.name, "path": str(p), "rel": str(p.relative_to(root)), "size": p.stat().st_size, "kind": "file"})
        except Exception:
            pass
        offset = max(0, int(offset or 0)); limit = max(1, min(2000, int(limit or 500)))
        return {"total": len(uploaded), "offset": offset, "limit": limit, "files": uploaded[offset:offset + limit]}

    def project_log(pid: str, tail: int = 30000):
        try:
            root = _project_root(mod, pid)
        except Exception:
            return JSONResponse({"error": "invalid project id"}, status_code=400)
        candidates = [root / "events.log", root / "project.log", root / "log.txt", root / "autosolve.log"]
        text = ""
        for p in candidates:
            if p.exists() and p.is_file() and _inside_project(mod, pid, p):
                text = p.read_text(encoding="utf-8", errors="replace")
                break
        n = max(1000, min(200000, int(tail or 30000)))
        return {"tail": text[-n:], "size": len(text)}

    def raw(path: str):
        p = _safe_path_from_query(path)
        if not (_inside_projects(mod, p) and p.exists() and p.is_file()):
            return JSONResponse({"error": "blocked: raw access is limited to project files and generated artifacts"}, status_code=403)
        return FileResponse(str(p.resolve()), filename=p.name)

    def raw_info(path: str):
        p = _safe_path_from_query(path)
        if not _inside_projects(mod, p):
            return {"exists": False, "size": 0, "mime": "application/octet-stream", "kind": "blocked", "basename": "", "url": ""}
        ok = p.exists() and p.is_file()
        mime, _enc = mimetypes.guess_type(str(p))
        return {"exists": bool(ok), "size": p.stat().st_size if ok else 0, "mime": mime or "application/octet-stream", "kind": (mime or "binary").split("/", 1)[0], "basename": p.name if ok else "", "url": "/api/raw?path=" + str(p) if ok else ""}

    def artifact_preview(pid: str, path: str):
        p = _safe_path_from_query(path)
        if not (_inside_project(mod, pid, p) and p.exists() and p.is_file()):
            return {"ok": False, "error": "missing or outside project", "path": ""}
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

    async def batch_import_zip(background_tasks: BackgroundTasks, files: UploadFile = File(...), auto_start: str = Form("false")):
        batch_dir = Path(getattr(mod, "BASE")) / "batches"
        batch_dir.mkdir(exist_ok=True)
        name = _safe_name(mod, getattr(files, "filename", "batch.zip"))
        zp = batch_dir / name
        size = 0
        tmp = zp.with_suffix(zp.suffix + ".uploading")
        with tmp.open("wb") as fh:
            while True:
                chunk = await files.read(UPLOAD_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_upload * 4:
                    tmp.unlink(missing_ok=True)
                    return {"ok": False, "error": "batch zip too large"}
                fh.write(chunk)
        os.replace(tmp, zp)
        res = mod.rb_batch_zip_import(zp, auto_start=str(auto_start).lower() == "true") if hasattr(mod, "rb_batch_zip_import") else {"ok": False, "error": "batch importer unavailable"}
        if res.get("ok") and str(auto_start).lower() == "true":
            for item in res.get("created", []):
                background_tasks.add_task(_safe_analyze, mod, item["id"])
        return res

    async def batch_import_zip_path(background_tasks: BackgroundTasks, path: str = Form(...), auto_start: str = Form("false")):
        p = _safe_path_from_query(path)
        batches = (Path(getattr(mod, "BASE")) / "batches").resolve()
        if not (_inside(p, batches) and p.exists() and p.is_file()):
            return JSONResponse({"ok": False, "error": "path import is limited to the local batches directory"}, status_code=403)
        res = mod.rb_batch_zip_import(p, auto_start=str(auto_start).lower() == "true") if hasattr(mod, "rb_batch_zip_import") else {"ok": False, "error": "batch importer unavailable"}
        if res.get("ok") and str(auto_start).lower() == "true":
            for item in res.get("created", []):
                background_tasks.add_task(_safe_analyze, mod, item["id"])
        return res

    for path, methods, endpoint in [
        ("/api/projects", ["POST"], create_project),
        ("/api/projects/{pid}/start", ["POST"], start_project),
        ("/api/projects/{pid}/stop", ["POST"], stop_project),
        ("/api/projects/{pid}/compact", ["GET"], project_compact),
        ("/api/projects/{pid}/artifacts", ["GET"], project_artifacts),
        ("/api/projects/{pid}/files", ["GET"], project_files),
        ("/api/projects/{pid}/log", ["GET"], project_log),
        ("/api/raw", ["GET"], raw),
        ("/api/raw_info", ["GET"], raw_info),
        ("/api/projects/{pid}/artifact_preview", ["GET"], artifact_preview),
        ("/api/projects/{pid}/file_preview", ["GET"], artifact_preview),
        ("/api/batch_import_zip", ["POST"], batch_import_zip),
        ("/api/batch_import_zip_path", ["POST"], batch_import_zip_path),
    ]:
        try:
            _rebind(mod, path, methods, endpoint)
        except Exception as exc:
            agent_crash(f"backend_guard rebind {path}", exc, None)


def _install_middleware(mod: Any) -> None:
    if getattr(mod.app.state, "sloper_backend_guard_middleware", False):
        return

    @mod.app.middleware("http")
    async def backend_guard_middleware(request: Request, call_next):
        path = request.url.path
        if "/api/projects/" in path:
            try:
                seg = path.split("/api/projects/", 1)[1].split("/", 1)[0]
                dec = unquote(seg)
                if not _valid_pid(dec):
                    return JSONResponse({"error": "invalid project id"}, status_code=400)
            except Exception:
                return JSONResponse({"error": "invalid project id"}, status_code=400)
        return await call_next(request)

    mod.app.state.sloper_backend_guard_middleware = True


def apply(mod: Any) -> None:
    _atomic_jwrite(mod)
    _patch_settings(mod)
    _patch_zip_limits(mod)
    _patch_dangerous_execution(mod)
    _patch_pyc_extractors(mod)
    _install_routes(mod)
    _install_middleware(mod)
    mod.SLOPER_BACKEND_GUARD = {
        "enabled": True,
        "version": "backend-guard-2026-05-08",
        "zip_member_cap": MAX_ZIP_MEMBER_BYTES,
        "zip_total_cap": MAX_ZIP_TOTAL_BYTES,
        "streaming_uploads": True,
        "binary_auto_execution": "blocked",
        "custom_regex": "sanitized",
    }
