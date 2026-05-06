"""v123 upload/start reliability guard.

The public UI creates projects with ``POST /api/projects`` and then starts
analysis with ``POST /api/projects/{pid}/start``.  Some legacy route-rebinding
layers can accidentally leave only the GET project list route active, which
turns a normal upload into a 405 and looks like an analysis crash.

This module is deliberately small and late-installed: it rebinds only the two
operator-critical routes and wraps background analysis so one solver exception
marks the project failed instead of crashing the request.
"""
from __future__ import annotations

import os
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, List

from fastapi import BackgroundTasks, File, Form, UploadFile

from .health import agent_crash


def _safe_name(mod: Any, name: str) -> str:
    try:
        return mod.safe(name)
    except Exception:
        import re
        cleaned = re.sub(r"[^A-Za-z0-9_. -]+", "_", str(name or "file")).strip(" .")
        return cleaned[:180] or "file"


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


def _job_update(mod: Any, pid: str, **updates: Any) -> None:
    try:
        with mod.LOCK:
            job = mod.JOBS.setdefault(pid, {})
            job.update(updates)
            job["updated"] = time.time()
    except Exception:
        pass


def _safe_analyze(mod: Any, pid: str) -> None:
    try:
        _job_update(mod, pid, status="running", color="yellow", stage="Analyzing", started=time.time())
        mod.analyze_project(pid)
    except Exception as exc:  # background tasks must never tear down upload
        agent_crash("v123 safe analyze_project", exc, None)
        try:
            root = mod.pdir(pid)
            rep = mod.jread(mod.report_path(pid), {}) or {}
            rep.setdefault("summary", {}).setdefault("warnings", []).append(
                "Analysis crashed; partial artifacts and logs were preserved. See /api/agent_health."
            )
            rep.setdefault("agent_health", []).append({
                "agent": "v123 safe analyze_project",
                "error": repr(exc),
                "traceback": traceback.format_exc()[-8000:],
                "time": time.time(),
            })
            mod.jwrite(mod.report_path(pid), rep)
            root.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        _job_update(mod, pid, status="failed", color="red", stage="Analysis crashed; partial report preserved", progress=100, finished=time.time())


def install(mod: Any) -> None:
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
        files: List[UploadFile] = File(...),
    ):
        if not files:
            return {"ok": False, "error": "no files uploaded"}
        pid = uuid.uuid4().hex[:12]
        root = mod.pdir(pid)
        fdir = root / "files"
        fdir.mkdir(parents=True, exist_ok=True)
        clean: list[str] = []
        total = 0
        for upload in files:
            raw_name = getattr(upload, "filename", "") or "file"
            name = _safe_name(mod, raw_name)
            if name.lower() in {"generated", "artifacts", "cache", "project.json", "report.json"}:
                name = "uploaded_" + name
            content = await upload.read()
            total += len(content)
            if len(content) > max_upload or total > max_upload * max(1, min(len(files), 8)):
                return {"ok": False, "error": f"upload too large: {name}; limit={max_upload} bytes per file"}
            target = fdir / name
            if target.exists():
                stem, suffix = target.stem, target.suffix
                i = 2
                while target.exists():
                    target = fdir / f"{stem}_{i}{suffix}"
                    i += 1
            target.write_bytes(content)
            clean.append(target.name)

        settings: dict[str, Any] = {}
        try:
            base = mod.sl111_read_settings() if hasattr(mod, "sl111_read_settings") else {}
            payload = {
                "flag_format": flag_format,
                "flag_prefix": flag_prefix,
                "custom_flag_regex": custom_flag_regex,
                "attack_preset": attack_preset,
                "difficulty": difficulty,
                "max_depth": max_depth,
                "max_artifacts": max_artifacts,
                "max_runtime_seconds": max_runtime_seconds,
            }
            payload = {k: v for k, v in payload.items() if str(v or "").strip()}
            if enabled_categories:
                cats = {c.strip() for c in enabled_categories.split(",") if c.strip()}
                payload["enabled_categories"] = {c: c in cats for c in getattr(mod, "sl111_CATEGORIES", [])}
            if hasattr(mod, "sl111_normalize_settings"):
                settings = mod.sl111_normalize_settings({**base, **payload})
            else:
                settings = {**base, **payload}
        except Exception as exc:
            agent_crash("v123 upload settings", exc, None)
            settings = {}

        auto_title = (title or "").strip() or (clean[0] if clean else "Untitled challenge")
        meta = {
            "id": pid,
            "title": auto_title,
            "statement": statement,
            "category": category or "auto",
            "created": mod.now() if hasattr(mod, "now") else time.time(),
            "file_count": len(clean),
            "uploaded_files": clean,
            "workspace_model": "v123 upload guard: files/ inputs, generated/ outputs",
            "solver_settings": settings,
        }
        mod.jwrite(mod.meta_path(pid), meta)
        _job_update(mod, pid, status="created", color="gray", progress=0, stage=f"Created {len(clean)} file(s)", settings=settings)
        try:
            mod.log(pid, f"Project created by v123 upload guard: {auto_title} ({len(clean)} files)")
        except Exception:
            pass
        if str(auto_start).lower() in {"1", "true", "yes", "on"}:
            _job_update(mod, pid, status="queued", color="yellow", progress=1, stage="Queued")
            background_tasks.add_task(_safe_analyze, mod, pid)
        return {"ok": True, "id": pid, "project": meta, "settings": settings}

    def start_project(pid: str, background_tasks: BackgroundTasks):
        root = mod.pdir(pid)
        if not root.exists():
            return {"ok": False, "error": "project not found"}
        _job_update(mod, pid, status="queued", color="yellow", progress=1, stage="Queued")
        background_tasks.add_task(_safe_analyze, mod, pid)
        return {"ok": True, "id": pid, "status": "queued"}

    _rebind(mod, "/api/projects", ["POST"], create_project)
    _rebind(mod, "/api/projects/{pid}/start", ["POST"], start_project)
    mod.SL123_UPLOAD_FLOW = "v123-upload-start-reliability"
