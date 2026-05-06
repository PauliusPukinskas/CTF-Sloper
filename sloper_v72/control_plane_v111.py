"""v111 operator control plane.

Adds real user-controlled flag formats, attack presets, bounded multi-step
settings, and clean artifact summary shaping without touching the legacy parts.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from fastapi import Body, Form

FORMAT_PRESETS: dict[str, dict[str, str]] = {
    "ctf_cs": {"label": "ctf_cs{...}", "regex": r"(?is)\bctf_cs\{[^{}\r\n]{1,220}\}"},
    "ctf_cm": {"label": "ctf_cm{...}", "regex": r"(?is)\bctf_cm\{[^{}\r\n]{1,220}\}"},
    "flag": {"label": "flag{...}", "regex": r"(?is)\bflag\{[^{}\r\n]{1,220}\}"},
    "picoctf": {"label": "picoCTF{...}", "regex": r"(?is)\bpicoCTF\{[^{}\r\n]{1,220}\}"},
    "htb": {"label": "HTB{...}", "regex": r"(?is)\bHTB\{[^{}\r\n]{1,220}\}"},
    "any_prefix": {"label": "anyPrefix{...}", "regex": r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}"},
    "braces_only": {"label": "{...}", "regex": r"(?is)(?<![A-Za-z0-9_])\{[^{}\r\n]{3,220}\}"},
    "custom_regex": {"label": "custom regex", "regex": r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}"},
}

ATTACK_PRESETS: dict[str, dict[str, Any]] = {
    "quick": {"label": "Quick", "max_depth": 1, "max_artifacts": 200, "max_runtime_seconds": 30, "legacy_deep": False, "note": "Fast grep/decode path."},
    "balanced": {"label": "Balanced", "max_depth": 2, "max_artifacts": 800, "max_runtime_seconds": 120, "legacy_deep": False, "note": "Good default for easy/medium tasks."},
    "deep": {"label": "Deep", "max_depth": 4, "max_artifacts": 2500, "max_runtime_seconds": 360, "legacy_deep": False, "note": "More transforms and artifact review."},
    "hardcore": {"label": "Hardcore", "max_depth": 6, "max_artifacts": 6000, "max_runtime_seconds": 900, "legacy_deep": True, "note": "May be slow; use for hard multi-step tasks."},
}

DIFFICULTIES = ["easy", "medium", "hard", "multi_step"]
CATEGORIES = ["crypto", "stego", "forensics", "reversing", "web", "osint", "misc", "archives", "network", "image", "audio"]

DEFAULTS: dict[str, Any] = {
    "profile_name": "Operator",
    "theme": "dark",
    "accent_color": "#35d07f",
    "tool_color": "#35d07f",
    "flag_format": "ctf_cs",
    "flag_prefix": "ctf_cs",
    "custom_flag_regex": "",
    "attack_preset": "balanced",
    "difficulty": "medium",
    "max_depth": 2,
    "max_artifacts": 800,
    "max_runtime_seconds": 120,
    "enabled_categories": {c: True for c in CATEGORIES},
    "artifact_view": "clean",
    "show_project_counter": True,
}


def _clean_color(value: Any, fallback: str) -> str:
    s = str(value or "").strip()
    return s if re.fullmatch(r"#[0-9A-Fa-f]{6}", s) else fallback


def _clean_key(value: Any, fallback: str, allowed: set[str] | None = None) -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "").strip()).strip("_").lower()
    if allowed and s not in allowed:
        return fallback
    return s or fallback


def _clean_prefix(value: Any) -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "", str(value or "").strip())[:32]
    return s or "ctf_cs"


def _clean_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except Exception:
        return default


def _clean_regex(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if len(s) > 500:
        s = s[:500]
    try:
        re.compile(s)
    except Exception:
        return ""
    return s


def normalize_settings(data: dict[str, Any] | None) -> dict[str, Any]:
    src = dict(data or {})
    prefs = json.loads(json.dumps(DEFAULTS))
    prefs.update(src)

    # Backward compatibility with old UI field: flag_prefix=ctf_cm should select the ctf_cm preset.
    if "flag_format" not in src and src.get("flag_prefix"):
        p = _clean_prefix(src.get("flag_prefix"))
        prefs["flag_format"] = p if p in FORMAT_PRESETS else "any_prefix"
        prefs["flag_prefix"] = p

    prefs["profile_name"] = str(prefs.get("profile_name") or "Operator")[:80]
    prefs["theme"] = prefs.get("theme") if prefs.get("theme") in {"dark", "light", "system"} else "dark"
    prefs["accent_color"] = _clean_color(prefs.get("accent_color"), "#35d07f")
    prefs["tool_color"] = _clean_color(prefs.get("tool_color"), prefs["accent_color"])
    prefs["flag_format"] = _clean_key(prefs.get("flag_format"), "ctf_cs", set(FORMAT_PRESETS))
    prefs["flag_prefix"] = _clean_prefix(prefs.get("flag_prefix") or prefs.get("flag_format") or "ctf_cs")
    if prefs["flag_format"] in {"ctf_cs", "ctf_cm", "flag", "htb", "picoctf"}:
        prefs["flag_prefix"] = {"picoctf": "picoCTF", "htb": "HTB"}.get(prefs["flag_format"], prefs["flag_format"])
    prefs["custom_flag_regex"] = _clean_regex(prefs.get("custom_flag_regex"))
    prefs["attack_preset"] = _clean_key(prefs.get("attack_preset"), "balanced", set(ATTACK_PRESETS))
    prefs["difficulty"] = _clean_key(prefs.get("difficulty"), "medium", set(DIFFICULTIES))

    preset = ATTACK_PRESETS[prefs["attack_preset"]]
    prefs["max_depth"] = _clean_int(prefs.get("max_depth", preset["max_depth"]), preset["max_depth"], 0, 10)
    prefs["max_artifacts"] = _clean_int(prefs.get("max_artifacts", preset["max_artifacts"]), preset["max_artifacts"], 50, 15000)
    prefs["max_runtime_seconds"] = _clean_int(prefs.get("max_runtime_seconds", preset["max_runtime_seconds"]), preset["max_runtime_seconds"], 5, 3600)
    prefs["artifact_view"] = prefs.get("artifact_view") if prefs.get("artifact_view") in {"clean", "detailed", "debug"} else "clean"
    prefs["show_project_counter"] = bool(prefs.get("show_project_counter", True))
    cats = prefs.get("enabled_categories") if isinstance(prefs.get("enabled_categories"), dict) else {}
    prefs["enabled_categories"] = {c: bool(cats.get(c, True)) for c in CATEGORIES}
    prefs["flag_label"] = flag_label(prefs)
    prefs["flag_regex"] = flag_regex(prefs)
    prefs["v111_profile"] = True
    return prefs


def flag_label(prefs: dict[str, Any]) -> str:
    fmt = prefs.get("flag_format", "ctf_cs")
    if fmt == "custom_regex" and prefs.get("custom_flag_regex"):
        return "custom regex"
    if fmt == "any_prefix":
        return "anyPrefix{...}"
    if fmt == "braces_only":
        return "{...}"
    return FORMAT_PRESETS.get(fmt, FORMAT_PRESETS["ctf_cs"])["label"]


def flag_regex(prefs: dict[str, Any]) -> str:
    fmt = prefs.get("flag_format", "ctf_cs")
    if fmt == "custom_regex" and prefs.get("custom_flag_regex"):
        return str(prefs["custom_flag_regex"])
    if fmt in FORMAT_PRESETS:
        return FORMAT_PRESETS[fmt]["regex"]
    prefix = re.escape(str(prefs.get("flag_prefix") or "ctf_cs"))
    return rf"(?is)\b{prefix}\{{[^{{}}\r\n]{{1,220}}\}}"


def compile_flag_patterns(prefs: dict[str, Any]) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    primary = flag_regex(prefs)
    for rx in [primary, FORMAT_PRESETS["any_prefix"]["regex"], FORMAT_PRESETS["braces_only"]["regex"]]:
        try:
            pat = re.compile(rx)
            if all(getattr(p, "pattern", "") != pat.pattern for p in patterns):
                patterns.append(pat)
        except Exception:
            pass
    return patterns


def classify_flag(flag: str, prefs: dict[str, Any]) -> str:
    s = str(flag or "")
    if not s:
        return "none"
    try:
        if re.search(flag_regex(prefs), s):
            return "preferred"
    except Exception:
        pass
    if re.search(FORMAT_PRESETS["any_prefix"]["regex"], s):
        return "alternate_prefix"
    if re.search(FORMAT_PRESETS["braces_only"]["regex"], s):
        return "braces_only"
    return "fragment"


def preferred_flag(value: str, prefs: dict[str, Any]) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    fmt = prefs.get("flag_format", "ctf_cs")
    if fmt in {"any_prefix", "custom_regex"}:
        return s
    if fmt == "braces_only":
        if s.startswith("{") and s.endswith("}"):
            return s
        m = re.match(r"(?is)^[A-Za-z0-9_]{1,32}\{(.+)\}$", s)
        body = m.group(1) if m else s.strip("{}")
        return "{" + body.strip() + "}"
    prefix = str(prefs.get("flag_prefix") or fmt)
    m = re.match(r"(?is)^[A-Za-z0-9_]{1,32}\{(.+)\}$", s)
    if m:
        return f"{prefix}" + "{" + m.group(1).strip() + "}"
    if s.startswith("{") and s.endswith("}"):
        return f"{prefix}" + "{" + s[1:-1].strip() + "}"
    return f"{prefix}" + "{" + s + "}"


def shape_summary(summary: dict[str, Any], prefs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(summary, dict):
        summary = {}
    flags = []
    related = []
    seen = set()
    for item in summary.get("flags", []) or []:
        row = dict(item) if isinstance(item, dict) else {"flag": str(item)}
        f = str(row.get("flag") or row.get("value") or "")
        if not f:
            continue
        row["flag_class"] = classify_flag(f, prefs)
        row["preferred_flag"] = preferred_flag(f, prefs)
        row.setdefault("score", 0)
        key = (row.get("preferred_flag") or f).lower()
        if key in seen:
            continue
        seen.add(key)
        if row["flag_class"] == "preferred":
            flags.append(row)
        else:
            related.append(row)
    if not flags:
        flags = related[:120]
        related = related[120:]
    def rank(row: dict[str, Any]) -> tuple[int, int, int]:
        cls = row.get("flag_class")
        pri = {"preferred": 5, "alternate_prefix": 3, "braces_only": 2, "fragment": 1}.get(cls, 0)
        return (pri, int(row.get("score", 0) or 0), len(str(row.get("flag", ""))))
    flags.sort(key=rank, reverse=True)
    related.sort(key=rank, reverse=True)
    summary["flags"] = flags[:120]
    summary["related_candidate_flags"] = related[:200]
    summary["preferred_flags"] = flags[:120]
    summary["preferred_flag_format"] = prefs.get("flag_label") or flag_label(prefs)
    summary["user_preferences"] = {k: prefs[k] for k in ["profile_name", "theme", "accent_color", "tool_color", "flag_format", "flag_prefix", "custom_flag_regex", "attack_preset", "difficulty", "max_depth", "max_artifacts", "max_runtime_seconds", "artifact_view", "show_project_counter"] if k in prefs}
    summary["attack_controls"] = {"preset": prefs["attack_preset"], "difficulty": prefs["difficulty"], "max_depth": prefs["max_depth"], "max_artifacts": prefs["max_artifacts"], "max_runtime_seconds": prefs["max_runtime_seconds"], "enabled_categories": prefs["enabled_categories"]}
    # Clean artifacts: keep highest score, stable metadata, no huge blobs.
    clean_arts = []
    for a in (summary.get("artifacts", []) or [])[: int(prefs.get("max_artifacts", 800))]:
        if not isinstance(a, dict):
            continue
        clean_arts.append({k: a.get(k) for k in ["name", "kind", "source", "file", "path", "url", "score", "size", "note", "exists"] if k in a})
    clean_arts.sort(key=lambda a: (int(a.get("score", 0) or 0), int(a.get("size", 0) or 0)), reverse=True)
    summary["artifacts"] = clean_arts[: int(prefs.get("max_artifacts", 800))]
    summary["v111_control_plane"] = {"enabled": True, "flag_label": prefs.get("flag_label"), "attack_preset": prefs.get("attack_preset"), "difficulty": prefs.get("difficulty")}
    return summary


def install(mod) -> None:
    pref_path = Path(getattr(mod, "BASE", Path("."))) / "data" / "user_preferences.json"

    def read_settings() -> dict[str, Any]:
        try:
            data = json.loads(pref_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        return normalize_settings(data if isinstance(data, dict) else {})

    def write_settings(payload: dict[str, Any]) -> dict[str, Any]:
        old = read_settings()
        if isinstance(payload, dict):
            old.update(payload)
        prefs = normalize_settings(old)
        pref_path.parent.mkdir(parents=True, exist_ok=True)
        pref_path.write_text(json.dumps(prefs, ensure_ascii=False, indent=2), encoding="utf-8")
        return prefs

    mod.sl111_read_settings = read_settings
    mod.sl111_write_settings = write_settings
    mod.sl111_compile_flag_patterns = compile_flag_patterns
    mod.sl111_preferred_flag = preferred_flag
    mod.sl111_shape_summary = shape_summary
    mod.sl111_normalize_settings = normalize_settings

    def unique_upload_name(raw_name: str, used: set[str]) -> str:
        """Return a safe, collision-free upload name for this project."""
        name = mod.safe(raw_name or "file")
        if name.lower() in {"generated", "artifacts", "cache", "project.json", "report.json"}:
            name = "uploaded_" + name
        stem = Path(name).stem or "file"
        suffix = Path(name).suffix
        candidate = name
        counter = 2
        while candidate.lower() in used:
            candidate = f"{stem}__{counter}{suffix}"
            counter += 1
        used.add(candidate.lower())
        return candidate

    mod.sl111_unique_upload_name = unique_upload_name

    @mod.app.get("/api/preferences")
    def get_preferences():
        prefs = read_settings()
        try:
            projects = [p for p in mod.PROJECTS.iterdir() if p.is_dir()]
        except Exception:
            projects = []
        return {"preferences": prefs, "project_counter": {"total": len(projects)}, "defaults": DEFAULTS, "formats": FORMAT_PRESETS, "attack_presets": ATTACK_PRESETS, "difficulties": DIFFICULTIES, "categories": CATEGORIES}

    @mod.app.post("/api/preferences")
    def save_preferences(payload: dict = Body(...)):
        prefs = write_settings(payload if isinstance(payload, dict) else {})
        return {"ok": True, "preferences": prefs, "formats": FORMAT_PRESETS, "attack_presets": ATTACK_PRESETS, "difficulties": DIFFICULTIES, "categories": CATEGORIES}

    # Earlier bootstrap layers also define /api/preferences.  Rebind these routes
    # after installing v111 so the full control-plane schema is the active one.
    try:
        if hasattr(mod, "sl103_rebind_route"):
            mod.sl103_rebind_route("/api/preferences", ["GET"], get_preferences)
            mod.sl103_rebind_route("/api/preferences", ["POST"], save_preferences)
    except Exception:
        pass

    @mod.app.get("/api/attack_profiles")
    def attack_profiles():
        return {"attack_presets": ATTACK_PRESETS, "difficulties": DIFFICULTIES, "categories": CATEGORIES, "current": read_settings()}

    @mod.app.post("/api/projects/{pid}/settings")
    def update_project_settings(pid: str, payload: dict = Body(...)):
        root = mod.pdir(pid)
        if not root.exists():
            return {"ok": False, "error": "project not found"}
        prefs = normalize_settings(payload if isinstance(payload, dict) else {})
        meta = mod.jread(mod.meta_path(pid), {}) or {"id": pid}
        meta["solver_settings"] = prefs
        meta["updated"] = time.time()
        mod.jwrite(mod.meta_path(pid), meta)
        return {"ok": True, "project": meta, "settings": prefs}

    old_summary = getattr(mod, "project_summary", None)
    if old_summary:
        def project_summary(reports, meta):
            summary = old_summary(reports, meta)
            prefs = read_settings()
            if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
                prefs = normalize_settings({**prefs, **meta.get("solver_settings", {})})
            return shape_summary(summary, prefs)
        mod.project_summary = project_summary

    # Patch create_project once more to store per-project solver settings from the upload form.
    try:
        from fastapi import BackgroundTasks, UploadFile, File
        from typing import List
        import uuid
        MAX_UPLOAD_BYTES = int(getattr(mod, "MAX_UPLOAD_BYTES", 80000000)) if hasattr(mod, "MAX_UPLOAD_BYTES") else int(__import__("os").environ.get("SLOPER_MAX_UPLOAD_BYTES", "80000000"))

        async def create_project(background_tasks: BackgroundTasks, title: str = Form(""), statement: str = Form(""), category: str = Form("auto"), auto_start: str = Form("true"), flag_format: str = Form(""), flag_prefix: str = Form(""), custom_flag_regex: str = Form(""), attack_preset: str = Form(""), difficulty: str = Form(""), max_depth: str = Form(""), max_artifacts: str = Form(""), max_runtime_seconds: str = Form(""), enabled_categories: str = Form(""), files: List[UploadFile] = File(...)):
            base = read_settings()
            payload: dict[str, Any] = {}
            for k, v in {"flag_format": flag_format, "flag_prefix": flag_prefix, "custom_flag_regex": custom_flag_regex, "attack_preset": attack_preset, "difficulty": difficulty, "max_depth": max_depth, "max_artifacts": max_artifacts, "max_runtime_seconds": max_runtime_seconds}.items():
                if str(v or "").strip():
                    payload[k] = v
            if enabled_categories:
                cats = {c.strip(): True for c in enabled_categories.split(",") if c.strip()}
                if cats:
                    payload["enabled_categories"] = {c: c in cats for c in CATEGORIES}
            settings = normalize_settings({**base, **payload})

            pid = uuid.uuid4().hex[:12]
            root = mod.pdir(pid)
            fdir = root / "files"
            fdir.mkdir(parents=True, exist_ok=True)
            clean: list[str] = []
            used_names: set[str] = set()
            for f in files:
                name = unique_upload_name(getattr(f, "filename", "file") or "file", used_names)
                content = await f.read()
                if len(content) > MAX_UPLOAD_BYTES:
                    return {"ok": False, "error": f"upload too large: {name}; limit={MAX_UPLOAD_BYTES} bytes"}
                (fdir / name).write_bytes(content)
                clean.append(name)
            auto_title = (title or "").strip() or (clean[0] if clean else "Untitled challenge")
            meta = {"id": pid, "title": auto_title, "statement": statement, "category": category, "created": mod.now(), "file_count": len(clean), "files": clean, "workspace_model": "v111: uploaded files in files/, generated artifacts separated", "solver_settings": settings}
            mod.jwrite(mod.meta_path(pid), meta)
            with mod.LOCK:
                mod.JOBS[pid] = {"status": "created", "progress": 0, "stage": "Created", "updated": time.time(), "color": "gray", "settings": {"attack_preset": settings["attack_preset"], "difficulty": settings["difficulty"]}}
            mod.log(pid, f"Project created: {auto_title} / {settings['flag_label']} / {settings['attack_preset']} / {settings['difficulty']}")
            if str(auto_start).lower() == "true":
                with mod.LOCK:
                    mod.JOBS[pid].update({"status": "running", "color": "yellow", "stage": "Queued", "updated": time.time()})
                background_tasks.add_task(mod.analyze_project, pid)
            return {"id": pid, "project": meta, "settings": settings, "ok": True}

        if hasattr(mod, "sl103_rebind_route"):
            mod.sl103_rebind_route("/api/projects", ["POST"], create_project)
    except Exception as e:
        try:
            print("warning: v111 create_project patch failed", e)
        except Exception:
            pass

    mod.SL111_VERSION = "v111-operator-control-plane"
