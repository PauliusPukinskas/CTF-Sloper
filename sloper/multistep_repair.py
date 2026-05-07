"""Focused backend agents for common multistep local CTF regressions."""
from __future__ import annotations

import base64
import gzip
import re
import sqlite3
import time
from pathlib import Path
from typing import Any


STRICT_RE = re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}")
ZERO_WIDTH = {"\u200b": "0", "\u200c": "1", "\u200d": "1", "\ufeff": "0"}


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "artifact"


def _root_from_path(path: Path) -> Path:
    try:
        return path.parent.parent if path.parent.name == "files" else path.parent
    except Exception:
        return path.parent


def _artifact(root: Path, report_or_summary: dict, name: str, data: bytes | str, method: str, note: str, source_file: str = "") -> dict:
    outdir = root / "artifacts" / "multistep_repair"
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / _safe_name(name)
    if isinstance(data, bytes):
        path.write_bytes(data[:2_000_000])
        preview = data[:800].decode("utf-8", errors="replace")
    else:
        path.write_text(data[:2_000_000], encoding="utf-8", errors="replace")
        preview = data[:800]
    art = {
        "name": path.name,
        "kind": "multistep_transform",
        "family": "crypto_decode",
        "method": method,
        "source": "multistep_repair",
        "source_file": source_file,
        "file": source_file,
        "path": str(path),
        "url": "/api/raw?path=" + str(path),
        "score": 3100,
        "note": note,
        "exists": True,
        "size": path.stat().st_size,
        "preview": preview,
    }
    report_or_summary.setdefault("artifacts", []).append(art)
    return art


def _add_report_flag(report: dict, flag: str, art: dict, method: str, why: str) -> None:
    report.setdefault("flags", []).append(flag)
    row = {
        "flag": flag,
        "preferred_flag": flag,
        "score": 4200,
        "status": "confirmed",
        "source": f"multistep_repair:{method}",
        "artifact": art.get("path"),
        "file": art.get("source_file"),
        "method": method,
        "why": why,
    }
    report.setdefault("verified_flags", []).append(row)
    report.setdefault("workflow_evidence", []).append(row)


def _add_summary_flag(summary: dict, flag: str, art: dict, method: str, why: str) -> None:
    summary.setdefault("flags", []).append({
        "flag": flag,
        "preferred_flag": flag,
        "score": 4300,
        "status": "confirmed",
        "source": f"multistep_repair:{method}",
        "artifact": art.get("path"),
        "file": art.get("source_file"),
        "method": method,
        "why": why,
    })


def _scan(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in STRICT_RE.finditer(text or ""):
        flag = m.group(0)
        if flag.lower() not in seen:
            seen.add(flag.lower())
            out.append(flag)
    return out


def _b64_decode(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text or "")
    if not (8 <= len(compact) <= 500_000):
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    for alt in (None, b"-_"):
        try:
            padded = compact + "=" * ((4 - len(compact) % 4) % 4)
            raw = base64.b64decode(padded.encode("ascii"), altchars=alt, validate=False)
            if raw:
                return raw
        except Exception:
            continue
    return None


def _rot47(s: str) -> str:
    return "".join(chr(33 + ((ord(ch) - 33 + 47) % 94)) if 33 <= ord(ch) <= 126 else ch for ch in s)


def _text_chain_agent(report: dict, root: Path, path: Path, data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    source = str(report.get("rel") or report.get("name") or path.name)
    decoded = _b64_decode(text)
    if decoded:
        variants = [
            ("base64", decoded.decode("utf-8", errors="replace")),
            ("base64_rot47", _rot47(decoded.decode("utf-8", errors="replace"))),
        ]
        try:
            variants.append(("base64_gzip", gzip.decompress(decoded).decode("utf-8", errors="replace")))
        except Exception:
            pass
        for method, out in variants:
            flags = _scan(out)
            if flags:
                art = _artifact(root, report, f"{path.stem}_{method}.txt", out, method, "Deterministic text chain transform.", source)
                for flag in flags:
                    _add_report_flag(report, flag, art, method, "Decoded payload produced a strict flag.")

    zw_bits = "".join(ZERO_WIDTH[ch] for ch in text if ch in ZERO_WIDTH)
    if len(zw_bits) >= 32:
        raw = bytes(int(zw_bits[i:i + 8], 2) for i in range(0, len(zw_bits) - 7, 8))
        zw_text = raw.decode("utf-8", errors="replace")
        variants = [("zero_width_bits", zw_text)]
        b64 = _b64_decode(zw_text)
        if b64:
            variants.append(("zero_width_bits_base64", b64.decode("utf-8", errors="replace")))
        for method, out in variants:
            flags = _scan(out)
            if flags:
                art = _artifact(root, report, f"{path.stem}_{method}.txt", out, method, "Zero-width character bit channel decoded.", source)
                for flag in flags:
                    _add_report_flag(report, flag, art, method, "Zero-width channel decoded into a strict flag.")


def _png_alpha_agent(report: dict, root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"\x89PNG"):
        return
    try:
        from PIL import Image  # lazy optional dependency
    except Exception:
        return
    try:
        im = Image.open(path).convert("RGBA")
        alpha = bytes(px[3] for px in im.getdata())
        alpha = alpha.split(b"\x00", 1)[0] if b"\x00" in alpha else alpha
        text = alpha.decode("utf-8", errors="replace")
    except Exception:
        return
    flags = _scan(text)
    if flags:
        source = str(report.get("rel") or report.get("name") or path.name)
        art = _artifact(root, report, f"{path.stem}_alpha_bytes.txt", text, "png_alpha_bytes", "PNG alpha byte stream decoded as ASCII.", source)
        for flag in flags:
            _add_report_flag(report, flag, art, "png_alpha_bytes", "Alpha channel byte values produced a strict flag.")


def _sqlite_agent(report: dict, root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"SQLite format 3"):
        return
    source = str(report.get("rel") or report.get("name") or path.name)
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        rows: list[str] = []
        for (table,) in con.execute("select name from sqlite_master where type='table'"):
            try:
                for row in con.execute(f"select * from \"{table}\" limit 1000"):
                    rows.extend(str(x) for x in row if x is not None)
            except Exception:
                continue
        con.close()
    except Exception:
        return
    for idx, value in enumerate(rows[:200]):
        variants = [("sqlite_text", value), ("sqlite_text_reverse", value[::-1])]
        for label, candidate in list(variants):
            raw = _b64_decode(candidate)
            if raw:
                variants.append((label + "_base64", raw.decode("utf-8", errors="replace")))
        for method, out in variants:
            flags = _scan(out)
            if flags:
                art = _artifact(root, report, f"{path.stem}_{method}_{idx}.txt", out, method, "SQLite text cell transform.", source)
                for flag in flags:
                    _add_report_flag(report, flag, art, method, "SQLite table text decoded into a strict flag.")


def analyze_file_agent(report: dict, root: Path, path: Path, data: bytes) -> None:
    if len(data) > 20_000_000:
        return
    _text_chain_agent(report, root, path, data[:5_000_000])
    _png_alpha_agent(report, root, path, data)
    _sqlite_agent(report, root, path, data)


def _report_path(report: dict) -> Path | None:
    for key in ("path", "source_path", "file_path"):
        val = report.get(key)
        if val and Path(str(val)).exists():
            return Path(str(val))
    name = report.get("name")
    return Path(str(name)) if name and Path(str(name)).exists() else None


def _project_xor(summary: dict, reports: list[dict]) -> None:
    paths = [p for p in (_report_path(r) for r in reports if isinstance(r, dict)) if p and p.is_file()]
    paths = [p for p in paths if p.name.lower() not in {"readme.md", "readme.txt", "statement.txt", "flag.txt"} and p.stat().st_size <= 2_000_000]
    if len(paths) < 2:
        return
    root = _root_from_path(paths[0])
    for i, a in enumerate(paths):
        da = a.read_bytes()
        for b in paths[i + 1:]:
            db = b.read_bytes()
            n = min(len(da), len(db))
            if n < 4:
                continue
            x = bytes(da[j] ^ db[j] for j in range(n))
            text = x.decode("utf-8", errors="replace")
            flags = _scan(text)
            if flags:
                art = _artifact(root, summary, f"xor_{a.stem}_{b.stem}.bin", x, "project_file_xor", f"XOR of {a.name} and {b.name}.", f"{a.name}+{b.name}")
                for flag in flags:
                    _add_summary_flag(summary, flag, art, "project_file_xor", "Pairwise XOR of project files produced a strict flag.")


def apply(mod: Any) -> None:
    old_analyze = getattr(mod, "analyze_file", None)
    old_summary = getattr(mod, "project_summary", None)

    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"path": str(path), "name": Path(path).name, "flags": [], "artifacts": []}
        if isinstance(report, dict):
            try:
                analyze_file_agent(report, Path(root), Path(path), Path(path).read_bytes())
            except Exception as exc:
                try:
                    from sloper_v72.health import agent_crash
                    agent_crash("multistep_repair.analyze_file", exc, report)
                except Exception:
                    pass
        return report

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        if isinstance(summary, dict):
            try:
                _project_xor(summary, [r for r in reports if isinstance(r, dict)])
            except Exception as exc:
                try:
                    from sloper_v72.health import agent_crash
                    agent_crash("multistep_repair.project_xor", exc, summary)
                except Exception:
                    pass
        return summary

    mod.analyze_file = analyze_file
    mod.project_summary = project_summary
    mod.SLOPER_MULTISTEP_REPAIR = "enabled"
