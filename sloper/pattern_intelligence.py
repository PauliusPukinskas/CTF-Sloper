"""Pattern-corpus workflow retrieval for local CTF artifacts.

The 3000-row AI pattern pack is a blueprint corpus, not a flag database.  This
module turns it into useful backend artifacts: for each analyzed file Sloper
records the likely CTF workflow families, the next actions, and verifier checks
that should prove or reject the path.
"""
from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any


MAX_PATTERNS = 3000
MAX_RAW = 2_000_000


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def load_patterns() -> tuple[dict[str, Any], ...]:
    path = _repo_root() / "data" / "ai_ctf_multistep_patterns.jsonl"
    if not path.exists():
        return ()
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(out) >= MAX_PATTERNS:
                break
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                triggers = list(obj.get("trigger_signals") or [])[:32]
                out.append({
                    "id": obj.get("id"),
                    "category": obj.get("category"),
                    "family": obj.get("family"),
                    "variant": obj.get("variant"),
                    "difficulty": obj.get("difficulty"),
                    "flag_profile": obj.get("flag_profile"),
                    "flag_context": obj.get("flag_context"),
                    "trigger_signals": triggers,
                    "_trigger_lc": tuple(str(x).lower() for x in triggers),
                    "workflow": list(obj.get("workflow") or [])[:18],
                    "recommended_tools": list(obj.get("recommended_tools") or [])[:16],
                    "sloper_actions": list(obj.get("sloper_actions") or [])[:16],
                    "verifiers": list(obj.get("verifiers") or [])[:14],
                    "false_positive_controls": list(obj.get("false_positive_controls") or [])[:10],
                    "artifact_outputs": list(obj.get("artifact_outputs") or [])[:12],
                    "ai_instruction": obj.get("ai_instruction"),
                })
    return tuple(out)


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "pattern"))[:140] or "pattern"


def _strings(raw: bytes) -> str:
    chunks = re.findall(rb"[\x09\x0a\x0d\x20-\x7e]{4,}", raw[:MAX_RAW])
    return "\n".join(x.decode("utf-8", errors="replace") for x in chunks)[:400_000]


def _signals(path: Path, raw: bytes, text: str) -> set[str]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    low = text.lower()
    sig: set[str] = set()
    sig.add("local_sandbox_execution")
    sig.add("case_sensitive_flag")
    if suffix:
        sig.add(suffix.lstrip("."))
    if path.name.lower() in {"readme.md", "readme.txt", "statement.txt", "task.txt"}:
        sig.update({"statement text", "decoy_statement_flag", "flag format text"})
    if raw.startswith(b"\x89PNG"):
        sig.update({"PNG magic", "IHDR/IDAT/IEND chunks", "forensics/image/png", "image"})
        idx = raw.rfind(b"IEND")
        if idx >= 0 and idx + 8 < len(raw):
            sig.add("bytes after IEND")
            sig.add("high entropy tail")
        for chunk in (b"tEXt", b"zTXt", b"iTXt", b"PLTE", b"tRNS"):
            if chunk in raw:
                sig.add("ancillary chunk names")
                sig.add(chunk.decode("ascii", "ignore"))
        if b"PLTE" in raw:
            sig.add("palette image")
        if b"tRNS" in raw or b"RGBA" in raw:
            sig.add("alpha channel")
    if raw.startswith(b"\xff\xd8"):
        sig.update({"JPEG SOI/EOI", "forensics/image/jpeg", "image"})
        if b"Exif" in raw:
            sig.add("EXIF tags")
        if b"\xff\xfe" in raw:
            sig.add("comment marker")
        idx = raw.rfind(b"\xff\xd9")
        if idx >= 0 and idx + 2 < len(raw):
            sig.add("bytes after EOI")
    if raw[:6] in (b"GIF87a", b"GIF89a") or suffix in {".gif", ".webp", ".bmp", ".ppm"}:
        sig.update({"animated frames", "palette entries", "forensics/image/gif_webp_bmp", "image"})
    if raw.startswith(b"RIFF") or suffix in {".wav", ".mp3", ".ogg", ".flac", ".mp4", ".mkv"}:
        sig.update({"WAV/MP3/OGG/MP4/MKV magic", "audio channels", "forensics/audio_video"})
    if raw.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")) or suffix in {".pcap", ".pcapng"}:
        sig.update({"pcap magic", "pcapng blocks", "HTTP streams", "DNS labels", "forensics/network/pcap"})
    if raw.startswith(b"PK\x03\x04") or suffix in {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt"}:
        sig.update({"ZIP local headers", "archives/containers", "nested_archive_child"})
        if suffix in {".docx", ".xlsx", ".pptx", ".odt"}:
            sig.update({"Office XML", "documents/pdf_office"})
    if raw.startswith(b"%PDF") or suffix == ".pdf":
        sig.update({"PDF magic", "documents/pdf_office", "metadata comments"})
    if raw.startswith(b"SQLite format 3"):
        sig.update({"SQLite magic", "database", "static/git_docker_cloud_config"})
    if raw.startswith(b"\x7fELF") or raw.startswith(b"MZ") or suffix in {".exe", ".dll", ".so", ".bin"}:
        sig.update({"ELF/PE magic", "reverse/native_binary", "strings", "imports", "sections"})
    if any(m in raw for m in (b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"PK\x03\x04", b"%PDF", b"\x89PNG", b"\xff\xd8")):
        sig.update({"polyglot_magic_mismatch", "nested_archive_child", "magic bytes"})
    if any(k in low for k in ("base64", "rot13", "caesar", "vigenere", "xor", "rail fence", "morse")) or suffix in {".txt", ".md"}:
        sig.add("crypto/encodings_classical")
    if any(k in low for k in ("password", "key", "raktas", "slaptazodis", "secret")):
        sig.update({"password_from_metadata", "sibling_file_key"})
    if re.search(r"[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}|\{[^{}\r\n]{3,220}\}", text):
        sig.add("exact flag regex")
    if any(k in low for k in ("ctf_cs", "veliava", "vėliava", "rastas", "tekstas")):
        sig.add("lithuanian_flag_terms")
        sig.add("custom Lithuanian CTF prefix")
    if re.search(r"\binput\s*\[\s*\d+\s*\]\s*(?:\^|\+|-|\*)", text):
        sig.update({"constraints", "reverse/native_binary"})
    if re.search(r"\b(?:0x[0-9a-fA-F]{2}|\d{1,3})\s*,\s*(?:0x[0-9a-fA-F]{2}|\d{1,3})", text):
        sig.update({"byte array", "reverse/native_binary"})
    return sig


def _category_bonus(category: str, signals: set[str], suffix: str) -> int:
    cat = str(category or "")
    score = 0
    if cat in signals:
        score += 70
    if cat.startswith("forensics/image") and "image" in signals:
        score += 40
    if cat == "documents/pdf_office" and ("documents/pdf_office" in signals or suffix in {".pdf", ".docx", ".xlsx", ".pptx"}):
        score += 55
    if cat == "archives/containers" and ("archives/containers" in signals or suffix in {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}):
        score += 55
    if cat.startswith("crypto/") and "crypto/encodings_classical" in signals:
        score += 35
    if cat.startswith("reverse/") and "reverse/native_binary" in signals:
        score += 45
    if cat.startswith("forensics/network") and "forensics/network/pcap" in signals:
        score += 70
    if cat.startswith("forensics/audio") and "forensics/audio_video" in signals:
        score += 70
    return score


def score_pattern(pattern: dict[str, Any], signals: set[str], suffix: str = "") -> int:
    triggers = set(pattern.get("_trigger_lc") or tuple(str(x).lower() for x in pattern.get("trigger_signals") or []))
    sig_low = {str(x).lower() for x in signals}
    overlap = len(triggers & sig_low)
    fuzzy = 0
    for t in triggers:
        if any(t in s or s in t for s in sig_low if len(s) >= 4):
            fuzzy += 1
    return _category_bonus(str(pattern.get("category") or ""), signals, suffix) + overlap * 18 + min(fuzzy, 12) * 5


def rank_patterns_for_signals(signals: set[str], suffix: str = "", limit: int = 8) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for pat in load_patterns():
        score = score_pattern(pat, signals, suffix)
        if score <= 0:
            continue
        row = dict(pat)
        row.pop("_trigger_lc", None)
        row["match_score"] = score
        trigger_lc = set(pat.get("_trigger_lc") or ())
        row["matched_signals"] = sorted({x for x in signals if str(x).lower() in trigger_lc})[:16]
        ranked.append(row)
    ranked.sort(key=lambda x: int(x.get("match_score", 0)), reverse=True)
    return ranked[:limit]


def _write_artifacts(root: Path, report: dict[str, Any], path: Path, ranked: list[dict[str, Any]], signals: set[str]) -> None:
    outdir = root / "artifacts" / "pattern_intelligence"
    outdir.mkdir(parents=True, exist_ok=True)
    stem = _safe_name(path.stem or "file")
    payload = {
        "source_file": str(report.get("rel") or report.get("name") or path.name),
        "generated_at": int(time.time()),
        "signals": sorted(signals),
        "top_patterns": ranked,
        "operator_use": "Use these as a workflow queue: run actions, inspect artifacts, then require verifier evidence before promoting a flag.",
    }
    json_path = outdir / f"{stem}_pattern_hypotheses.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8", errors="replace")
    lines = [f"# Pattern hypotheses for {path.name}", "", "Signals: " + ", ".join(sorted(signals)[:40]), ""]
    for i, pat in enumerate(ranked, 1):
        lines.extend([
            f"## {i}. {pat.get('category')} / {pat.get('variant')} (score {pat.get('match_score')})",
            str(pat.get("family") or ""),
            "",
            "Next actions:",
            *[f"- {x}" for x in (pat.get("workflow") or [])[:10]],
            "",
            "Verifier checks:",
            *[f"- {x}" for x in (pat.get("verifiers") or [])[:8]],
            "",
            "False-positive controls:",
            *[f"- {x}" for x in (pat.get("false_positive_controls") or [])[:6]],
            "",
        ])
    md_path = outdir / f"{stem}_workflow_queue.md"
    md_path.write_text("\n".join(lines)[:1_000_000], encoding="utf-8", errors="replace")
    source_file = str(report.get("rel") or report.get("name") or path.name)
    for p, kind, note, score in (
        (json_path, "pattern_hypotheses_json", "Top AI corpus workflow matches and verifier queue.", 1850),
        (md_path, "workflow_queue", "Human-readable next-step workflow queue from the 3000-pattern corpus.", 1900),
    ):
        report.setdefault("artifacts", []).append({
            "name": p.name,
            "kind": kind,
            "family": "workflow",
            "method": "pattern_intelligence",
            "source": "ai_ctf_multistep_patterns_3000",
            "source_file": source_file,
            "file": source_file,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "score": score,
            "note": note,
            "exists": True,
            "size": p.stat().st_size,
            "preview": p.read_text(encoding="utf-8", errors="replace")[:900],
        })


def analyze_file_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    patterns = load_patterns()
    if not patterns:
        return
    text = _strings(data)
    signals = _signals(path, data[:MAX_RAW], text)
    ranked = rank_patterns_for_signals(signals, path.suffix.lower(), limit=8)
    if not ranked:
        return
    report["pattern_intelligence"] = {
        "enabled": True,
        "corpus_records": len(patterns),
        "signals": sorted(signals)[:80],
        "top": [{k: p.get(k) for k in ("id", "category", "variant", "match_score", "family")} for p in ranked[:8]],
    }
    _write_artifacts(root, report, path, ranked, signals)


def apply(mod: Any) -> None:
    old_analyze = getattr(mod, "analyze_file", None)
    old_summary = getattr(mod, "project_summary", None)

    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"path": str(path), "name": Path(path).name, "flags": [], "artifacts": []}
        if isinstance(report, dict):
            try:
                p = Path(path)
                analyze_file_agent(report, Path(root), p, p.read_bytes()[:MAX_RAW])
            except Exception as exc:
                try:
                    from sloper_v72.health import agent_crash
                    agent_crash("pattern_intelligence.analyze_file", exc, report)
                except Exception:
                    pass
        return report

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        if isinstance(summary, dict):
            rows: list[dict[str, Any]] = []
            for report in reports or []:
                if isinstance(report, dict) and isinstance(report.get("pattern_intelligence"), dict):
                    rows.extend(report["pattern_intelligence"].get("top") or [])
            dedup: dict[str, dict[str, Any]] = {}
            for row in rows:
                key = str(row.get("id") or row.get("category") or row)
                if key not in dedup or int(row.get("match_score", 0) or 0) > int(dedup[key].get("match_score", 0) or 0):
                    dedup[key] = dict(row)
            summary["pattern_intelligence"] = {
                "enabled": True,
                "corpus_records": len(load_patterns()),
                "top_project_patterns": sorted(dedup.values(), key=lambda x: int(x.get("match_score", 0) or 0), reverse=True)[:12],
                "operator_hint": "Pattern hypotheses are workflow guidance, not flags; inspect generated workflow_queue artifacts for next actions and verifier checks.",
            }
        return summary

    mod.analyze_file = analyze_file
    mod.project_summary = project_summary
    mod.SLOPER_PATTERN_INTELLIGENCE = "ai-pattern-corpus-3000"
