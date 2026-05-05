"""v115 evidence summary polish.

Adds live-competition buckets on top of v114: trusted/promising/manual queues,
source coverage, and a concise operator verdict.  It does not invent flags; it
only reorders and annotates existing evidence rows.
"""
from __future__ import annotations

import time
from typing import Any

try:
    from .evidence_v114 import enrich_summary as enrich_v114
except Exception:  # pragma: no cover
    def enrich_v114(summary, profile=None): return summary if isinstance(summary, dict) else {}


def _flag_text(row: dict[str, Any]) -> str:
    return str(row.get("preferred_flag") or row.get("flag") or row.get("value") or "")


def _source(row: dict[str, Any]) -> str:
    return str(row.get("source") or row.get("chain_text") or "")


def _score(row: dict[str, Any]) -> int:
    conf = int(row.get("confidence", 0) or 0)
    risk = int(row.get("risk", 0) or 0)
    score = int(row.get("score", row.get("rank_score", 0)) or 0)
    src = _source(row).lower()
    flag = _flag_text(row)
    lowflag = flag.lower()
    bonus = 0
    for k in ("v115", "pdf_", "zip_dynamic", "image_lsb", "pcap_", "jpeg_", "gif_", "data_uri"):
        if k in src:
            bonus += 12
    # Strongly prefer normal CTF prefix flags over random brace-shaped XOR noise.
    if "{" in flag and not flag.startswith("{"):
        bonus += 180
    if lowflag.startswith(("ctf_cs{", "ctf_cm{", "flag{", "picoctf{", "htb{")):
        bonus += 260
    if flag.startswith("{"):
        bonus -= 140
    if src in {"input", "raw", "report_flags"} or src.startswith("input->html") or src.startswith("input->url"):
        bonus += 260
    if "xor_" in src:
        bonus -= 220
    if "quoted_printable" in src:
        bonus -= 80
    if "->rot" in src or "->reverse" in src:
        bonus -= 40
    body = flag.split("{", 1)[1][:-1] if "{" in flag and flag.endswith("}") else flag
    if "_" in body and len(body) >= 10:
        bonus += 70
    if sum(1 for c in body if c.islower()) >= 5:
        bonus += 25
    if any(ord(c) < 32 or ord(c) > 126 for c in body):
        bonus -= 240
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:+./=" for c in body):
        bonus -= 110
    if "example" in lowflag or "fake" in lowflag or "dummy" in lowflag:
        bonus -= 260
    return conf * 4 - risk * 2 + score // 25 + bonus


def enrich_summary(summary: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = enrich_v114(summary if isinstance(summary, dict) else {}, profile)
    rows = [r for r in summary.get("flags", []) or [] if isinstance(r, dict)]
    related = [r for r in summary.get("related_candidate_flags", []) or [] if isinstance(r, dict)]
    combined = []
    seen = set()
    for r in rows + related:
        ft = _flag_text(r).lower()
        if not ft or ft in seen:
            continue
        seen.add(ft); combined.append(r)
    combined.sort(key=_score, reverse=True)
    trusted = [r for r in combined if int(r.get("confidence", 0) or 0) >= 78 and int(r.get("risk", 0) or 0) <= 42]
    promising = [r for r in combined if r not in trusted and int(r.get("confidence", 0) or 0) >= 50 and int(r.get("risk", 0) or 0) <= 65]
    manual = [r for r in combined if r not in trusted and r not in promising]
    if trusted or promising:
        summary["flags"] = (trusted + promising)[:180]
        summary["preferred_flags"] = summary["flags"]
        summary["related_candidate_flags"] = manual[:350]
    sources: dict[str, int] = {}
    for r in combined:
        src = _source(r).split("->", 1)[0] or "unknown"
        sources[src] = sources.get(src, 0) + 1
    arts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
    priority_arts = []
    for a in arts:
        blob = " ".join(str(a.get(k, "")) for k in ("name", "kind", "source", "note")).lower()
        if any(k in blob for k in ("v115", "v114", "manifest", "operator_playbook", "image_lsb", "pdf", "pcap", "zip_dynamic")):
            priority_arts.append(a)
    best = (trusted or promising or combined[:1] or [None])[0]
    summary["v115_triage"] = {
        "enabled": True,
        "version": "v115-live-competition-triage",
        "updated": int(time.time()),
        "best_flag": _flag_text(best) if isinstance(best, dict) else None,
        "best_source": _source(best) if isinstance(best, dict) else None,
        "best_score": _score(best) if isinstance(best, dict) else 0,
        "trusted": len(trusted),
        "promising": len(promising),
        "manual_review": len(manual),
        "source_coverage": sources,
        "priority_artifacts": len(priority_arts),
        "operator_hint": "Submit only trusted/promising flags after checking chain/source; inspect v115 operator playbooks and manifests when no trusted flag appears.",
    }
    summary["priority_artifacts"] = priority_arts[:120] or summary.get("priority_artifacts", [])
    summary.setdefault("v114_triage", {})
    if isinstance(summary["v114_triage"], dict):
        summary["v114_triage"]["v115_layer"] = True
    return summary


def apply(mod) -> None:
    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        profile = meta.get("solver_settings", {}) if isinstance(meta, dict) else None
        return enrich_summary(summary if isinstance(summary, dict) else {}, profile)
    mod.project_summary = project_summary
    mod.sl115_enrich_summary = enrich_summary
    try:
        @mod.app.get("/api/v115_evidence_health")
        def v115_evidence_health():
            return {"ok": True, "version": "v115-live-competition-triage"}
    except Exception:
        pass
