"""v114 evidence triage and reporting polish.

Runs after v113 evidence and adds a competition operator summary: best flag,
risk buckets, evidence chains, and artifact triage counts.
"""
from __future__ import annotations

import time
from typing import Any

try:
    from .evidence_v113 import annotate_flag_row, annotate_summary
except Exception:  # pragma: no cover
    def annotate_flag_row(row, profile=None): return row if isinstance(row, dict) else {"flag": str(row)}
    def annotate_summary(summary, profile=None): return summary


def _profile(mod, meta: dict[str, Any] | None) -> dict[str, Any]:
    p: dict[str, Any] = {}
    try:
        p = mod.sl111_read_settings() if hasattr(mod, "sl111_read_settings") else {}
    except Exception:
        p = {}
    if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
        p = {**p, **meta["solver_settings"]}
    try:
        if hasattr(mod, "sl111_normalize_settings"):
            p = mod.sl111_normalize_settings(p)
    except Exception:
        pass
    return p


def _flag_quality(row: dict[str, Any]) -> int:
    flag = str(row.get("preferred_flag") or row.get("flag") or "")
    body = flag
    if "{" in flag and flag.endswith("}"):
        body = flag.split("{", 1)[1][:-1]
    printable = sum(1 for c in body if c.isalnum() or c in "_-:+./=")
    ratio = printable / max(1, len(body))
    q = int(ratio * 40)
    if 6 <= len(body) <= 96:
        q += 10
    if "_" in body or "-" in body:
        q += 8
    if any(c.isalpha() for c in body):
        q += 4
    if any(c.isdigit() for c in body):
        q += 2
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        q -= 80
    if ratio < 0.75:
        q -= 35
    return q


def _sort_key(row: dict[str, Any]) -> tuple[int, int, int, int]:
    conf = int(row.get("confidence", 0) or 0)
    risk = int(row.get("risk", 0) or 0)
    score = int(row.get("score", row.get("rank_score", 0)) or 0)
    chain = row.get("chain", []) or []
    chain_len = len(chain)
    source = str(row.get("source") or row.get("chain_text") or "")
    direct_bonus = 35 if source in {"input", "raw"} or source.startswith("input->html") or source.startswith("input->url") else 0
    # XOR/quoted-printable noise often generates brace-shaped garbage; require stronger quality.
    noisy_penalty = 25 if ("xor_" in source or "quoted_printable" in source) and _flag_quality(row) < 45 else 0
    return (conf - risk // 3 + _flag_quality(row) + direct_bonus - noisy_penalty, score, -chain_len, -len(str(row.get("flag", ""))))


def enrich_summary(summary: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        summary = {}
    rows: list[dict[str, Any]] = []
    seen = set()
    for pool_name in ("flags", "preferred_flags", "related_candidate_flags", "exact_flags"):
        for item in summary.get(pool_name, []) or []:
            row = annotate_flag_row(item, profile)
            if not isinstance(row, dict):
                continue
            flag_text = str(row.get("preferred_flag") or row.get("flag") or "")
            body = flag_text.split("{", 1)[1][:-1] if "{" in flag_text and flag_text.endswith("}") else flag_text
            if _flag_quality(row) < 0 or any((not (c.isalnum() or c in "_-:+./=")) for c in body):
                row["risk"] = max(int(row.get("risk", 0) or 0), 80)
                row["verdict"] = "low"
                row.setdefault("warnings", []).append("low or noisy flag-body quality")
            if 0 < len(body) < 6:
                row["risk"] = max(int(row.get("risk", 0) or 0), 70)
                row["verdict"] = "low"
                row.setdefault("warnings", []).append("very short brace body")
            key = str(row.get("preferred_flag") or row.get("flag") or "").lower()
            if not key or key in seen:
                continue
            seen.add(key)
            rows.append(row)
    rows.sort(key=_sort_key, reverse=True)
    high = [r for r in rows if r.get("verdict") == "high" and int(r.get("risk", 0) or 0) < 50]
    medium = [r for r in rows if r.get("verdict") == "medium" and int(r.get("risk", 0) or 0) < 65]
    low = [r for r in rows if r not in high and r not in medium]
    promoted = (high + medium) or rows[:20]
    summary["flags"] = promoted[:150]
    summary["preferred_flags"] = summary["flags"]
    summary["related_candidate_flags"] = low[:300]
    artifacts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
    artifact_kinds: dict[str, int] = {}
    for a in artifacts:
        k = str(a.get("kind") or "artifact")
        artifact_kinds[k] = artifact_kinds.get(k, 0) + 1
    best = summary["flags"][0] if summary.get("flags") else None
    summary["v114_triage"] = {
        "enabled": True,
        "version": "v114-evidence-triage",
        "updated": int(time.time()),
        "best_flag": (best.get("preferred_flag") or best.get("flag")) if isinstance(best, dict) else None,
        "best_confidence": int(best.get("confidence", 0) or 0) if isinstance(best, dict) else 0,
        "high_confidence": len(high),
        "medium_confidence": len(medium),
        "low_or_related": len(low),
        "artifact_kinds": artifact_kinds,
        "operator_hint": "Trust high confidence only when chain/source makes sense; inspect related candidates for hard red-herring challenges.",
    }
    # Keep v113 marker for old UI, but make it obvious v114 is active.
    summary.setdefault("v113_evidence", {})
    if isinstance(summary["v113_evidence"], dict):
        summary["v113_evidence"]["v114_layer"] = True
        summary["v113_evidence"]["version"] = "v114-evidence-triage"
    return summary


def apply(mod) -> None:
    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        if not isinstance(summary, dict):
            summary = {"flags": [], "artifacts": []}
        # v113 may trim raw report candidates before v114 sees them. Pull the
        # complete per-file candidate pools back in so direct/plain flags and
        # lower-scored decoded evidence cannot be buried by XOR garbage.
        extra = []
        for r in list(reports or [])[:500]:
            if not isinstance(r, dict):
                continue
            rel = r.get("rel") or r.get("name") or "?"
            for pool in (r.get("verified_flags", []), r.get("findings", []), r.get("chain_results", [])):
                for item in pool or []:
                    if isinstance(item, dict):
                        row = dict(item)
                        row.setdefault("file", rel)
                        extra.append(row)
            for f in r.get("flags", []) or []:
                extra.append({"flag": str(f), "file": rel, "source": "report_flags", "score": 900})
        if extra:
            summary.setdefault("flags", [])
            summary["flags"] = list(summary.get("flags", []) or []) + extra
        return enrich_summary(summary, _profile(mod, meta if isinstance(meta, dict) else {}))

    mod.project_summary = project_summary
    mod.sl114_enrich_summary = enrich_summary
    try:
        @mod.app.get("/api/v114_evidence_health")
        def v114_evidence_health():
            return {"ok": True, "version": "v114-evidence-triage"}
    except Exception:
        pass
