"""v113 competition evidence model.

This layer makes Sloper more useful during live CTFs by turning raw candidate
strings into ranked evidence objects.  It does not guess flags; it explains why a
candidate was promoted or demoted and keeps the transform chain visible.
"""
from __future__ import annotations

import re
import time
from typing import Any

DECOY_RE = re.compile(
    r"fake|dummy|placeholder|example|sample|test[_-]?flag|not[_-]?(?:the[_-]?)?flag|"
    r"wrong|ignore|lorem|todo|changeme",
    re.I,
)
SEMANTIC_RE = re.compile(
    r"slapt|rakt|v[eė]liav|atsak|answer|final|real|secret|key|token|winner|solve|cyber|sprint|nksc|ctf",
    re.I,
)
STRICT_WRAPPER_RE = re.compile(r"(?is)^([A-Za-z0-9_]{1,32})\{([^{}\r\n]{1,220})\}$")
BARE_RE = re.compile(r"(?is)^\{([^{}\r\n]{1,220})\}$")
CHAIN_SIGNAL = (
    "base64", "base32", "base85", "ascii85", "hex", "url", "percent", "html", "gzip", "zlib", "bz2", "xz",
    "zip", "tar", "xor", "rot", "morse", "binary", "decimal", "lsb", "stego", "whitespace", "case", "office",
)


def _profile_prefix(profile: dict[str, Any] | None) -> str:
    if not isinstance(profile, dict):
        return "ctf_cs"
    fmt = str(profile.get("flag_format") or "ctf_cs")
    if fmt in {"ctf_cs", "ctf_cm", "flag"}:
        return fmt
    if fmt == "picoctf":
        return "picoCTF"
    if fmt == "htb":
        return "HTB"
    return str(profile.get("flag_prefix") or "ctf_cs")


def split_chain(source: Any) -> list[str]:
    parts: list[str] = []
    if isinstance(source, (list, tuple)):
        for item in source:
            parts.extend(split_chain(item))
        return [p for p in parts if p]
    text = str(source or "")
    if not text:
        return []
    text = text.replace("=>", "->").replace("/", "/")
    for p in text.split("->"):
        p = p.strip().strip("|")
        if p:
            parts.append(p)
    return parts or [text]


def normalize_flag(flag: str, profile: dict[str, Any] | None = None) -> str:
    flag = str(flag or "").strip()
    if not flag:
        return ""
    if not isinstance(profile, dict):
        return flag
    fmt = str(profile.get("flag_format") or "ctf_cs")
    if fmt == "custom_regex":
        return flag
    if fmt == "braces_only":
        m = STRICT_WRAPPER_RE.match(flag)
        if m:
            return "{" + m.group(2).strip() + "}"
        return flag
    pref = _profile_prefix(profile)
    m = STRICT_WRAPPER_RE.match(flag)
    if m:
        return f"{pref}" + "{" + m.group(2).strip() + "}"
    m = BARE_RE.match(flag)
    if m:
        return f"{pref}" + "{" + m.group(1).strip() + "}"
    return flag


def classify_candidate(flag: str, source: Any = "", profile: dict[str, Any] | None = None, sources: list[str] | None = None) -> dict[str, Any]:
    raw = str(flag or "").strip()
    low = raw.lower()
    chain = split_chain(source)
    for s in sources or []:
        chain.extend(split_chain(s))
    # Deduplicate but preserve order.
    seen_chain = set()
    chain = [c for c in chain if not (c.lower() in seen_chain or seen_chain.add(c.lower()))]
    chain_text = " -> ".join(chain) or str(source or "input")
    norm = normalize_flag(raw, profile)

    score = 45
    risk = 0
    why: list[str] = []
    warnings: list[str] = []

    m = STRICT_WRAPPER_RE.match(raw)
    body = ""
    prefix = ""
    if m:
        prefix, body = m.group(1), m.group(2)
        score += 20
        why.append("strict wrapper")
    else:
        bm = BARE_RE.match(raw)
        if bm:
            body = bm.group(1)
            score += 8
            why.append("bare braces")
        elif isinstance(profile, dict) and profile.get("flag_format") == "custom_regex":
            score += 10
            why.append("custom regex hit")

    expected = _profile_prefix(profile)
    fmt = str(profile.get("flag_format") or "ctf_cs") if isinstance(profile, dict) else "ctf_cs"
    if fmt not in {"any_prefix", "braces_only", "custom_regex"} and prefix:
        if prefix == expected:
            score += 20
            why.append("matches selected flag prefix")
        else:
            score -= 45
            risk += 55
            warnings.append(f"prefix {prefix!r} differs from selected {expected!r}")
    elif fmt == "braces_only" and raw.startswith("{"):
        score += 15
        why.append("matches braces-only mode")

    depth = max(0, len(chain) - 1)
    if depth:
        score += min(22, depth * 7)
        why.append(f"decoded through {depth} transform(s)")
    if any(sig in chain_text.lower() for sig in CHAIN_SIGNAL):
        score += 18
        why.append("transform evidence")
    if len(set(c.lower() for c in chain)) >= 2:
        score += 8
        why.append("multiple evidence stages")

    body_text = body or raw
    if 6 <= len(body_text) <= 120:
        score += 8
    if "_" in body_text or "-" in body_text:
        score += 5
    if re.search(r"[A-Za-z]", body_text) and re.search(r"[0-9]", body_text):
        score += 4
    if SEMANTIC_RE.search(body_text) or SEMANTIC_RE.search(chain_text):
        score += 6
        why.append("semantic CTF signal")

    if DECOY_RE.search(low) or DECOY_RE.search(chain_text):
        score -= 48
        risk += 55
        warnings.append("decoy/example/test wording")
    if len(raw) > 180:
        score -= 12
        risk += 10
        warnings.append("very long candidate")
    if raw.count("{") != raw.count("}"):
        score -= 25
        risk += 35
        warnings.append("unbalanced braces")
    if chain_text in {"input", "raw", ""} and not any(x in low for x in ("ctf", "flag")):
        risk += 8

    confidence = max(1, min(99, score - risk // 3))
    if confidence >= 82 and risk < 35:
        verdict = "high"
    elif confidence >= 60 and risk < 55:
        verdict = "medium"
    else:
        verdict = "low"
    return {
        "flag": raw,
        "preferred_flag": norm,
        "confidence": confidence,
        "risk": max(0, min(99, risk)),
        "verdict": verdict,
        "rank_score": max(1, score - risk),
        "chain": chain,
        "chain_text": chain_text,
        "why": why[:8],
        "warnings": warnings[:8],
        "evidence_version": "v113",
    }


def annotate_flag_row(row: Any, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(row, dict):
        out = dict(row)
        flag = str(out.get("flag") or out.get("value") or "")
        source = out.get("source") or out.get("chain_text") or "input"
        sources = [str(x) for x in out.get("sources", [])] if isinstance(out.get("sources"), list) else []
    else:
        out = {"flag": str(row)}
        flag = str(row)
        source = "input"
        sources = []
    ev = classify_candidate(flag, source, profile, sources)
    out.update({k: v for k, v in ev.items() if k not in {"flag"} or not out.get("flag")})
    out["score"] = max(int(out.get("score", 0) or 0), int(ev["rank_score"]))
    out.setdefault("status", "candidate" if ev["verdict"] != "high" else "confirmed")
    return out


def annotate_summary(summary: dict[str, Any], profile: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        summary = {}
    annotated: list[dict[str, Any]] = []
    seen = set()
    pools = [summary.get("flags", []), summary.get("preferred_flags", []), summary.get("related_candidate_flags", [])]
    for pool in pools:
        for item in pool or []:
            row = annotate_flag_row(item, profile)
            key = str(row.get("preferred_flag") or row.get("flag") or "").lower()
            if not key or key in seen:
                continue
            seen.add(key)
            annotated.append(row)
    annotated.sort(key=lambda r: (int(r.get("confidence", 0)), int(r.get("rank_score", 0)), int(r.get("score", 0))), reverse=True)
    promoted = [r for r in annotated if r.get("verdict") in {"high", "medium"} and int(r.get("risk", 0)) < 65]
    related = [r for r in annotated if r not in promoted]
    summary["flags"] = (promoted or annotated)[:120]
    summary["preferred_flags"] = summary["flags"]
    summary["related_candidate_flags"] = related[:250]
    summary["v113_evidence"] = {
        "enabled": True,
        "version": "v113-competition-evidence",
        "candidates_seen": len(annotated),
        "promoted": len(summary["flags"]),
        "related": len(related),
        "updated": int(time.time()),
    }
    return summary


def _read_profile(mod, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    try:
        profile = mod.sl111_read_settings() if hasattr(mod, "sl111_read_settings") else {}
    except Exception:
        profile = {}
    if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
        profile = {**profile, **meta["solver_settings"]}
    try:
        if hasattr(mod, "sl111_normalize_settings"):
            profile = mod.sl111_normalize_settings(profile)
    except Exception:
        pass
    return profile


def apply(mod) -> None:
    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        profile = _read_profile(mod, meta if isinstance(meta, dict) else {})
        summary = annotate_summary(summary, profile)
        artifacts = []
        for a in summary.get("artifacts", []) or []:
            if not isinstance(a, dict):
                continue
            b = dict(a)
            txt = str(b.get("note") or b.get("name") or "")
            if DECOY_RE.search(txt):
                b["risk"] = max(int(b.get("risk", 0) or 0), 70)
                b["note"] = (str(b.get("note") or "") + " [v113: possible decoy/example artifact]").strip()
            artifacts.append(b)
        summary["artifacts"] = artifacts
        return summary

    mod.project_summary = project_summary
    mod.sl113_annotate_flag_row = annotate_flag_row
    mod.sl113_annotate_summary = annotate_summary

    try:
        @mod.app.get("/api/evidence_health")
        def evidence_health():
            return {"ok": True, "version": "v113-competition-evidence", "signals": list(CHAIN_SIGNAL)}
    except Exception:
        pass
