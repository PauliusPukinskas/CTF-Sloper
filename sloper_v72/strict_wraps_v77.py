
"""CTF SLOPER v77 strict wrapper-candidate filter.

v76 ranked too many random word combos. v77 makes wrapper candidates stricter:
- ctf_cs{...} remains the only final promoted flag format.
- wrap candidates are separate from promoted flags.
- wrap candidates normally require a braced {body} found inside an evidence artifact.
- no-brace candidates are accepted only when extremely strong leetspeak and from a transform artifact.
- random input text / README-style words are ignored.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .health import agent_crash

try:
    from .semantic_v76 import body_semantic_score, normalize_leet, body_tokens
except Exception:  # pragma: no cover
    def body_semantic_score(x): return 0
    def normalize_leet(x): return str(x).lower()
    def body_tokens(x): return re.split(r"[_\-\s.:+/=]+", str(x))

BRACE_RE = re.compile(r"\{([^{}]{3,160})\}")
STRICT_RE = re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,140}\}")
UNDERSCORE_PHRASE_RE = re.compile(r"\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+){1,8}\b")

BAD_BODIES = {
    "example","test","flag","placeholder","answer","answer_here","your_flag_here",
    "todo","dummy","sample","fake","lorem","ipsum","null","none","undefined",
    "vietos_pavadinimas","rastas_tekstas","ctf","ctf_cs"
}

EVIDENCE_KIND_HINTS = [
    "decode", "route", "transposition", "xor", "array", "lsb", "alpha", "palette",
    "transparent", "pcap", "wav", "sqlite", "pdf", "zip", "tar", "magic", "carve",
    "jwt", "classic", "numeric", "stego", "image", "payload", "extract", "transform"
]

STRONG_NO_BRACE_HINTS = [
    "route", "decode", "xor", "array", "lsb", "alpha", "palette", "transparent",
    "pcap", "wav", "jwt", "classic"
]

def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "file"))[:160] or "file"

def ensure(report: dict) -> None:
    report.setdefault("v77_wrap_candidates", [])
    report.setdefault("wrap_candidates", [])
    report.setdefault("candidate_flags", [])
    report.setdefault("artifacts", [])
    report.setdefault("transformations", [])
    report.setdefault("next_steps", [])

def artifact_is_evidence(a: dict) -> bool:
    text = (a.get("kind","") + " " + a.get("name","") + " " + a.get("source","") + " " + a.get("note","")).lower()
    if "readme" in text or "statement" in text or "answer" in text:
        return False
    return any(k in text for k in EVIDENCE_KIND_HINTS)

def strong_no_brace_artifact(a: dict) -> bool:
    text = (a.get("kind","") + " " + a.get("name","") + " " + a.get("source","") + " " + a.get("note","")).lower()
    return any(k in text for k in STRONG_NO_BRACE_HINTS)

def body_ok(body: str) -> bool:
    body = str(body or "").strip().strip("{}")
    if not body:
        return False
    low = body.lower()
    if low in BAD_BODIES:
        return False
    if any(x in low for x in ["libarchive", "com_apple", "quarantine", "provenance", "xmlns", "schema"]):
        return False
    if len(body) < 5 or len(body) > 140:
        return False
    if re.search(r"[^\w\-:+./=]", body):
        return False
    if body[0] in ".:/=+-_" or body[-1] in ".:/=+-_":
        return False
    if not re.search(r"[A-Za-z]", body):
        return False
    semantic_hint = re.search(r"(cyber|sprint|calc|archive|deleted|password|secret|hidden|bytes|byte|lsb|xor|zip|gzip|base|morse|rail|reverse|interleave|decode|ok|done|key)", low)
    if "_" not in low and not semantic_hint:
        if len(low) > 24:
            return False
        if len(low) < 10:
            return False
        if not re.search(r"[aeiouy]", low):
            return False
    if "_" in low and not semantic_hint:
        if len(low) < 10 and len([t for t in re.split(r"[_\-:+./=]+", low) if t]) <= 2:
            return False
    punct = sum(1 for c in body if not (c.isalnum() or c == "_"))
    if punct / max(1, len(body)) > 0.18:
        return False
    if "." in body and body.count(".") / max(1, len(body)) > 0.03:
        return False
    toks = [t for t in re.split(r"[_\-:+./=]+", low) if t]
    if len(toks) >= 4 and sum(1 for t in toks if len(t) <= 1) >= len(toks) // 2:
        return False
    if len(set(low)) <= 3 and len(body) > 9:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{16,}", body):
        return False
    return True

def leet_strength(body: str) -> int:
    body = str(body or "")
    score = 0
    if re.search(r"[a-zA-Z]", body) and re.search(r"\d", body):
        score += 40
    if "_" in body:
        score += 25
    toks = body_tokens(body)
    if 2 <= len(toks) <= 8:
        score += 20
    if any(re.search(r"\d", t) and re.search(r"[A-Za-z]", t) for t in toks):
        score += 35
    return score

def add_wrap(report: dict, body: str, source: str, artifact: str, why: str, base_score: int, origin: str) -> None:
    ensure(report)
    body = str(body or "").strip().strip("{}")
    if not body_ok(body):
        return
    score = body_semantic_score(body) + base_score
    if origin == "braced":
        # Braced content from evidence artifact is allowed, but still needs some semantic value.
        if score < 120:
            return
    else:
        # No-brace is much stricter.
        if score < 230 or leet_strength(body) < 60:
            return
    cand = f"ctf_cs{{{body}}}"
    item = {
        "candidate": cand,
        "body": body,
        "score": int(score),
        "priority": "top" if score >= 190 else "high" if score >= 150 else "medium",
        "origin": origin,
        "source": source,
        "artifact": artifact or "",
        "why": why,
        "normalized": normalize_leet(body),
        "tokens": body_tokens(body),
        "section": "wrap_candidates",
    }
    existing = {x.get("candidate") for x in report.get("v77_wrap_candidates", []) if isinstance(x, dict)}
    if cand not in existing:
        report["v77_wrap_candidates"].append(item)
        report["wrap_candidates"].append(item)

def scan_evidence_artifacts(report: dict) -> List[dict]:
    ensure(report)
    found = []
    for a in list(report.get("artifacts", []))[:800]:
        if not isinstance(a, dict) or not artifact_is_evidence(a):
            continue
        path = a.get("path")
        if not path:
            continue
        try:
            p = Path(path)
            if not p.exists() or p.stat().st_size > 4_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Braced bodies are the normal wrap source.
        for m in BRACE_RE.finditer(text):
            body = m.group(1).strip()
            before = text[max(0, m.start()-8):m.start()].lower()
            if "ctf_cs" in before:
                continue
            prev_count = len(report.get("v77_wrap_candidates", []))
            add_wrap(
                report, body,
                "SLOPER v77 strict brace scan",
                str(p),
                "Evidence artifact produced a braced {body}; safe to show as wrap candidate.",
                45,
                "braced"
            )
            if len(report.get("v77_wrap_candidates", [])) > prev_count:
                found.append(report["v77_wrap_candidates"][-1])

        # No-brace only from strong transform artifacts and only very strong leetspeak.
        if strong_no_brace_artifact(a):
            for phrase in UNDERSCORE_PHRASE_RE.findall(text):
                prev_count = len(report.get("v77_wrap_candidates", []))
                add_wrap(
                    report, phrase,
                    "SLOPER v77 strict no-brace scan",
                    str(p),
                    "Strong transform artifact produced a very strong leetspeak/word-combo phrase without braces.",
                    5,
                    "strong_no_brace"
                )
                if len(report.get("v77_wrap_candidates", [])) > prev_count:
                    found.append(report["v77_wrap_candidates"][-1])
    return found

def filter_legacy_candidates(report: dict) -> List[dict]:
    """Keep only older candidates that satisfy v77 rules.

    This prevents v76/v75 random word combos from dominating the UI.
    """
    ensure(report)
    kept = []
    for item in list(report.get("candidate_flags", [])) + list(report.get("semantic_answer_candidates", [])):
        if not isinstance(item, dict):
            continue
        cand = item.get("candidate") or item.get("suggested_flag") or ""
        m = re.fullmatch(r"ctf_cs\{([^{}]+)\}", str(cand))
        if not m:
            continue
        body = m.group(1)
        artifact = item.get("artifact") or ""
        source = item.get("source") or "legacy candidate"
        why = item.get("why") or ""
        origin = item.get("origin") or ""

        # If an artifact contains the braced body, keep it.
        artifact_ok = False
        if artifact:
            try:
                p = Path(artifact)
                if p.exists() and p.stat().st_size <= 4_000_000:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                    artifact_ok = ("{" + body + "}") in text
            except Exception:
                artifact_ok = False

        if artifact_ok:
            prev = len(report.get("v77_wrap_candidates", []))
            add_wrap(report, body, source, artifact, why or "Legacy candidate validated by braced evidence artifact.", 35, "braced")
            if len(report.get("v77_wrap_candidates", [])) > prev:
                kept.append(report["v77_wrap_candidates"][-1])
        elif origin == "strong_no_brace" or "without braces" in why.lower():
            # Very rare path.
            prev = len(report.get("v77_wrap_candidates", []))
            add_wrap(report, body, source, artifact, why or "Legacy no-brace candidate passed strict v77 threshold.", 0, "strong_no_brace")
            if len(report.get("v77_wrap_candidates", [])) > prev:
                kept.append(report["v77_wrap_candidates"][-1])
    return kept

def write_wrap_artifact(root: Path, report: dict) -> dict | None:
    ensure(report)
    # Dedupe and sort.
    out = []
    seen = set()
    for c in sorted(report.get("v77_wrap_candidates", []), key=lambda x: int(x.get("score", 0)), reverse=True):
        key = c.get("candidate")
        if key and key not in seen:
            out.append(c); seen.add(key)
    report["v77_wrap_candidates"] = out[:160]
    report["wrap_candidates"] = out[:160]
    report["candidate_flags"] = out[:160]
    report["semantic_answer_candidates"] = out[:160]

    if not out:
        return None
    try:
        outdir = Path(root) / "generated" / "sloper77" / safe_name(report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / "wrap_candidates_strict.json"
        p.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        art = {
            "kind": "sloper77_strict_wrap_candidates",
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v77",
            "score": 720,
            "note": "Strict wrap candidates. Usually requires braced {body} in evidence artifact.",
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report.setdefault("artifacts", []).insert(0, art)
        report.setdefault("transformations", []).insert(0, art)
        report.setdefault("next_steps", []).insert(0, {
            "priority": 100,
            "step": "Review Wrap Candidates section.",
            "why": "v77 moved wrapper-style answers into a strict separate section and filtered random word combos."
        })
        return art
    except Exception as e:
        agent_crash("v77 write_wrap_artifact", e, report)
        return None

def run_strict_wrap_layer(report: dict, root: Path, data: bytes) -> List[dict]:
    ensure(report)
    # Reset noisy v76 lists before rebuilding strict candidates from evidence.
    report["v77_wrap_candidates"] = []
    report["wrap_candidates"] = []
    # Do not trust raw input free phrases. Trust artifacts/evidence.
    scan_evidence_artifacts(report)
    filter_legacy_candidates(report)
    art = write_wrap_artifact(root, report)
    return [art] if art else []

def install(mod):
    old_run = getattr(mod, "sl_run_agents", None)

    def sl_run_agents(report, root, data):
        arts = []
        if old_run:
            try:
                prev = old_run(report, root, data)
                if prev:
                    arts += prev
            except Exception as e:
                agent_crash("legacy/v76 sl_run_agents before v77", e, report)
        try:
            new = run_strict_wrap_layer(report, Path(root), bytes(data or b""))
            if new:
                arts += new
        except Exception as e:
            agent_crash("v77 strict wrap layer", e, report)
        try:
            if hasattr(mod, "sl_finalize_report"):
                mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash("v77 sl_finalize_report", e, report)
        return arts

    mod.sl_run_agents = sl_run_agents

    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        artifacts = summary.get("artifacts", []) or []
        wraps = []
        for r in reports:
            for c in r.get("v77_wrap_candidates", []) or r.get("wrap_candidates", []) or []:
                if isinstance(c, dict):
                    wraps.append(c)
        out = []
        seen = set()
        for c in sorted(wraps, key=lambda x: int(x.get("score", 0)), reverse=True):
            key = c.get("candidate")
            if key and key not in seen:
                out.append(c); seen.add(key)
        summary["wrap_candidates"] = out[:120]
        summary["semantic_answer_candidates"] = out[:120]  # backwards-compatible but filtered
        lane = summary.get("sloper76_review_lanes", {}) or summary.get("sloper75_review_lanes", {}) or {}
        lane["v77_wrap_candidates"] = len(out)
        lane["v77_top_wrap_candidates"] = len([x for x in out if int(x.get("score", 0)) >= 190])
        summary["sloper77_review_lanes"] = lane

        def pri(a):
            s = int(a.get("score", 0) or 0)
            txt = (a.get("source","") + " " + a.get("kind","") + " " + a.get("name","")).lower()
            if "sloper77" in txt: s += 52000
            if "wrap_candidates" in txt: s += 9000
            if "sloper76" in txt: s += 25000
            if "sloper75" in txt: s += 20000
            if "sloper74" in txt: s += 12000
            return (bool(a.get("exists", False)), s, int(a.get("size", 0) or 0))
        summary["artifacts"] = sorted(artifacts, key=pri, reverse=True)[:9500]
        actions = []
        if out:
            actions.append({"priority": 100, "step": "Review Wrap Candidates separately from final flags.", "why": "v77 found strict braced answer bodies in evidence artifacts."})
        summary["sloper77_next_actions"] = actions + summary.get("sloper76_next_actions", [])[:8] + summary.get("sloper75_next_actions", [])[:8]
        try:
            from .artifact_hub import compact_hub
            summary["sloper77_artifact_hub"] = compact_hub(summary)
        except Exception:
            pass
        return summary

    mod.project_summary = project_summary
    mod.sl77_run_strict_wrap_layer = run_strict_wrap_layer
    mod.sl77_body_ok = body_ok
    return mod
