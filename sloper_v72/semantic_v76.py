
"""CTF SLOPER v76 semantic answer-ranker layer.

v76 focuses on realistic CTF answer candidates:
- detects {body} from strong transformations
- ranks LT/EN/leetspeak underscore word combos highly
- keeps strict ctf_cs{...} as final promoted flags
- surfaces high-confidence wrappers separately, not as random final flags
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .health import agent_crash

try:
    from . import workflow_v75 as v75
except Exception:  # pragma: no cover
    v75 = None

try:
    from . import workflow_v74 as v74
except Exception:  # pragma: no cover
    v74 = None

LEET_MAP = str.maketrans({
    "0":"o", "1":"i", "2":"z", "3":"e", "4":"a",
    "5":"s", "6":"g", "7":"t", "8":"b", "9":"g",
    "@":"a", "$":"s", "!":"i",
})

EN_WORDS = {
    "flag","secret","hidden","inside","answer","decode","encoded","cipher","key",
    "password","admin","token","route","table","column","row","sound","audio",
    "image","alpha","palette","pixel","transparent","noise","signal","loud",
    "quiet","lab","file","data","array","bytes","xor","reverse","reversing",
    "magic","carve","zip","archive","payload","packet","network","stream",
    "base","hex","binary","decimal","morse","rail","fence","vigenere","caesar",
    "good","nice","easy","hard","final","real","true","false","open","close",
    "look","see","read","write","find","found","lost","hunter","wolf","forest",
    "tree","bush","city","vilnius","sprint","cyber","level","stage","round",
    "very","loud","home","house","door","window","shadow","ghost","paint",
    "clock","time","space","white","black","red","green","blue"
}

LT_WORDS = {
    "slaptas","slapta","paslaptis","raktas","veliava","vėliava","atsakymas",
    "uzduotis","užduotis","tekstas","garsas","vaizdas","nuotrauka","paveikslelis",
    "paveikslėlis","failas","duomenys","miestas","vilnius","kaunas","kodas",
    "zodis","žodis","zodziai","žodžiai","labas","ieskok","ieškok","rask",
    "surask","paslepta","paslėpta","viduje","isore","išorė","vidus","kelias",
    "stulpelis","eilute","eilutė","lentele","lentelė","garsiai","tyliai",
    "krumai","krūmai","medis","miskas","miškas","vilkas","namas","durys",
    "langas","seselis","šešėlis","laikas","spalva","spalvos","zeme","žemė",
    "herbas","lobis","skrynia","vaiduoklis","srautas","pranesimas","pranešimas"
}

BAD_BODY_WORDS = {
    "example","test","flag","placeholder","answer","answer_here","your_flag_here",
    "todo","dummy","sample","fake","lorem","ipsum","null","none","undefined",
    "vietos_pavadinimas","rastas_tekstas"
}

STRICT_RE = re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,140}\}")
BRACE_RE = re.compile(r"\{([^{}]{3,160})\}")

def normalize_leet(s: str) -> str:
    return str(s or "").lower().translate(LEET_MAP)

def body_tokens(body: str) -> List[str]:
    parts = re.split(r"[_\-\s.:+/=]+", str(body or "").strip().lower())
    return [p for p in parts if p]

def token_score(tok: str) -> int:
    if not tok:
        return 0
    n = normalize_leet(tok)
    score = 0
    if n in EN_WORDS or n in LT_WORDS:
        score += 40
    elif any(w in n for w in EN_WORDS if len(w) >= 5):
        score += 22
    elif any(w in n for w in LT_WORDS if len(w) >= 5):
        score += 22
    if re.search(r"[a-z]", tok) and re.search(r"\d", tok):
        score += 8  # leetspeak
    if 2 <= len(tok) <= 18:
        score += 4
    if re.fullmatch(r"[a-z0-9]+", tok.lower()):
        score += 2
    return score

def body_semantic_score(body: str) -> int:
    body = str(body or "").strip()
    low = body.lower()
    norm = normalize_leet(low)
    if not body or low in BAD_BODY_WORDS or norm in BAD_BODY_WORDS:
        return -1000
    if len(body) < 4 or len(body) > 140:
        return -200
    if re.search(r"[^\w\-:+./=]", body):
        return -80
    toks = body_tokens(body)
    if not toks:
        return -100
    score = 0
    score += min(30, len(body))
    if "_" in body:
        score += 35
    if 2 <= len(toks) <= 9:
        score += 30
    if len(toks) >= 2:
        score += 20
    score += sum(token_score(t) for t in toks)
    if re.search(r"[a-zA-Z]", body):
        score += 20
    if re.search(r"\d", body):
        score += 8
    if re.fullmatch(r"[0-9a-fA-F]{16,}", body):
        score -= 70
    if len(set(body.lower())) <= 3 and len(body) > 8:
        score -= 100
    if any(w in norm for w in ["secret","hidden","flag","key","slapta","raktas","veliava","atsakymas","loud","lab","route","xor","stego"]):
        score += 35
    # Looks like CTF answer style: word_word, leet_word, etc.
    if re.fullmatch(r"[A-Za-z0-9]+(?:_[A-Za-z0-9]+){1,8}", body):
        score += 45
    return score

def is_high_conf_body(body: str) -> bool:
    return body_semantic_score(body) >= 115

def ensure(report: dict) -> None:
    report.setdefault("candidate_flags", [])
    report.setdefault("workflow_evidence", [])
    report.setdefault("artifacts", [])
    report.setdefault("flags", [])
    report.setdefault("semantic_answer_candidates", [])

def add_candidate(report: dict, body: str, source: str, artifact: str | None, why: str, score_bonus: int = 0) -> None:
    ensure(report)
    body = str(body or "").strip()
    if body.lower().startswith("ctf_cs{"):
        return
    score = body_semantic_score(body) + score_bonus
    if score < 85:
        return
    cand = "ctf_cs{" + body.strip("{}") + "}"
    item = {
        "candidate": cand,
        "body": body,
        "score": score,
        "source": source,
        "artifact": artifact or "",
        "why": why,
        "normalized": normalize_leet(body),
        "tokens": body_tokens(body),
        "priority": "top" if score >= 140 else "high" if score >= 115 else "medium",
    }
    # Dedupe by candidate + source artifact
    key = (item["candidate"], item["artifact"], item["source"])
    existing = {(x.get("candidate"), x.get("artifact"), x.get("source")) for x in report.get("semantic_answer_candidates", [])}
    if key not in existing:
        report["semantic_answer_candidates"].append(item)
    # Also mirror to older candidate list used by UI.
    old_existing = {x.get("candidate") for x in report.get("candidate_flags", []) if isinstance(x, dict)}
    if cand not in old_existing:
        report["candidate_flags"].append(item)

def scan_semantic_candidates(report: dict, text: str, source: str, artifact: str | None, why: str, score_bonus: int = 0) -> List[dict]:
    ensure(report)
    out = []
    text = str(text or "")
    for m in BRACE_RE.finditer(text):
        body = m.group(1).strip()
        # If it's already full strict flag, legacy/v74 should promote it. v76 only candidates for body.
        if body.lower().startswith("ctf_cs"):
            continue
        before = text[max(0, m.start()-8):m.start()].lower()
        if "ctf_cs" in before:
            continue
        score = body_semantic_score(body) + score_bonus
        if score >= 85:
            add_candidate(report, body, source, artifact, why, score_bonus)
            out.append({"body": body, "score": score})
    # Also catch clean underscore phrases without braces only as weak candidates if very strong.
    for phrase in re.findall(r"\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+){1,8}\b", text):
        if body_semantic_score(phrase) + score_bonus >= 155:
            add_candidate(report, phrase, source, artifact, why + " Clean underscore phrase without braces.", score_bonus - 20)
    return out

def rescore_existing(report: dict) -> None:
    ensure(report)
    # Score any existing candidate_flags from old layers.
    for item in list(report.get("candidate_flags", [])):
        if not isinstance(item, dict):
            continue
        cand = item.get("candidate") or item.get("suggested_flag") or ""
        m = re.fullmatch(r"ctf_cs\{([^{}]+)\}", cand)
        if m:
            body = m.group(1)
            score = max(int(item.get("score", 0) or 0), body_semantic_score(body))
            item["score"] = score
            item["priority"] = "top" if score >= 140 else "high" if score >= 115 else "medium"
            item["normalized"] = normalize_leet(body)
            if score >= 85:
                add_candidate(report, body, item.get("source","legacy candidate"), item.get("artifact",""), item.get("why","Existing candidate rescored by v76."), 0)
    report["semantic_answer_candidates"] = sorted(report.get("semantic_answer_candidates", []), key=lambda x: int(x.get("score",0)), reverse=True)[:200]
    report["candidate_flags"] = sorted([x for x in report.get("candidate_flags", []) if isinstance(x, dict)], key=lambda x: int(x.get("score",0)), reverse=True)[:250]

def semantic_artifact(root: Path, report: dict) -> dict | None:
    ensure(report)
    rescore_existing(report)
    if not report.get("semantic_answer_candidates"):
        return None
    try:
        outdir = Path(root) / "generated" / "sloper76" / re.sub(r"[^A-Za-z0-9._ -]+","_",str(report.get("name","file")))[:120]
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / "semantic_answer_candidates.json"
        p.write_text(json.dumps(report["semantic_answer_candidates"], indent=2, ensure_ascii=False), encoding="utf-8")
        art = {
            "kind": "sloper76_semantic_answer_candidates",
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v76",
            "score": 620,
            "note": "High-priority LT/EN/leetspeak answer candidates from evidence-bearing transforms.",
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report.setdefault("artifacts", []).insert(0, art)
        report.setdefault("transformations", []).insert(0, art)
        report.setdefault("next_steps", []).insert(0, {
            "priority": 100,
            "step": "Review semantic_answer_candidates.json.",
            "why": "v76 found LT/EN/leetspeak answer-like bodies from workflow evidence. These are top candidates, not random final flags."
        })
        return art
    except Exception as e:
        agent_crash("v76 semantic_artifact", e, report)
        return None

def route_boost(report: dict) -> None:
    # Route/transposition outputs are strong evidence: boost body candidates from those artifacts.
    for a in report.get("artifacts", []):
        name = (a.get("name","") + " " + a.get("kind","")).lower()
        if "route_transposition" in name and a.get("path"):
            try:
                text = Path(a["path"]).read_text(encoding="utf-8", errors="ignore")
                scan_semantic_candidates(report, text, "SLOPER v76 route artifact semantic scan", a["path"], "Route/transposition artifact produced answer-like body.", 35)
            except Exception:
                pass

def scan_all_artifacts(report: dict) -> None:
    for a in list(report.get("artifacts", []))[:500]:
        path = a.get("path")
        if not path:
            continue
        kind = (a.get("kind","") + " " + a.get("name","")).lower()
        # Only semantic-scan evidence artifacts, not random project README dumps.
        if not any(k in kind for k in ["decode", "route", "xor", "array", "lsb", "alpha", "palette", "transparent", "pcap", "wav", "sqlite", "pdf", "zip", "tar", "magic", "carve", "jwt", "classic", "numeric"]):
            continue
        try:
            p = Path(path)
            if not p.exists() or p.stat().st_size > 3_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            scan_semantic_candidates(report, text, "SLOPER v76 artifact semantic scan", str(p), "Evidence artifact contains LT/EN/leetspeak answer-like body.", 20)
        except Exception:
            pass

def run_semantic_layer(report: dict, root: Path, data: bytes) -> List[dict]:
    ensure(report)
    # Direct scan only for dense transform-like data; not arbitrary README/random prose.
    try:
        text = bytes(data or b"")[:1_000_000].decode("utf-8", "ignore")
        # Apply semantic scan when braces exist or dense underscore phrases exist.
        if "{" in text or re.search(r"\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+){1,8}\b", text):
            scan_semantic_candidates(report, text, "SLOPER v76 input semantic scan", None, "Input data itself contains answer-like body.", 0)
    except Exception:
        pass
    route_boost(report)
    scan_all_artifacts(report)
    art = semantic_artifact(root, report)
    return [art] if art else []

def install(mod):
    old_run = getattr(mod, "sl_run_agents", None)

    def sl_run_agents(report, root, data):
        arts = []
        # v75/v74/legacy first produce evidence.
        if old_run:
            try:
                prev = old_run(report, root, data)
                if prev:
                    arts += prev
            except Exception as e:
                agent_crash("legacy/v75 sl_run_agents before v76", e, report)
        # v76 ranks only evidence-bearing transform outputs.
        try:
            new = run_semantic_layer(report, Path(root), bytes(data or b""))
            if new:
                arts += new
        except Exception as e:
            agent_crash("v76 semantic layer", e, report)
        try:
            if hasattr(mod, "sl_finalize_report"):
                mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash("v76 sl_finalize_report", e, report)
        return arts

    mod.sl_run_agents = sl_run_agents

    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        artifacts = summary.get("artifacts", []) or []
        candidates = []
        for r in reports:
            for c in r.get("semantic_answer_candidates", []) or []:
                candidates.append(c)
            for c in r.get("candidate_flags", []) or []:
                if isinstance(c, dict):
                    candidates.append(c)
        # Dedupe and rank
        out = []
        seen = set()
        for c in sorted(candidates, key=lambda x: int(x.get("score",0)), reverse=True):
            key = c.get("candidate") or c.get("suggested_flag")
            if key and key not in seen and int(c.get("score",0)) >= 85:
                out.append(c); seen.add(key)
        summary["semantic_answer_candidates"] = out[:100]
        lane = summary.get("sloper75_review_lanes", {}) or summary.get("sloper74_review_lanes", {}) or {}
        lane["v76_semantic_candidates"] = len(out)
        lane["v76_top_candidates"] = len([x for x in out if int(x.get("score",0)) >= 140])
        summary["sloper76_review_lanes"] = lane
        def pri(a):
            s = int(a.get("score", 0) or 0)
            txt = (a.get("source","") + " " + a.get("kind","") + " " + a.get("name","")).lower()
            if "sloper76" in txt: s += 42000
            if "semantic_answer" in txt: s += 6000
            if "sloper75" in txt: s += 30000
            if "sloper74" in txt: s += 15000
            return (bool(a.get("exists", False)), s, int(a.get("size", 0) or 0))
        summary["artifacts"] = sorted(artifacts, key=pri, reverse=True)[:9500]
        actions = []
        if out:
            actions.append({"priority": 100, "step": "Review Semantic Answer Candidates first.", "why": "v76 ranked LT/EN/leetspeak answer-like bodies from evidence transforms."})
        summary["sloper76_next_actions"] = actions + summary.get("sloper75_next_actions", [])[:20] + summary.get("sloper72_next_actions", [])[:10]
        try:
            from .artifact_hub import compact_hub
            summary["sloper76_artifact_hub"] = compact_hub(summary)
        except Exception:
            pass
        return summary

    mod.project_summary = project_summary
    mod.sl76_run_semantic_layer = run_semantic_layer
    mod.sl76_body_semantic_score = body_semantic_score
    return mod
