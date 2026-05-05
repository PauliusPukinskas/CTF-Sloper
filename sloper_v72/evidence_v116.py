"""v116 triage hardening.

The v115 benchmark on Cyber Sprint showed that random XOR-derived short brace
strings could outrank real artifacts.  v116 keeps all candidates for manual
inspection but only marks a candidate trusted when the body is plausible and the
source chain is strong.
"""
from __future__ import annotations
import re, time
from typing import Any

PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{1,32}\{(.+)\}$", re.S)
GOOD_BODY_RE = re.compile(r"^[A-Za-z0-9_+./:=\-]{8,180}$")
PLACEHOLDER_RE = re.compile(r"\.\.\.|vietos_pavadinimas|gatves_pavadinimas|pastato_numeris|rastos\.vietos|frazė|fraze|example|sample|bench|dummy", re.I)
LT_LEET_RE = re.compile(r"[a-z0-9]+_[a-z0-9_]+|[a-z]*[013457][a-z0-9_]*", re.I)
COMMON_LEET_WORDS = {"it", "is", "very", "loud", "in", "the", "lab", "stego", "vilnius", "deleted", "not", "gone", "flag", "secret", "raktas", "lietuva"}
LEET_TRANS = str.maketrans({"0":"o", "1":"i", "3":"e", "4":"a", "5":"s", "7":"t", "8":"b"})
STRONG_SOURCE = ("v116", "carved_zip", "morse", "rect_", "cardan", "pcap", "pyc", "binary_printable", "zip:", "pwd=", "docx", "ooxml", "sqlite", "png", "jpeg")
WEAK_SOURCE = ("xor_", "direct_ascii_flagish", "legacy")

def _body(flag: str) -> str:
    m=PREFIX_RE.match(flag or "")
    if m: return m.group(1)
    if flag.startswith("{") and flag.endswith("}"): return flag[1:-1]
    return flag or ""

def _leet_words(body: str) -> list[str]:
    words=[]
    for tok in re.split(r"[_\-{}]+", body.lower()):
        if not tok:
            continue
        words.append(tok.translate(LEET_TRANS))
    return words

def _risk(flag: str, source: str) -> list[str]:
    b=_body(flag); risk=[]
    if not flag or PLACEHOLDER_RE.search(flag): risk.append("placeholder")
    if not all(32 <= ord(c) <= 126 for c in flag): risk.append("non_ascii")
    if len(b) < 8: risk.append("too_short")
    if not GOOD_BODY_RE.fullmatch(b or ""): risk.append("bad_charset")
    if b.count(".") >= 2 and "_" not in b and not re.search(r"[0-9]{2,}", b): risk.append("punctuation_fragment")
    if (":" in b or "/" in b) and "cardan" in source.lower() and "sha256" not in source.lower(): risk.append("cardan_intermediate_not_final")
    if re.search(r"[A-Z][a-z]?\.[a-z]{1,3}\.", b): risk.append("route_fragment")
    if re.fullmatch(r"[a-z]{5,8}", b or ""): risk.append("short_lowercase_noise")
    if "xor_" in source.lower() and (len(b) < 14 or not LT_LEET_RE.search(b)): risk.append("xor_weak")
    if b.lower() in {"ctf", "flag", "secret", "password", "raktas", "lietuva"}: risk.append("generic_word")
    if re.search(r"[A-Z]", b) and re.search(r"[a-z]", b): risk.append("mixed_case_body")
    if len(b) >= 8 and b.count("_") > max(3, len(b)//3): risk.append("underscore_noise")
    return risk

def _score(item: dict[str, Any]) -> int:
    flag=str(item.get("preferred_flag") or item.get("flag") or "")
    src=(str(item.get("source") or "") + " " + " ".join(map(str,item.get("chain") or []))).lower()
    s=int(item.get("score",0) or 0)
    body = _body(flag)
    for k in STRONG_SOURCE:
        if k in src: s += 260
    if any(k in src for k in ("carved_zip", "pwd=", "morse", "rect_", "cardan_sha256")): s += 420
    if "cardan" in src and "sha256" not in src: s -= 700
    if re.fullmatch(r"[0-9a-f]{64}", body.lower() or "") and ("sha256" in src or "hash" in src): s += 900
    if "bare_token_wrap" in src: s += 260
    # ROT after a route/rectangular transposition produces many plausible but
    # usually false leetspeak variants. Keep them visible, but rank the direct
    # route evidence above ROT hallucinations unless the operator chooses it.
    if "rect_" in src and "->input->rot" in src: s -= 620
    if LT_LEET_RE.search(body): s += 140
    good_words = [w for w in _leet_words(body) if w in COMMON_LEET_WORDS]
    if good_words:
        s += min(900, 160 * len(set(good_words)))
    if "_" in body and any(c.isdigit() for c in body): s += 260
    if body.count("_") >= 2: s += 180
    risks=_risk(flag, src)
    s -= 430*len(risks)
    if any(k in src for k in WEAK_SOURCE): s -= 120
    item["v116_risk"] = risks
    item["v116_score"] = s
    if not risks and s >= 900:
        item["v116_verdict"] = "trusted"
    elif len(risks) <= 1 and s >= 650:
        item["v116_verdict"] = "promising"
    else:
        item["v116_verdict"] = "manual-review"
    return s

def apply(mod) -> None:
    old_summary=getattr(mod,"project_summary",None)
    def project_summary(reports, meta):
        summary=old_summary(reports, meta) if old_summary else {"flags":[],"artifacts":[]}
        items=[x for x in (summary.get("flags") or []) if isinstance(x,dict)]
        # Deduplicate by preferred flag, preserving best evidence.
        best={}
        for item in items:
            f=str(item.get("preferred_flag") or item.get("flag") or "")
            if not f: continue
            sc=_score(item)
            if f not in best or sc > int(best[f].get("v116_score",-10**9)):
                best[f]=item
        ranked=sorted(best.values(), key=lambda x:int(x.get("v116_score",0) or 0), reverse=True)
        summary["flags"] = ranked[:300]
        trusted=[x for x in ranked if x.get("v116_verdict")=="trusted"]
        promising=[x for x in ranked if x.get("v116_verdict")=="promising"]
        manual=[x for x in ranked if x.get("v116_verdict")=="manual-review"]
        best_item=(trusted or promising or ranked or [{}])[0]
        summary["v116_triage"]={
            "enabled": True,
            "version": "v116-cybersprint-triage",
            "updated": int(time.time()),
            "best_flag": best_item.get("preferred_flag") or best_item.get("flag"),
            "best_score": best_item.get("v116_score"),
            "best_verdict": best_item.get("v116_verdict"),
            "trusted": len(trusted),
            "promising": len(promising),
            "manual_review": len(manual),
            "suppressed_noise": len([x for x in ranked if x.get("v116_risk")]),
            "operator_hint": "Prefer v116 trusted/promising candidates. Short XOR/non-ASCII/template candidates are kept but demoted.",
        }
        return summary
    mod.project_summary=project_summary
    try:
        @mod.app.get("/api/v116_evidence_health")
        def v116_evidence_health():
            return {"ok": True, "version": "v116-cybersprint-triage"}
    except Exception:
        pass
