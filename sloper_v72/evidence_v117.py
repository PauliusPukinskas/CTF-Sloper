"""v117 evidence triage layer."""
from __future__ import annotations
import re, time
from pathlib import Path
from typing import Any

SHA_BODY=re.compile(r"^[0-9a-f]{64}$", re.I)
STRICT_FLAG=re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,160}\}")
BRACE_TOKEN=re.compile(r"\{([A-Za-z0-9][A-Za-z0-9_\-:+./=]{5,160})\}")
ISO_TS=re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
UUIDISH=re.compile(r"^[A-Z0-9]{4,}-[A-Z0-9-]{8,}$", re.I)
TASK_PLACEHOLDER=re.compile(r"\.\.\.|vietos_pavadinimas|gatves_pavadinimas|pastato_numeris|rastos\.vietos|frazė|fraze|formatas", re.I)

def _body(f:str)->str:
    if "{" in f and f.endswith("}"):
        return f[f.find("{")+1:-1]
    return f

def apply(mod)->None:
    old_summary=getattr(mod,"project_summary",None)
    def project_summary(reports, meta):
        summary=old_summary(reports, meta) if old_summary else {"flags":[],"artifacts":[]}
        # v117 rescue: older layers sometimes store the exact flag only inside
        # a high-value transform artifact while ROT/wrapper variants dominate
        # summary flags. Re-scan only trusted artifact families for strict
        # ctf_cs{...} strings and inject those before triage.
        rescued=[]
        for art in summary.get("artifacts",[]) or []:
            if not isinstance(art, dict):
                continue
            probe=(str(art.get("name", ""))+" "+str(art.get("kind", ""))+" "+str(art.get("path", ""))).lower()
            if not any(k in probe for k in ["v116_rect", "rect_", "cardan", "custom.xml", "artifact_log_reconstructed"]):
                continue
            try:
                ap=Path(str(art.get("path") or ""))
                if not ap.exists() or ap.stat().st_size > 2_000_000:
                    continue
                txt=ap.read_bytes()[:1_000_000].decode("utf-8", "ignore")
            except Exception:
                continue
            for m in STRICT_FLAG.finditer(txt):
                rescued.append({
                    "flag": m.group(0),
                    "preferred_flag": m.group(0),
                    "source": "v117_strict_artifact_rescue",
                    "artifact": str(art.get("path", "")),
                    "score": int(art.get("score", 900) or 900) + 1800,
                    "why": "Strict ctf_cs flag recovered from high-value transform artifact before noisy ROT/wrapper candidates.",
                })
            for m in BRACE_TOKEN.finditer(txt):
                body=m.group(1)
                # High-signal transposition artifacts often contain the body in
                # bare braces even when the prefix is split/corrupted. Require
                # underscore/leet structure so random code braces are ignored.
                if "_" not in body and not re.search(r"[a-zA-Z][0-9]|[0-9][a-zA-Z]", body):
                    continue
                rescued.append({
                    "flag": "ctf_cs{"+body+"}",
                    "preferred_flag": "ctf_cs{"+body+"}",
                    "source": "v117_bare_brace_artifact_rescue",
                    "artifact": str(art.get("path", "")),
                    "score": int(art.get("score", 900) or 900) + 1700,
                    "why": "Bare brace token recovered from high-value transform artifact and wrapped with the declared ctf_cs format.",
                })
        if rescued:
            summary["flags"] = rescued + list(summary.get("flags",[]) or [])
        items=[x for x in summary.get("flags",[]) if isinstance(x,dict)]
        for item in items:
            f=str(item.get("preferred_flag") or item.get("flag") or "")
            src=(str(item.get("source") or "")+" "+" ".join(map(str,item.get("chain") or []))).lower()
            body=_body(f)
            score=int(item.get("v116_score", item.get("score",0)) or 0)
            low_flag=f.lower()
            prefix_penalty = bool(body and not low_flag.startswith("ctf_cs{"))
            raw_risk = item.get("v116_risk") or item.get("risk") or []
            if isinstance(raw_risk, (list, tuple, set)):
                risk = list(raw_risk)
            elif raw_risk:
                risk = [str(raw_risk)]
            else:
                risk = []
            if prefix_penalty:
                risk.append("non_target_prefix")
                score -= 900
            if TASK_PLACEHOLDER.search(f): risk.append("task_placeholder")
            if ISO_TS.fullmatch(body): risk.append("metadata_timestamp")
            if UUIDISH.fullmatch(body): risk.append("metadata_identifier")
            if (":" in body or "/" in body) and "sha256" not in src and "url" not in src: risk.append("intermediate_route_text")
            if SHA_BODY.fullmatch(body) and ("sha256" in src or "hash" in src or "cardan" in src): score += 1200
            if "v117" in src: score += 180
            if "artifact_log_reconstructed" in src: score += 400
            if "time_log" in src and any(w in body.lower() for w in ["time","clock","drift","anomaly"]): score += 350
            score -= 520*len(set(risk))
            item["v117_risk"]=sorted(set(risk))
            item["v117_score"]=score
            if not item["v117_risk"] and score >= 1200: verdict="trusted"
            elif len(item["v117_risk"]) <= 1 and score >= 750: verdict="promising"
            else: verdict="manual-review"
            item["v117_verdict"]=verdict
        # dedupe by preferred flag keeping best v117 score
        best={}
        for item in items:
            f=str(item.get("preferred_flag") or item.get("flag") or "")
            if not f: continue
            if f not in best or int(item.get("v117_score",0)) > int(best[f].get("v117_score",-10**9)):
                best[f]=item
        ranked=sorted(best.values(), key=lambda x:int(x.get("v117_score",0) or 0), reverse=True)
        summary["flags"]=ranked[:320]
        trusted=[x for x in ranked if x.get("v117_verdict")=="trusted"]
        promising=[x for x in ranked if x.get("v117_verdict")=="promising"]
        manual=[x for x in ranked if x.get("v117_verdict")=="manual-review"]
        best_item=(trusted or promising or ranked or [{}])[0]
        summary["v117_triage"]={
            "enabled":True,
            "version":"v117-real-corpus-triage",
            "updated":int(time.time()),
            "best_flag":best_item.get("preferred_flag") or best_item.get("flag"),
            "best_score":best_item.get("v117_score"),
            "best_verdict":best_item.get("v117_verdict"),
            "trusted":len(trusted),"promising":len(promising),"manual_review":len(manual),
            "suppressed_noise":len([x for x in ranked if x.get("v117_risk")]),
            "operator_hint":"v117 suppresses task placeholders, timestamps, metadata IDs, and intermediate route text; SHA/hash candidates are promoted when the task asks for them.",
        }
        return summary
    mod.project_summary=project_summary
