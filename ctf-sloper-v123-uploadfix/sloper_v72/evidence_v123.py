"""v123 final candidate ordering.

Earlier layers intentionally preserve lots of possible flags.  That is useful
for manual CTF work, but the top of the UI should prefer the logical path:
decoded/extracted payloads above obvious examples/decoys and noisy
transposition braces.
"""
from __future__ import annotations

import re
import time
from typing import Any


BAD_WORD_RE = re.compile(r"fake|example|ignore|sample|placeholder|not[_-]?the[_-]?flag|flag[_-]?here", re.I)
ENCODEDISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{34,}$")


def _body(value: str) -> str:
    s = str(value or "")
    if "{" in s and s.endswith("}"):
        return s[s.find("{") + 1:-1]
    return s.strip("{}")


def _risk_and_bonus(item: dict[str, Any]) -> tuple[list[str], int]:
    raw_flag = str(item.get("flag") or item.get("value") or "")
    flag = str(item.get("preferred_flag") or raw_flag)
    body = _body(flag)
    low_body = body.lower()
    src = (
        str(item.get("source") or "")
        + " "
        + str(item.get("artifact") or "")
        + " "
        + " ".join(map(str, item.get("chain") or []))
        + " "
        + str(item.get("why") or "")
    ).lower()
    risks: list[str] = []
    bonus = 0
    if BAD_WORD_RE.search(low_body):
        risks.append("decoy_or_example_body")
        bonus -= 4200
    if low_body in {"flag", "test", "example", "sample", "..."}:
        risks.append("placeholder_body")
        bonus -= 4200
    if "v117_bare_brace_artifact_rescue" in src and ("mixed_case_body" in " ".join(map(str, item.get("v117_risk") or [])) or len(body) > 28):
        risks.append("noisy_bare_brace_rescue")
        bonus -= 2200
    if "v117_strict_artifact_rescue" in src:
        bonus += 950
    if ("bare_token_wrap" in src or "serpentine" in src or "read_columns" in src or "rows_reversed" in src) and "v117_strict_artifact_rescue" not in src:
        risks.append("permutation_wrap_candidate")
        bonus -= 950
    if ENCODEDISH_RE.fullmatch(body) and not any(k in src for k in ("sha256", "hash", "jwt", "token")):
        risks.append("encoded_intermediate_body")
        bonus -= 900
    if "." in body and not any(k in src for k in ("domain", "url", "dns", "http")):
        risks.append("filename_or_intermediate_text")
        bonus -= 800
    if any(k in src for k in ("base64->gzip", "gzip", "zlib", "bz2", "lzma", "decompress", "docx", "custom.xml", "sqlite", "wav_lsb", "image_lsb", "png_ztxt", "pcap", "dns", "http payload")):
        bonus += 900
    if item.get("flag_class") == "alternate_prefix":
        risks.append("non_selected_prefix")
        bonus -= 1500
    if flag.lower().startswith("ctf_cs{") and raw_flag and "{" in raw_flag and not raw_flag.lower().startswith("ctf_cs{"):
        risks.append("non_selected_prefix")
        bonus -= 1500
    if re.search(r"input->(?:base64|hex|url|gzip|zlib|bz2|lzma)(?:$|->html|->url)", src):
        bonus += 850
    if "->rot" in src and item.get("flag_class") == "alternate_prefix":
        bonus -= 600
    if any(k in src for k in ("strict wrapper", "matches selected flag prefix", "multiple evidence", "transform evidence")):
        bonus += 350
    if (src.strip() == "input" or src.startswith("input ")) and item.get("flag_class") == "preferred":
        bonus += 2600
    if re.search(r"[a-z][0-9]|[0-9][a-z]|_", body, re.I) and len(body) <= 80:
        bonus += 120
    return risks, bonus


def apply(mod: Any) -> None:
    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        prefs = summary.get("user_preferences") if isinstance(summary.get("user_preferences"), dict) else {}
        if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
            prefs = {**prefs, **meta.get("solver_settings", {})}
        target_prefix = str(prefs.get("flag_prefix") or "").strip()
        target_format = str(prefs.get("flag_format") or "").strip()
        items = [dict(x) if isinstance(x, dict) else {"flag": str(x)} for x in summary.get("flags", []) or []]
        ranked: list[dict[str, Any]] = []
        for item in items:
            raw = str(item.get("flag") or item.get("preferred_flag") or "")
            m = re.match(r"(?is)^([A-Za-z0-9_]{1,32})\{(.+)\}$", raw)
            if m and target_prefix and target_format not in {"any_prefix", "custom_regex"}:
                raw_prefix = m.group(1).strip()
                if (
                    target_format != "braces_only"
                    and raw_prefix
                    and raw_prefix.lower() != target_prefix.lower()
                    and item.get("flag_class") != "preferred"
                ):
                    item["flag_class"] = "alternate_prefix"
                if target_format == "braces_only":
                    item["preferred_flag"] = "{" + m.group(2).strip() + "}"
                else:
                    item["preferred_flag"] = target_prefix + "{" + m.group(2).strip() + "}"
                    if raw_prefix.lower() == target_prefix.lower():
                        item["flag_class"] = "preferred"
            risks, bonus = _risk_and_bonus(item)
            base = int(item.get("v117_score", item.get("rank_score", item.get("score", 0))) or 0)
            score = base + bonus - 650 * len(set(risks))
            old_risks = item.get("v117_risk") or item.get("risk") or []
            if isinstance(old_risks, str):
                old_risks = [old_risks]
            all_risks = sorted(set(map(str, list(old_risks) + risks)))
            item["v123_score"] = score
            item["v123_risk"] = all_risks
            item["v123_verdict"] = "trusted" if not all_risks and score >= 1500 else ("promising" if score >= 800 else "manual-review")
            ranked.append(item)
        seen = set()
        deduped = []
        for item in sorted(ranked, key=lambda x: int(x.get("v123_score", 0) or 0), reverse=True):
            key = str(item.get("preferred_flag") or item.get("flag") or "").lower()
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        summary["flags"] = deduped[:320]
        summary["preferred_flags"] = deduped[:320]
        best = deduped[0] if deduped else {}
        summary["v123_triage"] = {
            "enabled": True,
            "version": "v123-solve-rate-evidence-ordering",
            "updated": int(time.time()),
            "best_flag": best.get("preferred_flag") or best.get("flag"),
            "best_score": best.get("v123_score"),
            "best_verdict": best.get("v123_verdict"),
            "demoted": len([x for x in deduped if x.get("v123_risk")]),
            "operator_hint": "Decoded/extracted evidence is ranked above decoys/examples and noisy bare-brace rescues; all candidates remain visible.",
        }
        return summary

    mod.project_summary = project_summary
    mod.SL123_EVIDENCE = "v123-solve-rate-evidence-ordering"
