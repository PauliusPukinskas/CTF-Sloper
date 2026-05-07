"""Final backend ranking gate for CTF SLOPER.

Older solver layers intentionally keep many candidates for human review.  This
module makes the submission-facing lists strict again: metadata labels and
generated wrappers are preserved as evidence, but they no longer outrank real
decoded/extracted flags.
"""
from __future__ import annotations

import re
import time
from typing import Any


STRICT_RE = re.compile(r"(?is)^([A-Za-z0-9_]{1,32})\{([^{}\r\n]{1,220})\}$")

METADATA_BODIES = {
    "author",
    "category",
    "challenge",
    "description",
    "difficulty",
    "easy",
    "file",
    "files",
    "flag_format",
    "format",
    "hard",
    "hint",
    "medium",
    "metadata",
    "name",
    "notes",
    "readme",
    "solution",
    "task",
    "title",
    "type",
}

PLACEHOLDER_BODIES = {
    "...",
    "answer",
    "answer_here",
    "example",
    "fake",
    "flag",
    "placeholder",
    "rastas_tekstas",
    "sample",
    "test",
    "vietos_pavadinimas",
}

WEAK_SOURCE_TERMS = re.compile(
    r"statement|readme|task\s*text|metadata|filename metadata|member names|bare_token_wrap|"
    r"wrapper demotion|route text|format hint|project settings",
    re.I,
)

DECODED_TERMS = re.compile(
    r"base64|base32|base85|ascii85|hex|url|html|gzip|zlib|bz2|lzma|xor|rot_?\d+|"
    r"rot47|caesar|atbash|vigenere|decode|decoded|decompress|transform|zero[-_ ]width|"
    r"whitespace|lsb|png|jpeg|zip|archive|carve|docx|sqlite|pdf|pcap|dns|http|wav",
    re.I,
)

HIGH_SIGNAL_TERMS = re.compile(
    r"artifact|payload|extract|extracted|comment|custom\.xml|office|document|database|"
    r"binary|strings|array|constraint|reversing|network|final_|classic_crypto",
    re.I,
)


def _flag_text(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("preferred_flag") or item.get("flag") or item.get("value") or "")
    return str(item or "")


def _body(flag: str) -> str:
    m = STRICT_RE.match(str(flag or "").strip())
    return m.group(2).strip() if m else str(flag or "").strip().strip("{}")


def _source_blob(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    vals: list[str] = []
    for key in ("source", "artifact", "file", "bucket", "why", "why_not_promoted", "method", "kind", "path"):
        vals.append(str(item.get(key) or ""))
    chain = item.get("chain")
    if isinstance(chain, (list, tuple)):
        vals.extend(str(x) for x in chain)
    return " ".join(vals)


def _has_artifact(item: Any) -> bool:
    return isinstance(item, dict) and bool(str(item.get("artifact") or item.get("path") or "").strip())


def classify_candidate(item: Any, selected_format: str = "") -> tuple[str, list[str], int]:
    flag = _flag_text(item).strip()
    body = _body(flag)
    low = body.lower().strip()
    blob = _source_blob(item)
    blob_low = blob.lower()
    reasons: list[str] = []
    bonus = 0

    if not STRICT_RE.match(flag):
        selected = (selected_format or "").lower()
        if ("brace" in selected or selected.strip().startswith("{")) and flag.startswith("{") and flag.endswith("}"):
            if low in METADATA_BODIES or low in PLACEHOLDER_BODIES or len(body) < 5:
                return "metadata_noise", ["brace_mode_metadata_or_placeholder"], -9000
            if _has_artifact(item) or "transform" in blob_low or "input" in blob_low:
                return "high_signal_artifact", ["selected_braces_only_candidate"], 2200
            return "direct_flag", ["selected_braces_only_candidate"], 1000
        if ("brace" in selected or selected.strip().startswith("{")) and not flag.startswith("{"):
            return "generated_noise", ["non_brace_candidate_in_braces_only_mode"], -13000
        if "custom" in selected and isinstance(item, dict):
            if "custom regex hit" in blob_low or str(item.get("flag_class") or "").lower() == "preferred":
                return "direct_flag", ["selected_custom_regex_candidate"], 1200
            return "generated_noise", ["non_custom_regex_candidate_in_custom_mode"], -13000
        return "manual_evidence", ["not_strict_submit_shape"], -1500
    selected = (selected_format or "").strip().lower()
    if ("brace" in selected or selected.startswith("{")) and not flag.startswith("{"):
        return "generated_noise", ["non_brace_candidate_in_braces_only_mode"], -13000
    if "custom" in selected and isinstance(item, dict) and "custom regex hit" not in blob_low and str(item.get("flag_class") or "").lower() != "preferred":
        return "generated_noise", ["non_custom_regex_candidate_in_custom_mode"], -13000
    selected_prefix = selected.split("{", 1)[0] if "{" in selected and not selected.startswith("{") else ""
    flag_prefix = flag.split("{", 1)[0].lower()
    if selected_prefix and flag_prefix and flag_prefix != selected_prefix and "custom" not in selected and "brace" not in selected:
        return "generated_noise", ["non_selected_flag_prefix"], -12000
    if isinstance(item, dict):
        raw_flag = str(item.get("flag") or "").strip()
        preferred = str(item.get("preferred_flag") or "").strip()
        risks = " ".join(str(x) for key in ("v123_risk", "v117_risk", "v116_risk", "warnings") for x in (item.get(key) or []))
        verdicts = " ".join(str(item.get(key) or "") for key in ("v123_verdict", "v117_verdict", "v116_verdict", "verdict"))
        if "permutation_wrap_candidate" in risks and "brace" not in (selected_format or "").lower() and not (selected_format or "").strip().startswith("{"):
            return "generated_noise", ["permutation_wrap_candidate"], -10000
        if re.search(r"manual-review|low", verdicts, re.I) and re.search(r"xor_weak|mixed_case_body|non_selected_prefix|very short", risks, re.I):
            return "generated_noise", ["prior_evidence_layer_marked_manual_or_low_risk"], -11000
        if raw_flag.startswith("{") and preferred.startswith("ctf_cs{") and "wrap" not in blob_low and "statement" not in blob_low:
            return "generated_noise", ["generated_wrapper_from_bare_braces"], -12000
        if raw_flag and preferred and raw_flag != preferred and STRICT_RE.match(raw_flag) and STRICT_RE.match(preferred):
            raw_prefix = raw_flag.split("{", 1)[0].lower()
            preferred_prefix = preferred.split("{", 1)[0].lower()
            if raw_prefix != preferred_prefix and "wrap" not in blob_low and "statement" not in blob_low:
                return "generated_noise", ["generated_wrapper_from_nonmatching_prefix"], -12000
    if low in METADATA_BODIES:
        return "metadata_noise", ["readme_or_statement_label"], -20000
    if low in PLACEHOLDER_BODIES or any(w in low for w in ("example", "placeholder", "not_the_flag", "fake")):
        return "metadata_noise", ["placeholder_or_decoy_body"], -18000
    if len(body) < 5:
        return "generated_noise", ["too_short_for_submit"], -9000
    if WEAK_SOURCE_TERMS.search(blob) and not _has_artifact(item):
        return "metadata_noise", ["weak_metadata_source_without_artifact"], -14000
    if WEAK_SOURCE_TERMS.search(blob) and re.fullmatch(r"[A-Za-z][A-Za-z0-9 -]{2,32}", body) and not re.search(r"[_0-9{}]", body):
        return "metadata_noise", ["metadata_like_plain_word"], -14000

    if DECODED_TERMS.search(blob):
        reasons.append("decoded_or_transformed_source")
        bonus += 3600
        if "classic_crypto" in blob_low:
            reasons.append("deterministic_classic_crypto_agent")
            bonus += 2600
        if _has_artifact(item):
            return "decoded_artifact", reasons, bonus
    if HIGH_SIGNAL_TERMS.search(blob) or _has_artifact(item):
        reasons.append("high_signal_artifact_source")
        bonus += 2600
        return "high_signal_artifact", reasons, bonus

    if isinstance(item, dict) and str(item.get("status") or "").lower() in {"confirmed", "trusted", "likely"}:
        reasons.append("strict_candidate_from_solver")
        bonus += 1400
        return "direct_flag", reasons, bonus
    return "direct_flag", ["strict_direct_candidate_no_metadata_body"], 800


def rerank_summary(summary: dict[str, Any]) -> dict[str, Any]:
    raw_items = [dict(x) if isinstance(x, dict) else {"flag": str(x)} for x in (summary.get("flags") or [])]
    promoted: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []
    seen_promoted: set[str] = set()
    seen_manual: set[str] = set()

    for item in raw_items:
        flag = _flag_text(item).strip()
        if not flag:
            continue
        cls, reasons, bonus = classify_candidate(item, str(summary.get("preferred_flag_format") or ""))
        row = dict(item)
        row["ranking_class"] = cls
        row["ranking_reasons"] = sorted(set(map(str, reasons)))
        row["ranking_score"] = int(row.get("v123_score", row.get("v117_score", row.get("rank_score", row.get("score", 0)))) or 0) + bonus
        key = str(row.get("preferred_flag") or row.get("flag") or flag).lower()
        if cls in {"direct_flag", "decoded_artifact", "high_signal_artifact"}:
            if key not in seen_promoted:
                seen_promoted.add(key)
                promoted.append(row)
        else:
            if key not in seen_manual:
                seen_manual.add(key)
                manual.append(row)

    promoted.sort(key=lambda x: (int(x.get("ranking_score", 0) or 0), int(x.get("score", 0) or 0)), reverse=True)
    manual.sort(key=lambda x: (int(x.get("ranking_score", 0) or 0), int(x.get("score", 0) or 0)), reverse=True)

    summary["flags"] = promoted[:160]
    summary["preferred_flags"] = promoted[:160]
    related = [dict(x) if isinstance(x, dict) else {"flag": str(x)} for x in (summary.get("related_candidate_flags") or [])]
    summary["related_candidate_flags"] = (manual + related)[:240]
    summary.setdefault("unconfirmed_evidence", [])
    existing_unc = {str(x.get("preferred_flag") or x.get("flag") or x.get("value") or "").lower() for x in summary["unconfirmed_evidence"] if isinstance(x, dict)}
    for row in manual:
        key = str(row.get("preferred_flag") or row.get("flag") or "").lower()
        if key and key not in existing_unc:
            ev = dict(row)
            ev.setdefault("bucket", "manual_evidence")
            ev["why_not_promoted"] = "Final ranking gate classified this as metadata/generated/low-context evidence, not a submit-ready flag."
            summary["unconfirmed_evidence"].append(ev)
            existing_unc.add(key)
    best = promoted[0] if promoted else {}
    summary["sloper_final_ranking"] = {
        "enabled": True,
        "version": "clean-ranking-gate",
        "updated": int(time.time()),
        "promoted": len(promoted),
        "manual_evidence": len(manual),
        "best_flag": best.get("preferred_flag") or best.get("flag"),
        "best_class": best.get("ranking_class"),
        "operator_hint": "Submission flags require direct/decoded/high-signal evidence; README metadata labels are kept only as manual evidence.",
    }
    return summary


def apply(mod: Any) -> None:
    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        if isinstance(summary, dict):
            for report in reports or []:
                if not isinstance(report, dict):
                    continue
                for key in ("verified_flags", "workflow_evidence"):
                    for row in report.get(key, []) or []:
                        if isinstance(row, dict) and row.get("flag"):
                            summary.setdefault("flags", []).append(dict(row))
        return rerank_summary(summary if isinstance(summary, dict) else {"flags": []})

    mod.project_summary = project_summary
    mod.sloper_clean_rerank_summary = rerank_summary
    mod.SLOPER_CLEAN_RANKING = "clean-ranking-gate"
