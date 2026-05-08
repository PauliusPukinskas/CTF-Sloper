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

REVERSED_PLACEHOLDER_BITS = {"elpmaxe", "tset", "galf", "redlohecalp", "ekaf", "rewsna"}

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

ROUTE_NOISE_TERMS = re.compile(
    r"rect_|read_columns|rows_reversed|serpentine|route|grid|stride|transpose|"
    r"permutation_wrap|bare_token_wrap|->rot\d+|classic_crypto:caesar_",
    re.I,
)

BODY_WORDS = {
    "admin", "alpha", "answer", "archive", "array", "base", "bytes", "calc",
    "caesar", "chain", "crypto", "cyber", "decode", "deleted", "docx",
    "extra", "flag", "forensics", "hidden", "inside", "interleave", "key",
    "lsb", "message", "negative", "office", "ok", "payload", "png",
    "pattern", "real", "recovered", "reverse", "rot", "secret", "shift", "sprint",
    "sqlite", "stego", "table", "text", "two", "vigenere", "wav", "xor",
    "zip", "zero", "width",
}


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


def _body_quality_bonus(flag: str, item: Any, cls: str) -> tuple[int, list[str]]:
    """Score flag body plausibility without requiring a private answer list.

    Older layers intentionally generate many transformed brace candidates.  A
    final submit list needs a second sanity pass: exact flags with word-like or
    leetspeak structure should float up, while alphabet-rotated route noise
    should remain available as manual evidence.
    """
    body = _body(flag)
    prefix = str(flag).split("{", 1)[0].lower() if "{" in str(flag) else ""
    low = body.lower()
    blob = _source_blob(item).lower()
    bonus = 0
    reasons: list[str] = []
    tokens = [t for t in re.split(r"[^A-Za-z0-9]+", low) if t]
    if not body:
        return -5000, ["empty_body"]
    word_hits = sum(1 for t in tokens if t in BODY_WORDS)
    if word_hits:
        bonus += min(1500, 360 * word_hits + (420 if word_hits >= 2 else 0))
        reasons.append("body_contains_ctf_workflow_word")
    if "_" in body and len(tokens) >= 2:
        bonus += 420
        reasons.append("structured_underscore_body")
    if any(ch.isdigit() for ch in body):
        bonus += 380
        reasons.append("digit_or_leetspeak_body")
    if re.search(r"[a-z][0-9][a-z0-9_]*|[0-9][a-z]", low):
        bonus += 320
        reasons.append("leetlike_body")
    if 8 <= len(body) <= 80:
        bonus += 180
        reasons.append("reasonable_body_length")
    known_prefixes = {"ctf_cs", "ctf_cm", "flag", "picoctf", "htb", "ductf", "csaw", "uiuctf", "ictf", "idekctf"}
    if prefix in known_prefixes:
        bonus += 700
        reasons.append("known_ctf_prefix")
    elif prefix and "_" in prefix and prefix not in {"ctf_cs", "ctf_cm"}:
        bonus -= 350
        reasons.append("odd_generated_prefix_shape")
    if re.search(r"(.)\1{4,}", body):
        bonus -= 1300
        reasons.append("repeated_character_noise")
    symbol_count = sum(1 for ch in body if not (ch.isalnum() or ch in "_-"))
    if len(body) >= 8 and symbol_count / max(1, len(body)) > 0.16:
        bonus -= 1700
        reasons.append("symbol_heavy_body")
    alpha = re.sub(r"[^A-Za-z]", "", body)
    if len(alpha) >= 12:
        vowels = sum(1 for ch in alpha.lower() if ch in "aeiou")
        ratio = vowels / max(1, len(alpha))
        if ratio < 0.18:
            bonus -= 750
            reasons.append("low_vowel_rot_noise")
        elif 0.22 <= ratio <= 0.55:
            bonus += 180
            reasons.append("natural_vowel_ratio")
    if ROUTE_NOISE_TERMS.search(blob):
        # Route/ROT candidates can still be real, but they should not outrank a
        # direct/decompressed/decrypted artifact unless the body itself has
        # strong structure.
        penalty = 1200
        if any(r in reasons for r in ("body_contains_ctf_workflow_word", "digit_or_leetspeak_body", "leetlike_body")):
            penalty = 450
        bonus -= penalty
        reasons.append("route_or_rotation_candidate_penalty")
        if len(tokens) >= 3 and word_hits <= 1 and not any(ch.isdigit() for ch in body):
            bonus -= 520
            reasons.append("mostly_unknown_route_tokens")
    if cls in {"decoded_artifact", "high_signal_artifact"} and re.search(r"base64|gzip|zlib|bz2|lzma|zip|sqlite|docx|png|wav|pcap|xor|zero_width|whitespace", blob):
        bonus += 850
        reasons.append("verified_transform_family_bonus")
    if re.fullmatch(r"(input|direct_ascii|plain|strict_direct)(\s+.*)?", blob.strip()) and "->" not in blob and not ROUTE_NOISE_TERMS.search(blob):
        bonus += 700
        reasons.append("direct_source_bonus")
    return bonus, reasons


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
            if any(ord(ch) < 32 or ord(ch) > 126 for ch in body):
                return "generated_noise", ["brace_mode_non_printable_body"], -12000
            if low in METADATA_BODIES or low in PLACEHOLDER_BODIES or len(body) < 5:
                return "metadata_noise", ["brace_mode_metadata_or_placeholder"], -9000
            if ROUTE_NOISE_TERMS.search(blob_low) and not re.search(r"base64|gzip|zlib|bz2|lzma|zip|sqlite|docx|png|wav|pcap|xor|zero_width|whitespace|direct_ascii", blob_low):
                return "manual_evidence", ["brace_mode_route_transform_needs_review"], -700
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
    selected_prefix = ""
    if "custom" not in selected and "brace" not in selected and not selected.startswith("{"):
        if "{" in selected:
            selected_prefix = selected.split("{", 1)[0]
        elif re.fullmatch(r"[a-z][a-z0-9_]{1,24}", selected) and selected not in {"any", "anyprefix", "any_prefix", "auto"}:
            selected_prefix = selected
    flag_prefix = flag.split("{", 1)[0].lower()
    if selected_prefix and flag_prefix and flag_prefix != selected_prefix and "custom" not in selected and "brace" not in selected:
        return "generated_noise", ["non_selected_flag_prefix"], -12000
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in body):
        return "generated_noise", ["non_printable_flag_body"], -12000
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
    if any(w in low for w in REVERSED_PLACEHOLDER_BITS) or low.startswith(("fak_", "ekaf_")):
        return "metadata_noise", ["reversed_placeholder_or_decoy_body"], -17500
    if len(body) < 5:
        return "generated_noise", ["too_short_for_submit"], -9000
    if ROUTE_NOISE_TERMS.search(blob_low) and len(body) <= 6 and not _has_artifact(item):
        return "generated_noise", ["short_route_transform_body"], -8500
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
    promoted_by_key: dict[str, dict[str, Any]] = {}
    manual_by_key: dict[str, dict[str, Any]] = {}

    for item in raw_items:
        flag = _flag_text(item).strip()
        if not flag:
            continue
        prefs = summary.get("user_preferences") if isinstance(summary.get("user_preferences"), dict) else {}
        selected_format = str(prefs.get("flag_format") or summary.get("preferred_flag_format") or "")
        cls, reasons, bonus = classify_candidate(item, selected_format)
        row = dict(item)
        row["ranking_class"] = cls
        quality_bonus, quality_reasons = _body_quality_bonus(str(row.get("preferred_flag") or row.get("flag") or flag), row, cls)
        row["ranking_reasons"] = sorted(set(map(str, reasons + quality_reasons)))
        row["ranking_score"] = int(row.get("v123_score", row.get("v117_score", row.get("rank_score", row.get("score", 0)))) or 0) + bonus + quality_bonus
        key = str(row.get("preferred_flag") or row.get("flag") or flag).lower()
        if cls in {"direct_flag", "decoded_artifact", "high_signal_artifact"}:
            if key not in promoted_by_key or int(row.get("ranking_score", 0) or 0) > int(promoted_by_key[key].get("ranking_score", 0) or 0):
                promoted_by_key[key] = row
        else:
            if key not in manual_by_key or int(row.get("ranking_score", 0) or 0) > int(manual_by_key[key].get("ranking_score", 0) or 0):
                manual_by_key[key] = row

    promoted = list(promoted_by_key.values())
    manual = [row for key, row in manual_by_key.items() if key not in promoted_by_key]
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
    best_flag = best.get("preferred_flag") or best.get("flag")
    best_score = int(best.get("ranking_score", best.get("score", 0)) or 0) if best else None
    for triage_key in ("v117_triage", "v116_triage", "v115_triage", "v114_triage"):
        triage = summary.get(triage_key)
        if isinstance(triage, dict) and best_flag:
            # Older evidence layers compute their own best flag before this
            # final gate runs.  Keep their counts, but make their headline
            # agree with the backend submit ordering so reports/benchmarks do
            # not point at stale ROT/route noise after reranking.
            triage["pre_clean_ranking_best_flag"] = triage.get("best_flag")
            triage["best_flag"] = best_flag
            triage["best_score"] = best_score
            triage["best_verdict"] = best.get("ranking_class") or triage.get("best_verdict")
            triage["clean_ranking_applied"] = True
    summary["sloper_final_ranking"] = {
        "enabled": True,
        "version": "clean-ranking-gate",
        "updated": int(time.time()),
        "promoted": len(promoted),
        "manual_evidence": len(manual),
        "best_flag": best_flag,
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
