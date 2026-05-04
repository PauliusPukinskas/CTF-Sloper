"""v112 bounded fast-lane solver.

Safe default analysis path for common CTF encodings.  It is intentionally
bounded: no execution of uploaded binaries, no recursive filesystem scans, and
all decode chains are limited by the user-selected profile.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import html
import lzma
import os
import re
import time
import zlib
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import unquote

DEFAULT_FLAG_RE = re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}")
TOKEN_RE = re.compile(r"%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){3,}|[A-Za-z0-9+/=_-]{10,}|[A-Za-z2-7=]{16,}|[0-9A-Fa-f]{8,}|(?:[01]{8}[\s_-]*){3,}")
MORSE_RE = re.compile(r"(?:[.\-/]{1,7}\s+){4,}[.\-/]{1,7}")
DECIMAL_BYTES_RE = re.compile(r"\b(?:\d{1,3}[,\s;:|]+){5,}\d{1,3}\b")

MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-----": "0",
    "-.-.--": "!", ".-.-.-": ".", "--..--": ",", "..--..": "?", "-....-": "-", "..--.-": "_",
}


def _flag_patterns(profile: dict[str, Any] | None = None) -> list[re.Pattern[str]]:
    if isinstance(profile, dict) and profile.get("_compiled_patterns"):
        return profile["_compiled_patterns"]
    patterns: list[re.Pattern[str]] = []
    if isinstance(profile, dict):
        rx = profile.get("flag_regex") or profile.get("custom_flag_regex")
        if rx:
            try:
                patterns.append(re.compile(str(rx)))
            except Exception:
                pass
    if all(getattr(p, "pattern", "") != DEFAULT_FLAG_RE.pattern for p in patterns):
        patterns.append(DEFAULT_FLAG_RE)
    return patterns


def _safe_text(raw: bytes, limit: int = 2_000_000) -> str:
    data = raw[:limit]
    chunks: list[str] = []
    for enc in ("utf-8", "utf-16le", "utf-16be", "latin1"):
        try:
            txt = data.decode(enc, errors="ignore")
            if txt and txt not in chunks:
                chunks.append(txt)
        except Exception:
            pass
    return "\n".join(chunks)


def _rot(s: str, n: int) -> str:
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + n) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + n) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    good = sum(1 for b in raw[:2000] if b in b"\t\n\r" or 32 <= b <= 126)
    return good / min(len(raw), 2000)


def _add_flag(flags: dict[str, dict[str, Any]], flag: str, source: str, score: int = 1000, allow_plain: bool = False) -> None:
    flag = str(flag).strip()
    if not flag:
        return
    if not allow_plain and ("{" not in flag or not flag.endswith("}")):
        return
    low = flag.lower()
    if any(bad in low for bad in ("fake", "dummy", "placeholder", "not_the_flag", "not-flag", "example")):
        return
    prev = flags.get(low)
    if not prev:
        flags[low] = {"flag": flag, "score": score, "status": "confirmed", "source": source, "sources": [source]}
    elif source not in prev.setdefault("sources", []):
        prev["sources"].append(source)
        prev["score"] = max(int(prev.get("score", 0)), score)


def _scan_direct(flags: dict[str, dict[str, Any]], text: str, label: str, profile: dict[str, Any] | None, score: int) -> None:
    patterns = _flag_patterns(profile)
    allow_plain = bool(isinstance(profile, dict) and profile.get("flag_format") == "custom_regex" and profile.get("custom_flag_regex"))
    for rx in patterns:
        for m in rx.finditer(text or ""):
            cand = m.group(0)
            try:
                for g in m.groups():
                    if isinstance(g, str) and ("{" in g and "}" in g or allow_plain):
                        cand = g
                        break
            except Exception:
                pass
            _add_flag(flags, cand, label, score, allow_plain=allow_plain)


def _dedupe_add(out: list[tuple[str, bytes]], seen: set[str], label: str, raw: bytes, max_len: int = 1_000_000) -> None:
    if not raw or len(raw) > max_len:
        return
    key = hashlib.sha256(raw[:4096] + str(len(raw)).encode()).hexdigest()
    if key in seen:
        return
    seen.add(key)
    out.append((label, raw))


def _decode_morse(seq: str) -> str:
    parts = seq.strip().replace("/", " / ").split()
    out = []
    for p in parts:
        if p == "/":
            out.append(" ")
        else:
            out.append(MORSE.get(p, ""))
    return "".join(out)


def _byte_candidates_from_text(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    small = text[:1_000_000]

    def add(label: str, raw: bytes) -> None:
        compressed = raw.startswith(b"\x1f\x8b") or raw.startswith(b"BZh") or raw.startswith(b"\xfd7zXZ") or raw.startswith(b"x\x9c") or raw.startswith(b"x\xda") or raw.startswith(b"x\x01")
        if compressed or _printable_ratio(raw) >= 0.35 or (b"{" in raw and b"}" in raw):
            _dedupe_add(out, seen, label, raw)

    # Whole-text transforms.
    stripped = re.sub(r"\s+", "", small.strip())
    if stripped:
        if len(stripped) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]{8,}", stripped):
            try: add("hex_whole", bytes.fromhex(stripped))
            except Exception: pass
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", stripped):
            pad = "=" * ((4 - len(stripped) % 4) % 4)
            for alt, name in ((None, "base64_whole"), (b"-_", "base64url_whole")):
                try: add(name, base64.b64decode((stripped + pad).encode(), altchars=alt, validate=False))
                except Exception: pass
        if re.fullmatch(r"[A-Z2-7=]{16,}", stripped.upper()):
            try: add("base32_whole", base64.b32decode(stripped.upper().encode(), casefold=True))
            except Exception: pass
        if len(stripped) >= 10:
            for fn, name in ((base64.b85decode, "base85_whole"), (base64.a85decode, "ascii85_whole")):
                try: add(name, fn(stripped.encode()))
                except Exception: pass

    # Token transforms.
    for tok in TOKEN_RE.findall(small)[:1000]:
        tok = tok.strip()
        if tok.startswith("%"):
            try: add("percent", unquote(tok).encode())
            except Exception: pass
        clean_bin = re.sub(r"[^01]", "", tok)
        if len(clean_bin) >= 24 and len(clean_bin) % 8 == 0:
            try: add("binary_bits", bytes(int(clean_bin[i:i+8], 2) for i in range(0, len(clean_bin), 8)))
            except Exception: pass
        clean_hex = tok[2:] if tok.lower().startswith("0x") else tok
        if len(clean_hex) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]{8,}", clean_hex):
            try: add("hex", bytes.fromhex(clean_hex))
            except Exception: pass
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", tok):
            pad = "=" * ((4 - len(tok) % 4) % 4)
            for alt, name in ((None, "base64"), (b"-_", "base64url")):
                try: add(name, base64.b64decode((tok + pad).encode(), altchars=alt, validate=False))
                except Exception: pass
        if re.fullmatch(r"[A-Z2-7=]{16,}", tok.upper()):
            try: add("base32", base64.b32decode(tok.upper().encode(), casefold=True))
            except Exception: pass

    for m in DECIMAL_BYTES_RE.findall(small)[:200]:
        nums = [int(x) for x in re.findall(r"\d{1,3}", m)]
        if nums and all(0 <= n <= 255 for n in nums):
            try: add("decimal_bytes", bytes(nums))
            except Exception: pass

    for m in MORSE_RE.findall(small)[:200]:
        decoded = _decode_morse(m)
        if len(decoded) >= 4:
            add("morse", decoded.encode())

    return out


def _byte_candidates_from_raw(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    data = raw[:1_500_000]

    def add(label: str, blob: bytes) -> None:
        if _printable_ratio(blob) >= 0.20 or (b"{" in blob and b"}" in blob):
            _dedupe_add(out, seen, label, blob, max_len=2_000_000)

    if len(data) >= 2:
        if data.startswith(b"\x1f\x8b"):
            try: add("gzip", gzip.decompress(data))
            except Exception: pass
        if data.startswith(b"BZh"):
            try: add("bz2", bz2.decompress(data))
            except Exception: pass
        if data.startswith(b"\xfd7zXZ"):
            try: add("xz_lzma", lzma.decompress(data))
            except Exception: pass
        for wbits, name in ((zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "zlib_raw")):
            try: add(name, zlib.decompress(data, wbits))
            except Exception: pass
    return out


def scan_text(text: str, profile: dict[str, Any] | None = None, raw: bytes | None = None) -> list[dict[str, Any]]:
    flags: dict[str, dict[str, Any]] = {}
    max_depth = 2
    max_nodes = 400
    if isinstance(profile, dict):
        try: max_depth = max(0, min(6, int(profile.get("max_depth", 2))))
        except Exception: pass
        try: max_nodes = max(80, min(3000, int(profile.get("max_artifacts", 800))))
        except Exception: pass
    raw = raw if raw is not None else text.encode("latin1", errors="ignore")

    queue: deque[tuple[str, bytes, int]] = deque([("input", raw[:2_000_000], 0)])
    seen_nodes: set[str] = set()
    processed = 0

    while queue and processed < max_nodes:
        label, blob, depth = queue.popleft()
        sig = hashlib.sha256(blob[:4096] + str(depth).encode() + label.encode()).hexdigest()
        if sig in seen_nodes:
            continue
        seen_nodes.add(sig)
        processed += 1
        txt = _safe_text(blob)
        base_score = max(650, 1150 - depth * 80)
        _scan_direct(flags, txt, label, profile, base_score)
        _scan_direct(flags, html.unescape(txt), f"{label}->html", profile, base_score - 40)
        _scan_direct(flags, unquote(txt), f"{label}->url", profile, base_score - 40)
        _scan_direct(flags, txt[::-1], f"{label}->reverse", profile, base_score - 80)
        for n in range(1, 26):
            _scan_direct(flags, _rot(txt, n), f"{label}->rot{n}", profile, base_score - (90 if n == 13 else 150))

        # Single-byte XOR only on small nodes to keep UI responsive.
        if len(blob) <= 250_000:
            for key in range(1, 256):
                x = bytes(b ^ key for b in blob)
                if b"{" in x and b"}" in x and (b"ctf" in x.lower() or b"flag" in x.lower()):
                    _scan_direct(flags, _safe_text(x), f"{label}->xor{key}", profile, base_score - 120)

        if depth >= max_depth:
            continue
        candidates = _byte_candidates_from_raw(blob) + _byte_candidates_from_text(txt)
        for name, child in candidates[:80]:
            queue.append((f"{label}->{name}", child, depth + 1))

    return sorted(flags.values(), key=lambda x: (int(x.get("score", 0)), len(x.get("sources", []))), reverse=True)


def analyze_bytes(raw: bytes, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.time()
    text = _safe_text(raw)
    flags = scan_text(text, profile=profile, raw=raw)
    strings = [s for s in re.findall(r"[ -~]{4,}", raw[:1_000_000].decode("latin1", errors="ignore"))[:1200]]
    return {
        "fast_lane_version": "v112-recursive-decoders",
        "profile": {k: profile.get(k) for k in ("flag_format", "flag_prefix", "flag_label", "attack_preset", "difficulty", "max_depth") if isinstance(profile, dict) and k in profile},
        "runtime_ms": int((time.time() - started) * 1000),
        "flags": flags,
        "strings": strings,
        "chain_results": flags[:80],
    }


def _profile_for_project(mod, pid: str) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    try:
        if hasattr(mod, "sl111_read_settings"):
            profile = mod.sl111_read_settings()
        meta = mod.jread(mod.meta_path(pid), {}) if hasattr(mod, "meta_path") else {}
        if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
            merged = {**profile, **meta.get("solver_settings", {})}
            if hasattr(mod, "sl111_normalize_settings"):
                profile = mod.sl111_normalize_settings(merged)
            else:
                profile = merged
        if hasattr(mod, "sl111_compile_flag_patterns"):
            profile["_compiled_patterns"] = mod.sl111_compile_flag_patterns(profile)
    except Exception:
        profile = {}
    return profile


def make_report(mod, pid: str, path: Path, root: Path, raw: bytes, index: int = 1, total: int = 1) -> dict[str, Any]:
    profile = _profile_for_project(mod, pid)
    res = analyze_bytes(raw, profile=profile)
    try:
        rel = str(path.relative_to(root))
    except Exception:
        rel = path.name
    fileout = ""
    try:
        if hasattr(mod, "exists") and mod.exists("file"):
            fileout = mod.run(["file", str(path)], timeout=5, maxchars=2000).get("out", "")
    except Exception:
        fileout = ""
    flat_flags = [x["flag"] for x in res["flags"]]
    arts = []
    for i, item in enumerate(res["flags"][:80], 1):
        arts.append({
            "name": f"flag_candidate_{i}.txt",
            "kind": "flag_candidate",
            "source": item.get("source", "fast_lane"),
            "file": rel,
            "score": item.get("score", 0),
            "size": len(item.get("flag", "")),
            "note": item.get("flag", ""),
            "exists": False,
        })
    return {
        "id": hashlib.sha256(str(path).encode()).hexdigest()[:12],
        "name": path.name,
        "path": str(path),
        "rel": rel,
        "size": len(raw),
        "kind": "fast_lane_text_or_bytes",
        "file": fileout,
        "flags": flat_flags,
        "verified_flags": res["flags"],
        "findings": res["flags"][:100],
        "chain_results": res["chain_results"],
        "strings": res["strings"],
        "outputs": [],
        "previews": [],
        "commands": [],
        "extracted": [],
        "expert_contexts": [],
        "decoders": res["chain_results"],
        "intermediate_files": [],
        "next_steps": [],
        "hypotheses": [],
        "structured_clues": [],
        "agent_runs": [],
        "agent_files": [],
        "transformations": [],
        "artifacts": arts,
        "v110_fast_lane": {"enabled": True, "runtime_ms": res["runtime_ms"], "legacy_deep_skipped": os.environ.get("SLOPER_ENABLE_LEGACY_DEEP", "0") != "1", "profile": res.get("profile", {})},
        "progress": {"index": index, "total": total},
    }


def apply(mod) -> None:
    old_analyze = getattr(mod, "analyze_file", None)

    def analyze_file(pid, path, root, i=1, total=1):
        p = Path(path)
        r = Path(root)
        max_bytes = int(os.environ.get("SLOPER_FAST_LANE_MAX_BYTES", "3000000"))
        try:
            raw = p.read_bytes()[:max_bytes]
        except Exception as e:
            return {"name": p.name, "path": str(p), "rel": p.name, "error": str(e), "flags": [], "artifacts": []}
        fast = make_report(mod, pid, p, r, raw, i, total)
        if os.environ.get("SLOPER_ENABLE_LEGACY_DEEP", "0") != "1":
            return fast
        if not old_analyze:
            return fast
        try:
            legacy = old_analyze(pid, path, root, i, total)
            if isinstance(legacy, dict):
                seen = {str(x).lower() for x in legacy.get("flags", [])}
                for f in fast.get("flags", []):
                    if f.lower() not in seen:
                        legacy.setdefault("flags", []).insert(0, f)
                legacy.setdefault("v110_fast_lane", fast.get("v110_fast_lane", {}))
                legacy.setdefault("chain_results", [])[:0] = fast.get("chain_results", [])[:40]
                legacy.setdefault("artifacts", [])[:0] = fast.get("artifacts", [])[:40]
                return legacy
        except Exception as e:
            fast["legacy_error"] = str(e)
        return fast

    mod.analyze_file = analyze_file

    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        flags = []
        seen = set()
        artifacts = []
        files = []
        for r in list(reports or [])[:500]:
            if not isinstance(r, dict):
                continue
            files.append({"name": r.get("name"), "rel": r.get("rel"), "path": r.get("path"), "size": r.get("size"), "kind": r.get("kind"), "flags": r.get("flags", [])[:20] if isinstance(r.get("flags", []), list) else []})
            for item in list(r.get("verified_flags", []) or []) + list(r.get("findings", []) or []) + [{"flag": f, "score": 900, "status": "confirmed"} for f in (r.get("flags", []) or [])]:
                f = item.get("flag") if isinstance(item, dict) else str(item)
                if not f or f.lower() in seen:
                    continue
                seen.add(f.lower())
                row = dict(item) if isinstance(item, dict) else {"flag": f}
                row.setdefault("file", r.get("rel") or r.get("name") or "?")
                row.setdefault("score", 900)
                row.setdefault("status", "confirmed")
                flags.append(row)
            artifacts.extend([a for a in (r.get("artifacts", []) or []) if isinstance(a, dict)][:100])
        profile = {}
        try:
            profile = mod.sl111_read_settings() if hasattr(mod, "sl111_read_settings") else {}
            if isinstance(meta, dict) and isinstance(meta.get("solver_settings"), dict):
                merged = {**profile, **meta.get("solver_settings", {})}
                profile = mod.sl111_normalize_settings(merged) if hasattr(mod, "sl111_normalize_settings") else merged
        except Exception:
            profile = {}

        def pref_score(row):
            f = str(row.get("flag", ""))
            try:
                if hasattr(mod, "sl111_shape_summary"):
                    cls = __import__("sloper_v72.control_plane_v111", fromlist=["classify_flag"]).classify_flag(f, profile)
                    return {"preferred": 5, "alternate_prefix": 3, "braces_only": 2, "fragment": 1}.get(cls, 0)
            except Exception:
                pass
            low = f.lower()
            if low.startswith("ctf_cs{"):
                return 4
            if low.startswith("ctf_cm{"):
                return 3
            if low.startswith("flag{"):
                return 2
            if low.startswith("ctf"):
                return 1
            return 0

        flags.sort(key=lambda x: (pref_score(x), int(x.get("score", 0) or 0), len(str(x.get("flag", "")))), reverse=True)
        preferred = [f for f in flags if pref_score(f) >= 2]
        related = [f for f in flags if pref_score(f) < 2]
        display_flags = (preferred or flags)[:120]
        summary = {
            "flags": display_flags,
            "related_candidate_flags": related[:120],
            "exact_flags": [f for f in display_flags if "{" in str(f.get("flag", ""))][:120],
            "artifacts": artifacts[:500],
            "files": files[:500],
            "v110_fast_summary": {"enabled": True, "version": "v112-recursive-decoders", "legacy_project_summary_skipped": os.environ.get("SLOPER_ENABLE_LEGACY_SUMMARY", "0") != "1", "related_suppressed": len(related)},
        }
        if hasattr(mod, "sl111_shape_summary"):
            summary = mod.sl111_shape_summary(summary, profile)
        if os.environ.get("SLOPER_ENABLE_LEGACY_SUMMARY", "0") == "1" and old_summary:
            try:
                legacy = old_summary(reports, meta)
                if isinstance(legacy, dict):
                    legacy.update(summary)
                    return legacy
            except Exception as e:
                summary["legacy_summary_error"] = str(e)
        return summary

    mod.project_summary = project_summary
    mod.sl110_fast_scan_text = scan_text
    mod.sl110_fast_analyze_bytes = analyze_bytes
    mod.SL112_FAST_LANE = "v112-recursive-decoders"
