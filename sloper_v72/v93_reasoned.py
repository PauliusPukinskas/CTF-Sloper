"""CTF SLOPER v93 reasoned stable pipeline.

This layer keeps the old monolith available, but makes the normal AutoSolve path
bounded and evidence-driven.  It runs targeted local workflows, writes real
transformation artifacts, then aggressively filters final flags so generated
candidate JSON cannot promote random text.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import html
import io
import json
import lzma
import quopri
import urllib.parse
import math
import re
import shutil
import struct
import tarfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any, Iterable

from .health import AGENT_HEALTH, agent_crash
from .artifact_hub import compact_hub

try:
    from . import workflow_v74 as v74
except Exception:  # pragma: no cover
    v74 = None

try:
    from . import workflow_v75 as v75
except Exception:  # pragma: no cover
    v75 = None

try:
    from . import universal_v89 as v89
except Exception:  # pragma: no cover
    v89 = None


STRICT_RE = re.compile(r"ctf_cs\{([A-Za-z0-9_\-:+./=]{1,140})\}")
ALT_RE = re.compile(r"(?<![A-Za-z0-9_])(?:flag|ctf|cyber|sprint|tsg)?\{([A-Za-z0-9][A-Za-z0-9_\-:+./=]{3,140})\}", re.I)
BARE_TOKEN_RE = re.compile(r"\b[a-z0-9]+(?:_[a-z0-9]+){1,10}\b", re.I)

BAD_BODIES = {
    "example", "example_flag", "test", "test_flag", "flag", "placeholder",
    "answer", "answer_here", "your_flag_here", "todo", "dummy", "sample",
    "fake", "ctf", "ctf_cs", "vietos_pavadinimas", "rastas_tekstas",
}

BAD_SUBSTRINGS = {
    "ctf_sloper", "documents", "users", "project", "projects", "generated",
    "semantic_answer_candidates", "wrap_candidates", "alternate_flag_candidates",
    "basefont", "helvetica", "endobj", "xmlns", "schema", "quarantine",
    "provenance", "com_apple", "integer_value_text", "create_table",
    "carved_", "gzip_offset", "bzip2_offset",
    "lsb_bit", "route_transposition", "generic_xor", "known_prefix", "chain_input", "input_rot", "utf_8",
}

SEMANTIC_HINTS = re.compile(
    r"(cyber|sprint|calc|archive|deleted|d3l3t3d|g0n3|secret|hidden|"
    r"password|raktas|slapta|steg|st3g|lsb|xor|zip|gzip|morse|rail|"
    r"route|interleave|decode|l0ud|l4b|ok|final|real|found|hash|sha256)",
    re.I,
)

LEET_TRANS = str.maketrans({"0": "o", "1": "i", "2": "z", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
WORD_HINTS = {
    "very", "loud", "lab", "in", "the", "you", "later", "not", "gone",
    "deleted", "calc", "byte", "array", "xor", "zip", "gzip", "archive",
    "password", "secret", "hidden", "stego", "vilnius", "sprint", "cyber",
    "base", "decode", "morse", "rail", "interleave", "flag", "ok",
}


def safe_name(name: str) -> str:
    if v74 and hasattr(v74, "safe_name"):
        return v74.safe_name(name)
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "file"))[:140] or "file"


def now_text(mod: Any) -> str:
    try:
        return mod.now()
    except Exception:
        return time.strftime("%Y-%m-%d %H:%M:%S")


def ensure(report: dict) -> None:
    report.setdefault("flags", [])
    report.setdefault("artifacts", [])
    report.setdefault("transformations", [])
    report.setdefault("workflow_evidence", [])
    report.setdefault("candidate_flags", [])
    report.setdefault("next_steps", [])


def wants_wrapper(report: dict) -> bool:
    text = (str(report.get("statement", "")) + " " + str(report.get("task", ""))).lower()
    return "ctf_cs" in text or "flag format" in text or "vėliav" in text or "veliav" in text


def body_quality(body: str, source: str = "") -> bool:
    raw = str(body or "").strip().strip("{}")
    low = raw.lower()
    if not (4 <= len(raw) <= 120):
        return False
    if low in BAD_BODIES or ('V96_BAD_FINAL_BODIES' in globals() and low in V96_BAD_FINAL_BODIES):
        return False
    if any(x in low for x in BAD_SUBSTRINGS):
        return False
    if raw[0] in ".:/=+-_" or raw[-1] in ".:/=+-_":
        return False
    # v95: reject tiny noise wrappers produced by XOR/ROT branches such as i_ok.
    if re.fullmatch(r"[a-z0-9]{1,2}_ok", low):
        return False
    if re.search(r"[^A-Za-z0-9_\-:+./=]", raw):
        return False
    if re.search(r"cwe[-_]?\d{2,4}", low) and re.search(r"[a-z]", low):
        return True
    if re.fullmatch(r"[0-9a-f]{64}", low) and re.search(r"sha256|hash", source, re.I):
        return True
    if re.fullmatch(r"[0-9a-f]{18,}", low) and not SEMANTIC_HINTS.search(low + " " + source):
        return False
    if "." in raw or "/" in raw or "=" in raw or ":" in raw:
        return False
    if not re.search(r"[A-Za-z]", raw):
        return False
    if re.fullmatch(r"[xX_0-9-]+", raw):
        return False
    if len(raw) > 50 and not re.search(r"\d", raw):
        return False
    if len(set(low)) <= 3 and len(raw) > 8:
        return False
    if low.startswith("vigenere_") and not (low.endswith("_ok") or re.search(r"\d", low)):
        return False
    if low.startswith(("rail_fence_", "grid_", "route_", "rot", "caesar_", "atbash_")) and not low.endswith("_ok"):
        return False
    if low.startswith("password_") and not (low.endswith("_ok") or re.search(r"\d", low)):
        return False
    if any(x in low for x in ["user_s_password", "admin_password", "wrong_password", "enter_password", "username_and_password"]):
        return False
    if "cyber" in low and "sprint" in low and re.search(r"[a-z]", raw):
        return True
    if "_" in low and re.search(r"[a-z]", low):
        toks = [t for t in re.split(r"[_\-:+./=]+", low) if t]
        norm_toks = [t.translate(LEET_TRANS) for t in toks]
        word_hits = sum(1 for t in norm_toks if t in WORD_HINTS or any(w in t for w in WORD_HINTS if len(w) >= 5))
        if low.endswith("_ok") and len(toks) >= 2 and (len(toks[-2]) >= 3 or len(toks) >= 3 or SEMANTIC_HINTS.search(low)):
            return True
        if SEMANTIC_HINTS.search(low + " " + source) and len(toks) >= 3 and word_hits >= 2:
            return True
        if word_hits >= 2 and not all(len(t) <= 1 for t in toks):
            return True
    if SEMANTIC_HINTS.search(low + " " + source) and "_" in low:
        return False
    if re.search(r"[a-z]", low) and re.search(r"\d", low) and len(low) >= 7:
        # Single-token leetspeak without underscores is a common false positive
        # from binary/LSB noise.  Keep it only when the token has clear bookends.
        if low.startswith(("cyber", "calc", "flag", "secret")) or low.endswith(("sprint", "ok", "done", "flag")):
            return True
    return False


def normalize_flag(flag_or_body: str, source: str = "", allow_wrap: bool = True) -> str | None:
    text = str(flag_or_body or "").strip()
    m = STRICT_RE.fullmatch(text)
    if m:
        body = m.group(1)
        if body.lower().startswith("ctf_cs_"):
            body = body[7:]
        return f"ctf_cs{{{body}}}" if body_quality(body, source) else None
    if allow_wrap:
        body = text.strip("{}")
        if body.lower().startswith("ctf_cs_"):
            body = body[7:]
        if body_quality(body, source):
            return f"ctf_cs{{{body.lower()}}}"
    return None


def add_flag(report: dict, flag_or_body: str, source: str, artifact: str | None, why: str, score: int = 800, allow_wrap: bool | None = None) -> str | None:
    ensure(report)
    if allow_wrap is None:
        allow_wrap = wants_wrapper(report)
    flag = normalize_flag(flag_or_body, source + " " + why, allow_wrap=allow_wrap)
    if not flag:
        return None
    existing = {x if isinstance(x, str) else x.get("flag") for x in report.get("flags", [])}
    if flag not in existing:
        report["flags"].append(flag)
    ev = {"flag": flag, "source": source, "artifact": artifact or "", "why": why, "score": int(score)}
    if ev not in report.get("workflow_evidence", []):
        report["workflow_evidence"].append(ev)
    return flag


def scan_text(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 760, allow_wrap: bool | None = None) -> list[str]:
    text = str(text or "")
    out: list[str] = []
    for m in STRICT_RE.finditer(text):
        f = add_flag(report, m.group(0), source, artifact, why, score, allow_wrap=False)
        if f:
            out.append(f)
    if allow_wrap is None:
        allow_wrap = wants_wrapper(report)
    if allow_wrap:
        for m in ALT_RE.finditer(text):
            before = text[max(0, m.start() - 16):m.start()].lower()
            if "ctf_cs" in before:
                continue
            f = add_flag(report, m.group(1), source, artifact, why + " Task declares ctf_cs{...}; wrapped extracted evidence body.", score - 10, allow_wrap=True)
            if f:
                out.append(f)
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        if 1 <= len(lines) <= 12:
            for line in lines:
                if 4 <= len(line) <= 140 and re.fullmatch(r"[A-Za-z0-9_\-:+./=]+", line):
                    f = add_flag(report, line, source, artifact, why + " Single clean extracted token was wrapped by task format.", score - 20, allow_wrap=True)
                    if f:
                        out.append(f)
        for tm in BARE_TOKEN_RE.finditer(text[:100000]):
            tok = tm.group(0)
            # Avoid wrapping percent-encoded braces such as %7Bbody%7D before URL decoding.
            if tm.start() > 0 and text[tm.start() - 1] == "%":
                continue
            if tok.lower().startswith(("7b", "7d")):
                continue
            if SEMANTIC_HINTS.search(tok):
                f = add_flag(report, tok, source, artifact, why + " Strong underscore token in evidence was wrapped by task format.", score - 60, allow_wrap=True)
                if f:
                    out.append(f)
    return list(dict.fromkeys(out))


def artifact(root: Path, report: dict, name: str, content: bytes | str, kind: str, note: str, score: int = 400, subdir: str = "v93") -> dict | None:
    ensure(report)
    try:
        outdir = Path(root) / "generated" / "sloper_v93" / subdir / safe_name(report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / safe_name(name)
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(bytes(content))
            text = bytes(content[:1_000_000]).decode("utf-8", "ignore")
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
            text = str(content)
        art = {
            "kind": kind,
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v93",
            "score": int(score),
            "note": note,
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report["artifacts"].append(art)
        report["transformations"].append(art)
        allow_wrap = not (
            p.suffix.lower() == ".json"
            or "manifest" in kind.lower()
            or "manifest" in p.name.lower()
            or kind.startswith("sloper_v93_carved_")
            or kind.startswith("sloper_v94_multistep")
        )
        scan_text(report, text, "SLOPER v93 artifact", str(p), "Generated transformation artifact contained answer evidence.", score + 120, allow_wrap=allow_wrap)
        return art
    except Exception as e:
        agent_crash("v93 artifact", e, report)
        return None


def text_quality(text: str) -> int:
    text = str(text or "")
    if not text:
        return 0
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t") / max(1, len(text))
    score = int(printable * 100)
    if re.search(r"ctf_cs\{|flag\{|secret|hidden|raktas|slapta|password|token", text, re.I):
        score += 140
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}", text, re.I):
        score += 55
    return score


def printable_strings(data: bytes, min_len: int = 4, limit: int = 1800) -> list[str]:
    out, cur = [], []
    for b in bytes(data or b""):
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
                if len(out) >= limit:
                    break
            cur = []
    if len(cur) >= min_len and len(out) < limit:
        out.append("".join(cur))
    return out


def printable_ratio(data: bytes) -> float:
    sample = bytes(data[:60000] or b"")
    if not sample:
        return 0.0
    return sum(1 for b in sample if 32 <= b < 127 or b in b"\r\n\t") / len(sample)


def decompress_one(kind: str, raw: bytes) -> bytes | None:
    try:
        if kind == "gzip":
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = obj.decompress(raw, 32_000_000) + obj.flush()
            return out or None
        if kind == "bz2":
            return bz2.decompress(raw)
        if kind == "xz":
            return lzma.decompress(raw)
        if kind == "zlib":
            obj = zlib.decompressobj()
            out = obj.decompress(raw, 32_000_000) + obj.flush()
            return out or None
    except Exception:
        return None
    return None


def archive_followups(report: dict, root: Path, raw: bytes, label: str, depth: int = 0) -> list[dict]:
    arts: list[dict] = []
    if depth > 2 or not raw:
        return arts
    text = raw[:2_000_000].decode("utf-8", "ignore")
    scan_text(report, text, f"SLOPER v93 {label}", None, "Decoded/carved bytes were scanned as evidence.", 760)
    if raw.startswith(b"PK\x03\x04"):
        try:
            if v74:
                arts += v74.zip_local_header_agent(report, root, raw) or []
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                manifest = []
                for info in zf.infolist()[:120]:
                    manifest.append({"name": info.filename, "size": info.file_size, "comment": info.comment.decode("utf-8", "ignore")})
                    scan_text(report, info.filename + "\n" + info.comment.decode("utf-8", "ignore"), "SLOPER v93 ZIP metadata", None, "ZIP name/comment evidence.", 710)
                    if info.file_size <= 10_000_000 and not info.is_dir():
                        child = zf.read(info)
                        a = artifact(root, report, "zip_" + safe_name(info.filename), child, "sloper_v93_zip_member", f"Extracted ZIP member {info.filename}.", 610, "archive")
                        if a:
                            arts.append(a)
                        arts += archive_followups(report, root, child, "zip member " + info.filename, depth + 1)
                artifact(root, report, "v93_zip_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False), "sloper_v93_zip_manifest", "ZIP members/comments extracted by v93.", 520, "archive")
        except Exception as e:
            agent_crash("v93 zip followup", e, report)
    try:
        if tarfile.is_tarfile(fileobj := io.BytesIO(raw)):
            fileobj.seek(0)
            with tarfile.open(fileobj=fileobj) as tf:
                names = []
                for info in tf.getmembers()[:100]:
                    names.append(info.name)
                    scan_text(report, info.name, "SLOPER v93 TAR metadata", None, "TAR filename evidence.", 700)
                    if info.isfile() and info.size <= 10_000_000:
                        fh = tf.extractfile(info)
                        if fh:
                            child = fh.read()
                            a = artifact(root, report, "tar_" + safe_name(info.name), child, "sloper_v93_tar_member", f"Extracted TAR member {info.name}.", 600, "archive")
                            if a:
                                arts.append(a)
                            arts += archive_followups(report, root, child, "tar member " + info.name, depth + 1)
                artifact(root, report, "v93_tar_manifest.json", json.dumps({"names": names}, indent=2, ensure_ascii=False), "sloper_v93_tar_manifest", "TAR manifest extracted by v93.", 500, "archive")
    except Exception:
        pass
    return arts


def carve_decode_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 120_000_000:
        return []
    sigs = [
        ("gzip", b"\x1f\x8b\x08", ".gz"), ("bz2", b"BZh", ".bz2"),
        ("xz", b"\xfd7zXZ\x00", ".xz"), ("zip", b"PK\x03\x04", ".zip"),
        ("zlib", b"\x78\x9c", ".zlib"), ("zlib", b"\x78\xda", ".zlib"),
        ("pdf", b"%PDF", ".pdf"), ("sqlite", b"SQLite format 3\x00", ".sqlite"),
    ]
    found: list[dict] = []
    arts: list[dict] = []
    for kind, sig, ext in sigs:
        start = 0
        count = 0
        while True:
            off = data.find(sig, start)
            if off < 0:
                break
            start = off + 1
            count += 1
            if count > 40:
                break
            raw = data[off:min(len(data), off + 32_000_000)]
            name = f"carved_{kind}_offset_{off:08x}{ext}"
            a = artifact(root, report, name, raw, f"sloper_v93_carved_{kind}", f"Carved {kind} stream at byte offset {off}.", 520, "carves")
            if a:
                arts.append(a)
            found.append({"kind": kind, "offset": off, "artifact": a.get("path") if a else ""})
            if kind in {"gzip", "bz2", "xz", "zlib"}:
                dec = decompress_one(kind, raw)
                if dec:
                    da = artifact(root, report, f"decoded_{name}.bin", dec, f"sloper_v93_{kind}_decoded", f"Decompressed carved {kind} stream from offset {off}.", 760, "carves")
                    if da:
                        arts.append(da)
                    arts += archive_followups(report, root, dec, f"{kind} offset {off}", 0)
            elif kind == "zip":
                arts += archive_followups(report, root, raw, f"zip offset {off}", 0)
    if found:
        ma = artifact(root, report, "v93_carve_manifest.json", json.dumps(found, indent=2, ensure_ascii=False), "sloper_v93_carve_manifest", "Bounded magic carving and decompression manifest.", 540, "carves")
        if ma:
            arts.insert(0, ma)
    return arts



# ---------- bounded universal multi-step transform layer ----------

def rot_alpha(s: str, n: int) -> str:
    out = []
    for ch in str(s or ""):
        if "a" <= ch <= "z": out.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z": out.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else: out.append(ch)
    return "".join(out)

def atbash_text(s: str) -> str:
    out = []
    for ch in str(s or ""):
        if "a" <= ch <= "z": out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z": out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else: out.append(ch)
    return "".join(out)

def rot47_text(s: str) -> str:
    return "".join(chr(33 + ((ord(ch) - 33 + 47) % 94)) if 33 <= ord(ch) <= 126 else ch for ch in str(s or ""))

def _candidate_text_views(raw: bytes) -> list[tuple[str, str]]:
    data = bytes(raw or b"")
    views: list[tuple[str, str]] = []
    if not data:
        return views
    pr = printable_ratio(data)
    # UTF-8 ignore is cheap, but do not treat opaque binary as a source of
    # further text transforms unless it contains obvious textual evidence.
    for enc in ("utf-8", "latin1", "utf-16le", "utf-16be"):
        if enc == "latin1" and pr < 0.72 and b"{" not in data and b"ctf" not in data.lower():
            continue
        if enc.startswith("utf-16") and pr < 0.35 and b"{" not in data and b"ctf" not in data.lower():
            continue
        try:
            txt = data[:2_000_000].decode(enc, "ignore")
        except Exception:
            continue
        if not txt.strip():
            continue
        if enc.startswith("utf-16") and text_quality(txt[:2000]) < 45 and "{" not in txt and "ctf" not in txt.lower():
            continue
        views.append((enc, txt))
    return views

def _push_decode_variant(out: list[tuple[str, bytes]], name: str, raw: bytes | str | None) -> None:
    if raw is None:
        return
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "ignore")
    raw = bytes(raw or b"")
    if not raw:
        return
    if len(raw) > 4_000_000:
        raw = raw[:4_000_000]
    out.append((name, raw))

def _decode_text_variants(txt: str) -> list[tuple[str, bytes]]:
    outs: list[tuple[str, bytes]] = []
    text = str(txt or "")
    if not text:
        return outs
    compact = re.sub(r"\s+", "", text.strip())
    try:
        u = urllib.parse.unquote_plus(text)
        if u != text: _push_decode_variant(outs, "url_decode", u)
    except Exception: pass
    try:
        h = html.unescape(text)
        if h != text: _push_decode_variant(outs, "html_unescape", h)
    except Exception: pass
    if re.search(r"=(?:[0-9A-Fa-f]{2}|\r?\n)", text):
        try:
            q = quopri.decodestring(text.encode("utf-8", "ignore"))
            if q and q != text.encode("utf-8", "ignore"):
                _push_decode_variant(outs, "quoted_printable", q)
        except Exception: pass
    if "\\x" in text or "\\u" in text or "\\n" in text:
        try: _push_decode_variant(outs, "unicode_escape", bytes(text, "utf-8").decode("unicode_escape"))
        except Exception: pass
    if len(text) <= 200_000:
        _push_decode_variant(outs, "reverse_text", text[::-1])
    alpha_count = sum(1 for c in compact[:12000] if c.isalpha())
    if 6 <= alpha_count and len(compact) <= 12000:
        for n in range(1, 26):
            _push_decode_variant(outs, f"rot{n}", rot_alpha(text, n))
        _push_decode_variant(outs, "atbash", atbash_text(text))
        if re.search(r"[!#$%&()*;<=>?@^`{|}~]", text):
            _push_decode_variant(outs, "rot47", rot47_text(text))
    if len(compact) >= 8 and re.fullmatch(r"[01]+", compact):
        for off in range(8):
            bits = compact[off:]
            raw = bytearray(); raw_rev = bytearray()
            for i in range(0, len(bits) - 7, 8):
                b = bits[i:i + 8]
                raw.append(int(b, 2)); raw_rev.append(int(b[::-1], 2))
            _push_decode_variant(outs, f"binary_ascii_offset_{off}", bytes(raw))
            _push_decode_variant(outs, f"binary_ascii_offset_{off}_bitrev", bytes(raw_rev))
    hex_compact = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(hex_compact) >= 8 and len(hex_compact) % 2 == 0 and len(hex_compact) <= 2_000_000 and len(hex_compact) / max(1, len(compact)) > 0.85:
        try: _push_decode_variant(outs, "hex", binascii.unhexlify(hex_compact))
        except Exception: pass
    nums = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", text[:300000])[:8000]]
    if len(nums) >= 4:
        for off in [0, 32, 48, 64, 100, 128, 255, 1000]:
            raw = bytes((n - off) & 255 for n in nums if 0 <= n - off <= 255)
            if len(raw) >= 4: _push_decode_variant(outs, f"decimal_minus_{off}", raw)
        _push_decode_variant(outs, "decimal_mod256", bytes(n & 255 for n in nums))
    blobs: list[str] = []
    if compact: blobs.append(compact)
    blobs += re.findall(r"[A-Za-z0-9+/=_-]{8,20000}", text)[:160]
    blobs += re.findall(r"[!-~]{10,20000}", text)[:80]
    seen_blob: set[str] = set()
    for blob in blobs:
        if blob in seen_blob: continue
        seen_blob.add(blob)
        for suffix, val in [("", blob), ("_reversed", blob[::-1])]:
            pad64 = "=" * ((4 - len(val) % 4) % 4)
            pad32 = "=" * ((8 - len(val) % 8) % 8)
            decoders = []
            if len(val) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", val):
                decoders.append(("base64" + suffix, lambda x, p=pad64: base64.b64decode(x + p, validate=False)))
                decoders.append(("urlsafe_base64" + suffix, lambda x, p=pad64: base64.urlsafe_b64decode(x + p)))
            if len(val) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", val.upper()):
                decoders.append(("base32" + suffix, lambda x, p=pad32: base64.b32decode(x + p, casefold=True)))
            # Base85/Ascii85 are expensive and noisy; try only when punctuation suggests them.
            if len(val) >= 10 and re.search(r"[!#$%&()*;<=>?@^`{|}~]", val):
                decoders.append(("base85" + suffix, lambda x: base64.b85decode(x)))
                decoders.append(("ascii85" + suffix, lambda x: base64.a85decode(x, adobe=False, ignorechars=b" \t\n\r\v")))
            for name, fn in decoders[:5]:
                try:
                    raw = fn(val)
                    if raw: _push_decode_variant(outs, name, raw)
                except Exception: pass
    # Keep breadth bounded; score-like order: whole-string transforms first, token decoders after.
    return outs[:180]

def _raw_unwrap_variants(raw: bytes) -> list[tuple[str, bytes]]:
    outs: list[tuple[str, bytes]] = []
    data = bytes(raw or b"")
    if not data:
        return outs
    for name in ("gzip", "zlib", "bz2", "xz"):
        dec = decompress_one(name, data)
        if dec: outs.append((name, dec))
    for sig, name in [(b"\x1f\x8b\x08", "gzip_carve"), (b"\x78\x9c", "zlib_carve"), (b"\x78\xda", "zlib_carve"), (b"BZh", "bz2_carve"), (b"\xfd7zXZ\x00", "xz_carve")]:
        off = data.find(sig)
        if 0 < off < 4096:
            dec = decompress_one(name.split("_")[0], data[off:])
            if dec: outs.append((f"{name}_{off}", dec))
    # XOR is only useful once a chain has produced opaque bytes. Avoid applying
    # it to plain printable text nodes, where it is slow and noisy.
    if 4 <= len(data) <= 200_000 and (printable_ratio(data) < 0.72 or any(((b < 32 and b not in b"\r\n\t") or b > 126) for b in data[:4096])):
        for key in range(1, 256):
            x = bytes(b ^ key for b in data[:200_000])
            t = x.decode("utf-8", "ignore")
            clean = t.strip().strip("\x00")
            if x.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04")):
                outs.append((f"xor_{key:02x}", x))
                continue
            if "{" in t or "ctf" in t.lower() or body_quality(clean, "xor multistep secret hidden l4b lab pipeline ok"):
                outs.append((f"xor_{key:02x}", x))
    return outs[:360]


def priority_chain_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Fast exact-chain sweeper for common hard CTF multi-step patterns.

    This is intentionally deterministic and small: try likely text transforms as
    seeds, then follow whole-string encodings, compression and single-byte XOR.
    It catches chains such as ROT13->base64->gzip, reverse->hex->zlib,
    base64->base32->xor, atbash->base64, ROT47->URL/HTML, decimal byte arrays,
    and reversed binary without flooding the broad graph with noisy candidates.
    """
    ensure(report)
    if not data or len(data) > 6_000_000:
        return []

    hits: list[dict[str, Any]] = []
    hit_texts: list[str] = []
    seen_raw: set[bytes] = set()

    def emit(chain: str, txt: str, depth: int) -> bool:
        found = scan_text(
            report,
            txt[:1_000_000],
            "SLOPER v94 priority chain",
            None,
            f"Priority chain {chain} produced answer evidence.",
            990 - depth * 18,
            allow_wrap=True,
        )
        if found:
            hits.append({"chain": chain, "flags": found[:8], "quality": text_quality(txt[:8000]), "preview": txt[:600]})
            hit_texts.append(f"CHAIN: {chain}\n{txt[:200000]}")
            return True
        return False

    def add(out: list[tuple[str, bytes]], name: str, val: bytes | str | None) -> None:
        if val is None:
            return
        if isinstance(val, str):
            val = val.encode("utf-8", "ignore")
        val = bytes(val or b"")
        if val:
            out.append((name, val[:4_000_000]))

    def decode_whole(txt: str) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        src = str(txt or "")
        try:
            u = urllib.parse.unquote_plus(src)
            if u != src: add(out, "url_decode", u)
        except Exception: pass
        try:
            h = html.unescape(src)
            if h != src: add(out, "html_unescape", h)
        except Exception: pass
        if re.search(r"=(?:[0-9A-Fa-f]{2}|\r?\n)", src):
            try:
                q = quopri.decodestring(src.encode("utf-8", "ignore"))
                if q and q != src.encode("utf-8", "ignore"): add(out, "quoted_printable", q)
            except Exception: pass
        compact = re.sub(r"\s+", "", src.strip())
        # Try unambiguous structural forms before broad base64.  Pure hex/binary
        # and decimal byte arrays are also legal base64-looking text, and trying
        # base64 first can waste the node budget before the real path.
        nums_early = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", src[:300000])[:8000]]
        if len(nums_early) >= 4:
            for off in [0, 32, 48, 64, 100, 128, 255, 1000]:
                raw = bytes((n - off) & 255 for n in nums_early if 0 <= n - off <= 255)
                if len(raw) >= 4: add(out, f"decimal_minus_{off}", raw)
            add(out, "decimal_mod256", bytes(n & 255 for n in nums_early))
        if len(compact) >= 8 and re.fullmatch(r"[01]+", compact):
            for off in range(8):
                bits = compact[off:]
                raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
                if raw:
                    add(out, f"binary_offset_{off}", raw)
                    add(out, f"binary_offset_{off}_bitrev", bytes(int(bits[i:i+8][::-1], 2) for i in range(0, len(bits)-7, 8)))
        if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            try: add(out, "hex", binascii.unhexlify(compact))
            except Exception: pass
        if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            pad64 = "=" * ((4 - len(compact) % 4) % 4)
            try: add(out, "base64", base64.b64decode(compact + pad64, validate=False))
            except Exception: pass
            try: add(out, "urlsafe_base64", base64.urlsafe_b64decode(compact + pad64))
            except Exception: pass
        if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", compact.upper()):
            pad32 = "=" * ((8 - len(compact) % 8) % 8)
            try: add(out, "base32", base64.b32decode(compact + pad32, casefold=True))
            except Exception: pass
        if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            try: add(out, "hex", binascii.unhexlify(compact))
            except Exception: pass
        if len(compact) >= 8 and re.fullmatch(r"[01]+", compact):
            for off in range(8):
                bits = compact[off:]
                raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
                if raw:
                    add(out, f"binary_offset_{off}", raw)
                    add(out, f"binary_offset_{off}_bitrev", bytes(int(bits[i:i+8][::-1], 2) for i in range(0, len(bits)-7, 8)))
        nums = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", src[:300000])[:8000]]
        if len(nums) >= 4:
            for off in [0, 32, 48, 64, 100, 128, 255, 1000]:
                raw = bytes((n - off) & 255 for n in nums if 0 <= n - off <= 255)
                if len(raw) >= 4: add(out, f"decimal_minus_{off}", raw)
            add(out, "decimal_mod256", bytes(n & 255 for n in nums))
        # Deduplicate while preserving order.
        dedup: list[tuple[str, bytes]] = []
        seen_local: set[bytes] = set()
        for name, raw in out:
            sig = hashlib.sha256(raw[:200000]).digest()[:12] + len(raw).to_bytes(8, "little", signed=False)
            if sig in seen_local:
                continue
            seen_local.add(sig)
            dedup.append((name, raw))
        return dedup[:28]

    def walk_raw(chain: str, raw: bytes, depth: int) -> bool:
        if depth > 5 or not raw or len(raw) > 4_000_000 or len(seen_raw) > 64:
            return False
        sig = hashlib.sha256(raw[:200000]).digest()[:16] + len(raw).to_bytes(8, "little", signed=False)
        if sig in seen_raw:
            return False
        seen_raw.add(sig)

        # Container/compression signatures should be unwrapped before generic
        # text probing; otherwise UTF-8/latin1 views of compressed bytes create
        # noisy branches that can bury the real path.
        for cname in ("gzip", "zlib", "bz2", "xz"):
            if cname == "gzip" and not raw.startswith(b"\x1f\x8b\x08"):
                continue
            if cname == "zlib" and not raw.startswith((b"\x78\x9c", b"\x78\xda", b"\x78\x01")):
                continue
            if cname == "bz2" and not raw.startswith(b"BZh"):
                continue
            if cname == "xz" and not raw.startswith(b"\xfd7zXZ\x00"):
                continue
            dec = decompress_one(cname, raw)
            if dec and walk_raw(chain + " -> " + cname, dec, depth + 1):
                return True

        for enc, txt in _candidate_text_views(raw):
            if emit(chain + " -> " + enc, txt, depth):
                return True
            if depth < 5:
                for name, child in decode_whole(txt):
                    if walk_raw(chain + " -> " + enc + " -> " + name, child, depth + 1):
                        return True

        # Try generic decompression once after text decoders too, for uncommon
        # headers/carved offsets that are not caught by the signature fast path.
        for cname in ("gzip", "zlib", "bz2", "xz"):
            dec = decompress_one(cname, raw)
            if dec and walk_raw(chain + " -> " + cname, dec, depth + 1):
                return True

        # Single-byte XOR is useful after an encoding/compression step has yielded
        # opaque bytes. Keep it gated so printable plain text is not brute-forced.
        if 4 <= len(raw) <= 200_000 and (printable_ratio(raw) < 0.72 or any(((b < 32 and b not in b"\r\n\t") or b > 126) for b in raw[:4096])):
            for key in range(1, 256):
                x = bytes(b ^ key for b in raw)
                if x.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04")):
                    if walk_raw(chain + f" -> xor_{key:02x}", x, depth + 1):
                        return True
                    continue
                t = x.decode("utf-8", "ignore").strip().strip("\x00")
                if "{" in t or "ctf" in t.lower() or body_quality(t, "xor priority secret hidden l4b lab pipeline ok"):
                    if emit(chain + f" -> xor_{key:02x} -> utf-8", t, depth + 1):
                        return True
                    # Only recurse from XOR if it clearly creates another container.
                    if x.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00")):
                        if walk_raw(chain + f" -> xor_{key:02x}", x, depth + 1):
                            return True
        return False

    initial = data[:300000].decode("utf-8", "ignore")
    seeds: list[tuple[str, str]] = []
    alpha_count = sum(1 for c in initial if c.isalpha())
    if alpha_count >= 6 and len(initial) <= 12000:
        seeds.append(("rot13", rot_alpha(initial, 13)))
    seeds.extend([("input", initial), ("reverse_text", initial[::-1]), ("atbash", atbash_text(initial))])
    if re.search(r"[!#$%&()*;<=>?@^`{|}~]", initial):
        seeds.append(("rot47", rot47_text(initial)))
    if alpha_count >= 6 and len(initial) <= 12000:
        seeds.extend((f"rot{n}", rot_alpha(initial, n)) for n in range(1, 26) if n != 13)

    seed_seen: set[str] = set()
    for sname, stxt in seeds:
        if report.get("flags"):
            break
        if not stxt or stxt in seed_seen:
            continue
        seed_seen.add(stxt)
        seen_raw.clear()
        if emit("seed " + sname, stxt, 0):
            break
        for name, child in decode_whole(stxt):
            if walk_raw("seed " + sname + " -> " + name, child, 1):
                break

    arts: list[dict] = []
    if hits:
        a = artifact(root, report, "v94_priority_chain_hits.json", json.dumps(hits[:80], indent=2, ensure_ascii=False), "sloper_v94_priority_chain", "High-priority deterministic multi-step chains that produced evidence.", 890, "multistep")
        if a: arts.append(a)
    for idx, txt in enumerate(hit_texts[:12], 1):
        a = artifact(root, report, f"v94_priority_chain_hit_{idx:02d}.txt", txt, "sloper_v94_priority_chain", "Readable priority-chain output containing answer evidence.", 870, "multistep")
        if a: arts.append(a)
    return arts

def multistep_decode_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 6_000_000:
        return []
    ensure(report)
    priority_arts = priority_chain_agent(report, root, data)
    if report.get("flags"):
        return priority_arts
    queue: list[tuple[str, bytes, int]] = [("input", bytes(data), 0)]
    seen: set[bytes] = set()
    manifest: list[dict[str, Any]] = []
    hit_texts: list[tuple[str, str]] = []
    max_nodes, max_depth = 20, 5

    # Deterministic priority sweep for common hard chains.  This runs before
    # the broad BFS so high-value paths do not get buried behind noisy decodes.
    quick_seen: set[bytes] = set()

    def quick_walk(label: str, raw: bytes, depth: int) -> None:
        if depth > 5 or len(quick_seen) > 220 or not raw:
            return
        sig = hashlib.sha256(raw[:200000]).digest()[:16] + len(raw).to_bytes(8, "little", signed=False)
        if sig in quick_seen:
            return
        quick_seen.add(sig)
        for vname, txt in _candidate_text_views(raw):
            chain = label + " -> " + vname
            found = scan_text(report, txt[:1_000_000], "SLOPER v94 multistep priority", None, f"Priority transform chain {chain} produced answer evidence.", 940 - depth * 20, allow_wrap=True)
            if found:
                manifest.append({"chain": chain, "size": len(raw), "quality": text_quality(txt[:8000]), "flags": found[:8], "preview": txt[:500]})
                hit_texts.append((chain, txt[:200000]))
            if depth >= 5 or len(txt) > 300_000:
                continue
            for name, child in _decode_text_variants(txt):
                if not name.startswith(("base64", "urlsafe_base64", "base32", "hex", "binary", "decimal", "url_decode", "html_unescape", "quoted_printable", "unicode_escape", "reverse_text")):
                    continue
                quick_walk(label + " -> " + name, child, depth + 1)
        if depth < 5:
            for name, child in _raw_unwrap_variants(raw):
                quick_walk(label + " -> " + name, child, depth + 1)

    try:
        initial_text = data[:300000].decode("utf-8", "ignore")
        targeted_seen: set[bytes] = set()

        def mark_text(chain: str, txt: str, depth: int) -> None:
            found = scan_text(report, txt[:1_000_000], "SLOPER v94 targeted multistep", None, f"Targeted transform chain {chain} produced answer evidence.", 960 - depth * 20, allow_wrap=True)
            if found:
                manifest.append({"chain": chain, "size": len(txt), "quality": text_quality(txt[:8000]), "flags": found[:8], "preview": txt[:500]})
                hit_texts.append((chain, txt[:200000]))

        def feed_raw(chain: str, raw: bytes, depth: int) -> None:
            if depth > 5 or not raw or len(targeted_seen) > 45:
                return
            sig = hashlib.sha256(raw[:200000]).digest()[:16] + len(raw).to_bytes(8, "little", signed=False)
            if sig in targeted_seen:
                return
            targeted_seen.add(sig)
            for enc, txt in _candidate_text_views(raw):
                mark_text(chain + " -> " + enc, txt, depth)
                if depth < 5:
                    feed_text(chain + " -> " + enc, txt, depth + 1)
            for cname in ("gzip", "zlib", "bz2", "xz"):
                dec = decompress_one(cname, raw)
                if dec:
                    feed_raw(chain + " -> " + cname, dec, depth + 1)
            if 4 <= len(raw) <= 200_000 and (printable_ratio(raw) < 0.72 or any(((b < 32 and b not in b"\r\n\t") or b > 126) for b in raw[:4096])):
                for key in range(1, 256):
                    x = bytes(b ^ key for b in raw)
                    if x.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04")):
                        feed_raw(chain + f" -> xor_{key:02x}", x, depth + 1)
                        continue
                    t = x.decode("utf-8", "ignore").strip().strip("\x00")
                    if "{" in t or "ctf" in t.lower() or body_quality(t, "xor targeted secret hidden l4b lab pipeline ok"):
                        mark_text(chain + f" -> xor_{key:02x} -> utf-8", t, depth + 1)
                        if x.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00")):
                            feed_raw(chain + f" -> xor_{key:02x}", x, depth + 1)

        def feed_text(chain: str, txt: str, depth: int) -> None:
            if depth > 5 or not txt:
                return
            variants: list[tuple[str, bytes]] = []
            def add(name: str, raw: bytes | str | None) -> None:
                if raw is None: return
                if isinstance(raw, str): raw = raw.encode("utf-8", "ignore")
                if raw: variants.append((name, bytes(raw)))
            try:
                u = urllib.parse.unquote_plus(txt)
                if u != txt: add("url_decode", u)
            except Exception: pass
            try:
                h = html.unescape(txt)
                if h != txt: add("html_unescape", h)
            except Exception: pass
            if re.search(r"=(?:[0-9A-Fa-f]{2}|\r?\n)", txt):
                try:
                    q = quopri.decodestring(txt.encode("utf-8", "ignore"))
                    if q and q != txt.encode("utf-8", "ignore"): add("quoted_printable", q)
                except Exception: pass
            compact = re.sub(r"\s+", "", txt.strip())
            if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
                pad64 = "=" * ((4 - len(compact) % 4) % 4)
                try: add("base64", base64.b64decode(compact + pad64, validate=False))
                except Exception: pass
                try: add("urlsafe_base64", base64.urlsafe_b64decode(compact + pad64))
                except Exception: pass
            if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", compact.upper()):
                pad32 = "=" * ((8 - len(compact) % 8) % 8)
                try: add("base32", base64.b32decode(compact + pad32, casefold=True))
                except Exception: pass
            if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
                try: add("hex", binascii.unhexlify(compact))
                except Exception: pass
            if len(compact) >= 8 and re.fullmatch(r"[01]+", compact):
                for off in range(8):
                    bits = compact[off:]
                    raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
                    if raw: add(f"binary_offset_{off}", raw)
            nums = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", txt[:300000])[:8000]]
            if len(nums) >= 4:
                for off in [0, 32, 48, 64, 100, 128, 255, 1000]:
                    raw = bytes((n - off) & 255 for n in nums if 0 <= n - off <= 255)
                    if raw: add(f"decimal_minus_{off}", raw)
            for name, raw in variants[:14]:
                feed_raw(chain + " -> " + name, raw, depth + 1)

        seeds: list[tuple[str, str]] = []
        if sum(1 for c in initial_text if c.isalpha()) >= 6 and len(initial_text) <= 12000:
            seeds.append(("rot13", rot_alpha(initial_text, 13)))
        seeds.extend([("input", initial_text), ("reverse_text", initial_text[::-1]), ("atbash", atbash_text(initial_text))])
        if re.search(r"[!#$%&()*;<=>?@^`{|}~]", initial_text):
            seeds.append(("rot47", rot47_text(initial_text)))
        # Full ROT fanout is handled by priority_chain_agent.  Keep this fallback
        # narrow so unsolved files do not spend time exploring dozens of equivalent
        # noisy branches.
        for sname, stxt in seeds[:6]:
            if report.get("flags"):
                break
            targeted_seen.clear()
            feed_raw("target " + sname, stxt.encode("utf-8", "ignore"), 0)
    except Exception as e:
        agent_crash("v94 targeted multistep sweep", e, report)
    while queue and len(seen) < max_nodes:
        label, raw, depth = queue.pop(0)
        sig = hashlib.sha256(raw[:200000]).digest()[:16] + len(raw).to_bytes(8, "little", signed=False)
        if sig in seen: continue
        seen.add(sig)
        if len(raw) > 4_000_000: raw = raw[:4_000_000]
        for view_name, txt in _candidate_text_views(raw):
            q = text_quality(txt[:8000])
            chain = label + " -> " + view_name
            found = scan_text(report, txt[:1_000_000], "SLOPER v94 multistep decode", None, f"Transform chain {chain} produced answer evidence.", 900 - depth * 20, allow_wrap=True)
            if q >= 120 or found or "{" in txt or "ctf" in txt.lower():
                manifest.append({"chain": chain, "size": len(raw), "quality": q, "flags": found[:8], "preview": txt[:500]})
                if found or ("{" in txt and len(hit_texts) < 20):
                    hit_texts.append((chain, txt[:200000]))
            compact_probe = re.sub(r"\s+", "", txt[:300000])
            text_transformable = (q >= 45 or "{" in txt or "ctf" in txt.lower()
                                  or re.fullmatch(r"[A-Za-z0-9+/=_-]{8,20000}", compact_probe or "")
                                  or re.fullmatch(r"[0-9a-fA-F]{8,200000}", compact_probe or "")
                                  or re.fullmatch(r"[01]{8,200000}", compact_probe or "")
                                  or len(re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", txt[:300000])) >= 4)
            if depth < max_depth and len(txt) <= 300_000 and text_transformable:
                for name, child in _decode_text_variants(txt):
                    if child and child != raw:
                        nxt = (label + " -> " + name, child, depth + 1)
                        low_child = child[:4096].lower()
                        structured_child = printable_ratio(child) > 0.72 or child.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04")) or b"ctf" in low_child
                        high_name = ((name.startswith(("base64", "urlsafe_base64", "hex")) and structured_child) or name.startswith("base32") or name.startswith(("binary", "decimal", "url_decode", "html_unescape", "quoted_printable")))
                        if high_name or child.startswith((b"\x1f\x8b\x08", b"\x78\x9c", b"\x78\xda", b"BZh", b"\xfd7zXZ\x00", b"PK\x03\x04")) or b"ctf" in low_child:
                            queue.insert(0, nxt)
                        else:
                            queue.append(nxt)
        if depth < max_depth:
            for name, child in _raw_unwrap_variants(raw):
                if child and child != raw:
                    # Decompressed/XOR-readable outputs are high-value; process next.
                    queue.insert(0, (label + " -> " + name, child, depth + 1))
    arts: list[dict] = []
    if manifest:
        manifest = sorted(manifest, key=lambda x: (bool(x.get("flags")), int(x.get("quality", 0))), reverse=True)[:260]
        a = artifact(root, report, "v94_multistep_decode_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False), "sloper_v94_multistep_decode", "Bounded multi-step transformation chains with previews and promoted evidence.", 780, "multistep")
        if a: arts.append(a)
    for idx, (chain, txt) in enumerate(hit_texts[:20], 1):
        a = artifact(root, report, f"v94_multistep_hit_{idx:02d}.txt", f"CHAIN: {chain}\n\n{txt}", "sloper_v94_multistep_hit", "Readable multi-step decode output containing brace/flag evidence.", 820, "multistep")
        if a: arts.append(a)
    return arts

def acrostic_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    text = data[:1_000_000].decode("utf-8", "ignore")
    lines = [ln.rstrip("\r\n") for ln in text.splitlines() if ln.strip()]
    if not (4 <= len(lines) <= 1000):
        return []
    variants = []
    for name, chars in [
        ("first_chars", [ln.lstrip()[0] for ln in lines if ln.lstrip()]),
        ("last_chars", [ln.rstrip()[-1] for ln in lines if ln.rstrip()]),
        ("first_words", [re.split(r"\s+", ln.strip())[0] for ln in lines if ln.strip()]),
    ]:
        out = "".join(chars)
        if "ctf" in out.lower() or "{" in out or text_quality(out) >= 120:
            variants.append({"method": name, "text": out, "score": text_quality(out)})
            scan_text(report, out, "SLOPER v93 acrostic", None, f"Acrostic {name} reconstruction.", 700)
    if not variants:
        return []
    a = artifact(root, report, "v93_acrostic_candidates.json", json.dumps(variants, indent=2, ensure_ascii=False), "sloper_v93_acrostic", "First/last character acrostic candidates.", 470, "text")
    return [a] if a else []


def time_anomaly_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    text = data[:3_000_000].decode("utf-8", "ignore")
    if ":" not in text or len(text.splitlines()) < 20:
        return []
    rows = []
    time_re = re.compile(r"(?:(\d{4})[-/](\d{2})[-/](\d{2})[ T])?(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))?")
    for idx, line in enumerate(text.splitlines()[:120000]):
        m = time_re.search(line)
        if not m:
            continue
        hh, mm, ss = int(m.group(4)), int(m.group(5)), int(m.group(6))
        micros = int((m.group(7) or "0").ljust(6, "0")[:6])
        stamp = ((hh * 60 + mm) * 60 + ss) * 1_000_000 + micros
        tail = line[m.end():]
        words = re.findall(r"\b[A-Z][A-Z0-9_]{1,16}\b", tail)
        module = words[0] if words else ""
        level = words[1] if len(words) > 1 else ""
        rows.append({"idx": idx, "time": stamp, "hh": hh, "mm": mm, "ss": ss, "module": module, "level": level, "line": line[:300]})
    if len(rows) < 10:
        return []
    anomalies = []
    prev = rows[0]
    for row in rows[1:]:
        delta = row["time"] - prev["time"]
        if delta < 0 or abs(delta) > 10_000_000:
            item = dict(row)
            item["delta_us"] = delta
            anomalies.append(item)
        prev = row
    if not anomalies:
        return []

    modules = sorted({a["module"] for a in anomalies if a["module"]})
    levels = sorted({a["level"] for a in anomalies if a["level"]})
    mod_map = {m: chr(65 + i) for i, m in enumerate(modules[:26])}
    level_map = {m: chr(65 + i) for i, m in enumerate(levels[:26])}
    seqs: dict[str, Any] = {
        "module_letters": "".join(mod_map.get(a["module"], "") for a in anomalies),
        "level_letters": "".join(level_map.get(a["level"], "") for a in anomalies),
        "seconds_raw": [a["ss"] for a in anomalies],
        "minutes_raw": [a["mm"] for a in anomalies],
        "delta_abs_low": [abs(int(a["delta_us"])) & 255 for a in anomalies],
        "line_indices_low": [a["idx"] & 255 for a in anomalies],
    }
    decoded: dict[str, Any] = {}
    for name, vals in seqs.items():
        if isinstance(vals, list):
            decoded[name] = decode_sequence([int(v) & 255 for v in vals])
            decoded[name + "_bits"] = decode_bit_channels([int(v) & 255 for v in vals], limit=20)
        elif isinstance(vals, str) and vals:
            decoded[name] = vals
            scan_text(report, vals, "SLOPER v93 time anomaly", None, f"Time anomaly {name} sequence.", 700)
    for name, variants in decoded.items():
        if isinstance(variants, dict):
            for method, txt in variants.items():
                scan_text(report, txt, "SLOPER v93 time anomaly", None, f"Time anomaly {name} decoded with {method}.", 720)
    payload = {
        "anomaly_count": len(anomalies),
        "module_map": mod_map,
        "level_map": level_map,
        "anomalies": anomalies[:1200],
        "decoded": decoded,
    }
    a = artifact(root, report, "v93_time_anomaly_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), "sloper_v93_time_anomaly", "Timestamp regressions/outliers decoded as module, level, delta and low-byte channels.", 560, "text")
    return [a] if a else []


def pcap_packets(data: bytes) -> Iterable[bytes]:
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        pos = 24
        while pos + 16 <= len(data):
            try:
                _ts1, _ts2, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
            except Exception:
                break
            pos += 16
            if incl <= 0 or incl > 10_000_000 or pos + incl > len(data):
                break
            yield data[pos:pos + incl]
            pos += incl
        return
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        pos = 0
        endian = "<"
        while pos + 12 <= len(data):
            btype = int.from_bytes(data[pos:pos + 4], endian == ">" and "big" or "little")
            blen = int.from_bytes(data[pos + 4:pos + 8], endian == ">" and "big" or "little")
            if blen < 12 or pos + blen > len(data):
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 0x0A0D0D0A and len(body) >= 8:
                bom = body[4:8]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            elif btype == 0x00000006 and len(body) >= 20:
                caplen = int.from_bytes(body[12:16], endian == ">" and "big" or "little")
                pkt = body[20:20 + caplen]
                if pkt:
                    yield pkt
            elif btype == 0x00000003 and len(body) >= 12:
                caplen = int.from_bytes(body[4:8], endian == ">" and "big" or "little")
                pkt = body[12:12 + caplen]
                if pkt:
                    yield pkt
            pos += blen


def decode_sequence(vals: list[int]) -> dict[str, str]:
    def to_text(seq: list[int]) -> str:
        return bytes([x & 255 for x in seq]).decode("utf-8", "ignore")
    variants: dict[str, str] = {}
    if not vals:
        return variants
    seqs = {
        "raw": vals,
        "reverse": vals[::-1],
        "diff": [(vals[i] - vals[i - 1]) & 255 for i in range(1, len(vals))],
        "xor_prev": [vals[i] ^ vals[i - 1] for i in range(1, len(vals))],
        "mod95": [32 + (v % 95) for v in vals],
        "mod26": [97 + (v % 26) for v in vals],
    }
    for name, seq in seqs.items():
        text = to_text(seq)
        if text.strip() and (text_quality(text) >= 90 or "ctf" in text.lower() or "{" in text):
            variants[name] = text[:5000]
    return variants


def pack_bits(bits: list[int], msb_first: bool = True) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        chunk = bits[i:i + 8]
        if msb_first:
            for bit in chunk:
                byte = (byte << 1) | (bit & 1)
        else:
            for j, bit in enumerate(chunk):
                byte |= (bit & 1) << j
        out.append(byte)
    return bytes(out)


def decode_bit_channels(vals: list[int], limit: int = 80) -> dict[str, str]:
    """Decode common covert channels where packet fields encode bits/symbols."""
    variants: dict[str, str] = {}
    if len(vals) < 16:
        return variants
    uniq = sorted(set(vals))
    starts = {0}
    for i in range(1, min(len(vals), 4096)):
        if vals[i] != vals[i - 1]:
            starts.update({i, max(0, i - 8), max(0, i - 16), max(0, i - 32)})
            break
    for pos in (64, 128, 256, 512, 768, 1024, 1200):
        if pos < len(vals) - 16:
            starts.add(pos)

    bit_streams: list[tuple[str, list[int]]] = []
    if 2 <= len(uniq) <= 16:
        mid = (min(uniq) + max(uniq)) / 2
        bit_streams.append(("threshold", [1 if v > mid else 0 for v in vals]))
        for u in uniq[:16]:
            bit_streams.append((f"is_{u}", [1 if v == u else 0 for v in vals]))
    if 3 <= len(uniq) <= 4:
        rank = {u: i for i, u in enumerate(uniq)}
        bit_streams.append(("rank_lsb", [rank[v] & 1 for v in vals]))
        bit_streams.append(("rank_msb", [(rank[v] >> 1) & 1 for v in vals]))
        if len(uniq) == 4:
            bits: list[int] = []
            for v in vals:
                r = rank[v]
                bits.extend([(r >> 1) & 1, r & 1])
            bit_streams.append(("rank_2bit", bits))

    seen = set()
    for name, bits0 in bit_streams[:80]:
        for start in sorted(starts):
            if start >= len(bits0) - 8:
                continue
            for rev in (False, True):
                bits = list(reversed(bits0[start:])) if rev else bits0[start:]
                for msb in (True, False):
                    raw = pack_bits(bits, msb)
                    if not raw:
                        continue
                    text = raw.decode("utf-8", "ignore")
                    quality = text_quality(text)
                    key = f"{name}_start{start}_{'rev_' if rev else ''}{'msb' if msb else 'lsb'}"
                    if key in seen:
                        continue
                    if "ctf" in text.lower() or "{" in text or quality >= 125:
                        variants[key] = text[:5000]
                        seen.add(key)
                        if len(variants) >= limit:
                            return variants
    return variants


def pcap_fragment_variants(strings: list[str], labels: list[str], limit: int = 80) -> list[dict[str, str]]:
    tokens: list[str] = []
    for s in list(strings[:5000]) + list(labels[:1000]):
        for tok in re.findall(r"[A-Za-z0-9_{}\-]{2,48}", s):
            low = tok.lower().strip("-")
            if low in {"internal", "service", "local", "google", "chat", "http", "https"}:
                continue
            if "{" in tok or "}" in tok or "_" in tok or re.search(r"[3470158]", tok):
                tokens.append(tok.strip("-"))
            elif 3 <= len(tok) <= 16 and SEMANTIC_HINTS.search(low):
                tokens.append(tok.strip("-"))
            if len(tokens) >= 800:
                break
        if len(tokens) >= 800:
            break
    out: list[dict[str, str]] = []
    if not tokens:
        return out
    joined_all = "".join(tokens)
    joined_underscore = "".join(t for t in tokens if "_" in t or "{" in t or "}" in t)
    joined_space = " ".join(tokens)
    for method, text in [
        ("interesting_tokens_joined", joined_all),
        ("interesting_tokens_joined_reverse", "".join(reversed(tokens))),
        ("underscore_brace_tokens_joined", joined_underscore),
        ("interesting_tokens_spaced", joined_space),
    ]:
        if text and len(text) >= 4:
            out.append({"method": method, "text": text[:12000]})
    return out[:limit]


def rotate_point(pt: tuple[int, int], n: int, turns: int) -> tuple[int, int]:
    r, c = pt
    for _ in range(turns % 4):
        r, c = c, n - 1 - r
    return r, c


def cardan_project_agent(root: Path, reports: list[dict], meta: dict) -> tuple[list[dict], list[dict]]:
    """Solve small message+ASCII-key rotating grille tasks at project scope."""
    texts: list[tuple[str, str]] = []
    for r in reports:
        p = Path(str(r.get("path", "")))
        if not p.exists() or p.stat().st_size > 250_000:
            continue
        try:
            txt = p.read_bytes().decode("utf-8", "ignore")
            if txt.strip():
                texts.append((r.get("rel", p.name), txt))
        except Exception:
            continue
    joined = "\n".join(t for _name, t in texts)
    if not texts or "key" not in joined.lower() and "rakt" not in joined.lower():
        return [], []

    cipher_candidates: list[str] = []
    for _name, txt in texts:
        for m in re.finditer(r"[A-Z0-9:/.\-]{48,96}", txt):
            cand = m.group(0).strip()
            if len(cand) in {64, 81} and len(set(cand)) > 10:
                cipher_candidates.append(cand)
    key_grids: list[list[str]] = []
    for _name, txt in texts:
        inners = []
        for line in txt.splitlines():
            if "|" in line:
                inner = line.strip().strip("|")
                if len(inner) >= 8:
                    inners.append(inner[:8])
        for i in range(0, max(0, len(inners) - 7)):
            grid = inners[i:i + 8]
            marks = sum(1 for row in grid for ch in row if ch not in {" ", "\t", "-", "+"})
            if marks == 16:
                key_grids.append(grid)
    if not cipher_candidates or not key_grids:
        return [], []

    report = {"name": "project", "rel": "project", "statement": meta.get("statement", ""), "flags": [], "artifacts": [], "transformations": [], "workflow_evidence": []}
    candidates: list[dict[str, Any]] = []
    words = ["KOTVIRTINO", "MOKSLAS", "REIKALINGAS", "CYBER", "SPRINT", "CRYPTO", "SECRET", "HIDDEN", "FLAG"]
    for cipher in list(dict.fromkeys(cipher_candidates))[:8]:
        n = int(math.isqrt(len(cipher)))
        if n * n != len(cipher) or n > 9:
            continue
        grid_chars = [list(cipher[i * n:(i + 1) * n]) for i in range(n)]
        for key_grid in key_grids[:4]:
            holes = [(r, c) for r, row in enumerate(key_grid[:n]) for c, ch in enumerate(row[:n]) if ch not in {" ", "\t", "-", "+"}]
            if not holes or len(holes) * 4 != len(cipher):
                continue
            for order in ([0, 1, 2, 3], [0, 3, 2, 1], [1, 2, 3, 0], [3, 2, 1, 0]):
                for sorted_holes in (True, False):
                    pos: list[tuple[int, int]] = []
                    for turn in order:
                        hs = [rotate_point(h, n, turn) for h in holes]
                        pos.extend(sorted(hs) if sorted_holes else hs)
                    if len(set(pos)) != len(cipher):
                        continue
                    text = "".join(grid_chars[r][c] for r, c in pos)
                    score = sum(100 for w in words if w in text.upper())
                    score += int(printable_ratio(text.encode("utf-8", "ignore")) * 50)
                    if score < 250:
                        continue
                    variants = [text]
                    if text.endswith(("A", "X", "Z")):
                        variants.append(text.rstrip(text[-1]))
                    hashes = []
                    for plain in dict.fromkeys(variants):
                        digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
                        hashes.append({"plaintext": plain, "sha256": digest, "flag": f"ctf_cs{{{digest}}}"})
                    candidates.append({
                        "method": "cardan_grille_read_holes",
                        "rotation_order": order,
                        "hole_order": "row_sorted" if sorted_holes else "key_file_order",
                        "score": score,
                        "plaintext": text,
                        "hashes": hashes,
                    })
    if not candidates:
        return [], []
    candidates = sorted(candidates, key=lambda x: int(x.get("score", 0)), reverse=True)[:20]
    art = artifact(root, report, "v93_project_cardan_grille_candidates.json", json.dumps(candidates, indent=2, ensure_ascii=False), "sloper_v93_cardan_grille", "Project-scope rotating grille candidates from a message file and ASCII key.", 690, "project")
    flags: list[dict] = []
    statement = (meta.get("statement", "") + " " + joined[:1000]).lower()
    if "sha256" in statement or "hash" in statement:
        for h in candidates[0].get("hashes", [])[:2]:
            flag = normalize_flag(h["flag"], "sha256 hash from Cardan grille plaintext", allow_wrap=False)
            if flag:
                flags.append({
                    "flag": flag,
                    "file": "project",
                    "score": int(candidates[0].get("score", 0)) + 780,
                    "why": "Message+ASCII key matched a rotating grille; task asks for SHA256 of the decoded plaintext.",
                    "artifact": art.get("path") if art else "",
                })
    return ([art] if art else []), flags


def pcap_fast_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not (data.startswith(b"\x0a\x0d\x0d\x0a") or data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        return []
    packets = list(pcap_packets(data))[:25000]
    scalars: dict[str, list[int]] = {
        "ip_id": [], "ttl": [], "ip_len": [], "src4": [], "dst4": [],
        "udp_sport": [], "udp_dport": [], "udp_len": [], "udp_checksum": [],
        "dns_txid_hi": [], "dns_txid_lo": [], "dns_label_len": [],
        "icmp_id": [], "icmp_seq": [],
    }
    payloads = bytearray()
    dns_labels: list[str] = []
    http_chunks: list[str] = []
    for pkt in packets:
        if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
            off = 0
        elif len(pkt) >= 34 and (pkt[14] >> 4) == 4:
            off = 14
        else:
            continue
        if len(pkt) >= off + 20 and (pkt[off] >> 4) == 4:
            ihl = (pkt[off] & 15) * 4
            proto = pkt[off + 9]
            total = int.from_bytes(pkt[off + 2:off + 4], "big")
            scalars["ip_len"].append(total)
            scalars["ip_id"].append(int.from_bytes(pkt[off + 4:off + 6], "big"))
            scalars["ttl"].append(pkt[off + 8])
            scalars["src4"].append(pkt[off + 15])
            scalars["dst4"].append(pkt[off + 19])
            l4 = off + ihl
            if proto == 17 and len(pkt) >= l4 + 8:
                sport = int.from_bytes(pkt[l4:l4 + 2], "big")
                dport = int.from_bytes(pkt[l4 + 2:l4 + 4], "big")
                scalars["udp_sport"].append(sport & 255)
                scalars["udp_dport"].append(dport & 255)
                scalars["udp_len"].append(int.from_bytes(pkt[l4 + 4:l4 + 6], "big") & 255)
                scalars["udp_checksum"].append(int.from_bytes(pkt[l4 + 6:l4 + 8], "big") & 255)
                pl = pkt[l4 + 8:]
                payloads.extend(pl[:4000])
                if sport == 53 or dport == 53:
                    if len(pl) >= 2:
                        txid = int.from_bytes(pl[:2], "big")
                        scalars["dns_txid_hi"].append((txid >> 8) & 255)
                        scalars["dns_txid_lo"].append(txid & 255)
                    # Lightweight DNS label walk.
                    q = pl[12:] if len(pl) > 12 else b""
                    labels = []
                    i = 0
                    while i < len(q) and 0 < q[i] < 64 and i + 1 + q[i] <= len(q):
                        scalars["dns_label_len"].append(q[i])
                        labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "ignore"))
                        i += 1 + q[i]
                    if labels:
                        dns_labels.append(".".join(labels))
            elif proto == 6 and len(pkt) >= l4 + 20:
                data_off = ((pkt[l4 + 12] >> 4) & 15) * 4
                pl = pkt[l4 + data_off:]
                payloads.extend(pl[:4000])
                if b"HTTP" in pl[:50] or pl.startswith((b"GET ", b"POST ", b"PUT ")):
                    http_chunks.append(pl[:4000].decode("utf-8", "ignore"))
            elif proto == 1 and len(pkt) >= l4 + 8:
                scalars["icmp_id"].append(int.from_bytes(pkt[l4 + 4:l4 + 6], "big") & 255)
                scalars["icmp_seq"].append(int.from_bytes(pkt[l4 + 6:l4 + 8], "big") & 255)
                payloads.extend(pkt[l4 + 8:l4 + 4000])
    matrix = {k: decode_sequence(v) for k, v in scalars.items() if v}
    bit_matrix = {k: decode_bit_channels(v) for k, v in scalars.items() if v}
    bit_matrix = {k: v for k, v in bit_matrix.items() if v}
    text_blob = "\n".join(printable_strings(bytes(payloads), 4, 2000) + dns_labels + http_chunks)
    for name, variants in matrix.items():
        for method, txt in variants.items():
            scan_text(report, txt, "SLOPER v93 PCAP covert matrix", None, f"{name} decoded with {method}.", 760)
    for name, variants in bit_matrix.items():
        for method, txt in variants.items():
            scan_text(report, txt, "SLOPER v93 PCAP bit channel", None, f"{name} field decoded as packed bits with {method}.", 780)
    scan_text(report, text_blob, "SLOPER v93 PCAP payload strings", None, "Payload/DNS/HTTP strings extracted from packets.", 760)
    fragment_variants = pcap_fragment_variants(printable_strings(bytes(payloads), 3, 4000) + http_chunks, dns_labels)
    for item in fragment_variants:
        scan_text(report, item["text"], "SLOPER v93 PCAP fragment reconstruction", None, f"Packet fragments reconstructed by {item['method']}.", 750)
    arts = []
    a = artifact(root, report, "v93_pcap_summary.json", json.dumps({"packet_count": len(packets), "dns_labels": dns_labels[:300], "http_chunks": http_chunks[:80]}, indent=2, ensure_ascii=False), "sloper_v93_pcap_summary", "Pure Python PCAP/PCAPNG summary with DNS/HTTP strings.", 520, "pcap")
    if a:
        arts.append(a)
    a = artifact(root, report, "v93_pcap_covert_matrix.json", json.dumps({"scalars": {k: v[:1000] for k, v in scalars.items() if v}, "decoded": matrix, "bit_decoded": bit_matrix}, indent=2, ensure_ascii=False), "sloper_v93_pcap_covert_matrix", "Scalar covert channels decoded raw/reverse/diff/xor/mod and packed-bit variants.", 560, "pcap")
    if a:
        arts.append(a)
    if text_blob.strip():
        a = artifact(root, report, "v93_pcap_payload_strings.txt", text_blob[:1_000_000], "sloper_v93_pcap_payload_strings", "Printable packet payload, DNS label and HTTP text.", 540, "pcap")
        if a:
            arts.append(a)
    if fragment_variants:
        a = artifact(root, report, "v93_pcap_fragment_reconstruction.json", json.dumps(fragment_variants, indent=2, ensure_ascii=False), "sloper_v93_pcap_fragments", "Joined packet fragments that look like CTF text pieces.", 570, "pcap")
        if a:
            arts.append(a)
    return arts



# ---------- v95 stronger real-challenge reasoning agents ----------

V95_MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}

def _v95_ascii_ratio(raw: bytes) -> float:
    raw = bytes(raw or b"")
    if not raw:
        return 0.0
    sample = raw[:60000]
    return sum(1 for b in sample if 32 <= b < 127 or b in b"\r\n\t") / max(1, len(sample))

def _v95_extract_text_from_xml(raw: bytes) -> str:
    s = raw.decode("utf-8", "ignore")
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()

def _v95_scan_and_artifact(root: Path, report: dict, name: str, text: str | bytes, kind: str, note: str, score: int = 760, subdir: str = "v95") -> dict | None:
    a = artifact(root, report, name, text, kind, note, score, subdir)
    try:
        scan_text(report, text.decode("utf-8", "ignore") if isinstance(text, (bytes, bytearray)) else str(text),
                  "SLOPER v95 " + kind, a.get("path") if a else None, note, score + 80, allow_wrap=True)
    except Exception:
        pass
    return a

def v95_openxml_local_header_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Recover deleted/truncated DOCX/XLSX/PPTX members from ZIP local headers.

    zipfile.ZipFile needs a valid central directory. Deleted files carved from
    FAT/USB images often still contain local headers but not a clean EOCD.  This
    parser walks local headers directly and inflates raw-deflate members.
    """
    ensure(report)
    raw = bytes(data or b"")
    if not raw or len(raw) > 80_000_000:
        return []
    arts: list[dict] = []
    members: list[dict[str, Any]] = []
    pos = 0
    limit = 0
    while True:
        off = raw.find(b"PK\x03\x04", pos)
        if off < 0:
            break
        pos = off + 4
        limit += 1
        if limit > 600:
            break
        if off + 30 > len(raw):
            continue
        try:
            sig, ver, flags, comp, mtime, mdate, crc, csize, usize, nlen, elen = struct.unpack_from("<IHHHHHIIIHH", raw, off)
            if sig != 0x04034B50 or nlen <= 0 or nlen > 4096 or elen > 65535:
                continue
            name_b = raw[off + 30: off + 30 + nlen]
            name = name_b.decode("utf-8", "ignore") or name_b.decode("latin1", "ignore")
            start = off + 30 + nlen + elen
            if start > len(raw):
                continue
            # If sizes are zero because data descriptors are used, bound to next header.
            next_off = raw.find(b"PK\x03\x04", start + 1)
            if csize and start + csize <= len(raw):
                payload = raw[start:start + csize]
            elif next_off > start:
                payload = raw[start:next_off]
            else:
                payload = raw[start:min(len(raw), start + 20_000_000)]
            content = None
            if comp == 0:
                content = payload
            elif comp == 8:
                try:
                    content = zlib.decompress(payload, -15)
                except Exception:
                    # Some carved deflate members contain trailing bytes; retry with decompressobj.
                    try:
                        obj = zlib.decompressobj(-15)
                        content = obj.decompress(payload, max(usize or 0, 32_000_000)) + obj.flush()
                    except Exception:
                        content = None
            if content is None:
                continue
            info = {"offset": off, "name": name, "method": comp, "compressed": len(payload), "size": len(content)}
            members.append(info)
            interesting = name.endswith((".xml", ".rels", ".txt", ".json", ".html")) or any(x in name.lower() for x in ["document", "custom", "core", "sharedstrings", "comment"])
            if interesting:
                plain = _v95_extract_text_from_xml(content) if name.endswith((".xml", ".rels")) else content.decode("utf-8", "ignore")
                if plain.strip():
                    a = _v95_scan_and_artifact(root, report, "v95_localzip_" + safe_name(name) + ".txt", plain, "openxml_local_header_text", "Recovered text from ZIP local header member " + name + ".", 870, "openxml")
                    if a: arts.append(a)
            if len(content) <= 5_000_000:
                child_arts = archive_followups(report, root, content, "v95 localzip " + name, 0)
                arts.extend(child_arts or [])
        except Exception as e:
            agent_crash("v95 local zip header member", e, report)
    if members:
        a = artifact(root, report, "v95_openxml_local_headers.json", json.dumps(members[:600], indent=2, ensure_ascii=False), "openxml_local_header_manifest", "Recovered ZIP local-header members even if central directory is broken/deleted.", 820, "openxml")
        if a: arts.insert(0, a)
    return arts

def v95_container_reasoning_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Unwrap common containers and then run targeted recovery agents on children."""
    ensure(report)
    raw = bytes(data or b"")
    if not raw or len(raw) > 90_000_000:
        return []
    arts: list[dict] = []
    variants: list[tuple[str, bytes]] = []
    ext = Path(str(report.get("path", ""))).suffix.lower()
    try:
        if raw.startswith(b"\x1f\x8b"):
            dec = gzip.decompress(raw)
            variants.append(("gzip", dec))
            if ext in {".tgz", ".gz"}:
                _v95_scan_and_artifact(root, report, "v95_gzip_unwrapped.bin", dec[:8_000_000], "container_unwrapped", "Gzip stream unwrapped for child analysis.", 700, "containers")
        elif raw.startswith(b"BZh"):
            variants.append(("bz2", bz2.decompress(raw)))
        elif raw.startswith(b"\xfd7zXZ\x00"):
            variants.append(("xz", lzma.decompress(raw)))
    except Exception as e:
        agent_crash("v95 container unwrap", e, report)
    # Also carve embedded gzip streams before the real payload; common in disk/forensics images.
    for sig, name in [(b"\x1f\x8b\x08", "gzip"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz")]:
        off = raw.find(sig)
        if 0 <= off < min(len(raw), 2_000_000):
            try:
                dec = gzip.decompress(raw[off:]) if name == "gzip" else (bz2.decompress(raw[off:]) if name == "bz2" else lzma.decompress(raw[off:]))
                if dec and all(dec != v for _, v in variants):
                    variants.append((name + f"_offset_{off}", dec))
            except Exception:
                pass
    for label, child in variants[:12]:
        if not child:
            continue
        scan_text(report, child[:2_000_000].decode("utf-8", "ignore"), "SLOPER v95 container child", None, "Unwrapped " + label + " child text was scanned.", 760, allow_wrap=True)
        arts.extend(v95_openxml_local_header_agent(report, root, child) or [])
        arts.extend(archive_followups(report, root, child, "v95 " + label, 0) or [])
    return arts

def v95_static_strings_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """High-signal string/token pass with nested base decodes and leet hints."""
    ensure(report)
    raw = bytes(data or b"")
    if not raw:
        return []
    strings = printable_strings(raw, 4, 6000)
    blob = "\n".join(strings)
    scan_text(report, blob[:1_500_000], "SLOPER v95 static strings", None, "Printable strings were scanned as direct evidence.", 700, allow_wrap=True)
    decoded: list[dict[str, str]] = []
    tokens = list(dict.fromkeys(re.findall(r"[A-Za-z0-9+/=_-]{8,4000}", blob)[:1200]))
    for tok in tokens:
        low = tok.lower()
        if low in BAD_BODIES or any(x in low for x in ["http", "schema", "xmlns"]):
            continue
        vals: list[tuple[str, bytes]] = []
        try:
            vals.append(("base64", base64.b64decode(tok + "=" * ((4 - len(tok) % 4) % 4), validate=False)))
        except Exception:
            pass
        try:
            vals.append(("urlsafe_base64", base64.urlsafe_b64decode(tok + "=" * ((4 - len(tok) % 4) % 4))))
        except Exception:
            pass
        if re.fullmatch(r"[A-Z2-7]+=*", tok.upper()):
            try:
                vals.append(("base32", base64.b32decode(tok + "=" * ((8 - len(tok) % 8) % 8), casefold=True)))
            except Exception:
                pass
        if len(tok) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) <= 4000:
            try:
                vals.append(("hex", binascii.unhexlify(tok)))
            except Exception:
                pass
        for method, val in vals:
            if not val:
                continue
            txt = val.decode("utf-8", "ignore").strip()
            if not txt or len(txt) > 20000:
                continue
            if text_quality(txt[:2000]) >= 55 or re.search(r"ctf|flag|secret|token|admin|back|cwe|slap|veli|rakt", txt, re.I):
                decoded.append({"token": tok[:120], "method": method, "text": txt[:800]})
                scan_text(report, txt, "SLOPER v95 decoded static token", None, f"Static token decoded with {method}.", 820, allow_wrap=True)
    arts: list[dict] = []
    if blob.strip():
        a = artifact(root, report, "v95_strings.txt", blob[:1_500_000], "static_strings", "High-signal printable strings for manual review.", 520, "static")
        if a: arts.append(a)
    if decoded:
        a = artifact(root, report, "v95_decoded_static_tokens.json", json.dumps(decoded[:300], indent=2, ensure_ascii=False), "decoded_static_tokens", "Base/hex decoded strings from binary/text tokens.", 790, "static")
        if a: arts.append(a)
    return arts

def v95_morse_hex_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    text0 = data[:1_000_000].decode("utf-8", "ignore")
    if not re.search(r"(?:^|\s)[.\-]{1,5}(?:\s|$)", text0):
        return []
    tokens = re.findall(r"[.\-]{1,5}|/", text0.replace("_", "-"))
    if len(tokens) < 4:
        return []
    out = []
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        else:
            out.append(V95_MORSE.get(tok, "?"))
    decoded = "".join(out)
    arts: list[dict] = []
    a = _v95_scan_and_artifact(root, report, "v95_morse_decoded.txt", decoded, "morse_decode", "Morse-like tokens decoded.", 790, "text")
    if a: arts.append(a)
    hexed = re.sub(r"[^0-9A-Fa-f]", "", decoded)
    if len(hexed) >= 8 and len(hexed) % 2 == 0 and len(hexed) / max(1, len(decoded.replace(" ", ""))) > 0.75:
        try:
            raw = binascii.unhexlify(hexed)
            txt = raw.decode("utf-8", "ignore")
            a = _v95_scan_and_artifact(root, report, "v95_morse_hex_decoded.txt", txt, "morse_hex_decode", "Morse decoded to hex, then hex decoded.", 880, "text")
            if a: arts.append(a)
        except Exception:
            pass
    return arts

def v95_pyc_static_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if Path(str(report.get("path", ""))).suffix.lower() != ".pyc" and not data[:4]:
        return []
    arts: list[dict] = []
    try:
        import marshal, types
        # Try common pyc header sizes.
        code = None
        for off in (16, 12, 8):
            try:
                obj = marshal.loads(data[off:])
                if isinstance(obj, types.CodeType):
                    code = obj
                    break
            except Exception:
                pass
        if code is None:
            return []
        rows: list[dict[str, Any]] = []
        def walk(co):
            for c in co.co_consts:
                if isinstance(c, types.CodeType):
                    walk(c)
                    rows.append({"type": "code", "name": c.co_name, "names": list(c.co_names), "varnames": list(c.co_varnames)})
                elif isinstance(c, (str, bytes, int, tuple, list, dict)):
                    val = c.decode("utf-8", "ignore") if isinstance(c, bytes) else c
                    rows.append({"type": type(c).__name__, "value": val})
        walk(code)
        text_blob = json.dumps(rows, ensure_ascii=False, indent=2)
        scan_text(report, text_blob, "SLOPER v95 pyc constants", None, "PYC constants/names scanned for hidden credentials/backdoor tokens.", 760, allow_wrap=True)
        # Decode base64 constants and add CWE hint if the task asks for Frazė+CWE_kodas.
        decoded = []
        for r in rows:
            val = str(r.get("value", ""))
            if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,300}", val):
                try:
                    dec = base64.b64decode(val + "=" * ((4 - len(val) % 4) % 4), validate=False).decode("utf-8", "ignore")
                    if dec and text_quality(dec) >= 20:
                        decoded.append({"source": val, "decoded": dec})
                        scan_text(report, dec, "SLOPER v95 pyc decoded constant", None, "Base64 constant inside PYC decoded.", 850, allow_wrap=True)
                except Exception:
                    pass
        # Very common backdoor CWE mapping: hardcoded secret/key/password/token.
        if "CWE_kodas" in str(report.get("statement", "")) or "CWE" in text_blob:
            if re.search(r"sk_live_|secret|token|password|hardcoded|APP_SECRET_KEY", text_blob, re.I):
                for item in decoded:
                    d = item.get("decoded", "").strip()
                    # For CWE-format challenges, the phrase may be leetspeak and
                    # not look like a normal dictionary token yet.  The CWE suffix
                    # gives it the required semantic anchor.
                    if (4 <= len(d) <= 80 and re.search(r"[A-Za-z]", d)
                        and not re.search(r"[^A-Za-z0-9_\-:+./=]", d)
                        and (re.search(r"b4ck|back|final|f1n4l|d33t|leet|[034571].*_", d, re.I))):
                        add_flag(report, d + "+CWE-798", "SLOPER v95 pyc CWE heuristic", None, "Decoded leetspeak/final-looking phrase combined with CWE-798 for hard-coded credentials/secrets.", 890, allow_wrap=True)
        a = artifact(root, report, "v95_pyc_static_constants.json", text_blob[:2_000_000], "pyc_static_constants", "PYC constants, names and decoded hints for review.", 760, "rev")
        if a: arts.append(a)
        if decoded:
            a = artifact(root, report, "v95_pyc_decoded_constants.json", json.dumps(decoded, indent=2, ensure_ascii=False), "pyc_decoded_constants", "Decoded base64 constants from PYC.", 850, "rev")
            if a: arts.append(a)
    except Exception as e:
        agent_crash("v95 pyc static", e, report)
    return arts

def v95_image_deep_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF")):
        return []
    arts: list[dict] = []
    # Metadata and raw chunk text.
    meta_lines: list[str] = []
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data))
        meta_lines.append(f"format={getattr(im, 'format', '')} mode={im.mode} size={im.size}")
        for k, v in getattr(im, "info", {}).items():
            if isinstance(v, bytes):
                shown = v[:4000].decode("utf-8", "ignore")
            else:
                shown = str(v)
            meta_lines.append(f"{k}: {shown}")
        # PNG chunks including zTXt/iTXt/tEXt and unknown chunk names.
        if data.startswith(b"\x89PNG"):
            pos = 8
            chunks = []
            while pos + 8 <= len(data):
                ln = int.from_bytes(data[pos:pos+4], "big"); typ = data[pos+4:pos+8]; chunk = data[pos+8:pos+8+ln]
                pos2 = pos + 12 + ln
                if pos2 > len(data): break
                name = typ.decode("latin1", "ignore")
                chunks.append({"type": name, "length": ln})
                if typ in (b"tEXt", b"iTXt"):
                    meta_lines.append(f"PNG {name}: " + chunk[:8000].decode("utf-8", "ignore"))
                elif typ == b"zTXt":
                    try:
                        nul = chunk.find(b"\x00")
                        payload = chunk[nul+2:] if nul >= 0 and nul+2 < len(chunk) else chunk
                        meta_lines.append("PNG zTXt: " + zlib.decompress(payload).decode("utf-8", "ignore"))
                    except Exception:
                        pass
                pos = pos2
                if typ == b"IEND": break
            a = artifact(root, report, "v95_png_chunks.json", json.dumps(chunks, indent=2), "image_png_chunks", "PNG chunk map for manual review.", 520, "image")
            if a: arts.append(a)
        meta = "\n".join(meta_lines)
        if meta.strip():
            # Include reversed metadata strings too; many CTFs hide reversed words in EXIF/XMP.
            rev_lines = "\n".join(line[::-1] for line in meta_lines if 4 <= len(line) <= 1000)
            a = _v95_scan_and_artifact(root, report, "v95_image_metadata.txt", meta + "\n\n--- reversed lines ---\n" + rev_lines, "image_metadata", "Image metadata and reversed metadata lines.", 820, "image")
            if a: arts.append(a)
    except Exception as e:
        agent_crash("v95 image metadata", e, report)
    # Bit-plane previews and LSB text. Keep bounded: only first 1.5M bits per channel.
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data)).convert("RGBA")
        w, h = im.size
        px = list(im.getdata())
        chans = {
            "R": [p[0] for p in px], "G": [p[1] for p in px], "B": [p[2] for p in px], "A": [p[3] for p in px],
            "RGB": [v for p in px for v in p[:3]], "RGBA": [v for p in px for v in p],
        }
        lsb_hits = []
        for cname, vals in chans.items():
            if len(vals) > 2_000_000:
                vals = vals[:2_000_000]
            for bit in (0, 1):
                bits = [(v >> bit) & 1 for v in vals]
                for rev in (False, True):
                    seq = list(reversed(bits)) if rev else bits
                    for bit_order in ("msb", "lsb"):
                        raw = bytearray()
                        for i in range(0, min(len(seq), 1_600_000) - 7, 8):
                            b = seq[i:i+8]
                            if bit_order == "lsb":
                                b = list(reversed(b))
                            val = 0
                            for x in b:
                                val = (val << 1) | x
                            raw.append(val)
                        if not raw:
                            continue
                        txt = bytes(raw).decode("utf-8", "ignore")
                        if re.search(r"ctf|flag|secret|hidden|slap|veli|rakt|[a-z0-9]+_[a-z0-9_]+", txt, re.I) and text_quality(txt[:4000]) >= 20:
                            lsb_hits.append({"channel": cname, "bit": bit, "reverse": rev, "bit_order": bit_order, "preview": txt[:1200]})
                            scan_text(report, txt[:200000], "SLOPER v95 image LSB", None, f"Image LSB channel {cname} bit {bit} reverse={rev} order={bit_order}.", 850, allow_wrap=True)
        # Create visual bit-plane previews for the user; these are high utility for visual stego.
        for cname, idx in [("R",0),("G",1),("B",2),("A",3)]:
            if w*h <= 4_500_000:
                plane = Image.new("L", (w, h))
                plane.putdata([255 if (p[idx] & 1) else 0 for p in px])
                out = io.BytesIO(); plane.save(out, format="PNG")
                a = artifact(root, report, f"v95_lsb_plane_{cname}.png", out.getvalue(), "image_lsb_plane", f"Visual preview of {cname} channel bit 0.", 640, "image")
                if a: arts.append(a)
        if lsb_hits:
            a = artifact(root, report, "v95_image_lsb_hits.json", json.dumps(lsb_hits[:80], indent=2, ensure_ascii=False), "image_lsb_hits", "Readable LSB text candidates from image channels.", 850, "image")
            if a: arts.append(a)
    except Exception as e:
        agent_crash("v95 image lsb", e, report)
    return arts

def v95_crypto_transposition_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """More visible transposition search for short text messages."""
    ensure(report)
    txt = data.decode("utf-8", "ignore").strip()
    compact = re.sub(r"\s+", "", txt)
    if not (8 <= len(compact) <= 2000):
        return []
    if len(set(compact)) < 8:
        return []
    outs: list[dict[str, Any]] = []
    seen: set[str] = set()
    def push(method: str, out: str, score: int = 720):
        if not out or out in seen:
            return
        seen.add(out)
        q = text_quality(out[:4000])
        hit = scan_text(report, out, "SLOPER v95 transposition", None, method, score + q // 3, allow_wrap=True)
        if hit or q >= 70 or re.search(r"ctf|flag|secret|slap|veli|rakt|sha256", out, re.I):
            outs.append({"method": method, "quality": q, "flags": hit[:6], "preview": out[:600]})
    n = len(compact)
    # Rectangle route reads.
    for rows in range(2, min(80, n) + 1):
        if n % rows:
            continue
        cols = n // rows
        if cols < 2 or cols > 200:
            continue
        grid = [list(compact[i*cols:(i+1)*cols]) for i in range(rows)]
        push(f"rows {rows}x{cols} read columns", "".join(grid[r][c] for c in range(cols) for r in range(rows)))
        push(f"rows {rows}x{cols} read columns reversed", "".join(grid[r][c] for c in reversed(range(cols)) for r in range(rows)))
        push(f"rows {rows}x{cols} snake columns", "".join(grid[r][c] for c in range(cols) for r in (range(rows) if c % 2 == 0 else reversed(range(rows)))))
        grid2 = [[""] * cols for _ in range(rows)]
        it = iter(compact)
        for c in range(cols):
            for r in range(rows):
                grid2[r][c] = next(it)
        push(f"columns {rows}x{cols} read rows", "".join("".join(row) for row in grid2))
        grid3 = [[""] * cols for _ in range(rows)]
        it = iter(compact)
        for c in range(cols):
            rr = range(rows) if c % 2 == 0 else reversed(range(rows))
            for r in rr:
                grid3[r][c] = next(it)
        push(f"snake columns {rows}x{cols} read rows", "".join("".join(row) for row in grid3))
    # Rail fence, both decrypt/encrypt-ish.
    def rail_decrypt(cipher: str, rails: int) -> str:
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        pat = [pattern[i % len(pattern)] for i in range(len(cipher))]
        counts = [pat.count(r) for r in range(rails)]
        rails_s = []
        pos = 0
        for c in counts:
            rails_s.append(list(cipher[pos:pos+c])); pos += c
        idxs = [0] * rails
        out = []
        for r in pat:
            out.append(rails_s[r][idxs[r]]); idxs[r] += 1
        return "".join(out)
    for rails in range(2, min(12, max(3, len(compact)//2))):
        try:
            push(f"rail_fence_decrypt_{rails}", rail_decrypt(compact, rails), 780)
        except Exception:
            pass
    arts: list[dict] = []
    if outs:
        a = artifact(root, report, "v95_transposition_candidates.json", json.dumps(sorted(outs, key=lambda x: x["quality"], reverse=True)[:160], indent=2, ensure_ascii=False), "transposition_candidates", "Bounded route/rail transposition candidates ranked for review.", 800, "crypto")
        if a: arts.append(a)
    return arts

def v95_folder_reasoning_summary(root: Path, reports: list[dict], meta: dict) -> list[dict]:
    """Build a user-facing folder/challenge view so the workflow is not a pile of zlib files."""
    groups: dict[str, dict[str, Any]] = {}
    for r in reports:
        rel = str(r.get("rel") or r.get("name") or "")
        parts = re.split(r"[\\/]", rel)
        group = "/".join(parts[:-1]) if len(parts) > 1 else "."
        g = groups.setdefault(group, {"files": [], "task_text": "", "flags": [], "hints": set(), "artifacts": 0})
        g["files"].append(rel)
        g["artifacts"] += len(r.get("artifacts", []) or [])
        for f in r.get("flags", []) or []:
            g["flags"].append(f if isinstance(f, str) else f.get("flag", ""))
        if rel.lower().endswith(".txt"):
            try:
                txt = Path(str(r.get("path", ""))).read_text(encoding="utf-8", errors="ignore")
                if "vėliav" in txt.lower() or "formatas" in txt.lower() or "užduot" in txt.lower() or "flag" in txt.lower():
                    g["task_text"] += txt[:2000] + "\n"
            except Exception:
                pass
        kind = str(r.get("kind", ""))
        if kind:
            g["hints"].add(kind)
    out = []
    for group, g in sorted(groups.items()):
        task = g["task_text"].lower()
        suggested = []
        if "transpozic" in task: suggested.append("crypto: route/rail/columnar transposition")
        if "sha256" in task: suggested.append("hash final decoded message with sha256")
        if "pcap" in " ".join(g["files"]).lower() or "sraut" in task: suggested.append("network: payload + scalar covert channels")
        if "docx" in task or "usb" in task or ".dd" in " ".join(g["files"]).lower(): suggested.append("forensics: decompress disk image + recover deleted DOCX local headers")
        if "steganograf" in task or "paslėp" in task or "png" in " ".join(g["files"]).lower(): suggested.append("stego: metadata, chunks, LSB text and visual bit planes")
        if ".pyc" in " ".join(g["files"]).lower(): suggested.append("rev: PYC constants/base64/CWE mapping")
        if not suggested: suggested.append("general: strings, metadata, multistep decode, artifacts-first review")
        out.append({"challenge": group, "files": g["files"][:20], "task_excerpt": g["task_text"][:600], "final_flags": [x for x in g["flags"] if x][:20], "artifact_count": g["artifacts"], "suggested_workflow": suggested})
    a = artifact(root, {"name": "project", "rel": "project", "flags": [], "artifacts": [], "workflow_evidence": [], "statement": meta.get("statement", "")}, "v95_challenge_workflow_map.json", json.dumps(out, indent=2, ensure_ascii=False), "challenge_workflow_map", "Folder-level workflow map: what to open first and why.", 900, "project")
    return [a] if a else []



# ---------- v96 pattern engine: broader but evidence-ranked workflows ----------

V96_BAD_FINAL_BODIES = {
    "enter_password", "wrong_password", "try_again", "access_denied", "usage", "username",
    "password", "success", "failure", "invalid_password", "correct_password", "input_password",
}

# Common homoglyphs that appear in AI-proofed CTF text and copy/paste traps.
HOMOGLYPH_MAP = str.maketrans({
    "а":"a", "е":"e", "о":"o", "р":"p", "с":"c", "х":"x", "у":"y", "і":"i", "ј":"j",
    "Α":"A", "Β":"B", "Ε":"E", "Η":"H", "Ι":"I", "Κ":"K", "Μ":"M", "Ν":"N", "Ο":"O", "Ρ":"P", "Τ":"T", "Χ":"X", "Υ":"Y", "Ζ":"Z",
    "Α".lower():"a", "Β".lower():"b", "Ε".lower():"e", "Η".lower():"h", "Ι".lower():"i", "Κ".lower():"k", "Μ".lower():"m", "Ν".lower():"n", "Ο".lower():"o", "Ρ".lower():"p", "Τ".lower():"t", "Χ".lower():"x", "Υ".lower():"y", "Ζ".lower():"z",
})

ZERO_WIDTH_BITS = {"\u200b":"0", "\u200c":"1", "\u2060":"0", "\ufeff":"1"}
WHITESPACE_BITS = {" ": "0", "\t": "1"}

def v96_decode_escaped_filename(name: str) -> str:
    s = str(name or "")
    # Cyber Sprint exports sometimes contain #U0161 instead of Unicode.
    def repl(m):
        try: return chr(int(m.group(1), 16))
        except Exception: return m.group(0)
    s2 = re.sub(r"#U([0-9A-Fa-f]{4})", repl, s)
    try:
        s2 = urllib.parse.unquote(s2)
    except Exception:
        pass
    return s2

def v96_score_text_signal(txt: str) -> int:
    txt = str(txt or "")
    low = txt.lower()
    score = text_quality(txt[:8000])
    score += sum(80 for w in ["ctf", "flag", "secret", "hidden", "slapta", "raktas", "cyber", "sprint", "sha256"] if w in low)
    if re.search(r"[a-z0-9]{2,}_[a-z0-9_]{2,}", low): score += 65
    if re.search(r"https?://|pastebin|raw|github", low): score += 60
    return score

def v96_decode_bits_to_text(bits: str) -> list[str]:
    outs=[]
    bits=re.sub(r"[^01]", "", str(bits or ""))
    if len(bits) < 8:
        return outs
    for off in range(8):
        b=bits[off:]
        if len(b) < 8: continue
        for rev in (False, True):
            arr=bytearray()
            for i in range(0, len(b)-7, 8):
                chunk=b[i:i+8]
                if rev: chunk=chunk[::-1]
                arr.append(int(chunk,2))
            try:
                txt=bytes(arr).decode("utf-8", "ignore")
            except Exception:
                txt=""
            if v96_score_text_signal(txt) >= 90 or "{" in txt or "ctf" in txt.lower():
                outs.append(txt)
    return list(dict.fromkeys(outs))[:16]

def v96_context_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Decode file/path/task context, invisible bits and confusable text before heavy brute-force."""
    ensure(report)
    arts=[]
    pieces=[]
    try:
        pieces.append("name=" + v96_decode_escaped_filename(str(report.get("name", ""))))
        pieces.append("rel=" + v96_decode_escaped_filename(str(report.get("rel", ""))))
        pieces.append("path=" + v96_decode_escaped_filename(str(report.get("path", ""))))
        pieces.append("statement=" + str(report.get("statement", ""))[:20000])
    except Exception:
        pass
    txt = data[:1_500_000].decode("utf-8", "ignore") if data else ""
    if txt:
        pieces.append("text_head=" + txt[:200000])
    joined="\n".join(pieces)
    normalized=joined.translate(HOMOGLYPH_MAP)
    if normalized != joined:
        a=artifact(root, report, "v96_homoglyph_normalized_context.txt", normalized, "v96_homoglyph_context", "Normalized common Cyrillic/Greek homoglyphs in filename/task/text context.", 760, "v96_context")
        if a: arts.append(a)
        scan_text(report, normalized, "SLOPER v96 homoglyph context", a.get("path") if a else None, "Homoglyph-normalized context contained answer evidence.", 820, allow_wrap=True)
    # Zero-width channels: map selected invisible chars to bits and also remove them.
    zw_bits="".join(ZERO_WIDTH_BITS.get(ch, "") for ch in joined)
    if len(zw_bits) >= 8:
        decoded=v96_decode_bits_to_text(zw_bits)
        if decoded:
            payload={"bit_count":len(zw_bits), "decoded":decoded[:12]}
            a=artifact(root, report, "v96_zero_width_bits.json", json.dumps(payload, indent=2, ensure_ascii=False), "v96_zero_width_bits", "Zero-width characters decoded as binary channel.", 860, "v96_context")
            if a: arts.append(a)
            for out in decoded:
                scan_text(report, out, "SLOPER v96 zero-width bits", a.get("path") if a else None, "Invisible zero-width bit channel decoded to text.", 900, allow_wrap=True)
    stripped="".join(ch for ch in joined if ch not in ZERO_WIDTH_BITS)
    if stripped != joined:
        scan_text(report, stripped, "SLOPER v96 zero-width stripped", None, "Zero-width characters stripped from context/text.", 760, allow_wrap=True)
    # Whitespace bits are common in task text and logs; only try when line endings look intentional.
    ws_bits="".join(WHITESPACE_BITS.get(ch, "") for ch in txt if ch in WHITESPACE_BITS)
    if 32 <= len(ws_bits) <= 200000 and ("\t" in txt or re.search(r" {2,}\n", txt)):
        decoded=v96_decode_bits_to_text(ws_bits)
        if decoded:
            payload={"bit_count":len(ws_bits), "decoded":decoded[:12]}
            a=artifact(root, report, "v96_whitespace_bits.json", json.dumps(payload, indent=2, ensure_ascii=False), "v96_whitespace_bits", "Spaces/tabs decoded as binary channel.", 840, "v96_context")
            if a: arts.append(a)
            for out in decoded:
                scan_text(report, out, "SLOPER v96 whitespace bits", a.get("path") if a else None, "Whitespace bit channel decoded to text.", 880, allow_wrap=True)
    # Context itself may hold URLs, hashes or explicit answers.
    a=artifact(root, report, "v96_context_normalized.txt", normalized[:500000], "v96_context_summary", "Decoded filename/path/task context gathered before file-specific agents.", 520, "v96_context")
    if a: arts.append(a)
    return arts

def v96_try_decoded_value(label: str, val: str) -> list[tuple[str, str]]:
    """Decode one structured value through high-signal formats."""
    outs=[]
    s=str(val or "").strip().strip('"\'')
    if not s:
        return outs
    def add(name, raw):
        if raw is None: return
        if isinstance(raw, bytes):
            txt=raw.decode("utf-8", "ignore")
        else:
            txt=str(raw)
        if txt and txt != s:
            outs.append((name, txt))
    try:
        u=urllib.parse.unquote_plus(s)
        if u != s: add(label+":url", u)
    except Exception: pass
    try:
        h=html.unescape(s)
        if h != s: add(label+":html", h)
    except Exception: pass
    if re.fullmatch(r"[A-Fa-f0-9]{8,}", s) and len(s)%2==0:
        try: add(label+":hex", binascii.unhexlify(s))
        except Exception: pass
    # octal bytes: 143 164 146 or \143\164\146
    octs=re.findall(r"(?<!\d)([0-7]{2,3})(?!\d)", s)
    if len(octs)>=4 and len("".join(octs)) >= len(s.replace(" ",""))*0.55:
        try: add(label+":octal", bytes(int(x,8)&255 for x in octs))
        except Exception: pass
    nums=[int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", s)[:5000]]
    if len(nums)>=4:
        for off in (0,32,48,64,100,128,255):
            arr=[(n-off)&255 for n in nums if 0 <= n-off <= 255]
            if len(arr)>=4:
                try: add(label+f":charcodes_minus_{off}", bytes(arr))
                except Exception: pass
        try: add(label+":charcodes_mod256", bytes(n & 255 for n in nums))
        except Exception: pass
    # Powershell -EncodedCommand is UTF-16LE base64; also try normal base64/base32.
    if 8 <= len(s) <= 20000 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        pad="="*((4-len(s)%4)%4)
        for nm, fn in [("base64", lambda: base64.b64decode(s+pad, validate=False)), ("urlsafe_base64", lambda: base64.urlsafe_b64decode(s+pad))]:
            try:
                raw=fn(); add(label+":"+nm, raw); 
                try: add(label+":"+nm+":utf16le", raw.decode("utf-16le", "ignore"))
                except Exception: pass
            except Exception: pass
    if 8 <= len(s) <= 20000 and re.fullmatch(r"[A-Z2-7]+=*", s.upper()):
        try: add(label+":base32", base64.b32decode(s + "="*((8-len(s)%8)%8), casefold=True))
        except Exception: pass
    # JWT sections are just base64url JSON; useful in web/misc tasks.
    if s.count(".") == 2 and all(re.fullmatch(r"[A-Za-z0-9_-]+", part or "") for part in s.split(".")):
        for i,part in enumerate(s.split(".")):
            try: add(label+f":jwt_part_{i}", base64.urlsafe_b64decode(part + "="*((4-len(part)%4)%4)))
            except Exception: pass
    return outs[:80]

def v96_structured_text_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Decode structured text values: JSON lines, URLs/query params, JWTs, charcodes and UTF-16LE base64."""
    ensure(report)
    if not data or len(data) > 4_000_000:
        return []
    text=data.decode("utf-8", "ignore")
    if not text.strip():
        return []
    values=[]
    # Whole text and compact value first.
    values.append(("whole", text.strip()[:200000]))
    compact=re.sub(r"\s+", "", text.strip())
    if compact and compact != text.strip(): values.append(("compact", compact[:200000]))
    # JSON/key-value/url params.
    for m in re.finditer(r"[A-Za-z0-9_.-]{2,40}\s*[:=]\s*['\"]?([^'\"\s,;&]{4,4000})", text[:600000]):
        values.append(("kv_"+m.group(0)[:30], m.group(1)))
    for url in re.findall(r"https?://[^\s'\"<>]+", text[:600000], flags=re.I):
        values.append(("url", url))
        try:
            pr=urllib.parse.urlparse(url)
            for k, vals in urllib.parse.parse_qs(pr.query, keep_blank_values=True).items():
                for v in vals: values.append(("url_param_"+k, v))
        except Exception: pass
    for tok in re.findall(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text[:600000]):
        values.append(("jwt", tok))
    # JS/Python bytes literal / hex escape strings.
    for m in re.finditer(r"(?:\\x[0-9A-Fa-f]{2}){4,}|(?:\\u[0-9A-Fa-f]{4}){2,}", text[:600000]):
        values.append(("escape_literal", m.group(0)))
    decoded_rows=[]
    seen=set()
    for label,val in values[:500]:
        for name,out in v96_try_decoded_value(label, val):
            key=(name,out[:200])
            if key in seen: continue
            seen.add(key)
            q=v96_score_text_signal(out)
            if q >= 90 or "{" in out or re.search(r"ctf|flag|secret|slapta|raktas|cyber|sprint|sha256", out, re.I):
                decoded_rows.append({"method":name, "quality":q, "text":out[:1200]})
                scan_text(report, out, "SLOPER v96 structured decode", None, f"Structured value decoded by {name}.", 830 + min(q,200)//4, allow_wrap=True)
                # Follow one extra bounded transform layer for values that decode to encoded text again.
                for subname, raw in _decode_text_variants(out)[:20]:
                    st=raw.decode("utf-8", "ignore")
                    if v96_score_text_signal(st) >= 110 or "{" in st:
                        decoded_rows.append({"method":name+" -> "+subname, "quality":v96_score_text_signal(st), "text":st[:1200]})
                        scan_text(report, st, "SLOPER v96 structured chain", None, f"Structured value decoded by {name} then {subname}.", 860, allow_wrap=True)
    arts=[]
    if decoded_rows:
        a=artifact(root, report, "v96_structured_decoded_values.json", json.dumps(decoded_rows[:240], indent=2, ensure_ascii=False), "v96_structured_decodes", "High-signal decoded values from JSON/KV/URL/JWT/charcode/UTF16/base encodings.", 860, "v96_text")
        if a: arts.append(a)
    return arts

def v96_artifact_log_ascii_ocr_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Reconstruct coordinate-tile JSON logs and add an OCR-assist lane for large ASCII banners."""
    ensure(report)
    text=data.decode("utf-8", "ignore")
    if '"x"' not in text or '"rows"' not in text:
        return []
    entries=[]
    for line in text.splitlines():
        try:
            obj=json.loads(line)
            if all(k in obj for k in ("x","y","rows")) and isinstance(obj.get("rows"), list):
                obj["x"]=int(obj.get("x",0)); obj["y"]=int(obj.get("y",0)); obj["rows"]=[str(r) for r in obj.get("rows", [])]
                entries.append(obj)
        except Exception: pass
    if len(entries)<3:
        return []
    useful=set(" $/_\\|()[]{}<>.:;,_-+ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    artchars=set(" $/_\\|")
    scored=[]
    for i,e in enumerate(entries):
        raw="".join(e["rows"])
        if not raw: continue
        art_ratio=sum(ch in artchars for ch in raw)/max(1,len(raw))
        useful_ratio=sum(ch in useful for ch in raw)/max(1,len(raw))
        noise_ratio=sum(ch in "@#%?!*&" for ch in raw)/max(1,len(raw))
        nonspace=sum(ch!=" " for ch in raw)
        e2=dict(e); e2["_score"]=round(art_ratio*100 + useful_ratio*30 + min(nonspace,40) - noise_ratio*130,2); e2["_line_index"]=i
        scored.append(e2)
    byslot={}
    for e in scored:
        h=len(e["rows"]); w=max((len(r) for r in e["rows"]), default=0)
        key=(e["x"],e["y"],w,h)
        if key not in byslot or e["_score"]>byslot[key]["_score"]:
            byslot[key]=e
    chosen=[e for e in byslot.values() if e["_score"]>=45]
    if not chosen: chosen=sorted(scored,key=lambda x:x["_score"],reverse=True)[:max(3,len(scored)//3)]
    maxx=max(e["x"]+max(len(r) for r in e["rows"]) for e in chosen)
    maxy=max(e["y"]+len(e["rows"]) for e in chosen)
    canvas=[[" "]*maxx for _ in range(maxy)]
    for e in sorted(chosen,key=lambda x:(x["y"],x["x"],-x["_score"])):
        for dy,row in enumerate(e["rows"]):
            for dx,ch in enumerate(row):
                if ch!=" ":
                    yy=e["y"]+dy; xx=e["x"]+dx
                    if 0<=yy<maxy and 0<=xx<maxx: canvas[yy][xx]=ch
    art_text="\n".join("".join(row).rstrip() for row in canvas)
    arts=[]
    a=artifact(root, report, "00_OPEN_FIRST_v96_artifact_log_ascii.txt", art_text, "v96_artifact_ascii_canvas", "OPEN FIRST: coordinate JSON tiles reconstructed into a clean ASCII canvas.", 920, "v96_artifact_log")
    if a: arts.append(a)
    # OCR-assist: split the banner into fixed 12-column tiles because common FIGlet money fonts use 12-wide blocks.
    tiles=[]
    widths=[8,9,10,11,12,13]
    for w in widths:
        row=[]
        for x in range(0, maxx, w):
            block="\n".join(line[x:x+w].rstrip() for line in art_text.splitlines()).strip("\n")
            density=sum(ch!=" " for ch in block)/max(1,len(block))
            if density>0.03: row.append({"x":x,"w":w,"block":block})
        if len(row)>=4: tiles.append({"width":w,"tiles":row[:80]})
    manifest={"entries_total":len(entries),"slots":len(byslot),"chosen":len(chosen),"width":maxx,"height":maxy,"ocr_assist":"Open the ASCII canvas; if it is a FIGlet banner, read the glyphs visually or compare 8-13 column tiles.","tile_sets":tiles[:6]}
    m=artifact(root, report, "v96_artifact_log_ocr_assist.json", json.dumps(manifest, indent=2, ensure_ascii=False), "v96_artifact_ocr_assist", "OCR-assist manifest for noisy coordinate ASCII art; includes candidate glyph tiles.", 760, "v96_artifact_log")
    if m: arts.append(m)
    scan_text(report, art_text, "SLOPER v96 artifact ascii", a.get("path") if a else None, "Reconstructed artifact canvas contained direct text evidence.", 820, allow_wrap=True)
    return arts

def v96_network_exfil_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """PCAP/PCAPNG exfil workflow: HTTP params, DNS labels, payload strings, chunk reassembly and value decoding."""
    ensure(report)
    if not data or len(data)>30_000_000:
        return []
    packets=list(pcap_packets(data))[:8000]
    if not packets:
        return []
    strings=[]; dns=[]; params=[]; decoded=[]
    for payload in packets:
        if not payload: continue
        s=payload.decode("latin1", "ignore")
        # Printable payload snippets.
        for m in re.finditer(r"[ -~]{6,500}", s):
            chunk=m.group(0)
            if any(x in chunk.lower() for x in ["get ","post ","host:","http/", "ctf", "flag", "secret", "token", "data=", "q=", "id="]):
                strings.append(chunk)
        # Crude DNS label extraction from UDP/TCP payload bytes.
        b=bytes(payload)
        i=0
        while i < len(b)-3 and len(dns)<2000:
            ln=b[i]
            if 1 <= ln <= 63 and i+1+ln <= len(b):
                lab=b[i+1:i+1+ln]
                if all(32 < c < 127 and chr(c) not in " /\\:;" for c in lab):
                    token=lab.decode("ascii", "ignore")
                    if len(token)>=3: dns.append(token)
                    i += 1+ln; continue
            i += 1
    blob="\n".join(strings[:2000] + dns[:2000])
    # URL/query parameter extraction from payloads and DNS-like chunks.
    for m in re.finditer(r"(?:GET|POST)\s+([^\s]+)|https?://[^\s'\"<>]+|[?&]([A-Za-z0-9_.-]{1,30})=([^\s&]{1,2000})", blob, re.I):
        full=m.group(0)
        try:
            if full.upper().startswith(("GET ","POST ")):
                path=m.group(1) or ""
                qs=urllib.parse.urlparse(path).query
                for k,vals in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
                    for v in vals: params.append((k,v))
            elif full.startswith(("?","&")) and m.group(2):
                params.append((m.group(2), m.group(3)))
            elif full.lower().startswith("http"):
                pr=urllib.parse.urlparse(full)
                for k,vals in urllib.parse.parse_qs(pr.query, keep_blank_values=True).items():
                    for v in vals: params.append((k,v))
        except Exception: pass
    # DNS exfil often uses ordered labels or hex/base labels split across packets.
    label_join="".join([x for x in dns if re.fullmatch(r"[A-Za-z0-9+/=_-]{2,80}", x)])[:200000]
    dot_join=".".join(dns[:1200])
    for label,val in [("dns_join",label_join),("dns_dot_join",dot_join),("payload_blob",blob[:200000])]:
        for name,out in v96_try_decoded_value(label, val):
            if v96_score_text_signal(out)>=90 or "{" in out or "ctf" in out.lower():
                decoded.append({"method":name,"text":out[:1500],"quality":v96_score_text_signal(out)})
                scan_text(report, out, "SLOPER v96 network exfil", None, f"Network exfil value decoded by {name}.", 860, allow_wrap=True)
    # Reassemble params by name and by numeric suffix order.
    byname={}
    for k,v in params[:3000]: byname.setdefault(k,[]).append(v)
    # Decode individual parameter values before chunk joins; a single d=base64 flag should not be broken by noisy DNS parser duplicates.
    for k, vals in byname.items():
        for v in vals[:200]:
            clean_v = urllib.parse.unquote_plus(str(v))
            scan_text(report, clean_v, "SLOPER v96 network param value", None, f"HTTP/query parameter {k} individual value.", 820, allow_wrap=True)
            for name,out in v96_try_decoded_value("param_"+k, clean_v):
                if v96_score_text_signal(out)>=90 or "{" in out:
                    decoded.append({"method":"param_"+k+" individual -> "+name,"text":out[:1500],"quality":v96_score_text_signal(out)})
                    scan_text(report, out, "SLOPER v96 network param value decode", None, f"HTTP/query parameter {k} individual value decoded by {name}.", 900, allow_wrap=True)
    for k,vals in byname.items():
        variants=["".join(vals), "\n".join(vals)]
        # Sort by numbers in the values if present.
        try:
            variants.append("".join(v for v in sorted(vals, key=lambda x:int(re.search(r"\d+", x).group(0)) if re.search(r"\d+", x) else 0)))
        except Exception: pass
        for vi,var in enumerate(dict.fromkeys(variants)):
            scan_text(report, urllib.parse.unquote_plus(var), "SLOPER v96 network param reassembly", None, f"HTTP/query parameter {k} reassembled variant {vi}.", 820, allow_wrap=True)
            for name,out in v96_try_decoded_value("param_"+k, var):
                if v96_score_text_signal(out)>=90 or "{" in out:
                    decoded.append({"method":"param_"+k+" -> "+name,"text":out[:1500],"quality":v96_score_text_signal(out)})
                    scan_text(report, out, "SLOPER v96 network param decode", None, f"HTTP/query parameter {k} decoded by {name}.", 880, allow_wrap=True)
    arts=[]
    summary={"packet_payloads":len(packets),"http_or_interesting_strings":strings[:500],"dns_labels":dns[:500],"params":params[:500],"decoded":decoded[:160]}
    a=artifact(root, report, "v96_network_exfil_summary.json", json.dumps(summary, indent=2, ensure_ascii=False), "v96_network_exfil", "HTTP/DNS/payload exfil reconstruction with decoded params and labels.", 850, "v96_pcap")
    if a: arts.append(a)
    scan_text(report, blob, "SLOPER v96 network payload strings", a.get("path") if a else None, "PCAP payload/DNS/HTTP strings scanned before decoding.", 760, allow_wrap=True)
    return arts

def v96_binary_static_reasoning_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Static binary lane: high-value strings, encoded constants and safer false-positive handling."""
    ensure(report)
    if not data or len(data)>20_000_000:
        return []
    strings=printable_strings(data,4,5000)
    interesting=[]; decoded=[]
    for s in strings:
        low=s.lower()
        if any(x in low for x in ["ctf", "flag", "secret", "password", "correct", "token", "key", "congrat", "sha256", "cyber", "sprint", "wrong", "enter"]):
            interesting.append(s)
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{12,500}", s) or re.fullmatch(r"[A-Fa-f0-9]{12,500}", s):
            for name,out in v96_try_decoded_value("binstr", s):
                if v96_score_text_signal(out)>=90 or "{" in out:
                    decoded.append({"source":s[:120],"method":name,"text":out[:1000],"quality":v96_score_text_signal(out)})
                    scan_text(report, out, "SLOPER v96 binary encoded strings", None, f"Binary string constant decoded by {name}.", 850, allow_wrap=True)
    # Only scan direct strings with wrapping if the token is not a prompt/status phrase.
    for s in interesting[:1000]:
        low=s.lower().strip().strip("{}")
        if low in V96_BAD_FINAL_BODIES or any(x in low for x in ["wrong password", "enter password", "invalid password", "usage:"]):
            continue
        scan_text(report, s, "SLOPER v96 binary high-signal strings", None, "High-signal binary string scanned with prompt/status false-positive filter.", 760, allow_wrap=True)
    arts=[]
    if interesting or decoded:
        payload={"interesting_strings":interesting[:400],"decoded_constants":decoded[:160],"note":"Prompt/status strings such as enter_password/wrong_password are intentionally not promoted as final flags."}
        a=artifact(root, report, "v96_binary_static_summary.json", json.dumps(payload, indent=2, ensure_ascii=False), "v96_binary_static", "Static binary review: high-signal strings + decoded constants with false-positive suppression.", 780, "v96_binary")
        if a: arts.append(a)
    return arts

def v96_project_reasoning_agent(root: Path, reports: list[dict], meta: dict) -> tuple[list[dict], list[dict]]:
    """Project-level finishers for challenge folders: hash finalization and pairwise message/key review."""
    arts=[]; flags=[]
    groups={}
    for r in reports:
        rel=str(r.get("rel") or r.get("name") or "")
        parts=re.split(r"[\\/]", rel)
        group="/".join(parts[:-1]) if len(parts)>1 else "."
        groups.setdefault(group,[]).append(r)
    for group, rs in groups.items():
        task="\n".join(str(r.get("statement", "")) for r in rs)[:30000]
        if "sha256" not in task.lower() and "hash" not in task.lower():
            continue
        # Collect plausible plaintexts from report evidence/artifacts and direct small text files.
        plains=[]
        for r in rs:
            p=Path(str(r.get("path", "")))
            if p.exists() and p.stat().st_size <= 300000:
                txt=p.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"(?:plaintext|decoded|message|žinutė|zinute)\s*[:=]\s*([^\n]{8,200})", txt, re.I):
                    plains.append(("text_label", m.group(1).strip()))
            for ev in r.get("workflow_evidence", []) or []:
                why=str(ev.get("why", "")); src=str(ev.get("source", ""))
                if "plaintext" in why.lower() or "decoded" in why.lower():
                    plains.append(("evidence", why[:200]))
        # Also use Cardan candidates artifact if present.
        for r in rs:
            for a in r.get("artifacts", []) or []:
                if not isinstance(a, dict): continue
                if "cardan" in str(a.get("kind", "")).lower() and a.get("path"):
                    try:
                        obj=json.loads(Path(a["path"]).read_text(encoding="utf-8", errors="ignore"))
                        for cand in obj[:20]:
                            if cand.get("plaintext"): plains.append(("cardan", cand["plaintext"]))
                    except Exception: pass
        rows=[]; seen=set()
        for src,plain in plains[:120]:
            plain=str(plain).strip()
            if not (8 <= len(plain) <= 500): continue
            for variant in [plain, plain.rstrip("AXZ"), plain.replace(" ", "")]:
                if variant in seen or len(variant)<8: continue
                seen.add(variant)
                digest=hashlib.sha256(variant.encode("utf-8")).hexdigest()
                rows.append({"source":src,"plaintext":variant,"sha256":digest,"flag":"ctf_cs{"+digest+"}"})
        if rows:
            report={"name":"project","rel":group,"statement":task,"flags":[],"artifacts":[],"workflow_evidence":[]}
            a=artifact(root, report, "v96_project_sha256_candidates_"+safe_name(group)+".json", json.dumps(rows[:100], indent=2, ensure_ascii=False), "v96_project_sha256_candidates", "Task asks for sha256; candidate plaintexts were finalized into ctf_cs{sha256} options.", 850, "v96_project")
            if a: arts.append(a)
            # Promote only the first cardan-derived row; other generic rows remain artifacts.
            for row in rows:
                if row["source"] == "cardan":
                    flags.append({"flag":row["flag"],"file":group,"score":910,"why":"Project-level decoded plaintext finalized with SHA256 because task explicitly asks for sha256.","artifact":a.get("path") if a else ""})
                    break
    return arts, flags


# ---------- v97 reasoning engine: CTF-organizer pattern workflows ----------

# v97 expands generic CTF vocabulary used by the final evidence filter.
try:
    WORD_HINTS.update({"charcode", "layer", "payload", "icmp", "packet", "deep", "nested", "zip", "html", "hidden", "git", "commit", "repo", "jwt", "base85", "b85", "gzip"})
except Exception:
    pass

V97_BAD_FINAL_BODIES = V96_BAD_FINAL_BODIES | {
    "required", "try_more", "debug", "development", "localhost", "undefined",
    "null", "true", "false", "authorized", "unauthorized", "denied", "accepted",
}

V97_SECRET_HINTS = re.compile(r"(flag|ctf|gigem|secret|hidden|slapta|raktas|token|key|exfil|leak|admin|sha256|answer|final|decoded|message|phantom|commit|reflog|git)", re.I)


def v97_extra_decode_value(label: str, val: str) -> list[tuple[str, str]]:
    """Extra high-signal decoders used by v97 structured/binary/network agents.

    This intentionally avoids broad unbounded brute force.  It adds formats that
    CTF authors often use in web/misc/rev tasks: base58, base85/ascii85,
    uuencode-like lines, ROT47, base64+compression and escaped JS/Python arrays.
    """
    outs: list[tuple[str, str]] = []
    s = str(val or "").strip().strip('"\'')
    if not s:
        return outs

    def add(name: str, raw):
        if raw is None:
            return
        if isinstance(raw, bytes):
            txt = raw.decode("utf-8", "ignore")
        else:
            txt = str(raw)
        if txt and txt != s and len(txt.strip()) >= 3:
            outs.append((label + ":" + name, txt))

    # Reuse v96 first so existing behavior stays stable.
    for nm, out in v96_try_decoded_value(label, s):
        outs.append((nm, out))

    compact = re.sub(r"\s+", "", s)
    # base58 is common for blockchain/OSINT-ish misc challenges.
    if 8 <= len(compact) <= 20000 and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", compact):
        try:
            import base58  # type: ignore
            add("base58", base58.b58decode(compact))
        except Exception:
            pass
    # ascii85/base85 often appears in text/web snippets.
    if 8 <= len(s) <= 50000:
        for nm, fn in [("ascii85", base64.a85decode), ("base85", base64.b85decode)]:
            try:
                add(nm, fn(s.encode("utf-8", "ignore"), adobe=(nm == "ascii85")))
            except TypeError:
                try: add(nm, fn(s.encode("utf-8", "ignore")))
                except Exception: pass
            except Exception:
                pass
    # ROT47 is better kept as evidence-ranked, not in final spam.
    if any(33 <= ord(c) <= 126 for c in s) and len(s) <= 12000:
        try: add("rot47", rot47_text(s))
        except Exception: pass
    # base64 -> compression is a very common two-step.
    if 8 <= len(compact) <= 200000 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        pad = "=" * ((4 - len(compact) % 4) % 4)
        for bnm, bfn in [("b64", base64.b64decode), ("b64url", base64.urlsafe_b64decode)]:
            try:
                raw = bfn(compact + pad)
            except Exception:
                continue
            for cnm, cfn in [
                ("gzip", gzip.decompress),
                ("zlib", zlib.decompress),
                ("bz2", bz2.decompress),
                ("xz", lzma.decompress),
            ]:
                try: add(bnm + "+" + cnm, cfn(raw))
                except Exception: pass
    # JS/Python char arrays: [99,116,102] or String.fromCharCode(...)
    nums = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])-?\d{1,5}(?![A-Za-z0-9])", s)[:20000]]
    if 4 <= len(nums) <= 20000:
        plausible = [n for n in nums if 0 <= n <= 255]
        if len(plausible) >= max(4, len(nums) * 0.70):
            add("byte_array", bytes(n & 255 for n in plausible))
            # CTF authors sometimes offset by a constant.
            for off in sorted({min(plausible), max(plausible), 1, 13, 32, 48, 64, 100, 128})[:12]:
                arr = [(n - off) & 255 for n in plausible if 0 <= n - off <= 255]
                if len(arr) >= 4:
                    add(f"byte_array_minus_{off}", bytes(arr))
    return list(dict.fromkeys(outs))[:160]


def v97_scan_outputs(report: dict, root: Path, rows: list[dict], artifact_name: str, kind: str, note: str, score: int, subdir: str) -> list[dict]:
    arts=[]
    if rows:
        a = artifact(root, report, artifact_name, json.dumps(rows[:300], indent=2, ensure_ascii=False), kind, note, score, subdir)
        if a: arts.append(a)
    return arts


def v97_structured_code_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Web/code/config reasoning: comments, hidden values, JS charcodes and nested encodings."""
    ensure(report)
    if not data or len(data) > 5_000_000:
        return []
    text = data.decode("utf-8", "ignore")
    if not text.strip():
        return []
    values: list[tuple[str, str]] = []
    head = text[:900000]
    values.append(("whole", head[:250000]))
    # HTML/XML/JS/C/CSS/Python comments frequently hold challenge clues.
    for m in re.finditer(r"<!--([\s\S]{0,4000}?)-->|/\*([\s\S]{0,4000}?)\*/|//([^\n\r]{4,4000})|#([^\n\r]{4,4000})", head):
        val = next((g for g in m.groups() if g), "")
        if val.strip(): values.append(("comment", val.strip()))
    # Hidden inputs, data-* attrs, CSS display:none blocks.
    for m in re.finditer(r"(?:value|content|data-[\w-]+|token|secret|flag|key)\s*=\s*['\"]([^'\"]{4,4000})", head, re.I):
        values.append(("attr", m.group(1)))
    for m in re.finditer(r"display\s*:\s*none[^>]*>([\s\S]{0,4000}?)<", head, re.I):
        values.append(("display_none", re.sub(r"<[^>]+>", "", m.group(1))))
    for m in re.finditer(r"String\.fromCharCode\(([^)]{5,5000})\)", head):
        values.append(("js_fromCharCode", m.group(1)))
    for m in re.finditer(r"(?:atob|btoa|decodeURIComponent|unescape)\(['\"]([^'\"]{4,20000})['\"]\)", head):
        values.append(("js_builtin_arg", m.group(1)))
    for m in re.finditer(r"[A-Za-z_][\w.-]{1,40}\s*[:=]\s*['\"]?([^'\"\s,;<>]{4,8000})", head):
        label = m.group(0)[:40]
        if V97_SECRET_HINTS.search(label) or re.fullmatch(r"[A-Za-z0-9+/=_-]{12,}", m.group(1)) or re.fullmatch(r"[0-9A-Fa-f]{12,}", m.group(1)):
            values.append(("kv", m.group(1)))
    rows=[]; seen=set()
    for label, val in values[:900]:
        # Scan raw evidence too, because comments sometimes directly contain bare answer bodies.
        scan_text(report, val, "SLOPER v97 structured raw", None, f"Structured/code {label} value scanned before decoding.", 790, allow_wrap=True)
        for nm, out in v97_extra_decode_value(label, val):
            key=(nm, out[:240])
            if key in seen: continue
            seen.add(key)
            q=v96_score_text_signal(out)
            if q >= 90 or "{" in out or V97_SECRET_HINTS.search(out):
                rows.append({"method": nm, "quality": q, "text": out[:1600]})
                scan_text(report, out, "SLOPER v97 structured/code decode", None, f"Structured/code value decoded by {nm}.", 870 + min(q, 200)//5, allow_wrap=True)
                for subnm, raw in _decode_text_variants(out)[:30]:
                    st = raw.decode("utf-8", "ignore")
                    if v96_score_text_signal(st) >= 110 or "{" in st or V97_SECRET_HINTS.search(st):
                        rows.append({"method": nm + " -> " + subnm, "quality": v96_score_text_signal(st), "text": st[:1600]})
                        scan_text(report, st, "SLOPER v97 structured/code chain", None, f"Structured/code value decoded by {nm} then {subnm}.", 890, allow_wrap=True)
    return v97_scan_outputs(report, root, rows, "v97_structured_code_decodes.json", "v97_structured_code", "HTML/JS/code/config hidden values and nested encodings decoded with evidence ranking.", 900, "v97_text")


def v97_iter_ip_packets(data: bytes) -> list[dict]:
    out=[]
    for pkt in list(pcap_packets(data))[:12000]:
        # Ethernet IPv4 or raw IPv4.
        offs=[]
        if len(pkt) >= 34 and pkt[12:14] == b"\x08\x00": offs.append(14)
        if len(pkt) >= 20 and (pkt[0] >> 4) == 4: offs.append(0)
        for off in offs[:1]:
            if off + 20 > len(pkt): continue
            ip = pkt[off:]
            ver = ip[0] >> 4; ihl = (ip[0] & 15) * 4
            if ver != 4 or ihl < 20 or len(ip) < ihl: continue
            total = int.from_bytes(ip[2:4], "big") if len(ip) >= 4 else len(ip)
            ident = int.from_bytes(ip[4:6], "big") if len(ip) >= 6 else 0
            ttl = ip[8] if len(ip) > 8 else 0
            proto = ip[9] if len(ip) > 9 else 0
            src = ip[12:16]; dst = ip[16:20]
            l4 = ip[ihl: max(ihl, min(total, len(ip)))]
            app=b""; tcpseq=tcpack=tcpwin=0; sport=dport=0; icmp_type=icmp_code=0
            if proto == 6 and len(l4) >= 20:
                sport=int.from_bytes(l4[0:2],"big"); dport=int.from_bytes(l4[2:4],"big")
                tcpseq=int.from_bytes(l4[4:8],"big"); tcpack=int.from_bytes(l4[8:12],"big")
                doff=(l4[12]>>4)*4; tcpwin=int.from_bytes(l4[14:16],"big")
                if doff >= 20: app=l4[doff:]
            elif proto == 17 and len(l4) >= 8:
                sport=int.from_bytes(l4[0:2],"big"); dport=int.from_bytes(l4[2:4],"big"); app=l4[8:]
            elif proto == 1 and len(l4) >= 8:
                icmp_type=l4[0]; icmp_code=l4[1]; app=l4[8:]
            out.append({"id":ident,"ttl":ttl,"tos":ip[1],"len":total,"proto":proto,"src":src,"dst":dst,"sport":sport,"dport":dport,"seq":tcpseq,"ack":tcpack,"win":tcpwin,"icmp_type":icmp_type,"icmp_code":icmp_code,"app":app,"l4":l4})
    return out


def v97_scan_int_channel(report: dict, rows: list[dict], name: str, vals: list[int]) -> None:
    if len(vals) < 4:
        return
    dec = decode_sequence([v & 255 for v in vals])
    for method, txt in dec.items():
        rows.append({"channel": name, "method": method, "text": txt[:1600]})
        scan_text(report, txt, "SLOPER v97 packet scalar channel", None, f"Packet scalar channel {name} decoded by {method}.", 890, allow_wrap=True)
    bitdec = decode_bit_channels([v & 255 for v in vals], limit=40)
    for method, txt in bitdec.items():
        rows.append({"channel": name, "method": "bits_" + method, "text": txt[:1600]})
        scan_text(report, txt, "SLOPER v97 packet bit channel", None, f"Packet scalar channel {name} bits decoded by {method}.", 900, allow_wrap=True)
    # Also try high/low bytes for 16/32 bit fields.
    if max(vals) > 255:
        for shift in (0,8,16,24):
            arr=[(v>>shift)&255 for v in vals]
            if len(set(arr)) > 1:
                for method, txt in decode_sequence(arr).items():
                    rows.append({"channel": name+f"_byte{shift//8}", "method": method, "text": txt[:1600]})
                    scan_text(report, txt, "SLOPER v97 packet field byte channel", None, f"Packet field {name} byte {shift//8} decoded by {method}.", 890, allow_wrap=True)


def v97_pcap_lowlevel_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Network reasoning for low-level IP modulation: IDs, TTL/TOS, seq/ack/window and ICMP/UDP/TCP payloads."""
    ensure(report)
    if not data or len(data) > 40_000_000:
        return []
    pkts = v97_iter_ip_packets(data)
    if not pkts:
        return []
    rows=[]
    fields={
        "ip_id":[p["id"] for p in pkts],
        "ip_len":[p["len"] for p in pkts],
        "ip_ttl":[p["ttl"] for p in pkts],
        "ip_tos":[p["tos"] for p in pkts],
        "ip_proto":[p["proto"] for p in pkts],
        "src_last":[p["src"][-1] for p in pkts if len(p["src"])==4],
        "dst_last":[p["dst"][-1] for p in pkts if len(p["dst"])==4],
        "sport":[p["sport"] for p in pkts if p["sport"]],
        "dport":[p["dport"] for p in pkts if p["dport"]],
        "tcp_seq":[p["seq"] for p in pkts if p["seq"]],
        "tcp_ack":[p["ack"] for p in pkts if p["ack"]],
        "tcp_win":[p["win"] for p in pkts if p["win"]],
        "icmp_type":[p["icmp_type"] for p in pkts if p["icmp_type"]],
        "icmp_code":[p["icmp_code"] for p in pkts if p["icmp_code"]],
    }
    for name, vals in fields.items():
        if len(vals) >= 4 and 1 < len(set(vals)) <= max(256, len(vals)//2 + 4):
            v97_scan_int_channel(report, rows, name, vals[:12000])
    # Application payloads in order and by protocol.
    app_blob=b"".join(p["app"] for p in pkts if p.get("app"))[:3_000_000]
    if app_blob:
        for enc in ("utf-8", "latin1"):
            txt=app_blob.decode(enc, "ignore")
            if txt.strip():
                rows.append({"channel":"app_payload_joined","method":enc,"text":txt[:1600]})
                scan_text(report, txt, "SLOPER v97 pcap app payload", None, "Joined TCP/UDP/ICMP payload bytes scanned.", 850, allow_wrap=True)
                for nm,out in v97_extra_decode_value("pcap_payload", txt[:200000]):
                    if v96_score_text_signal(out) >= 90 or "{" in out or V97_SECRET_HINTS.search(out):
                        rows.append({"channel":"app_payload_joined","method":nm,"text":out[:1600]})
                        scan_text(report, out, "SLOPER v97 pcap app payload decode", None, f"Joined application payload decoded by {nm}.", 900, allow_wrap=True)
    return v97_scan_outputs(report, root, rows, "v97_pcap_lowlevel_channels.json", "v97_pcap_lowlevel", "Low-level IP/TCP/UDP/ICMP scalar fields and payloads decoded as covert channels.", 910, "v97_pcap")


def v97_deep_archive_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Safe nested archive walker for zip-in-zip / tar-in-tar / gzip chains and filename clues."""
    ensure(report)
    if not data or len(data) > 35_000_000:
        return []
    rows=[]; arts=[]; q=[("input", data, 0)]; seen=set(); extracted=0
    while q and extracted < 160:
        label, blob, depth = q.pop(0)
        sig=hashlib.sha256(blob[:1024] + str(len(blob)).encode()).hexdigest()
        if sig in seen or depth > 35:
            continue
        seen.add(sig)
        # Scan direct bytes/text at each depth.
        txt=blob[:500000].decode("utf-8", "ignore")
        if txt.strip():
            scan_text(report, txt, "SLOPER v97 nested archive text", None, f"Nested archive {label} depth {depth} text scan.", 800, allow_wrap=True)
        try:
            if blob.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    names=z.namelist()
                    rows.append({"depth":depth,"label":label,"type":"zip","members":names[:60]})
                    scan_text(report, "\n".join(names), "SLOPER v97 zip member names", None, "ZIP member names scanned as clue text.", 820, allow_wrap=True)
                    for info in z.infolist()[:60]:
                        if info.is_dir():
                            continue
                        try:
                            child=z.read(info.filename)
                        except Exception:
                            continue
                        extracted += 1
                        if child[:4] == b"PK\x03\x04" or child.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")) or child[:262].find(b"ustar") >= 0:
                            q.append((info.filename, child, depth+1))
                        else:
                            st=child[:300000].decode("utf-8", "ignore")
                            if st.strip():
                                rows.append({"depth":depth+1,"label":info.filename,"type":"file_text","preview":st[:1000]})
                                scan_text(report, st, "SLOPER v97 nested archive member", None, f"Nested archive member {info.filename} text scan.", 850, allow_wrap=True)
            elif blob.startswith(b"\x1f\x8b"):
                q.append((label+":gunzip", gzip.decompress(blob), depth+1)); rows.append({"depth":depth,"label":label,"type":"gzip"})
            elif blob.startswith(b"BZh"):
                q.append((label+":bunzip2", bz2.decompress(blob), depth+1)); rows.append({"depth":depth,"label":label,"type":"bz2"})
            elif blob.startswith(b"\xfd7zXZ"):
                q.append((label+":xz", lzma.decompress(blob), depth+1)); rows.append({"depth":depth,"label":label,"type":"xz"})
            elif b"ustar" in blob[:512*4]:
                with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
                    members=tf.getmembers()[:80]
                    rows.append({"depth":depth,"label":label,"type":"tar","members":[m.name for m in members[:60]]})
                    scan_text(report, "\n".join(m.name for m in members), "SLOPER v97 tar member names", None, "TAR member names scanned as clue text.", 820, allow_wrap=True)
                    for m in members:
                        if not m.isfile() or m.size > 20_000_000: continue
                        f=tf.extractfile(m)
                        if not f: continue
                        child=f.read()
                        extracted += 1
                        q.append((m.name, child, depth+1))
        except Exception as e:
            rows.append({"depth":depth,"label":label,"error":type(e).__name__+": "+str(e)[:120]})
    arts += v97_scan_outputs(report, root, rows, "v97_deep_archive_walk.json", "v97_deep_archive", "Nested archive walker with member-name scanning and bounded zip/tar/gzip/bz2/xz recursion.", 880, "v97_archive")
    return arts


def v97_git_repo_reasoning_agent(root: Path, reports: list[dict], meta: dict) -> tuple[list[dict], list[dict]]:
    """Offline Git archaeology workflow for CTF repo challenges.

    It does not brute-force GitHub or require tokens.  It scans local .git data,
    task text URLs, refs/logs/loose objects that are already present, and emits a
    clear next-step artifact for public GitHub archaeology patterns such as TAMU
    Phantom/CFOR without doing abusive remote enumeration.
    """
    arts=[]; flags=[]
    report={"name":"project","rel":"project","statement":str(meta.get("statement","")),"flags":[],"artifacts":[],"workflow_evidence":[]}
    texts=[]
    for r in reports:
        texts.append(str(r.get("statement", "")))
        p=Path(str(r.get("path", "")))
        if p.exists() and p.stat().st_size <= 300000:
            try: texts.append(p.read_text("utf-8", "ignore"))
            except Exception: pass
    joined="\n".join(texts)[:600000]
    urls=re.findall(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", joined)
    rows=[]
    if urls or ".git" in joined.lower() or re.search(r"commit|reflog|phantom|fork|github", joined, re.I):
        for u in sorted(set(urls))[:20]:
            rows.append({"repo_url":u, "workflow":"public Git repo archaeology: check commits, refs, releases, events, issue/PR comments, branches/tags, and local .git artifacts if provided; do not promote placeholders without evidence."})
    # Local .git folder artifacts inside upload.
    roots=set()
    for r in reports:
        p=Path(str(r.get("path", "")))
        for parent in [p.parent] + list(p.parents)[:5]:
            if (parent/".git").exists(): roots.add(parent)
            if parent.name == ".git": roots.add(parent.parent)
    import subprocess
    for gr in list(roots)[:5]:
        row={"local_repo":str(gr),"refs":[],"logs":[],"objects":[]}
        try:
            cp=subprocess.run(["git","-C",str(gr),"log","--all","--decorate","--oneline","--graph","-n","200"],capture_output=True,text=True,timeout=5)
            row["log"]=cp.stdout[:12000]
            scan_text(report, cp.stdout, "SLOPER v97 local git log", None, "Local Git log/reflog scanned for challenge flag evidence.", 880, allow_wrap=True)
        except Exception as e: row["log_error"]=str(e)[:160]
        try:
            cp=subprocess.run(["git","-C",str(gr),"fsck","--lost-found","--no-reflogs"],capture_output=True,text=True,timeout=8)
            row["fsck"]= (cp.stdout + cp.stderr)[:12000]
        except Exception as e: row["fsck_error"]=str(e)[:160]
        try:
            cp=subprocess.run(["git","-C",str(gr),"cat-file","--batch-all-objects","--batch-check"],capture_output=True,text=True,timeout=8)
            objs=cp.stdout.splitlines()[:400]
            row["objects"]=objs[:80]
            for line in objs[:120]:
                sha=line.split()[0]
                if re.fullmatch(r"[0-9a-f]{40}", sha):
                    try:
                        co=subprocess.run(["git","-C",str(gr),"cat-file","-p",sha],capture_output=True,text=True,timeout=2)
                        txt=co.stdout[:20000]
                        if V97_SECRET_HINTS.search(txt) or "{" in txt:
                            scan_text(report, txt, "SLOPER v97 local git object", None, f"Local Git object {sha[:12]} scanned.", 910, allow_wrap=True)
                    except Exception: pass
        except Exception as e: row["objects_error"]=str(e)[:160]
        rows.append(row)
    if rows:
        a=artifact(root, report, "v97_git_archaeology_workflow.json", json.dumps(rows, indent=2, ensure_ascii=False), "v97_git_archaeology", "Git history/reflog/object archaeology workflow for repo-based CTF tasks; local-only, non-bruteforce.", 920, "v97_project")
        if a: arts.append(a)
        for f in sanitize_flag_items(report.get("flags", []), report):
            flags.append({"flag": f if isinstance(f,str) else f.get("flag"), "file":"project", "score":920, "why":"v97 local Git archaeology found evidence in refs/logs/objects.", "artifact":a.get("path") if a else ""})
    return arts, flags


def v97_project_pair_reasoning_agent(root: Path, reports: list[dict], meta: dict) -> tuple[list[dict], list[dict]]:
    """Pair files in the same challenge folder for common CTF transformations.

    This is intentionally organic: it uses task text + sibling files and tries
    key/message transforms, recursive archive walk summaries, and finalizes SHA256
    only when the task asks for hash output.
    """
    arts=[]; flags=[]; groups={}
    for r in reports:
        rel=str(r.get("rel") or r.get("name") or "")
        parts=re.split(r"[\\/]", rel)
        group="/".join(parts[:-1]) if len(parts)>1 else "."
        groups.setdefault(group,[]).append(r)
    for group, rs in groups.items():
        task="\n".join(str(r.get("statement", "")) for r in rs)[:30000]
        files=[]
        for r in rs:
            p=Path(str(r.get("path", "")))
            if p.exists() and p.stat().st_size <= 2_000_000:
                try: files.append((p.name, p.read_bytes()))
                except Exception: pass
        rows=[]
        # Message + key pairs: XOR and Vigenere, with SHA256 finalization if asked.
        texts=[(n,b.decode("utf-8","ignore")) for n,b in files if b]
        for n1,t1 in texts:
            for n2,t2 in texts:
                if n1==n2: continue
                if not (4 <= len(t2.strip()) <= 2000): continue
                msg=t1.strip(); key=t2.strip()
                if len(msg) < 8: continue
                # repeating XOR over bytes if key is not mostly natural language only.
                kb=key.encode("utf-8","ignore")
                mb=msg.encode("utf-8","ignore")
                if kb and len(mb) <= 20000:
                    xb=bytes(mb[i] ^ kb[i % len(kb)] for i in range(len(mb)))
                    xt=xb.decode("utf-8","ignore")
                    if v96_score_text_signal(xt) >= 90 or "{" in xt:
                        rows.append({"method":"repeating_xor","message":n1,"key":n2,"plaintext":xt[:1000]})
                        scan_text({"flags":[],"artifacts":[],"workflow_evidence":[],"statement":task}, xt, "", None, "", 0)
                # Vigenere decrypt using alphabetic key.
                kletters="".join(c.lower() for c in key if c.isalpha())
                cletters=sum(ch.isalpha() for ch in msg)
                if 2 <= len(kletters) <= 80 and cletters >= 8 and len(msg) <= 10000:
                    out=[]; j=0
                    for ch in msg:
                        if 'a' <= ch <= 'z' or 'A' <= ch <= 'Z':
                            base=97 if ch.islower() else 65
                            sh=ord(kletters[j % len(kletters)])-97; j+=1
                            out.append(chr((ord(ch)-base-sh)%26+base))
                        else: out.append(ch)
                    vt="".join(out)
                    if v96_score_text_signal(vt) >= 90 or "{" in vt:
                        rows.append({"method":"vigenere_decrypt","message":n1,"key":n2,"plaintext":vt[:1000]})
        if rows:
            rep={"name":"project","rel":group,"statement":task,"flags":[],"artifacts":[],"workflow_evidence":[]}
            a=artifact(root, rep, "v97_project_pair_candidates_"+safe_name(group)+".json", json.dumps(rows[:100],indent=2,ensure_ascii=False), "v97_project_pair_candidates", "Sibling message/key files tried with XOR/Vigenere and evidence-ranked plaintexts.", 900, "v97_project")
            if a: arts.append(a)
            wants_hash=bool(re.search(r"sha\s*-?256|hash", task, re.I))
            for row in rows[:20]:
                plain=str(row.get("plaintext","")).strip()
                if wants_hash and 8 <= len(plain) <= 5000:
                    digest=hashlib.sha256(plain.encode("utf-8")).hexdigest()
                    flags.append({"flag":"ctf_cs{"+digest+"}","file":group,"score":900,"why":"v97 sibling file transform produced plaintext and task asks for SHA256 finalization.","artifact":a.get("path") if a else ""})
                else:
                    tmp={"name":"project","rel":group,"statement":task,"flags":[],"artifacts":[],"workflow_evidence":[]}
                    scan_text(tmp, plain, "SLOPER v97 project pair", a.get("path") if a else None, "Sibling message/key transform produced evidence plaintext.", 900, allow_wrap=True)
                    for f in sanitize_flag_items(tmp.get("flags",[]), tmp):
                        flags.append({"flag":f if isinstance(f,str) else f.get("flag"),"file":group,"score":900,"why":"v97 sibling file transform produced flag-like plaintext.","artifact":a.get("path") if a else ""})
    return arts, flags


def kind_for(mod: Any, path: Path, data: bytes) -> str:
    try:
        if hasattr(mod, "sl92_kind_from_name"):
            k = mod.sl92_kind_from_name(path.name)
            if k != "generic":
                return k
    except Exception:
        pass
    ext = path.suffix.lower()
    head = data[:16]
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"} or head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8")):
        return "image"
    if ext in {".pcap", ".pcapng"} or head.startswith(b"\x0a\x0d\x0d\x0a") or head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return "pcap"
    if ext in {".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".docx", ".pptx", ".xlsx"} or head.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh")):
        return "archive"
    if ext in {".wav", ".mp3", ".flac", ".ogg"} or b"WAVE" in data[:32]:
        return "media"
    if ext in {".txt", ".md", ".log", ".csv", ".json", ".xml", ".html", ".js", ".py", ".c", ".cpp", ".java"}:
        return "text"
    return "generic"


def call_agent(report: dict, root: Path, data: bytes, name: str, fn: Any, arts: list[dict], budget: float | None = None) -> None:
    try:
        cancel_check = report.get("_cancel_check") if isinstance(report, dict) else None
        if callable(cancel_check) and cancel_check():
            report.setdefault("agent_health", []).append({
                "agent": name,
                "error": "Skipped because project stop was requested.",
                "file": report.get("rel", report.get("name", "")),
                "time": time.time(),
            })
            return
    except Exception:
        pass
    start = time.time()
    try:
        res = fn(report, root, data)
        if res:
            arts.extend([x for x in res if x])
    except Exception as e:
        agent_crash("v93 " + name, e, report)
    finally:
        elapsed = time.time() - start
        report.setdefault("agent_timings", []).append({"agent": name, "seconds": round(elapsed, 3)})
        if budget and elapsed > budget:
            report.setdefault("slow_agents", []).append({"agent": name, "seconds": round(elapsed, 3), "budget": budget})


def run_file_fast(mod: Any, report: dict, root: Path, data: bytes) -> list[dict]:
    ensure(report)
    kind = report.get("kind") or kind_for(mod, Path(report.get("path", "")), data)
    report["kind"] = kind
    arts: list[dict] = []

    # v96 front-loads context/pattern evidence before broad decode graphs.
    # Goal: solve real folders by intent and make the path visible instead of dumping zlib/XOR noise.
    call_agent(report, root, data, "v96_context", v96_context_agent, arts, 4)
    if kind in {"text", "generic"} and len(data) <= 4_000_000:
        call_agent(report, root, data, "v96_structured_text", v96_structured_text_agent, arts, 5)
    if kind in {"text", "generic"} and len(data) <= 5_000_000:
        call_agent(report, root, data, "v97_structured_code", v97_structured_code_agent, arts, 6)
    call_agent(report, root, data, "v95_static_strings", v95_static_strings_agent, arts, 5)
    # Broad multistep is valuable for short text/generic blobs, but expensive
    # and noisy on archives/disk images; v95 container agents handle those first.
    ext_for_v95 = Path(str(report.get("path", ""))).suffix.lower()
    if (kind == "text" or (kind == "generic" and ext_for_v95 not in {".pyc", ".exe", ".dll", ".so"} and printable_ratio(data) > 0.72)) and len(data) <= 1_500_000:
        call_agent(report, root, data, "multistep_decode", multistep_decode_agent, arts, 8)
    if len(data) <= 90_000_000:
        call_agent(report, root, data, "v95_container_reasoning", v95_container_reasoning_agent, arts, 10)
    if len(data) <= 90_000_000:
        call_agent(report, root, data, "v95_openxml_local_headers", v95_openxml_local_header_agent, arts, 8)
    if kind == "text" and len(data) <= 2_000_000:
        call_agent(report, root, data, "v95_morse_hex", v95_morse_hex_agent, arts, 4)
        call_agent(report, root, data, "v95_transposition", v95_crypto_transposition_agent, arts, 5)
    if Path(str(report.get("path", ""))).suffix.lower() == ".pyc":
        call_agent(report, root, data, "v95_pyc_static", v95_pyc_static_agent, arts, 6)
        # PYC bytecode creates many XOR/string false positives. The static PYC
        # analyzer is the correct workflow; stop before generic legacy brute passes.
        report["flags"] = sanitize_flag_items(report.get("flags", []), report)
        return arts
    if kind == "archive":
        call_agent(report, root, data, "v97_deep_archive", v97_deep_archive_agent, arts, 10)
    early_solved = bool(report.get("flags"))
    if early_solved and kind == "archive":
        report["flags"] = sanitize_flag_items(report.get("flags", []), report)
        return arts

    if kind == "image":
        call_agent(report, root, data, "v95_image_deep", v95_image_deep_agent, arts, 14)
        if hasattr(mod, "sl92_visual_first_image_agent") and len(data) <= 8_000_000:
            call_agent(report, root, data, "visual_first_image", mod.sl92_visual_first_image_agent, arts, 18)
        if v74 and len(data) <= 4_000_000:
            call_agent(report, root, data, "image_lsb_palette", v74.image_agent, arts, 12)
        call_agent(report, root, data, "carve_decode", carve_decode_agent, arts, 10)
    elif kind == "pcap":
        call_agent(report, root, data, "v97_pcap_lowlevel", v97_pcap_lowlevel_agent, arts, 10)
        call_agent(report, root, data, "v96_network_exfil", v96_network_exfil_agent, arts, 8)
        call_agent(report, root, data, "pcap_fast", pcap_fast_agent, arts, 10)
    elif kind == "media":
        if v74:
            call_agent(report, root, data, "wav_lsb", v74.wav_lsb_agent, arts, 8)
        call_agent(report, root, data, "carve_decode", carve_decode_agent, arts, 8)
    elif kind == "archive":
        call_agent(report, root, data, "v97_deep_archive", v97_deep_archive_agent, arts, 10)
        call_agent(report, root, data, "carve_decode", carve_decode_agent, arts, 12)
        if v74 and len(data) <= 1_000_000:
            call_agent(report, root, data, "archive", v74.archive_agent, arts, 12)
            call_agent(report, root, data, "magic_carve", v74.magic_carve_agent, arts, 12)
    else:
        if kind == "generic" or Path(str(report.get("path", ""))).suffix.lower() in {".exe", ".elf", "", ".bin"}:
            call_agent(report, root, data, "v96_binary_static", v96_binary_static_reasoning_agent, arts, 6)
        if v74:
            call_agent(report, root, data, "hidden_text", v74.hidden_text_agent, arts, 5)
            call_agent(report, root, data, "misc_text_patterns", v74.misc_text_patterns_agent, arts, 6)
            if not early_solved:
                call_agent(report, root, data, "decode_graph", v74.decode_graph_agent, arts, 8)
                call_agent(report, root, data, "classic_crypto", v74.classic_crypto_agent, arts, 8)
            if len(data) <= 2_000_000:
                call_agent(report, root, data, "array_transform", v74.array_transform_agent, arts, 8)
            if (not early_solved) and len(data) <= 400_000:
                call_agent(report, root, data, "xor", v74.xor_agent, arts, 8)
            # v96: known-prefix XOR is useful on opaque small blobs, but can hang/noise on solved Unicode/text clues.
            if (not early_solved) and len(data) <= 8_000 and printable_ratio(data) < 0.88:
                call_agent(report, root, data, "known_prefix_xor", v74.known_prefix_xor_agent, arts, 5)
            call_agent(report, root, data, "strings", v74.strings_agent, arts, 5)
            if Path(str(report.get("path", ""))).suffix.lower() == ".log":
                call_agent(report, root, data, "time_anomaly", time_anomaly_agent, arts, 6)
            call_agent(report, root, data, "log_lowbyte", v74.log_lowbyte_agent, arts, 5)
            call_agent(report, root, data, "binary_elf_stack_array", v74.binary_elf_stack_array_agent, arts, 10)
        if v75:
            call_agent(report, root, data, "route_transposition", v75.route_transposition_agent, arts, 8)
        call_agent(report, root, data, "acrostic", acrostic_agent, arts, 4)
        call_agent(report, root, data, "carve_decode", carve_decode_agent, arts, 8)

    try:
        text_head = data[:200000].decode("utf-8", "ignore")
        if Path(report.get("path", "")).name.lower() == "artifact.log" or ('"x"' in text_head and '"rows"' in text_head):
            call_agent(report, root, data, "v96_artifact_log_ascii_ocr", v96_artifact_log_ascii_ocr_agent, arts, 5)
            if hasattr(mod, "sl92_artifact_log_reconstruct"):
                call_agent(report, root, data, "artifact_log_reconstruct", mod.sl92_artifact_log_reconstruct, arts, 8)
    except Exception as e:
        agent_crash("v96 artifact_log gate", e, report)

    ext = Path(str(report.get("path", ""))).suffix.lower()
    v89_text_ok = kind == "text" and len(data) <= 30_000 and ext not in {".log", ".csv"}
    v89_binary_ok = kind not in {"text", "pcap", "image"} and len(data) <= 200_000 and printable_ratio(data) >= 0.55
    if v89 and kind not in {"pcap", "image"} and (v89_text_ok or v89_binary_ok):
        call_agent(report, root, data, "universal_v89", v89.run_v89, arts, 10)

    report["flags"] = sanitize_flag_items(report.get("flags", []), report)
    return arts


def sanitize_flag_items(items: list[Any], report: dict | None = None) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    evidence_by_flag = {}
    if report:
        for ev in report.get("workflow_evidence", []) or []:
            if isinstance(ev, dict) and ev.get("flag"):
                evidence_by_flag.setdefault(ev["flag"], ev)
    for item in items or []:
        if isinstance(item, dict):
            raw = item.get("flag") or item.get("value") or item.get("candidate") or ""
        else:
            raw = str(item or "")
        flag = normalize_flag(raw, json.dumps(item, ensure_ascii=False)[:400] if isinstance(item, dict) else raw, allow_wrap=False)
        if not flag:
            continue
        if flag in seen:
            continue
        seen.add(flag)
        if isinstance(item, dict):
            item = dict(item)
            item["flag"] = flag
            item.setdefault("score", evidence_by_flag.get(flag, {}).get("score", 760))
            item.setdefault("why", evidence_by_flag.get(flag, {}).get("why", "Strict v93 evidence filter kept this final flag."))
            out.append(item)
        else:
            out.append(flag)
    # v96: if one final is clearly a substring artifact of a longer evidence-backed flag, keep the longer one.
    def _fb(x):
        f = x if isinstance(x, str) else x.get("flag", "")
        m = STRICT_RE.fullmatch(str(f or ""))
        return m.group(1).lower() if m else ""
    bodies=[_fb(x) for x in out]
    drop=set()
    for i,b in enumerate(bodies):
        if not b or len(b) < 8: continue
        for j,bb in enumerate(bodies):
            if i != j and len(bb) >= len(b)+3 and b in bb:
                drop.add(i); break
    if drop:
        out=[x for i,x in enumerate(out) if i not in drop]
    return out


def build_summary(reports: list[dict], meta: dict, project_flags: list[dict], project_artifacts: list[dict]) -> dict:
    artifacts: list[dict] = []
    evidence: list[dict] = []
    flags: list[dict] = []
    candidates: list[dict] = []
    timings: list[dict] = []
    for r in reports:
        artifacts.extend([a for a in r.get("artifacts", []) or [] if isinstance(a, dict)])
        evidence.extend([e for e in r.get("workflow_evidence", []) or [] if isinstance(e, dict)])
        candidates.extend([c for c in (r.get("candidate_flags", []) or []) + (r.get("wrap_candidates", []) or []) + (r.get("alternate_flag_candidates", []) or []) if isinstance(c, dict)])
        timings.extend(r.get("agent_timings", []) or [])
        for f in sanitize_flag_items(r.get("flags", []), r):
            flag = f if isinstance(f, str) else f.get("flag")
            if flag:
                flags.append({
                    "flag": flag,
                    "file": r.get("rel", r.get("name", "")),
                    "score": 900,
                    "why": "v93 stable pipeline kept strict evidence-backed final flag.",
                })
    flags.extend(project_flags)
    artifacts.extend(project_artifacts)

    # Legacy/v74-v92 agents often write the correct evidence into artifacts or
    # wrapper candidate lists without adding it to report["flags"]. Re-scan only
    # high-signal transform artifacts so final promotion is evidence based, not
    # a broad random strings pass over every generated JSON file.
    for c in candidates[:1000]:
        raw = c.get("flag") or c.get("candidate") or c.get("value") or ""
        src = str(c.get("source", "")) + " " + str(c.get("why", ""))
        if "wrapper" not in src.lower() and "route" not in src.lower() and not str(raw).lower().startswith("ctf_cs{"):
            continue
        flag = normalize_flag(str(raw).strip("{}") if not str(raw).lower().startswith("ctf_cs{") else str(raw), src, allow_wrap=True)
        if flag:
            flags.append({
                "flag": flag,
                "file": c.get("file", "candidate"),
                "score": int(c.get("score", 760) or 760) + 520,
                "why": "Legacy wrapper candidate passed the v93 strict body-quality filter.",
                "artifact": c.get("artifact", ""),
            })

    high_signal_names = (
        "zip_local_header_text", "route_transposition_candidates", "decoded_carved",
        "payload_strings", "fragment_reconstruction", "time_anomaly", "acrostic",
        "multistep_decode", "multistep_hit",
        "artifact_log_reconstructed", "text_pattern_candidates", "office", "custom.xml",
    )
    for a in artifacts[:4000]:
        path = str(a.get("path") or "")
        probe = (str(a.get("kind", "")) + " " + str(a.get("name", "")) + " " + path).lower()
        if not any(x in probe for x in high_signal_names):
            continue
        try:
            p = Path(path)
            if not p.exists() or p.stat().st_size > 3_000_000:
                continue
            text = p.read_bytes()[:1_000_000].decode("utf-8", "ignore")
            tmp = {"flags": [], "workflow_evidence": [], "statement": meta.get("statement", "")}
            scan_text(tmp, text, "SLOPER v93 high-signal artifact rescan", path, "High-signal transform artifact contained a strict/wrappable answer token.", 820, allow_wrap=True)
            for ev in tmp.get("workflow_evidence", []):
                flag = ev.get("flag")
                if flag:
                    flags.append({
                        "flag": flag,
                        "file": a.get("file", ""),
                        "score": int(ev.get("score", 820) or 820),
                        "why": ev.get("why", "High-signal artifact rescan."),
                        "artifact": path,
                    })
        except Exception as e:
            agent_crash("v93 high-signal artifact rescan", e, None)

    seen_flags: set[str] = set()
    clean_flags: list[dict] = []
    for f in sorted(flags, key=lambda x: int(x.get("score", 0) or 0), reverse=True):
        flag = normalize_flag(f.get("flag", ""), f.get("why", ""), allow_wrap=False)
        if flag and flag not in seen_flags:
            item = dict(f)
            item["flag"] = flag
            clean_flags.append(item)
            seen_flags.add(flag)

    # Drop legacy wrapper supersets that accidentally fuse prose with a real
    # braced/body flag already present in the final set, e.g.
    # final_body_only_<real_flag_body>.  This keeps the UI focused on the
    # shortest evidence-backed answer instead of noisy whole-line wrappers.
    def _body_of(flag: str) -> str:
        m = STRICT_RE.fullmatch(str(flag or ""))
        return m.group(1).lower() if m else ""
    prose_tokens = {"final", "body", "only", "answer", "result", "text", "line", "found", "real"}
    bodies = [_body_of(f.get("flag", "")) for f in clean_flags]
    drop_idx: set[int] = set()
    for i, long_body in enumerate(bodies):
        if not long_body:
            continue
        long_toks = set(t for t in re.split(r"[_\-:+./=]+", long_body) if t)
        for j, short_body in enumerate(bodies):
            if i == j or not short_body or len(long_body) <= len(short_body) + 5:
                continue
            if short_body in long_body and long_toks.intersection(prose_tokens):
                drop_idx.add(i)
                break
    if drop_idx:
        clean_flags = [f for idx, f in enumerate(clean_flags) if idx not in drop_idx]

    seen_art: set[str] = set()
    clean_artifacts: list[dict] = []
    for a in sorted(artifacts, key=lambda x: (int(x.get("score", 0) or 0), int(x.get("size", 0) or 0)), reverse=True):
        key = a.get("path") or a.get("name")
        if key and key not in seen_art:
            clean_artifacts.append(a)
            seen_art.add(key)

    actions = []
    if clean_flags:
        actions.append({"priority": 100, "step": "Submit only flags in Final Flags after checking evidence.", "why": "v93 removed noisy generated candidates from final promotion."})
    if evidence:
        actions.append({"priority": 95, "step": "Open Workflow Evidence artifacts first.", "why": "These artifacts are direct transform outputs that produced final/wrapper evidence."})
    if clean_artifacts:
        actions.append({"priority": 90, "step": "Use Artifact Hub Start Here and Carves/Decode groups.", "why": "Generated child files are grouped by transformation family."})

    summary = {
        "flags": clean_flags[:80],
        "artifacts": clean_artifacts[:2500],
        "transformations": clean_artifacts[:2500],
        "workflow_evidence": evidence[:500],
        "candidate_flags": candidates[:240],
        "wrap_candidates": candidates[:240],
        "agent_timings": sorted(timings, key=lambda x: float(x.get("seconds", 0) or 0), reverse=True)[:300],
        "agent_health": list(AGENT_HEALTH)[-200:],
        "sloper93_review_lanes": {
            "files": len(reports),
            "final_flags": len(clean_flags),
            "artifacts": len(clean_artifacts),
            "workflow_evidence": len(evidence),
        },
        "sloper93_next_actions": actions,
        "workflow_steps": actions,
        "kinds": {},
    }
    for r in reports:
        summary["kinds"][r.get("kind", "generic")] = summary["kinds"].get(r.get("kind", "generic"), 0) + 1
    try:
        summary["sloper93_artifact_hub"] = compact_hub(summary)
        summary["sloper72_artifact_hub"] = summary["sloper93_artifact_hub"]
        summary["sloper75_artifact_hub"] = summary["sloper93_artifact_hub"]
        summary["sloper93_agent_health"] = summary["agent_health"]
    except Exception:
        pass
    return summary


def stable_analyze_project(mod: Any, pid: str) -> None:
    root = mod.pdir(pid)
    meta = mod.jread(mod.meta_path(pid), {})
    files_dir = root / "files"
    reports: list[dict] = []
    project_flags: list[dict] = []
    project_artifacts: list[dict] = []
    t0 = time.time()
    try:
        mod.progress(pid, 1, "v93 stable solver: preparing project")
    except Exception:
        pass

    def cancel_requested() -> bool:
        try:
            return bool(mod.JOBS.get(pid, {}).get("cancel_requested") or mod.JOBS.get(pid, {}).get("status") == "cancelled")
        except Exception:
            return False

    def write_partial(stage: str) -> None:
        try:
            summary = build_summary(reports, meta, project_flags, project_artifacts)
            report_doc = {
                "project": meta,
                "files": reports,
                "summary": summary,
                "ai_prompt": "CTF SLOPER partial report. Solver was stopped; inspect existing Workflow Evidence, Open First artifacts and Logs.",
                "generated_at": now_text(mod),
                "runtime_seconds": round(time.time() - t0, 3),
                "engine": "v102_reasoning_engine_partial",
                "cancelled": True,
            }
            mod.jwrite(mod.report_path(pid), report_doc)
            with mod.LOCK:
                mod.JOBS.setdefault(pid, {}).update({"status": "cancelled", "stage": stage, "updated": time.time()})
        except Exception as e:
            agent_crash("v102 write_partial_cancel_report", e, None)

    all_files = [p for p in files_dir.rglob("*") if p.is_file()]
    total = max(1, len(all_files))
    for idx, path in enumerate(all_files):
        if cancel_requested():
            write_partial("Cancelled after current file boundary")
            return
        try:
            pct = 5 + int((idx / total) * 78)
            try:
                mod.progress(pid, pct, "v93 analyzing " + path.name)
            except Exception:
                pass
            data = path.read_bytes()
            rel = "files\\" + str(path.relative_to(files_dir))
            kind = kind_for(mod, path, data)
            # v95: pull task/statement text from sibling .txt files in the same
            # challenge folder.  A uploaded CTF set often stores the task prompt
            # beside binaries/images; without this, file-level agents miss format
            # requirements like sha256 finalization or ctf_cs wrapping.
            local_statement = str(meta.get("statement", ""))
            try:
                task_texts = []
                for sp in path.parent.glob("*.txt"):
                    if sp != path and sp.stat().st_size <= 20_000:
                        st = sp.read_text(encoding="utf-8", errors="ignore")
                        if re.search(r"vėliav|veliav|formatas|užduot|flag|ctf|sha256|rakt|paslėp|paslep", st, re.I):
                            task_texts.append(st)
                if task_texts:
                    local_statement = (local_statement + "\n" + "\n".join(task_texts))[:12000]
            except Exception:
                pass
            report = {
                "id": re.sub(r"[^A-Za-z0-9]+", "_", path.stem)[:32],
                "name": path.name,
                "path": str(path),
                "rel": rel,
                "size": len(data),
                "entropy": 0,
                "kind": kind,
                "statement": local_statement,
                "strings": printable_strings(data, 4, 1600),
                "flags": [],
                "artifacts": [],
                "transformations": [],
                "workflow_evidence": [],
                "next_steps": [],
                "previews": [],
                "_cancel_check": cancel_requested,
            }
            try:
                report["entropy"] = round(-sum((data.count(bytes([b])) / len(data)) * math.log2(data.count(bytes([b])) / len(data)) for b in set(data)) if data else 0, 4)
            except Exception:
                report["entropy"] = 0
            run_file_fast(mod, report, root, data)
            report.pop("_cancel_check", None)
            reports.append(report)
        except Exception as e:
            try:
                report.pop("_cancel_check", None)
            except Exception:
                pass
            agent_crash("v93 stable_analyze file " + str(path), e, None)
    if cancel_requested():
        write_partial("Cancelled before project-level transforms")
        return
    try:
        mod.progress(pid, 88, "v93 project-level multi-file transforms")
    except Exception:
        pass
    if v74 and not cancel_requested():
        try:
            arts, flags = v74.project_multifile(root)
            project_artifacts.extend(arts or [])
            for flag in flags or []:
                flag = normalize_flag(flag, "project multifile", allow_wrap=False)
                if flag:
                    project_flags.append({"flag": flag, "file": "project", "score": 880, "why": "Project-level file pair transform produced strict flag."})
        except Exception as e:
            agent_crash("v93 project_multifile", e, None)

    if cancel_requested():
        write_partial("Cancelled after project-level multifile")
        return

    try:
        arts, flags = cardan_project_agent(root, reports, meta)
        project_artifacts.extend(arts or [])
        project_flags.extend(flags or [])
    except Exception as e:
        agent_crash("v93 cardan_project_agent", e, None)

    if cancel_requested():
        write_partial("Cancelled after Cardan/project workflows")
        return

    try:
        project_artifacts.extend(v95_folder_reasoning_summary(root, reports, meta) or [])
    except Exception as e:
        agent_crash("v95 folder_reasoning_summary", e, None)

    if cancel_requested():
        write_partial("Cancelled after folder reasoning")
        return

    try:
        arts, flags = v96_project_reasoning_agent(root, reports, meta)
        project_artifacts.extend(arts or [])
        project_flags.extend(flags or [])
    except Exception as e:
        agent_crash("v96 project_reasoning_agent", e, None)

    if cancel_requested():
        write_partial("Cancelled after project reasoning")
        return

    try:
        arts, flags = v97_git_repo_reasoning_agent(root, reports, meta)
        project_artifacts.extend(arts or [])
        project_flags.extend(flags or [])
    except Exception as e:
        agent_crash("v97 git_repo_reasoning_agent", e, None)

    if cancel_requested():
        write_partial("Cancelled after git reasoning")
        return

    try:
        arts, flags = v97_project_pair_reasoning_agent(root, reports, meta)
        project_artifacts.extend(arts or [])
        project_flags.extend(flags or [])
    except Exception as e:
        agent_crash("v97 project_pair_reasoning_agent", e, None)

    try:
        mod.progress(pid, 96, "v96 ranking evidence")
    except Exception:
        pass
    summary = build_summary(reports, meta, project_flags, project_artifacts)
    report_doc = {
        "project": meta,
        "files": reports,
        "summary": summary,
        "ai_prompt": "CTF SLOPER v102 stronger reasoned report. Start with Final Flags, Logical Preflight, Workflow Evidence, and Open First artifacts.",
        "generated_at": now_text(mod),
        "runtime_seconds": round(time.time() - t0, 3),
        "engine": "v102_reasoning_engine",
    }
    mod.jwrite(mod.report_path(pid), report_doc)
    try:
        mod.progress(pid, 100, "Done")
        with mod.LOCK:
            mod.JOBS.setdefault(pid, {})["status"] = "done"
    except Exception:
        pass


def install(mod: Any) -> Any:
    mod.sl93_stable_analyze_project = lambda pid: stable_analyze_project(mod, pid)
    mod.sl93_run_file_fast = lambda report, root, data: run_file_fast(mod, report, root, data)
    mod.sl93_sanitize_flags = sanitize_flag_items

    old_analyze = getattr(mod, "analyze_project", None)
    mod.sl93_legacy_analyze_project = old_analyze

    def analyze_project(pid: str):
        # Keep the old analyzer available through sl93_legacy_analyze_project, but the UI
        # default must be bounded and cannot hang on one legacy agent.
        try:
            return stable_analyze_project(mod, pid)
        except Exception as e:
            agent_crash("v93 stable analyze_project", e, None)
            if old_analyze and str(getattr(mod, "SLOPER_V93_FALLBACK_LEGACY", "")).lower() == "true":
                return old_analyze(pid)
            raise

    mod.analyze_project = analyze_project

    old_summary = getattr(mod, "project_summary", None)

    def project_summary(reports, meta):
        try:
            summary = build_summary(reports or [], meta or {}, [], [])
            if summary.get("flags") or summary.get("artifacts"):
                return summary
        except Exception as e:
            agent_crash("v93 project_summary", e, None)
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        try:
            summary["flags"] = sanitize_flag_items(summary.get("flags", []), {"workflow_evidence": summary.get("workflow_evidence", [])})
        except Exception:
            pass
        return summary

    mod.project_summary = project_summary
    mod.APP_TITLE = "CTF SLOPER v97 Reasoning Engine"
    return mod
