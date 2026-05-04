
"""CTF SLOPER v74 deterministic workflow layer.

The goal is to solve through evidence-producing transformations, not guessing:
- promoted flags must be strict ctf_cs{...}
- each promoted flag gets evidence in workflow_evidence
- generated transformations are saved as artifacts
- filenames/folder names are never used as answer guesses
"""
from __future__ import annotations

import base64
import bz2
import gzip
import html
import io
import json
import lzma
import re
import sqlite3
import struct
import tarfile
import urllib.parse
import wave
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .health import agent_crash

FLAG_RE = re.compile(r"ctf_cs\{[A-Za-z0-9_\-:+./=]{1,120}\}")
DECOY_BODIES = {
    "example", "test", "flag", "placeholder", "answer", "answer_here",
    "vietos_pavadinimas", "rastas_tekstas", "your_flag_here", "todo",
    "dummy", "sample", "fake"
}

def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "file"))[:160] or "file"

def ensure_report(report: dict) -> None:
    report.setdefault("flags", [])
    report.setdefault("artifacts", [])
    report.setdefault("transformations", [])
    report.setdefault("workflow_evidence", [])
    report.setdefault("next_steps", [])

def is_decoy(flag: str) -> bool:
    m = re.fullmatch(r"ctf_cs\{([^{}]+)\}", str(flag or ""))
    if not m:
        return True
    raw_body = m.group(1).strip()
    body = raw_body.lower()
    if body in DECOY_BODIES:
        return True
    if any(x in body for x in ["libarchive", "com_apple", "quarantine", "provenance", "xmlns", "schema"]):
        return True
    if any(x in body for x in ["basefont", "endobj", "subtype", "helvetica", "create_table", "integer_value_text"]):
        return True
    if len(body) < 3:
        return True
    if body[0] in ".:/=+-_" or body[-1] in ".:/=+-_":
        return True
    if re.fullmatch(r"[xX_]+", body):
        return True
    if not re.search(r"[a-z]", body):
        return True
    if re.fullmatch(r"[0-9a-f]{18,}", body):
        return True
    semantic_hint = re.search(r"(cyber|sprint|calc|archive|deleted|d3l3t3d|g0n3|password|secret|hidden|bytes|byte|lsb|xor|zip|gzip|base|morse|rail|reverse|interleave|decode|done|key|l0ud|l4b|steg|st3g)", body) or re.search(r"(^|_)ok($|_)", body)
    if any(c in body for c in ".=/") and not semantic_hint:
        return True
    if "_" not in body and not semantic_hint:
        if len(body) > 24:
            return True
        if len(body) < 10:
            return True
        if not re.search(r"[aeiouy]", body):
            return True
    if "_" in body and not semantic_hint:
        shortish = len(body) < 10
        if shortish and len([t for t in re.split(r"[_\-:+./=]+", body) if t]) <= 2:
            return True
    punct = sum(1 for c in raw_body if not (c.isalnum() or c == "_"))
    if punct / max(1, len(raw_body)) > 0.18:
        return True
    if "." in raw_body and raw_body.count(".") / max(1, len(raw_body)) > 0.03:
        return True
    toks = [t for t in re.split(r"[_\-:+./=]+", body) if t]
    if len(toks) >= 4 and sum(1 for t in toks if len(t) <= 1) >= len(toks) // 2:
        return True
    alnumish = sum(1 for c in raw_body if c.isalnum() or c == "_")
    if alnumish / max(1, len(raw_body)) < 0.78:
        return True
    return False

def add_flag(report: dict, flag: str, source: str, artifact: str | None, why: str, score: int = 600) -> None:
    ensure_report(report)
    if not FLAG_RE.fullmatch(str(flag or "")):
        return
    if is_decoy(flag):
        return
    if flag not in report["flags"]:
        report["flags"].append(flag)
    ev = {"flag": flag, "source": source, "artifact": artifact or "", "why": why, "score": score}
    if ev not in report["workflow_evidence"]:
        report["workflow_evidence"].append(ev)

def scan_text(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 600) -> List[str]:
    found = []
    text = str(text or "")
    for m in FLAG_RE.finditer(text):
        flag = m.group(0)
        if not is_decoy(flag):
            add_flag(report, flag, source, artifact, why, score)
            found.append(flag)
    for m in re.finditer(r"ctf_cs\{([A-Za-z0-9_\-:+./=]{1,120})$", text):
        flag = "ctf_cs{" + m.group(1) + "}"
        if not is_decoy(flag):
            add_flag(report, flag, source, artifact, why + " Repaired missing closing brace.", score)
            found.append(flag)
    found += wrap_evidence_text(report, text, source, artifact, why, score)
    return found

def wants_ctf_wrapper(report: dict) -> bool:
    txt = (str(report.get("statement", "")) + " " + str(report.get("task", ""))).lower()
    return "ctf_cs" in txt or "flag format" in txt or "vėliav" in txt or "veliav" in txt

def body_from_phrase(text: str) -> str:
    s = str(text or "").strip()
    s = re.sub(r"(?i)\bctf\s*[_ -]?\s*cs\b", " ", s)
    s = re.sub(r"(?i)\bflag\b", " ", s)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    s = re.sub(r"_+", "_", s)
    return s[:120]

def strong_body(body: str) -> bool:
    if not body or len(body) < 5 or len(body) > 120:
        return False
    if body in DECOY_BODIES:
        return False
    if body.startswith("ctf_cs_"):
        body = body[7:]
    if any(c in body for c in ".=/"):
        return False
    semantic_hint = re.search(r"(cyber|sprint|calc|archive|deleted|d3l3t3d|g0n3|password|secret|hidden|bytes|byte|lsb|xor|zip|gzip|base|morse|rail|reverse|interleave|decode|done|key|l0ud|l4b|steg|st3g)", body) or re.search(r"(^|_)ok($|_)", body)
    if semantic_hint and re.search(r"[a-z]", body):
        return True
    if "_" in body and re.search(r"[a-z]", body) and re.search(r"\d", body) and semantic_hint:
        toks = [t for t in body.split("_") if t]
        if len(toks) >= 2 and not all(len(t) <= 1 for t in toks):
            return True
    if re.search(r"[a-z]", body) and re.search(r"\d", body) and semantic_hint:
        return True
    if len(body) >= 18 and semantic_hint:
        return True
    return False

def wrap_evidence_text(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 600) -> List[str]:
    if not wants_ctf_wrapper(report):
        return []
    source_low = str(source or "").lower()
    if any(x in source_low for x in ["readme", "statement", "folder"]):
        return []
    artifact_low = str(artifact or "").lower()
    if artifact_low.endswith(".json"):
        return []
    standalone_ok = any(x in source_low + " " + artifact_low for x in [
        "classic", "transposition", "morse", "bacon", "decompressed", "gzip",
        "bz2", "zip member", "tar member", "zero-width", "whitespace", "elf",
        "sqlite", "pdf", "docx", "office", "local_header"
    ])
    found = []
    text = str(text or "")
    bodies = []
    for m in re.finditer(r"(?<!ctf_cs)\{([A-Za-z0-9_\-:+./=]{4,120})\}", text):
        bodies.append(m.group(1))
    for line in text.splitlines()[:2000]:
        raw_line = line.strip()
        if raw_line.upper().startswith("MORSE_DECODE:"):
            continue
        if not standalone_ok and not re.search(r"(?i)\b(ctf|cyber|sprint|calc|archive|password|deleted|d3l3t3d|morse|rail|l0ud|l4b|flag|answer|atsak)\b", raw_line):
            continue
        if len(raw_line) > 180 or any(x in raw_line for x in ['"method"', '"score"', '"preview"', '"path"', "\\x"]):
            continue
        printable_ratio = sum(1 for c in raw_line if 32 <= ord(c) < 127 or c in "\t") / max(1, len(raw_line))
        if printable_ratio < 0.92:
            continue
        body = body_from_phrase(line)
        if strong_body(body) or (re.search(r"(?i)\b(flag|answer|atsak)", raw_line) and 5 <= len(body) <= 120 and re.search(r"[a-z]", body)):
            bodies.append(body)
    seen=set()
    for body in bodies:
        body = body.strip().strip("{}").lower()
        if not strong_body(body) or body in seen:
            continue
        seen.add(body)
        flag = f"ctf_cs{{{body}}}"
        add_flag(report, flag, source, artifact, why + " Statement declares ctf_cs{...}; wrapped strong extracted body.", score)
        found.append(flag)
    return found

def printable(bs: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9,10,13) else "." for b in bytes(bs or b""))

def gzip_first_member(data: bytes) -> bytes | None:
    """Return the first gzip member even when a carved stream has trailing bytes."""
    try:
        obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = obj.decompress(bytes(data or b""))
        raw += obj.flush()
        return raw if raw else None
    except Exception:
        return None

def quality_text(txt: str) -> int:
    txt = str(txt or "")
    if not txt:
        return 0
    printable_ratio = sum(1 for c in txt if 32 <= ord(c) < 127 or c in "\r\n\t") / max(1, len(txt))
    score = int(printable_ratio * 100)
    low = txt.lower()
    for w in ["ctf_cs{", "flag{", "secret", "password", "token", "cyber", "sprint", "raktas", "slapta"]:
        if w in low:
            score += 140
    if "{" in txt and "}" in txt:
        score += 80
    return score

def artifact(root: Path, report: dict, name: str, content, kind: str, note: str, score: int = 350) -> dict | None:
    ensure_report(report)
    try:
        outdir = Path(root) / "generated" / "sloper74" / safe_name(report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / safe_name(name)
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(content)
            scan = bytes(content[:1_000_000]).decode("utf-8", "ignore")
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
            scan = str(content)
        a = {
            "kind": kind,
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v74",
            "score": int(score),
            "note": note,
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report["artifacts"].append(a)
        report["transformations"].append(a)
        scan_text(report, scan, "SLOPER v74 artifact", str(p), "Strict flag found inside generated evidence artifact.", score + 100)
        return a
    except Exception as e:
        agent_crash("v74 artifact", e, report)
        return None

def magic_kind(raw: bytes) -> List[str]:
    out = []
    if raw.startswith(b"PK\x03\x04"): out.append("zip")
    if raw.startswith(b"\x7fELF"): out.append("elf")
    if raw.startswith(b"%PDF"): out.append("pdf")
    if raw.startswith(b"\x89PNG\r\n\x1a\n"): out.append("png")
    if raw.startswith(b"SQLite format 3\x00"): out.append("sqlite")
    if raw.startswith(b"\x1f\x8b\x08"): out.append("gzip")
    return out

def add_password_candidate(report: dict, value: str, source: str) -> None:
    val = re.sub(r"[^A-Za-z0-9_\-]+", "", str(value or "")).strip()
    if not (3 <= len(val) <= 64):
        return
    report.setdefault("password_candidates", [])
    variants = {val, val.lower(), val.upper(), val.capitalize()}
    for v in variants:
        if v and v not in report["password_candidates"]:
            report["password_candidates"].append(v)
    report.setdefault("workflow_evidence", []).append({"source": source, "artifact": "", "why": f"Password/key candidate extracted: {val}", "score": 420})

def decode_morse_text(seq: str) -> str:
    table = globals().get("MORSE", {})
    words = []
    for word in re.split(r"\s*/\s*", str(seq or "").strip()):
        letters = []
        for tok in re.split(r"\s+", word.strip()):
            if tok:
                letters.append(table.get(tok, "?"))
        if letters:
            words.append("".join(letters))
    return " ".join(words)

def strings_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data or len(data) > 20_000_000:
        return []
    found = re.findall(rb"[ -~]{5,300}", data[:8_000_000])
    if not found:
        return []
    lines = []
    for raw in found[:5000]:
        s = raw.decode("latin1", "ignore")
        lines.append(s)
        scan_text(report, s, "SLOPER v74 binary strings", None, "Strict flag or answer-like text found in printable strings.", 610)
        if re.search(r"(?i)(password|pass|key|rakt|important|secret)", s):
            for w in re.findall(r"[A-Za-z0-9_\-]{3,64}", s):
                if w.lower() not in {"important", "password", "secret", "key", "raktas"}:
                    add_password_candidate(report, w, "SLOPER v74 binary strings")
        for morse in re.findall(r"(?:[.\-]{1,6}\s+){2,}[.\-]{1,6}", s):
            decoded = decode_morse_text(morse)
            if decoded and "?" not in decoded:
                lines.append(f"MORSE_DECODE: {decoded}")
                add_password_candidate(report, decoded, "SLOPER v74 morse clue in strings")
                scan_text(report, decoded, "SLOPER v74 morse clue in strings", None, "Morse sequence in strings decoded.", 640)
    a = artifact(root, report, "binary_strings.txt", "\n".join(lines[:5000])[:1_000_000], "sloper74_binary_strings", "Printable strings from binary/container, including decoded clue candidates.", 360)
    return [a] if a else []

# ---------- recursive decode graph ----------
def decode_candidates_from_text(s: str) -> List[Tuple[str, bytes]]:
    s = str(s or "").strip()
    out: List[Tuple[str, bytes]] = []
    if not s:
        return out
    try:
        u = urllib.parse.unquote_plus(s)
        if u != s:
            out.append(("url_decode", u.encode()))
    except Exception:
        pass
    compact = re.sub(r"\s+", "", s)
    if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try: out.append(("hex", bytes.fromhex(compact)))
        except Exception: pass
    if len(compact) >= 8 and len(compact) % 8 == 0 and re.fullmatch(r"[01]+", compact):
        try: out.append(("binary", bytes(int(compact[i:i+8], 2) for i in range(0, len(compact), 8))))
        except Exception: pass
    toks = re.findall(r"\b\d{1,3}\b", s)
    if len(toks) >= 4:
        try:
            vals = [int(x) for x in toks]
            if all(0 <= v <= 255 for v in vals):
                out.append(("decimal_bytes", bytes(vals)))
        except Exception:
            pass
    def add_decoded(name: str, raw: bytes) -> None:
        if raw:
            out.append((name, raw))
            for cname, fn in [("zlib", zlib.decompress), ("gzip", gzip.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
                try:
                    dec = gzip_first_member(raw) if cname == "gzip" else fn(raw)
                    if dec:
                        out.append((name + "->" + cname, dec))
                except Exception:
                    pass
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        for name, fn in [
            ("base64", base64.b64decode),
            ("urlsafe_base64", base64.urlsafe_b64decode),
            ("base32", base64.b32decode),
            ("base85", base64.b85decode),
            ("ascii85", base64.a85decode),
        ]:
            for pad in ["", "=", "==", "===", "===="]:
                try:
                    raw = fn(compact + pad)
                    if raw and raw != s.encode():
                        add_decoded(name, raw)
                        break
                except Exception:
                    pass
    for tok in re.findall(r"[A-Za-z0-9+/=_-]{12,}", s):
        if tok == compact:
            continue
        for name, fn in [("embedded_base64", base64.b64decode), ("embedded_urlsafe_base64", base64.urlsafe_b64decode), ("embedded_base32", base64.b32decode)]:
            for pad in ["", "=", "==", "===", "===="]:
                try:
                    raw = fn(tok + pad)
                    if raw and raw != tok.encode():
                        add_decoded(name, raw)
                        raise StopIteration
                except StopIteration:
                    break
                except Exception:
                    pass
    raw0 = s.encode("utf-8", "ignore")
    for name, fn in [("zlib", zlib.decompress), ("gzip", gzip.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
        try:
            raw = gzip_first_member(raw0) if name == "gzip" else fn(raw0)
            if raw:
                out.append((name, raw))
        except Exception:
            pass
    return out

def decode_graph_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data or len(data) > 8_000_000:
        return []
    seeds = []
    text = data[:1_000_000].decode("utf-8", "ignore")
    if text.strip():
        seeds.append(("raw_text", text))
        for line in text.splitlines()[:1000]:
            line = line.strip()
            if 4 <= len(line) <= 5000:
                seeds.append(("line", line))
    if len(data) <= 200000:
        seeds.append(("file_hex", data.hex()))
    q = [{"path": [src], "text": val, "depth": 0} for src, val in seeds[:600]]
    seen = set()
    nodes = []
    best = []
    while q and len(nodes) < 1400:
        item = q.pop(0)
        for method, raw in decode_candidates_from_text(item["text"]):
            if not raw or len(raw) > 4_000_000:
                continue
            sig = (method, raw[:256])
            if sig in seen:
                continue
            seen.add(sig)
            txt = raw[:1_000_000].decode("utf-8", "ignore")
            preview = printable(raw[:5000])
            score = quality_text(preview)
            node = {"path": item["path"] + [method], "method": method, "depth": item["depth"]+1, "size": len(raw), "score": score, "preview": preview[:4000], "hex_head": raw[:64].hex()}
            nodes.append(node)
            flags = scan_text(report, preview, "SLOPER v74 decode graph", None, "Decoded graph node produced strict flag.", 560 + min(score,200))
            if flags or score >= 160 or magic_kind(raw):
                best.append(node)
            if item["depth"] < 5 and txt.strip():
                q.append({"path": item["path"] + [method], "text": txt, "depth": item["depth"]+1})
    if not nodes:
        return []
    result = {"node_count": len(nodes), "best": sorted(best, key=lambda x: x["score"], reverse=True)[:120], "nodes": sorted(nodes, key=lambda x: x["score"], reverse=True)[:500]}
    a = artifact(root, report, "decode_graph.json", json.dumps(result, indent=2, ensure_ascii=False), "sloper74_decode_graph", "Recursive decode graph with evidence-ranked nodes.", 410)
    return [a] if a else []

# ---------- XOR and arrays ----------
def xor_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data or len(data) > 3_000_000:
        return []
    keys = list(range(1,256)) if len(data) <= 500000 else [0x01,0x02,0x03,0x07,0x10,0x20,0x21,0x30,0x37,0x42,0x52,0x55,0x66,0x69,0x7f,0xaa,0xff]
    candidates = []
    for k in keys:
        raw = bytes(b ^ k for b in data[:1_000_000])
        txt = printable(raw[:12000])
        score = quality_text(txt)
        flags = FLAG_RE.findall(txt)
        if flags or score >= 180 or magic_kind(raw):
            candidates.append({"method": "xor_single_byte", "key": k, "key_hex": f"0x{k:02x}", "score": score, "magic": magic_kind(raw), "preview": txt[:5000], "hex_head": raw[:64].hex()})
            scan_text(report, txt, "SLOPER v74 XOR", None, "Single-byte XOR produced strict flag/readable evidence.", 600 + min(score,200))
    if not candidates:
        return []
    a = artifact(root, report, "generic_xor_candidates.json", json.dumps(sorted(candidates, key=lambda x:x["score"], reverse=True)[:140], indent=2, ensure_ascii=False), "sloper74_xor_candidates", "Single-byte XOR candidates.", 390)
    return [a] if a else []

def array_transform_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:2_000_000].decode("utf-8", "ignore")
    arrays: List[Tuple[str, bytes]] = []
    for m in re.finditer(r"(?:0x[0-9a-fA-F]{1,2}\s*,?\s*){6,}", text):
        vals = [int(x,16)&255 for x in re.findall(r"0x([0-9a-fA-F]{1,2})", m.group(0))]
        if 6 <= len(vals) <= 8192:
            arrays.append(("hex_array", bytes(vals)))
    for m in re.finditer(r"((?:\b\d{1,3}\b\s*,?\s*){6,})", text):
        vals = [int(x)&255 for x in re.findall(r"\b\d{1,3}\b", m.group(1))]
        if 6 <= len(vals) <= 8192 and all(0 <= v <= 255 for v in vals):
            arrays.append(("dec_array", bytes(vals)))
    if not arrays:
        return []
    keys = [0x01,0x02,0x03,0x07,0x10,0x20,0x21,0x30,0x37,0x42,0x52,0x55,0x66,0x69,0x7f,0xaa,0xff]
    for hx in re.findall(r"0x([0-9a-fA-F]{1,2})", text[:20000]):
        k = int(hx,16)&255
        if k not in keys:
            keys.append(k)
    def ror(b,n): return ((b >> n) | ((b << (8-n)) & 255)) & 255
    def rol(b,n): return (((b << n) & 255) | (b >> (8-n))) & 255
    outs = []
    for src, bs in arrays[:120]:
        transforms = [("raw", bs), ("reverse", bs[::-1]), ("not", bytes((~b)&255 for b in bs))]
        for k in keys:
            transforms += [(f"xor_{k:02x}", bytes(b^k for b in bs)), (f"add_{k:02x}", bytes((b+k)&255 for b in bs)), (f"sub_{k:02x}", bytes((b-k)&255 for b in bs))]
        for n in range(1,8):
            transforms += [(f"ror_{n}", bytes(ror(b,n) for b in bs)), (f"rol_{n}", bytes(rol(b,n) for b in bs))]
        for method, raw in transforms:
            txt = printable(raw[:12000])
            score = quality_text(txt)
            if FLAG_RE.search(txt) or score >= 170:
                outs.append({"array_source": src, "method": method, "score": score, "text": txt[:5000], "hex_head": raw[:64].hex()})
                scan_text(report, txt, "SLOPER v74 array transform", None, "Byte/int array transform produced strict flag/readable evidence.", 610 + min(score,200))
    if not outs:
        return []
    a = artifact(root, report, "array_transform_candidates.json", json.dumps(sorted(outs, key=lambda x:x["score"], reverse=True)[:180], indent=2, ensure_ascii=False), "sloper74_array_transforms", "Byte/int array transform candidates.", 420)
    return [a] if a else []

# ---------- archives / carving / databases / docs ----------
def zip_local_header_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if b"PK\x03\x04" not in data[:80_000_000]:
        return []
    arts: List[dict] = []
    outbase = Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))/"zip_local_headers"
    outbase.mkdir(parents=True, exist_ok=True)
    entries = []
    texts = []
    pos = 0
    count = 0
    while count < 700:
        off = data.find(b"PK\x03\x04", pos)
        if off < 0 or off + 30 > len(data):
            break
        pos = off + 4
        try:
            sig, ver, flags, method, mtime, mdate, crc, comp_size, uncomp_size, nlen, xlen = struct.unpack_from("<IHHHHHIIIHH", data, off)
            name_start = off + 30
            data_start = name_start + nlen + xlen
            if nlen <= 0 or nlen > 4096 or data_start > len(data):
                continue
            name = data[name_start:name_start+nlen].decode("utf-8", "ignore")
            if not name or name.endswith("/"):
                continue
            if comp_size <= 0 or comp_size > 50_000_000 or data_start + comp_size > len(data):
                continue
            comp = data[data_start:data_start+comp_size]
            raw = b""
            if method == 0:
                raw = comp
            elif method == 8:
                try:
                    raw = zlib.decompress(comp, -15)
                except Exception:
                    raw = b""
            if not raw:
                continue
            count += 1
            child = outbase / safe_name(name.replace("/", "__"))
            child.write_bytes(raw)
            entry = {"name": name, "offset": off, "method": method, "compressed": comp_size, "uncompressed": len(raw), "path": str(child)}
            entries.append(entry)
            text = raw[:2_000_000].decode("utf-8", "ignore")
            if text:
                if "<" in text and ">" in text:
                    values = []
                    for val in re.findall(r">([^<]{2,240})<", text):
                        val = html.unescape(re.sub(r"\s+", " ", val)).strip()
                        if val and not val.startswith(("http://", "https://", "urn:")):
                            values.append(val)
                    clean = "\n".join(dict.fromkeys(values))
                    if clean:
                        texts.append(f"--- {name} ---\n{clean}")
                        for val in list(dict.fromkeys(values))[:500]:
                            scan_text(report, val, "SLOPER v74 ZIP local header XML value", str(child), f"Text value extracted from damaged/local ZIP entry {name}.", 740)
                else:
                    clean = html.unescape(re.sub(r"<[^>]+>", " ", text))
                    clean = re.sub(r"\s+", " ", clean).strip()
                    if clean:
                        texts.append(f"--- {name} ---\n{clean}")
                        scan_text(report, clean, "SLOPER v74 ZIP local header", str(child), f"Text extracted from damaged/local ZIP entry {name}.", 720)
                decode_graph_agent(report, root, raw)
        except Exception:
            continue
    if not entries:
        return []
    man = artifact(root, report, "zip_local_header_manifest.json", json.dumps({"entries": entries[:700]}, indent=2, ensure_ascii=False), "sloper74_zip_local_header_manifest", "Recovered ZIP entries from local headers without requiring a central directory.", 470)
    if man: arts.append(man)
    if texts:
        txtart = artifact(root, report, "zip_local_header_text.txt", "\n\n".join(texts)[:2_000_000], "sloper74_zip_local_header_text", "Text/XML extracted from recovered ZIP local-header entries.", 650)
        if txtart: arts.append(txtart)
    return arts

def archive_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    arts: List[dict] = []
    if b"PK\x03\x04" in data[:80_000_000]:
        arts += zip_local_header_agent(report, root, data) or []
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            outbase = Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))/"zip_extract"
            outbase.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                manifest = {"comment": z.comment.decode("utf-8","ignore"), "names": z.namelist()}
                scan_text(report, manifest["comment"], "SLOPER v74 ZIP comment", None, "Flag in ZIP comment.", 660)
                pwds = []
                for x in report.get("password_candidates", []):
                    pwds.append(str(x))
                seed_text = str(report.get("statement", "")) + " " + str(report.get("name", ""))
                for w in re.findall(r"[A-Za-z0-9_\-]{3,64}", seed_text):
                    pwds += [w, w.lower(), w.upper(), w.capitalize()]
                pwds = list(dict.fromkeys([p for p in pwds if p]))
                for n in z.namelist()[:600]:
                    if n.endswith("/"):
                        continue
                    used_pwd = ""
                    try:
                        raw = z.read(n)
                    except RuntimeError:
                        raw = b""
                        for pw in pwds[:250]:
                            try:
                                raw = z.read(n, pwd=pw.encode("utf-8"))
                                used_pwd = pw
                                break
                            except Exception:
                                pass
                    if not raw:
                        continue
                    p = outbase/safe_name(Path(n).name)
                    p.write_bytes(raw)
                    scan_text(report, raw[:1_000_000].decode("utf-8","ignore"), "SLOPER v74 ZIP member", str(p), f"Flag in ZIP member {n}." + (f" Password candidate used: {used_pwd}." if used_pwd else ""), 700 if used_pwd else 670)
                    strings_agent(report, root, raw)
                    decode_graph_agent(report, root, raw)
                    magic_carve_agent(report, root, raw)
                    archive_agent(report, root, raw)
                a = artifact(root, report, "zip_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False), "sloper74_zip_manifest", "ZIP manifest/comment and extracted child files.", 370)
                if a: arts.append(a)
    except Exception as e:
        agent_crash("v74 archive zip", e, report)
    for name, fn in [("gzip", gzip.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
        try:
            raw = gzip_first_member(data) if name == "gzip" else fn(data)
            if not raw:
                continue
            a = artifact(root, report, f"{name}_decompressed.bin", raw, f"sloper74_{name}_decompressed", f"{name} decompressed bytes.", 390)
            if a: arts.append(a)
            scan_text(report, raw[:1_000_000].decode("utf-8", "ignore"), f"SLOPER v74 {name} decompressed", a.get("path") if a else None, f"Flag/text in {name} decompressed payload.", 690)
            decode_graph_agent(report, root, raw)
            zip_local_header_agent(report, root, raw)
            magic_carve_agent(report, root, raw)
            archive_agent(report, root, raw)
        except Exception:
            pass
    for off in [m.start() for m in re.finditer(b"\x78[\x01\x5e\x9c\xda]", data[:2_000_000])][:80]:
        try:
            raw = zlib.decompress(data[off:])
            a = artifact(root, report, f"zlib_offset_{off:08x}.bin", raw, "sloper74_zlib_carve", f"Raw zlib stream decompressed from offset {off}.", 410)
            if a: arts.append(a)
            decode_graph_agent(report, root, raw)
            archive_agent(report, root, raw)
        except Exception:
            pass
    try:
        bio = io.BytesIO(data)
        with tarfile.open(fileobj=bio, mode="r:*") as t:
            names = t.getnames()
            outbase = Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))/"tar_extract"
            outbase.mkdir(parents=True, exist_ok=True)
            for m in t.getmembers()[:600]:
                if not m.isfile(): continue
                f = t.extractfile(m)
                if not f: continue
                raw = f.read()
                p = outbase/safe_name(Path(m.name).name)
                p.write_bytes(raw)
                scan_text(report, raw[:1_000_000].decode("utf-8","ignore"), "SLOPER v74 TAR member", str(p), f"Flag in TAR member {m.name}.", 670)
                old_path, old_name = report.get("path"), report.get("name")
                report["path"], report["name"] = str(p), p.name
                strings_agent(report, root, raw)
                if raw.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a")):
                    image_agent(report, root, raw)
                report["path"], report["name"] = old_path, old_name
                decode_graph_agent(report, root, raw)
                magic_carve_agent(report, root, raw)
                archive_agent(report, root, raw)
            a = artifact(root, report, "tar_manifest.json", json.dumps({"names": names}, indent=2), "sloper74_tar_manifest", "TAR manifest and extracted child files.", 370)
            if a: arts.append(a)
    except Exception:
        pass
    return arts

def magic_carve_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data or len(data) > 80_000_000:
        return []
    sigs = [("zip", b"PK\x03\x04", ".zip"), ("gzip", b"\x1f\x8b\x08", ".gz"), ("bz2", b"BZh", ".bz2"), ("xz", b"\xfd7zXZ\x00", ".xz"), ("png", b"\x89PNG\r\n\x1a\n", ".png"), ("pdf", b"%PDF", ".pdf"), ("sqlite", b"SQLite format 3\x00", ".sqlite")]
    found = []
    outbase = Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))/"magic_carves"
    outbase.mkdir(parents=True, exist_ok=True)
    for kind, sig, ext in sigs:
        start = 0
        count = 0
        while True:
            off = data.find(sig, start)
            if off < 0: break
            start = off + 1
            if off == 0:
                continue
            count += 1
            if count > 30: break
            raw = data[off:min(len(data), off+8_000_000)]
            p = outbase/f"offset_{off:08x}_{kind}{ext}"
            p.write_bytes(raw)
            found.append({"kind": kind, "offset": off, "path": str(p), "size": len(raw)})
            scan_text(report, raw[:1_000_000].decode("utf-8","ignore"), "SLOPER v74 magic carve", str(p), f"Flag in carved {kind} at offset {off}.", 680)
            if kind == "zip":
                zip_local_header_agent(report, root, raw)
            archive_agent(report, root, raw)
            decode_graph_agent(report, root, raw)
    if not found:
        return []
    a = artifact(root, report, "magic_carve_manifest.json", json.dumps({"carves": found}, indent=2), "sloper74_magic_carve_manifest", "Embedded file magic carving manifest.", 450)
    return [a] if a else []

def sqlite_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data.startswith(b"SQLite format 3\x00"):
        return []
    try:
        dbp = Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))/"tmp.sqlite"
        dbp.parent.mkdir(parents=True, exist_ok=True)
        dbp.write_bytes(data)
        con = sqlite3.connect(str(dbp)); cur = con.cursor()
        schema = cur.execute("select type,name,tbl_name,sql from sqlite_master").fetchall()
        dump = {"schema": schema, "tables": {}}
        blob = ""
        for row in schema:
            name = row[1]
            try:
                rows = cur.execute(f"select * from {json.dumps(name)} limit 1000").fetchall()
                dump["tables"][name] = rows
                blob += "\n".join(map(str, rows)) + "\n"
            except Exception:
                pass
        con.close()
        a = artifact(root, report, "sqlite_dump.json", json.dumps(dump, indent=2, ensure_ascii=False, default=str), "sloper74_sqlite_dump", "SQLite schema and rows dump.", 400)
        scan_text(report, blob, "SLOPER v74 SQLite", a.get("path") if a else None, "Flag in SQLite rows.", 690)
        return [a] if a else []
    except Exception as e:
        agent_crash("v74 sqlite", e, report)
        return []

def pdf_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data.startswith(b"%PDF"):
        return []
    raw = data[:5_000_000].decode("latin1","ignore")
    strings = re.findall(r"\(([^()]{3,500})\)", raw)
    hex_strings = []
    for hx in re.findall(r"<([0-9A-Fa-f\s]{8,800})>", raw)[:300]:
        try:
            t = bytes.fromhex(re.sub(r"\s+","",hx)).decode("utf-8","ignore")
            if t.strip(): hex_strings.append(t)
        except Exception:
            pass
    text = "\n".join(strings + hex_strings)
    a = artifact(root, report, "pdf_raw_strings.txt", text, "sloper74_pdf_raw_strings", "Raw PDF string/hex literals.", 350)
    return [a] if a else []

# ---------- PCAP/WAV/image ----------
def pcap_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if len(data) < 24 or data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return []
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    off = 24
    texts = []
    rows = []
    while off + 16 <= len(data) and len(rows) < 50000:
        ts, us, inc, orig = struct.unpack(endian+"IIII", data[off:off+16]); off += 16
        pkt = data[off:off+inc]; off += inc
        if len(pkt) >= 20 and pkt[0] >> 4 == 4:
            ihl = (pkt[0] & 15) * 4
            proto = pkt[9]
            payload = pkt[ihl:]
            txt = payload.decode("utf-8","ignore")
            if txt:
                texts.append(txt)
            rows.append({"proto": proto, "payload_preview": printable(payload[:200])})
    blob = "\n".join(texts)
    a = artifact(root, report, "pcap_payloads.txt", blob, "sloper74_pcap_payloads", "Pure-Python raw IP PCAP payload extraction.", 400)
    return [a] if a else []

def wav_lsb_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if b"WAVE" not in data[:64]:
        return []
    try:
        wf = wave.open(io.BytesIO(data), "rb")
        width = wf.getsampwidth()
        frames = wf.readframes(min(wf.getnframes(), 1_000_000))
        wf.close()
        candidates = []
        if width == 2:
            samples = struct.unpack("<" + "h"*(len(frames)//2), frames[:(len(frames)//2)*2])
            for bit in range(4):
                bits = "".join("1" if ((s >> bit) & 1) else "0" for s in samples)
                for offset in range(8):
                    usable = bits[offset:]
                    raw = bytes(int(usable[i:i+8],2) for i in range(0, len(usable)-7, 8))
                    txt = raw.decode("utf-8","ignore")
                    score = quality_text(txt)
                    if FLAG_RE.search(txt) or score >= 150:
                        candidates.append({"sample_width": width, "bit": bit, "offset": offset, "preview": txt[:5000], "score": score})
                        scan_text(report, txt, "SLOPER v74 WAV LSB", None, "Flag in WAV PCM LSB stream.", 680)
        a = artifact(root, report, "wav_lsb_candidates.json", json.dumps(candidates, indent=2, ensure_ascii=False), "sloper74_wav_lsb", "WAV PCM LSB candidates.", 390)
        return [a] if a else []
    except Exception as e:
        agent_crash("v74 wav", e, report)
        return []

def image_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    arts: List[dict] = []
    try:
        from PIL import Image, ImageDraw
        p = Path(report.get("path",""))
        img = Image.open(p); img.load()
        rgba = img.convert("RGBA")
        w,h = rgba.size
        if w*h > 3_000_000:
            return []
        pix = list(rgba.getdata())
        # alpha bytes
        alpha = bytes(px[3] for px in pix[:1_000_000])
        atext = alpha.decode("utf-8","ignore")
        if quality_text(atext) >= 100 or FLAG_RE.search(atext):
            a = artifact(root, report, "alpha_bytes.txt", atext[:300000], "sloper74_alpha_bytes", "Alpha channel values interpreted as bytes.", 370)
            if a: arts.append(a)
        # RGB/A LSB
        candidates = []
        for chname, idx in [("R",0),("G",1),("B",2),("A",3)]:
            for bit in range(4):
                bits = "".join("1" if ((px[idx] >> bit) & 1) else "0" for px in pix[:800000])
                for offset in range(8):
                    usable = bits[offset:]
                    raw = bytes(int(usable[i:i+8],2) for i in range(0, len(usable)-7, 8))
                    txt = raw.decode("utf-8","ignore")
                    score = quality_text(txt)
                    if FLAG_RE.search(txt) or score >= 170:
                        candidates.append({"channel": chname, "bit": bit, "offset": offset, "score": score, "preview": txt[:4000]})
                        scan_text(report, txt, "SLOPER v74 image LSB", None, f"Flag in {chname} bit {bit}.", 690)
        if candidates:
            a = artifact(root, report, "image_lsb_candidates.json", json.dumps(candidates, indent=2, ensure_ascii=False), "sloper74_image_lsb", "Image channel LSB text candidates.", 420)
            if a: arts.append(a)
        # transparent RGB
        tb = bytearray()
        tchannels = {0: bytearray(), 1: bytearray(), 2: bytearray()}
        for r,g,b,a0 in pix[:1_000_000]:
            if a0 == 0:
                tb.extend([r,g,b])
                tchannels[0].append(r); tchannels[1].append(g); tchannels[2].append(b)
        if tb:
            txt = bytes(tb).decode("utf-8","ignore")
            if quality_text(txt) >= 100 or FLAG_RE.search(txt):
                a = artifact(root, report, "transparent_rgb_bytes.txt", txt[:300000], "sloper74_transparent_rgb", "RGB bytes from fully transparent pixels.", 390)
                if a: arts.append(a)
            for cname, raw in [("R", tchannels[0]), ("G", tchannels[1]), ("B", tchannels[2])]:
                txt = bytes(raw).decode("utf-8","ignore")
                if quality_text(txt) >= 100 or FLAG_RE.search(txt):
                    a = artifact(root, report, f"transparent_{cname}_bytes.txt", txt[:300000], "sloper74_transparent_rgb_channel", f"{cname} bytes from fully transparent pixels.", 410)
                    if a: arts.append(a)
        # palette indices
        if img.mode == "P":
            idxbytes = bytes(list(img.getdata())[:1_000_000])
            txt = idxbytes.decode("utf-8","ignore")
            if quality_text(txt) >= 100 or FLAG_RE.search(txt):
                a = artifact(root, report, "palette_indices_bytes.txt", txt[:300000], "sloper74_palette_indices", "Palette pixel indices interpreted as bytes.", 390)
                if a: arts.append(a)
        # bitplane sheet
        if w*h <= 500_000:
            thumb = (180,120); label_h=20; planes=[]; labels=[]
            for cname, idx in [("R",0),("G",1),("B",2),("A",3)]:
                for bit in range(8):
                    plane = Image.new("L", rgba.size)
                    plane.putdata([255 if ((px[idx]>>bit)&1) else 0 for px in pix])
                    planes.append(plane); labels.append(f"{cname} bit {bit}")
            cols=4; rows=(len(planes)+cols-1)//cols
            sheet=Image.new("RGB",(cols*thumb[0], rows*(thumb[1]+label_h)), "white")
            draw=ImageDraw.Draw(sheet)
            for i,pl in enumerate(planes):
                im=pl.convert("RGB"); im.thumbnail(thumb)
                x=(i%cols)*thumb[0]+(thumb[0]-im.width)//2
                y=(i//cols)*(thumb[1]+label_h)
                sheet.paste(im,(x,y)); draw.text(((i%cols)*thumb[0]+5,y+thumb[1]+2),labels[i],fill=(0,0,0))
            outdir=Path(root)/"generated"/"sloper74"/safe_name(report.get("name","file"))
            outdir.mkdir(parents=True,exist_ok=True)
            sp=outdir/"bitplane_contact_sheet.png"; sheet.save(sp)
            art = {"kind":"sloper74_bitplane_contact_sheet","name":sp.name,"path":str(sp),"url":"/api/raw?path="+str(sp),"source":"CTF SLOPER v74","score":340,"note":"R/G/B/A bitplane contact sheet.","exists":True,"size":sp.stat().st_size,"file":report.get("rel","")}
            report["artifacts"].append(art); report["transformations"].append(art); arts.append(art)
    except Exception as e:
        agent_crash("v74 image", e, report)
    return arts

# ---------- tokens/logs/classic ----------
def jwt_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:2_000_000].decode("utf-8","ignore")
    toks = re.findall(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]*)?\b", text)
    if not toks:
        return []
    decoded=[]
    for tok in list(dict.fromkeys(toks))[:50]:
        parts=[]
        for part in tok.split("."):
            try:
                raw = base64.urlsafe_b64decode(part + "="*((4-len(part)%4)%4))
                t = raw.decode("utf-8","ignore"); parts.append(t)
                scan_text(report, t, "SLOPER v74 JWT", None, "Flag in JWT decoded part.", 690)
            except Exception:
                parts.append("<decode error>")
        decoded.append({"token": tok, "parts": parts})
    a = artifact(root, report, "jwt_token_decode.json", json.dumps(decoded, indent=2, ensure_ascii=False), "sloper74_jwt_decode", "JWT token decoded parts.", 370)
    return [a] if a else []

def log_lowbyte_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:2_000_000].decode("utf-8","ignore")
    ids = re.findall(r"\bid\s*=\s*(\d{1,10})\b", text, re.I)
    nums = [int(x) for x in ids] if len(ids) >= 4 else [int(x) for x in re.findall(r"\b\d{3,10}\b", text)]
    if len(nums) < 6:
        return []
    nums = nums[:200000]
    variants: List[dict] = []
    def add_variant(name: str, vals: List[int]) -> None:
        if not vals or any(v < 0 or v > 255 for v in vals):
            return
        raw = bytes(vals)
        txt = raw.decode("utf-8", "ignore")
        score = quality_text(txt)
        if score < 100 and not FLAG_RE.search(txt):
            return
        scan_text(report, txt, "SLOPER v74 numeric/log bytes", None, f"{name} interpreted decimal sequence as ASCII.", 680)
        variants.append({"method": name, "score": score, "preview": txt[:10000], "hex_head": raw[:64].hex()})
    add_variant("low_byte_n_and_255", [n & 255 for n in nums])
    add_variant("mod_256", [n % 256 for n in nums])
    add_variant("mod_1000", [n % 1000 for n in nums if n % 1000 <= 255])
    for base in [100, 1000, 1024, 2000, 10000]:
        add_variant(f"minus_{base}", [n - base for n in nums])
    if nums:
        rounded = (min(nums) // 100) * 100
        for base in sorted(set([rounded, rounded - 100, min(nums) - 32, min(nums) - 95])):
            if base >= 0:
                add_variant(f"minus_dynamic_{base}", [n - base for n in nums])
    if not variants:
        return []
    variants = sorted(variants, key=lambda x: int(x.get("score", 0)), reverse=True)[:80]
    a = artifact(root, report, "numeric_low_bytes.json", json.dumps(variants, indent=2, ensure_ascii=False), "sloper74_numeric_low_bytes", "Decimal/log number byte interpretations including offset bases.", 390)
    return [a] if a else []

def caesar(s: str, shift: int) -> str:
    out=[]
    for ch in s:
        if "a" <= ch <= "z": out.append(chr((ord(ch)-97+shift)%26+97))
        elif "A" <= ch <= "Z": out.append(chr((ord(ch)-65+shift)%26+65))
        else: out.append(ch)
    return "".join(out)

def rot47(s: str) -> str:
    out=[]
    for ch in s:
        o=ord(ch)
        out.append(chr(33+((o-33+47)%94)) if 33 <= o <= 126 else ch)
    return "".join(out)

def vigenere_decrypt(s: str, key: str) -> str:
    key = re.sub(r"[^A-Za-z]", "", key).lower()
    if not key: return ""
    out=[]; ki=0
    for ch in s:
        if ch.isalpha():
            base=65 if ch.isupper() else 97
            k=ord(key[ki%len(key)])-97
            out.append(chr((ord(ch)-base-k)%26+base)); ki+=1
        else:
            out.append(ch)
    return "".join(out)

MORSE = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}

def classic_crypto_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:1_000_000].decode("utf-8","ignore")
    if not text.strip():
        return []
    words = re.findall(r"[A-Za-z]{3,24}", text + " " + str(report.get("name","")) + " sprint cyber secret password key flag")
    keys = list(dict.fromkeys([w.lower() for w in words]))[:120]
    chunks = [text[:20000]] + [line.strip() for line in text.splitlines()[:1000] if 4 <= len(line.strip()) <= 5000]
    outs=[]
    for chunk in chunks[:400]:
        for sh in range(1,26):
            out=caesar(chunk, sh)
            if FLAG_RE.search(out):
                outs.append({"method":f"caesar_{sh}","text":out[:5000],"score":quality_text(out)})
                scan_text(report,out,"SLOPER v74 classic crypto",None,"Caesar transform produced strict flag.",650)
        out=rot47(chunk)
        if FLAG_RE.search(out):
            outs.append({"method":"rot47","text":out[:5000],"score":quality_text(out)})
            scan_text(report,out,"SLOPER v74 classic crypto",None,"ROT47 produced strict flag.",650)
        if re.fullmatch(r"[.\-/| _\n\r\t]+", chunk):
            decoded=[]
            for word in re.split(r"\s*/\s*", chunk.replace("_","-").replace("|"," / ")):
                decoded.append("".join(MORSE.get(tok,"?") for tok in re.split(r"\s+",word.strip()) if tok))
            out=" ".join(decoded)
            if "?" not in out and out.strip():
                outs.append({"method":"morse","text":out[:5000],"score":quality_text(out)})
                scan_text(report,out,"SLOPER v74 classic crypto",None,"Morse decode produced evidence text.",650)
        if re.fullmatch(r"[ABab\s]+", chunk.strip()) and len(re.findall(r"[ABab]{5}", chunk)) >= 2:
            groups=re.findall(r"[ABab]{5}", chunk)
            for inv in [False, True]:
                txt=""
                for g in groups:
                    bits=g.upper().replace("A","0" if not inv else "1").replace("B","1" if not inv else "0")
                    val=int(bits,2)
                    if 0 <= val < 26:
                        txt += chr(65+val)
                if txt:
                    outs.append({"method":"bacon_inverse" if inv else "bacon","text":txt[:5000],"score":quality_text(txt)})
                    scan_text(report,txt,"SLOPER v74 classic crypto",None,"Bacon A/B decode produced evidence text.",620)
        for key in keys[:80]:
            out=vigenere_decrypt(chunk,key)
            if FLAG_RE.search(out):
                outs.append({"method":f"vigenere_{key}","key":key,"text":out[:5000],"score":quality_text(out)})
                scan_text(report,out,"SLOPER v74 classic crypto",None,f"Vigenere key {key} produced strict flag.",650)
    if not outs:
        return []
    a = artifact(root, report, "classic_crypto_candidates.json", json.dumps(sorted(outs,key=lambda x:x["score"],reverse=True)[:160], indent=2, ensure_ascii=False), "sloper74_classic_crypto", "Classical crypto candidates with strict flag evidence.", 390)
    return [a] if a else []

def known_prefix_xor_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data or len(data) > 2_000_000:
        return []
    # Crib-XOR is expensive and not useful against structured containers; let
    # carving/image/archive agents handle those first so one PNG never stalls a project.
    container_magic = [
        b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF",
        b"PK\x03\x04", b"\x1f\x8b\x08", b"BZh", b"\xfd7zXZ\x00",
        b"SQLite format 3\x00", b"\x7fELF", b"MZ", b"RIFF",
    ]
    if any(data.startswith(sig) for sig in container_magic):
        return []
    cribs = [b"ctf_cs{", b"flag{"]
    outs=[]
    max_offsets = 2048 if len(data) <= 80_000 else 384
    max_keylen = 32 if len(data) <= 80_000 else 16
    scan_len = min(len(data), 240_000 if len(data) > 80_000 else 800_000)
    for crib in cribs:
        for off in range(min(max_offsets, len(data)-len(crib)+1)):
            keyseg = bytes(data[off+i]^crib[i] for i in range(len(crib)))
            for keylen in range(1,max_keylen+1):
                if len(keyseg) < keylen: continue
                key = keyseg[:keylen]
                raw = bytes(data[i]^key[i%keylen] for i in range(scan_len))
                txt = printable(raw[:12000])
                if FLAG_RE.search(txt):
                    outs.append({"crib":crib.decode(),"offset":off,"key_len":keylen,"key_hex":key.hex(),"key_ascii":printable(key),"preview":txt[:5000],"score":quality_text(txt)})
                    scan_text(report,txt,"SLOPER v74 known-prefix XOR",None,"Known ctf_cs{ prefix recovered repeating XOR key.",700)
    if not outs:
        return []
    a = artifact(root, report, "known_prefix_xor_candidates.json", json.dumps(outs[:120], indent=2, ensure_ascii=False), "sloper74_known_prefix_xor", "Known-prefix repeating XOR candidates.", 420)
    return [a] if a else []

def hidden_text_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:2_000_000].decode("utf-8", "ignore")
    outs=[]
    zw = [c for c in text if c in "\u200b\u200c\u200d\ufeff"]
    if len(zw) >= 8:
        for one in ["\u200c", "\u200d"]:
            bits = "".join("1" if c == one else "0" for c in zw if c in "\u200b\u200c\u200d")
            for offset in range(8):
                raw = bytes(int(bits[i:i+8],2) for i in range(offset, len(bits)-7, 8))
                txt = raw.decode("utf-8","ignore")
                if quality_text(txt) >= 80 or FLAG_RE.search(txt):
                    outs.append({"method":"zero_width","one":repr(one),"offset":offset,"text":txt[:5000],"score":quality_text(txt)})
                    scan_text(report, txt, "SLOPER v74 zero-width", None, "Zero-width Unicode bits decoded.", 680)
    lines=text.splitlines()
    if lines:
        bits=[]
        for line in lines:
            if line.endswith("\t"): bits.append("1")
            elif line.endswith(" "): bits.append("0")
        if len(bits) >= 8:
            bitstr="".join(bits)
            for inv in [False, True]:
                cur=''.join('1' if (b=='0' if inv else b=='1') else '0' for b in bitstr)
                for offset in range(8):
                    raw=bytes(int(cur[i:i+8],2) for i in range(offset,len(cur)-7,8))
                    txt=raw.decode("utf-8","ignore")
                    if quality_text(txt)>=80 or FLAG_RE.search(txt):
                        outs.append({"method":"trailing_space_tab","invert":inv,"offset":offset,"text":txt[:5000],"score":quality_text(txt)})
                        scan_text(report, txt, "SLOPER v74 whitespace bits", None, "Trailing spaces/tabs decoded as bits.", 680)
    if not outs:
        return []
    a=artifact(root, report, "hidden_text_candidates.json", json.dumps(sorted(outs,key=lambda x:x["score"],reverse=True)[:80], indent=2, ensure_ascii=False), "sloper74_hidden_text", "Zero-width and whitespace bit candidates.", 430)
    return [a] if a else []

def rail_decode(cipher: str, rails: int) -> str:
    pattern=[]; r=0; d=1
    for _ in cipher:
        pattern.append(r)
        if r == 0: d=1
        elif r == rails-1: d=-1
        r += d
    counts=[pattern.count(i) for i in range(rails)]
    rows=[]; idx=0
    for c in counts:
        rows.append(list(cipher[idx:idx+c])); idx += c
    out=[]
    for r in pattern:
        out.append(rows[r].pop(0))
    return "".join(out)

def misc_text_patterns_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    text = data[:1_000_000].decode("utf-8","ignore")
    if not text.strip():
        return []
    outs=[]
    variants=[("reverse", text[::-1])]
    compact=re.sub(r"\s+","",text)
    for step in range(2,8):
        for off in range(step):
            variants.append((f"every_{step}_offset_{off}", compact[off::step]))
    lines=[ln for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 3:
        variants.append(("acrostic_first_chars", "".join(ln.lstrip()[0] for ln in lines if ln.lstrip())))
        variants.append(("acrostic_first_tokens", "_".join(ln.split()[0] for ln in lines if ln.split())))
    for rails in range(2,8):
        if 6 <= len(compact) <= 5000:
            variants.append((f"rail_fence_{rails}", rail_decode(compact, rails)))
    if 6 <= len(compact) <= 20000:
        import math
        for width in range(2, min(120, len(compact))):
            height = math.ceil(len(compact) / width)
            if height < 2 or width * height > len(compact) + width:
                continue
            padded = compact + " " * (width * height - len(compact))
            grid = [padded[i*width:(i+1)*width] for i in range(height)]
            cols = "".join(grid[r][c] for c in range(width) for r in range(height))
            cols_rev = "".join(grid[r][c] for c in range(width-1,-1,-1) for r in range(height))
            snake_cols = "".join("".join(grid[r][c] for r in (range(height) if c % 2 == 0 else range(height-1,-1,-1))) for c in range(width))
            for name, out in [(f"grid_cols_{width}", cols), (f"grid_cols_rev_{width}", cols_rev), (f"grid_snake_cols_{width}", snake_cols)]:
                if "{" in out and "}" in out:
                    variants.append((name, out))
                    variants.append((name + "_reverse", out[::-1]))
    for name,out in variants:
        if not out:
            continue
        fs=scan_text(report, out, "SLOPER v74 text pattern", None, f"{name} produced evidence.", 650)
        if fs or quality_text(out) >= 150:
            outs.append({"method":name,"text":out[:5000],"score":quality_text(out)})
    if not outs:
        return []
    a=artifact(root, report, "text_pattern_candidates.json", json.dumps(sorted(outs,key=lambda x:x["score"],reverse=True)[:120], indent=2, ensure_ascii=False), "sloper74_text_patterns", "Reverse, every-nth, acrostic and route/rail text candidates.", 420)
    return [a] if a else []

def binary_elf_stack_array_agent(report: dict, root: Path, data: bytes) -> List[dict]:
    if not data.startswith(b"\x7fELF") or len(data) > 20_000_000:
        return []
    outs=[]; arts=[]
    try:
        from elftools.elf.elffile import ELFFile
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        ef=ELFFile(io.BytesIO(data)); text_sec=ef.get_section_by_name(".text")
        if not text_sec:
            return []
        md=Cs(CS_ARCH_X86, CS_MODE_64)
        ins=list(md.disasm(text_sec.data(), text_sec["sh_addr"]))
        arr=[]
        for insn in ins:
            m=re.match(r"dword ptr \[rbp - 0x[0-9a-f]+\], 0x([0-9a-f]+)$", insn.op_str)
            if insn.mnemonic == "mov" and m:
                v=int(m.group(1),16)&255
                arr.append(v)
                continue
            if len(arr) >= 5:
                keys=set()
                for near in ins[max(0, ins.index(insn)-80): min(len(ins), ins.index(insn)+220)]:
                    xm=re.match(r"e?ax, 0x([0-9a-f]+)$", near.op_str)
                    if near.mnemonic == "xor" and xm:
                        keys.add(int(xm.group(1),16)&255)
                keys.update([0x52,0x42,0x13,0x37])
                for k in keys:
                    raw=bytes(v^k for v in arr)
                    txt=raw.decode("utf-8","ignore")
                    if FLAG_RE.search(txt) or ("{" in txt and "}" in txt) or quality_text(txt) >= 130:
                        scan_text(report, txt, "SLOPER v74 ELF stack array", None, f"Stack dword byte array XOR 0x{k:02x}.", 720)
                        outs.append({"method":f"stack_dword_xor_{k:02x}","text":txt,"score":quality_text(txt)})
                arr=[]
            else:
                arr=[]
        symsec=ef.get_section_by_name(".symtab")
        if symsec:
            for sym in symsec.iter_symbols():
                for tok in re.findall(r"[A-Za-z0-9+/]{8,}", sym.name):
                    try:
                        raw=base64.b64decode(tok + "="*((4-len(tok)%4)%4))
                        txt=raw.decode("utf-8","ignore")
                        if txt.strip():
                            outs.append({"method":"symbol_base64","symbol":sym.name,"text":txt,"score":quality_text(txt)})
                    except Exception:
                        pass
    except Exception as e:
        agent_crash("v74 elf stack array", e, report)
    if not outs:
        return []
    a=artifact(root, report, "elf_stack_array_candidates.json", json.dumps(outs[:120], indent=2, ensure_ascii=False), "sloper74_elf_stack_array", "ELF stack dword arrays, XOR constants and encoded symbol hints.", 520)
    return [a] if a else []

def run_file_workflows(mod, report: dict, root: Path, data: bytes) -> List[dict]:
    ensure_report(report)
    funcs = [
        hidden_text_agent, misc_text_patterns_agent,
        strings_agent, decode_graph_agent, archive_agent, magic_carve_agent, sqlite_agent, pdf_agent,
        pcap_agent, wav_lsb_agent, image_agent, jwt_agent, log_lowbyte_agent,
        xor_agent, known_prefix_xor_agent, array_transform_agent, binary_elf_stack_array_agent, classic_crypto_agent,
    ]
    arts=[]
    for fn in funcs:
        try:
            res = fn(report, Path(root), bytes(data or b""))
            if res: arts += res
        except Exception as e:
            agent_crash("v74 " + fn.__name__, e, report)
    if arts:
        report.setdefault("next_steps", []).insert(0, {"priority": 100, "step": "Open v74 workflow artifacts first.", "why": "Deterministic transformations produced evidence artifacts."})
    return arts

# ---------- project multifile ----------
def project_multifile(root: Path) -> Tuple[List[dict], List[str]]:
    files=[]
    for p in (Path(root)/"files").rglob("*"):
        if p.is_file():
            try:
                raw=p.read_bytes()
                if 1 <= len(raw) <= 2_000_000:
                    files.append((p, raw))
            except Exception: pass
    if len(files) < 2 or len(files) > 50:
        return [], []
    outdir=Path(root)/"generated"/"sloper74_project"
    outdir.mkdir(parents=True, exist_ok=True)
    cands=[]; flags=[]
    for i in range(len(files)):
        for j in range(i+1,len(files)):
            pa,a=files[i]; pb,b=files[j]; n=min(len(a),len(b),1_000_000)
            if n < 4: continue
            variants=[
                ("xor", bytes(a[k]^b[k] for k in range(n))),
                ("add", bytes((a[k]+b[k])&255 for k in range(n))),
                ("sub_a_b", bytes((a[k]-b[k])&255 for k in range(n))),
                ("sub_b_a", bytes((b[k]-a[k])&255 for k in range(n))),
            ]
            for method, raw in variants:
                txt=printable(raw[:12000]); score=quality_text(txt)
                fs=[f for f in FLAG_RE.findall(txt) if not is_decoy(f)]
                if fs or score >= 190 or magic_kind(raw):
                    out=outdir/safe_name(f"{method}_{pa.name}_VS_{pb.name}.bin")
                    out.write_bytes(raw)
                    cands.append({"method":method,"file_a":pa.name,"file_b":pb.name,"score":score,"flags":fs,"preview":txt[:5000],"artifact":str(out)})
                    flags += fs
    if not cands:
        return [], []
    manifest=outdir/"project_multifile_candidates.json"
    manifest.write_text(json.dumps(sorted(cands,key=lambda x:x["score"],reverse=True)[:240], indent=2, ensure_ascii=False), encoding="utf-8")
    art={"kind":"sloper74_project_multifile","name":manifest.name,"path":str(manifest),"url":"/api/raw?path="+str(manifest),"source":"CTF SLOPER v74","score":500,"note":"Project-level fileA/fileB XOR/ADD/SUB evidence candidates.","exists":True,"size":manifest.stat().st_size,"file":"project"}
    return [art], list(dict.fromkeys(flags))

def install(mod):
    old_run = getattr(mod, "sl_run_agents", None)
    def sl_run_agents(report, root, data):
        arts=[]
        if old_run:
            try:
                prev=old_run(report, root, data)
                if prev: arts+=prev
            except Exception as e:
                agent_crash("legacy sl_run_agents under v74", e, report)
        try:
            arts += run_file_workflows(mod, report, root, data) or []
        except Exception as e:
            agent_crash("v74 run_file_workflows", e, report)
        try:
            if hasattr(mod, "sl_finalize_report"):
                mod.sl_finalize_report(report)
        except Exception as e:
            agent_crash("v74 sl_finalize_report", e, report)
        return arts
    mod.sl_run_agents = sl_run_agents

    old_analyze = getattr(mod, "analyze_project", None)
    def analyze_project(pid):
        res = old_analyze(pid) if old_analyze else None
        try:
            root = mod.pdir(pid)
            rep = mod.jread(mod.report_path(pid), {})
            summary = rep.setdefault("summary", {})
            arts, flags = project_multifile(root)
            if arts:
                summary.setdefault("artifacts", [])
                summary["artifacts"] = arts + summary["artifacts"]
                summary.setdefault("sloper74_review_lanes", {})
                summary["sloper74_review_lanes"]["project_multifile"] = len(arts)
                summary.setdefault("workflow_evidence", [])
                for flag in flags:
                    if not is_decoy(flag):
                        summary.setdefault("flags", [])
                        item = {"flag": flag, "file": "project_multifile_candidates.json", "score": 800, "why": "v74 project-level file operation produced strict flag."}
                        if item not in summary["flags"]:
                            summary["flags"].insert(0, item)
                        summary["workflow_evidence"].append({"flag": flag, "source": "SLOPER v74 project multifile", "artifact": arts[0]["path"], "why": "fileA/fileB operation produced strict flag.", "score": 800})
                mod.jwrite(mod.report_path(pid), rep)
        except Exception as e:
            agent_crash("v74 analyze_project multifile", e, None)
        return res
    mod.analyze_project = analyze_project

    old_summary = getattr(mod, "project_summary", None)
    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        artifacts = summary.get("artifacts", []) or []
        lane = summary.get("sloper74_review_lanes", {}) or summary.get("sloper72_review_lanes", {}) or summary.get("sloper57_review_lanes", {}) or {}
        lane["v74_workflow_artifacts"] = len([a for a in artifacts if "sloper74" in (a.get("kind","")+a.get("source","")).lower()])
        lane["v74_project_multifile"] = lane.get("project_multifile", 0)
        summary["sloper74_review_lanes"] = lane
        def pri(a):
            s=int(a.get("score",0) or 0)
            txt=(a.get("source","")+" "+a.get("kind","")+" "+a.get("name","")).lower()
            if "sloper74" in txt: s+=22000
            return (bool(a.get("exists",False)), s, int(a.get("size",0) or 0))
        summary["artifacts"] = sorted(artifacts, key=pri, reverse=True)[:9000]
        try:
            from .artifact_hub import compact_hub
            summary["sloper74_artifact_hub"] = compact_hub(summary)
        except Exception:
            pass
        return summary
    mod.project_summary = project_summary
    mod.sl74_run_file_workflows = run_file_workflows
    mod.sl74_project_multifile = project_multifile
    return mod
