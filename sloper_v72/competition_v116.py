"""v116 Cyber Sprint competition layer.

This layer is still generic and local-only: it does not execute submitted
binaries and does not contact the network.  It adds the workflows that were
missing when benchmarking Cyber Sprint 2026 stage-1 style tasks:

- bounded recursive archive/frontier extraction for gzip/tar/zip and embedded
  ZIP/OOXML members carved from disk images or images;
- Morse decoding and Morse-derived ZIP passwords;
- rectangular/route transposition recovery for short ciphertext files;
- sibling-aware combined text analysis, including message+key tasks;
- pcapng payload/IP-field extraction;
- pyc constant/disassembly extraction;
- ELF/PE printable strings and packed integer byte streams;
- stricter candidate metadata so v116 triage can suppress random XOR garbage.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import html
import io
import json
import marshal
import os
import quopri
import re
import struct
import tarfile
import time
import types
import zipfile
import zlib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote_plus

from .fast_lane_v110 import scan_text, _safe_text, _profile_for_project
try:
    from .competition_v113 import _append_flags, _artifact, MAX_MEMBER_BYTES, MAX_EXTRA_BYTES, MAX_IMAGE_PIXELS
except Exception:  # pragma: no cover
    MAX_MEMBER_BYTES = 2_500_000
    MAX_EXTRA_BYTES = 8_000_000
    MAX_IMAGE_PIXELS = 1_400_000
    def _append_flags(report: dict[str, Any], rows: list[dict[str, Any]], rel: str) -> None:
        report.setdefault("verified_flags", []).extend(rows)
        for r in rows:
            f = r.get("flag") if isinstance(r, dict) else None
            if f and f not in report.setdefault("flags", []):
                report["flags"].append(f)
    def _artifact(report: dict[str, Any], root: Path, name: str, data: bytes | str, kind: str, note: str, score: int, source: str, rel: str) -> dict[str, Any]:
        d = root / "artifacts_v116"; d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:180] or "artifact.bin"
        p = d / safe
        if isinstance(data, bytes):
            p.write_bytes(data[:MAX_MEMBER_BYTES]); size = min(len(data), MAX_MEMBER_BYTES)
        else:
            p.write_text(str(data)[:1_000_000], encoding="utf-8", errors="replace"); size = min(len(str(data).encode()), 1_000_000)
        row = {"name": safe, "kind": kind, "source": source, "file": rel, "path": str(p), "score": score, "size": size, "note": note, "exists": True, "evidence_version": "v116"}
        report.setdefault("artifacts", []).append(row); return row

V116_FILE_BUDGET_MS = int(os.environ.get("SLOPER_V116_FILE_BUDGET_MS", "5200"))
V116_MAX_FRONTIER = int(os.environ.get("SLOPER_V116_MAX_FRONTIER", "180"))
V116_MAX_PAYLOAD = int(os.environ.get("SLOPER_V116_MAX_PAYLOAD", "2500000"))
FLAGISH_RE = re.compile(rb"(?is)(?:[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}|\{[^{}\r\n]{3,220}\})")
PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
ASCII_FLAG_RE = re.compile(r"(?is)([A-Za-z0-9_]{1,32}\{[ -~]{3,220}\}|\{[A-Za-z0-9_+./:=\-]{4,160}\})")
BARE_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9][A-Za-z0-9_+./:=\-]{7,120})(?![A-Za-z0-9_])")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{16,})(?![A-Za-z0-9+/=_-])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{16,})(?![0-9a-fA-F])")
MORSE_RE = re.compile(r"(?:^|\s)([.\-/ ]{12,})(?:$|\s)")
MORSE = {
    ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",
    ".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R",
    "...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9",
}
COMMON_PASSWORDS = [
    "", "ctf", "flag", "nksc", "cybersprint", "sprint", "cyber", "secret", "raktas", "Raktas", "slaptas", "slaptazodis",
    "veliava", "vėliava", "lietuva", "LIETUVA", "Lietuva", "vilnius", "Vilnius", "kaunas", "admin", "password", "pass",
    "stego", "forensics", "2026", "2025", "1234", "12345", "0000", "venona",
]


def _budget(start: float) -> bool:
    return ((time.time() - start) * 1000) < V116_FILE_BUDGET_MS


def _sha(data: bytes | str) -> str:
    raw = data.encode("utf-8", "ignore") if isinstance(data, str) else bytes(data or b"")
    return hashlib.sha256(raw[:8192] + str(len(raw)).encode()).hexdigest()[:16]


def _txt(data: bytes | str, limit: int = 2_000_000) -> str:
    if isinstance(data, str):
        return data[:limit]
    return bytes(data or b"")[:limit].decode("utf-8", "ignore")


def _printable(raw: bytes, limit: int = 1_300_000) -> str:
    return "\n".join(m.group(0).decode("utf-8", "ignore") for m in PRINTABLE_RE.finditer(raw[:limit]))[:1_000_000]


def _looks_interesting(raw: bytes | str) -> bool:
    text = _txt(raw, 160_000)
    low = text.lower()
    if ASCII_FLAG_RE.search(text):
        return True
    if any(k in low for k in ["ctf", "flag", "secret", "slapt", "rakt", "password", "veli", "vėli", "sha256", "pastebin", "http"]):
        return True
    b = raw.encode("utf-8", "ignore") if isinstance(raw, str) else bytes(raw or b"")
    return b.startswith((b"PK\x03\x04", b"%PDF", b"\x89PNG", b"RIFF", b"SQLite format 3\x00", b"MZ", b"\x7fELF"))


def _scan(label: str, blob: bytes | str, profile: dict[str, Any], rel: str, boost: int = 520, confidence: str = "medium") -> list[dict[str, Any]]:
    raw = blob.encode("utf-8", "ignore") if isinstance(blob, str) else bytes(blob or b"")
    text = _safe_text(raw)
    prof = dict(profile or {})
    prof["max_depth"] = min(3, int(prof.get("max_depth", 3) or 3))
    prof["max_artifacts"] = min(420, int(prof.get("max_artifacts", 420) or 420))
    scan_rows = scan_text(text, profile=prof, raw=raw)
    priority_rows: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    # Add direct brace-only wrapping when a challenge says ctf_cs{...} and the
    # transform produced only {...}. This is crucial for Lithuanian task packs.
    prefix = str(prof.get("flag_prefix") or "ctf_cs")
    for m in ASCII_FLAG_RE.finditer(text[:800_000]):
        f = m.group(1).strip()
        cand = f
        if f.startswith("{") and f.endswith("}") and prof.get("flag_format", "ctf_cs") not in {"braces_only", "custom_regex"}:
            cand = f"{prefix}{f}"
        priority_rows.append({"flag": cand, "preferred_flag": cand, "score": 880, "source": "direct_ascii_flagish"})
    # Many Cyber Sprint tasks say ctf_cs{...} where the recovered text is
    # printed bare as `FLAG: token` or stored in a custom property. Promote
    # high-signal leetspeak/underscore tokens, but leave triage to suppress
    # generic words and GUIDs.
    for m in BARE_TOKEN_RE.finditer(text[:800_000]):
        tok = m.group(1).strip(".,;:()[]<>\"\' ")
        if not (8 <= len(tok) <= 120):
            continue
        ctx = text[max(0, m.start()-40):m.end()+40].lower()
        leetish = ("_" in tok and any(ch.isdigit() for ch in tok)) or re.search(r"[a-z][0-9][a-z0-9_]*", tok, re.I)
        keyword = any(k in ctx for k in ["flag", "secret", "slapt", "rakt", "hidden", "custom", "value", "recovered"])
        # v117 hardening: do not wrap tokens that come from the task statement
        # itself (flag format text, instructions, example placeholders). This
        # was a major source of fake ctf_cs{...} candidates on real packs.
        task_ctx = any(k in ctx for k in ["vėliav", "veliav", "formatas", "pateikt", "kur ...", "sha256 kod", "gatves_pavadinimas", "vietos_pavadinimas"])
        if (leetish or keyword) and not task_ctx:
            cand = f"{prefix}{{{tok}}}"
            priority_rows.append({"flag": cand, "preferred_flag": cand, "score": 1040 if leetish else 880, "source": "bare_token_wrap", "why": "wrapped recovered bare token using selected flag prefix"})
    rows = priority_rows + scan_rows
    for row in rows[:260]:
        if not isinstance(row, dict):
            continue
        nr = dict(row)
        f = str(nr.get("preferred_flag") or nr.get("flag") or "")
        if not f:
            continue
        nr["source"] = f"{label}->{nr.get('source') or 'input'}"
        nr["file"] = rel
        nr["score"] = int(nr.get("score", 0) or 0) + boost
        nr["evidence_version"] = "v116"
        nr["confidence"] = confidence
        nr.setdefault("chain", [label, str(nr.get("source") or "input")])
        # mark high-risk garbage patterns for v116 triage to demote
        inside = f[f.find("{")+1:f.rfind("}")] if "{" in f and "}" in f else f
        risk = []
        if not all(32 <= ord(c) <= 126 for c in f):
            risk.append("non_ascii_candidate")
        if len(inside) < 8:
            risk.append("too_short")
        if re.fullmatch(r"[a-z]{5,8}", inside or ""):
            risk.append("short_lowercase_noise")
        if "xor_" in nr["source"].lower() and len(inside) < 14:
            risk.append("xor_short_candidate")
        if risk:
            nr["risk"] = risk
        out.append(nr)
    return out


def _morse_decode(text: str) -> list[str]:
    outs: list[str] = []
    candidates: list[str] = []
    if re.fullmatch(r"[.\-/\s]+", text.strip() or "") and len(text.strip()) >= 12:
        candidates.append(text.strip())
    for m in MORSE_RE.finditer(text[:300_000]):
        val = m.group(1).strip()
        if len(val) >= 12:
            candidates.append(val)
    for c in candidates[:40]:
        # slash separates words; whitespace separates symbols
        chars = []
        for word in c.replace("/", " / ").split():
            if word == "/":
                chars.append(" ")
            elif word in MORSE:
                chars.append(MORSE[word])
        s = "".join(chars).strip()
        if s and s not in outs:
            outs.append(s)
    return outs


def _decode_layers_from_text(text: str) -> list[tuple[str, bytes | str]]:
    out: list[tuple[str, bytes | str]] = []
    seen: set[str] = set()
    def add(label: str, value: bytes | str):
        raw = value.encode("utf-8", "ignore") if isinstance(value, str) else bytes(value or b"")
        if len(raw) < 3:
            return
        key = hashlib.sha1(label.encode()+raw[:4096]+str(len(raw)).encode()).hexdigest()
        if key in seen:
            return
        seen.add(key)
        if _looks_interesting(raw) or len(_printable(raw, 4000)) > 20:
            out.append((label, value))
    for m in _morse_decode(text):
        add("morse_text", m)
        for tok in [m, m.replace(" ", "")]:
            if re.fullmatch(r"[0-9A-Fa-f]+", tok or "") and len(tok) % 2 == 0:
                try: add("morse_hex", bytes.fromhex(tok))
                except Exception: pass
            try: add("morse_b64", base64.b64decode(tok + "="*((4-len(tok)%4)%4)))
            except Exception: pass
    for i, tok in enumerate(HEX_RE.findall(text[:700_000])[:80]):
        if len(tok) % 2 == 0:
            try: add(f"hex_token_{i}", bytes.fromhex(tok))
            except Exception: pass
    for i, tok in enumerate(B64_RE.findall(text[:700_000])[:100]):
        try: add(f"b64_token_{i}", base64.b64decode(tok + "="*((4-len(tok)%4)%4)))
        except Exception:
            try: add(f"b64url_token_{i}", base64.urlsafe_b64decode(tok + "="*((4-len(tok)%4)%4)))
            except Exception: pass
    try:
        u = html.unescape(unquote_plus(text))
        if u != text:
            add("url_html_unescape", u)
    except Exception: pass
    try:
        qp = quopri.decodestring(text.encode("utf-8", "ignore"))
        if qp and qp != text.encode("utf-8", "ignore"):
            add("quoted_printable", qp)
    except Exception: pass
    return out


def _rect_transpositions(text: str) -> list[tuple[str, str]]:
    raw_text = str(text or "")[:20000]
    low_raw = raw_text.lower()
    # v117: do not transpose natural-language task statements. Only short,
    # compact ciphertext/data blobs should enter this route. This prevents
    # thousands of fake wrapped tokens from instructions like "formatas ctf_cs".
    if any(k in low_raw for k in ["vėliav", "veliav", "formatas", "jūsų užduotis", "jusu uzduotis", "dekoduok", "pateikti", "raskite"]):
        compact_lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        if len(compact_lines) != 1 or len(compact_lines[0]) < 24:
            return []
    s = re.sub(r"\s+", "", raw_text)
    if not (24 <= len(s) <= 2500):
        return []
    # Avoid exploding on natural language pages.
    if sum(ch.isalnum() or ch in "{}_-$!@[]=,.;:+/()" for ch in s) / max(1, len(s)) < 0.92:
        return []
    if len(re.findall(r"[A-Za-zÀ-ž]{4,}", raw_text)) >= 6 and (raw_text.count(" ") + raw_text.count("\n")) > len(raw_text) * 0.10:
        return []
    outs: list[tuple[str, str]] = []
    seen = set()
    def add(label: str, val: str):
        if len(val) != len(s):
            return
        if val in seen:
            return
        seen.add(val)
        if "{" in val or "}" in val or re.search(r"[a-zA-Z0-9_]{6,}", val):
            outs.append((label, val))
    n = len(s)
    factors = [d for d in range(2, min(96, n)+1) if n % d == 0]
    for rows in factors:
        cols = n // rows
        if rows > 96 or cols > 240:
            continue
        grid = [s[i*cols:(i+1)*cols] for i in range(rows)]
        add(f"rect_{rows}x{cols}_read_columns", "".join(grid[r][c] for c in range(cols) for r in range(rows)))
        add(f"rect_{rows}x{cols}_read_columns_rev_rows", "".join(grid[r][c] for c in range(cols) for r in range(rows-1, -1, -1)))
        add(f"rect_{rows}x{cols}_rows_reversed", "".join(row[::-1] for row in grid))
        add(f"rect_{rows}x{cols}_serpentine_rows", "".join((grid[r] if r % 2 == 0 else grid[r][::-1]) for r in range(rows)))
        add(f"rect_{rows}x{cols}_serpentine_cols", "".join(("".join(grid[r][c] for r in range(rows)) if c % 2 == 0 else "".join(grid[r][c] for r in range(rows-1,-1,-1))) for c in range(cols)))
    return outs[:260]


def _password_candidates_from_text(text: str, rel: str) -> list[bytes | None]:
    # Deterministic priority matters in CTF archives: the old set/list slicing
    # could drop the real Morse/common password once noisy sibling context added
    # hundreds of tokens. Keep common + path + Morse candidates first, then only
    # bounded context tokens.
    words: list[str] = []
    seen_words: set[str] = set()
    def add_word(w: str) -> None:
        w = str(w or "").strip()
        if not w or w in seen_words:
            return
        seen_words.add(w); words.append(w)
    for w in COMMON_PASSWORDS:
        add_word(w)
    add_word(Path(rel).stem); add_word(Path(rel).name)
    for m in _morse_decode(text):
        add_word(m); add_word(m.lower()); add_word(m.upper()); add_word(m.title())
    for tok in re.findall(r"[A-Za-z0-9_@!#.$%+\-]{3,32}", text[:200_000]):
        add_word(tok)
        if len(words) >= 260:
            break
    out: list[bytes | None] = [None]
    seen_out: set[bytes] = set()
    for w in words[:260]:
        variants = [w, w.lower(), w.upper(), w.capitalize(), w + "!", w + "123", w + "2026", w + "2025"]
        for v in variants:
            if not v:
                continue
            b = v.encode("utf-8", "ignore")
            if b and b not in seen_out:
                seen_out.add(b); out.append(b)
            if len(out) >= 420:
                return out
    return out


def _zip_extract(raw: bytes, rel: str, context_text: str = "") -> list[tuple[str, bytes, str]]:
    out: list[tuple[str, bytes, str]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return out
    pwds = _password_candidates_from_text(context_text + "\n" + _printable(raw, 100_000), rel)
    try:
        for info in zf.infolist()[:160]:
            if info.is_dir() or info.file_size > V116_MAX_PAYLOAD * 4:
                continue
            for pwd in pwds:
                label = pwd.decode("utf-8", "ignore") if pwd else "none"
                try:
                    data = zf.read(info, pwd=pwd)[:V116_MAX_PAYLOAD]
                    out.append((info.filename, data, label))
                    break
                except RuntimeError:
                    continue
                except Exception:
                    break
    finally:
        try: zf.close()
        except Exception: pass
    return out


def _carve_zips(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    start_positions = [m.start() for m in re.finditer(re.escape(b"PK\x03\x04"), raw[:MAX_EXTRA_BYTES])]
    for si, start in enumerate(start_positions[:16]):
        end = raw.find(b"PK\x05\x06", start)
        if end == -1 or end + 22 > len(raw):
            continue
        comment = int.from_bytes(raw[end+20:end+22], "little", signed=False) if end + 22 <= len(raw) else 0
        blob = raw[start:min(len(raw), end+22+comment)]
        if len(blob) >= 64:
            out.append((f"carved_zip_{si}_offset_{start}", blob))
    return out


def _frontier_payloads(raw: bytes, rel: str, context_text: str, start: float) -> list[tuple[str, bytes, str]]:
    """Return (chain, data, note). Bounded BFS for embedded/archive payloads."""
    out: list[tuple[str, bytes, str]] = []
    q: list[tuple[str, bytes]] = [("input", raw[:V116_MAX_PAYLOAD*3])]
    seen: set[str] = set()
    while q and len(out) < V116_MAX_FRONTIER and _budget(start):
        chain, data = q.pop(0)
        key = hashlib.sha1(data[:4096] + str(len(data)).encode()).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        if chain != "input" and (_looks_interesting(data) or len(_printable(data, 4000)) > 20):
            out.append((chain, data[:V116_MAX_PAYLOAD], "frontier payload"))
        # gzip
        if data.startswith(b"\x1f\x8b"):
            try:
                child = gzip.decompress(data)[:V116_MAX_PAYLOAD*3]
                q.append((chain + "->gzip", child))
            except Exception: pass
        # zlib raw-ish
        for wbits, label in [(zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "raw_zlib")]:
            try:
                child = zlib.decompress(data, wbits)[:V116_MAX_PAYLOAD*3]
                if child and child != data:
                    q.append((chain + f"->{label}", child))
            except Exception: pass
        # tar
        try:
            if tarfile.is_tarfile(fileobj := io.BytesIO(data)):
                fileobj.seek(0)
                with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
                    for m in tf.getmembers()[:100]:
                        if not m.isfile() or m.size > V116_MAX_PAYLOAD*4:
                            continue
                        f = tf.extractfile(m)
                        if f:
                            q.append((chain + f"->tar:{m.name}", f.read(V116_MAX_PAYLOAD*3)))
        except Exception: pass
        # zip direct + carved
        zips = []
        if data.startswith(b"PK\x03\x04") or zipfile.is_zipfile(io.BytesIO(data)):
            zips.append(("zip", data))
        zips.extend(_carve_zips(data))
        for zlabel, zdata in zips[:12]:
            for name, child, pwd in _zip_extract(zdata, rel, context_text + "\n" + _printable(data, 180_000))[:80]:
                child_chain = chain + f"->{zlabel}:{name}:pwd={pwd}"
                if _looks_interesting(child) or len(_printable(child, 4000)) > 20:
                    out.append((child_chain, child[:V116_MAX_PAYLOAD], "frontier embedded zip member"))
                q.append((child_chain, child))
        # token/text layers. Only do this for mostly-text payloads; otherwise
        # binary JPEG/WAV/archives waste the frontier budget before embedded
        # archive children are reached.
        sample = data[:12000]
        printable_ratio = (sum(1 for b in sample if 32 <= b <= 126 or b in (9,10,13)) / max(1, len(sample))) if sample else 0
        if printable_ratio >= 0.68 or data[:1].isalnum():
            text = _txt(data, 800_000)
            if text:
                for label, child in _decode_layers_from_text(text)[:40]:
                    bchild = child.encode("utf-8", "ignore") if isinstance(child, str) else bytes(child)
                    q.append((chain + f"->{label}", bchild))
    return out


def _pcapng_extract(raw: bytes) -> list[tuple[str, bytes | str]]:
    out: list[tuple[str, bytes | str]] = []
    # Classic pcap is already partly handled by v115, but this parser also handles
    # raw IPv4 pcapng used by Cyber Sprint tasks.
    def add(label: str, data: bytes | str):
        if data and (isinstance(data, str) or len(data) > 0):
            out.append((label, data))
    # pcapng enhanced packet block: type 0x00000006, total length, iface, ts, caplen, pktlen, data
    if raw.startswith(b"\x0a\x0d\x0d\x0a") or b"\x06\x00\x00\x00" in raw[:4096]:
        pos = 0; payloads=[]; ipids=[]; ttls=[]; protos=[]; dns=[]
        while pos + 12 <= len(raw) and len(payloads) < 5000:
            btype = int.from_bytes(raw[pos:pos+4], "little")
            blen = int.from_bytes(raw[pos+4:pos+8], "little")
            if blen < 12 or pos + blen > len(raw):
                pos += 4; continue
            body = raw[pos+8:pos+blen-4]
            if btype == 6 and len(body) >= 20:
                caplen = int.from_bytes(body[12:16], "little", signed=False)
                pkt = body[20:20+caplen]
                if len(pkt) >= 20 and (pkt[0] >> 4) == 4:
                    ihl = (pkt[0] & 15) * 4
                    if len(pkt) >= ihl:
                        ipids.append(pkt[4:6]); ttls.append(pkt[8]); protos.append(pkt[9])
                        payloads.append(pkt[ihl:])
                elif len(pkt) >= 34 and (pkt[12:14] == b"\x08\x00"):
                    ip = pkt[14:]
                    ihl = (ip[0] & 15) * 4
                    ipids.append(ip[4:6]); ttls.append(ip[8]); protos.append(ip[9]); payloads.append(ip[ihl:])
            pos += blen
        blob = b"\n".join(payloads[:1000])
        add("pcapng_payload_printables", _printable(blob, 1_000_000))
        if ipids:
            add("pcapng_ip_id_low_bytes", bytes(x[1] for x in ipids))
            add("pcapng_ip_id_high_bytes", bytes(x[0] for x in ipids))
            add("pcapng_ip_id_words_be", b"".join(ipids))
        if ttls:
            add("pcapng_ttl_bytes", bytes(ttls))
        if protos:
            add("pcapng_protocol_bytes", bytes(protos))
    return out


def _classic_pcap_extra(raw: bytes) -> list[tuple[str, bytes | str]]:
    out=[]
    if len(raw) < 24 or raw[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return out
    le = raw[:4] == b"\xd4\xc3\xb2\xa1"
    endian = "<" if le else ">"
    pos=24; payloads=[]; dns_names=[]; http=[]; ipid=[]; ttl=[]
    for _ in range(3000):
        if pos+16 > len(raw): break
        ts, us, incl, orig = struct.unpack(endian+"IIII", raw[pos:pos+16]); pos += 16
        pkt = raw[pos:pos+incl]; pos += incl
        if len(pkt) < 14: continue
        off=14 if pkt[12:14]==b"\x08\x00" else 0
        if off and len(pkt) >= off+20 and (pkt[off]>>4)==4:
            ihl=(pkt[off]&15)*4; proto=pkt[off+9]
            ipid.append(pkt[off+4:off+6]); ttl.append(pkt[off+8])
            seg=pkt[off+ihl:]
            if proto==6 and len(seg)>=20:
                doff=(seg[12]>>4)*4; pay=seg[doff:]
            elif proto==17 and len(seg)>=8:
                pay=seg[8:]
            else:
                pay=seg
            if pay:
                payloads.append(pay)
                if b"HTTP/" in pay or b"GET " in pay or b"POST " in pay:
                    http.append(pay.decode("latin1","ignore"))
    blob=b"\n".join(payloads[:1500])
    out.append(("pcap_payload_printables", _printable(blob, 1_000_000)))
    if http: out.append(("pcap_http_messages", "\n---\n".join(http[:300])))
    if ipid: out.append(("pcap_ip_id_low_bytes", bytes(x[1] for x in ipid)))
    if ttl: out.append(("pcap_ttl_bytes", bytes(ttl)))
    return out


def _pyc_extract(raw: bytes) -> list[tuple[str, str]]:
    out=[]
    if len(raw) < 20 or raw[:2] not in (b"\xcb\r", b"\xa7\r", b"\x6f\r", b"\xe3\r"):
        return out
    for off in (12, 16):
        try:
            obj = marshal.loads(raw[off:])
        except Exception:
            continue
        consts=[]; names=[]
        def walk(co: Any):
            if isinstance(co, types.CodeType):
                names.extend(list(co.co_names)); names.extend(list(co.co_varnames))
                for c in co.co_consts:
                    walk(c)
            elif isinstance(co, (str, bytes, int, float)):
                consts.append(co)
        walk(obj)
        text=[]
        for c in consts[:5000]:
            if isinstance(c, bytes):
                try: text.append(c.decode("utf-8", "ignore"))
                except Exception: pass
            else:
                text.append(str(c))
        text.append("\n# names\n" + "\n".join(map(str, names[:2000])))
        try:
            import dis
            sio=io.StringIO(); dis.dis(obj, file=sio); text.append("\n# disassembly\n"+sio.getvalue()[:400_000])
        except Exception: pass
        out.append((f"pyc_marshal_offset_{off}", "\n".join(text)))
        break
    return out


def _binary_static_extract(raw: bytes) -> list[tuple[str, bytes | str]]:
    out=[]
    if raw.startswith((b"\x7fELF", b"MZ")):
        text=_printable(raw, min(len(raw), 3_000_000))
        out.append(("binary_printable_strings", text))
        # little-endian 32/64-bit constants as byte streams can hide flags.
        for width in (4,8):
            bs=[]
            for i in range(0, min(len(raw)-width+1, 500_000), width):
                chunk=raw[i:i+width]
                if all(32 <= b <= 126 or b in (9,10,13) for b in chunk):
                    bs.append(chunk)
            if bs:
                out.append((f"binary_aligned_printable_{width}", b"".join(bs[:10000])))
    return out


def _sibling_context(root: Path) -> str:
    texts=[]
    base=root/"files"
    if not base.exists():
        return ""
    for p in sorted(base.rglob("*"))[:240]:
        if p.is_file() and p.stat().st_size <= 500_000:
            try:
                raw=p.read_bytes()
                if b"\x00" not in raw[:2000]:
                    texts.append(f"\n--- {p.name} ---\n" + raw.decode("utf-8", "ignore"))
            except Exception: pass
    return "\n".join(texts)[:1_500_000]


def _cybersprint_pair_routes(context: str) -> list[tuple[str, str]]:
    out=[]
    # Message + ASCII grille pair. Emit many candidates plus sha256 wrappers when
    # a candidate looks human. This helps the "message and key" style task.
    msgs=re.findall(r"(?:Radote pranešimą:|message:)?\s*([A-Z0-9:./]{48,120})", context)
    key_lines=[]
    for block in re.findall(r"\+-\[key\]--\+(.+?)\+-\[key\]--\+", context, re.S):
        for line in block.splitlines():
            if "|" in line:
                try: key_lines.append(line.split("|",2)[1][:8].ljust(8))
                except Exception: pass
    if not key_lines:
        kl=[]
        for line in context.splitlines():
            if re.fullmatch(r"\|[ o#=.*]{8}\|", line):
                kl.append(line[1:9])
        if len(kl)>=8: key_lines=kl[:8]
    if key_lines and msgs:
        N=8
        pos=[(r,c) for r,row in enumerate(key_lines[:8]) for c,ch in enumerate(row[:8]) if ch != " "]
        def rot(p,k):
            r,c=p
            for _ in range(k): r,c=c,N-1-r
            return r,c
        import itertools
        for msg in msgs[:4]:
            clean=msg.strip()
            if len(clean) != 64: continue
            grid=[clean[i*N:(i+1)*N] for i in range(N)]
            orders=[("row", sorted(pos)), ("given", pos), ("col", sorted(pos,key=lambda x:(x[1],x[0])))]
            for name, ps in orders:
                for rots in itertools.permutations(range(4)):
                    s="".join(grid[r][c] for k in rots for p in ps for r,c in [rot(p,k)])
                    if len(s)>=12:
                        out.append((f"cardan_{name}_{''.join(map(str,rots))}", s))
                        # v117: when the task context asks for SHA256, every
                        # valid Cardan route should emit a hash candidate. The
                        # previous heuristic skipped all-uppercase plaintexts,
                        # which is common in grille tasks.
                        if "sha256" in context.lower() or re.search(r"[A-Za-z]{5}", s):
                            out.append((f"cardan_{name}_{''.join(map(str,rots))}_sha256", "ctf_cs{"+hashlib.sha256(s.encode()).hexdigest()+"}"))
    return out[:220]


def extra_analyze_v116(path: Path, root: Path, report: dict[str, Any], profile: dict[str, Any], rel: str) -> dict[str, Any]:
    started=time.time(); manifest=[]; rows=[]
    try:
        raw=path.read_bytes()
    except Exception as e:
        report.setdefault("v116_competition", {})["error"] = repr(e); return report
    context=_sibling_context(root)
    text=_txt(raw, 1_200_000)
    if context and text not in context:
        context += "\n" + text

    def record(label: str, payload: bytes | str, note: str, score: int = 980, conf: str = "high"):
        if not _budget(started):
            return
        rawp = payload.encode("utf-8", "ignore") if isinstance(payload, str) else bytes(payload or b"")
        if not rawp:
            return
        manifest.append({"label": label, "note": note, "size": len(rawp), "sha16": _sha(rawp)})
        _artifact(report, root, f"v116_{re.sub(r'[^A-Za-z0-9_.-]+','_',label)}_{_sha(rawp)}.txt", payload if isinstance(payload,str) else _printable(rawp) or rawp, "v116_evidence", note, score, label, rel)
        rows.extend(_scan(label, payload, profile, rel, boost=score//2, confidence=conf))

    # Text encodings, Morse, URL/HTML, base64/hex.
    for label, payload in _decode_layers_from_text(context or text)[:140]:
        record(label, payload, "v116 decoded text/token layer", 980, "high" if "morse" in label or "hex" in label else "medium")

    # Rectangular transposition for short ciphertext files.
    for label, val in _rect_transpositions(text)[:260]:
        if "{" in val or re.search(r"[a-z0-9_]{8,}\}", val):
            record(label, val, "v116 rectangular/route transposition candidate", 1040, "high")

    # Sibling-aware message+key routes.
    for label, val in _cybersprint_pair_routes(context):
        record(label, val, "v116 sibling-aware message/key route", 900 if "sha256" not in label else 1140, "medium" if "sha256" not in label else "high")

    # Recursive payload extraction and carving.
    for chain, payload, note in _frontier_payloads(raw, rel, context, started):
        record(chain, payload, note, 1080 if "carved_zip" in chain or "pwd=" in chain else 930, "high" if "pwd=" in chain or "carved_zip" in chain else "medium")

    # PCAP/PCAPNG extraction.
    for label, payload in (_pcapng_extract(raw) + _classic_pcap_extra(raw))[:80]:
        record(label, payload, "v116 packet payload/IP-field extraction", 1020, "medium")

    # PYC/binary static.
    for label, payload in (_pyc_extract(raw) + _binary_static_extract(raw))[:80]:
        record(label, payload, "v116 static code/binary extraction", 900, "medium")

    # Generic ASCII strings as lower priority but useful for PE/ELF/PCAP.
    ptxt=_printable(raw, 1_500_000)
    if ptxt and any(k in ptxt.lower() for k in ["flag", "ctf", "secret", "password", "cwe", "http", "slapt", "rakt"]):
        record("printable_strings_context", ptxt, "v116 printable strings with CTF-relevant keywords", 760, "low")

    if rows:
        _append_flags(report, rows, rel)
    if manifest:
        _artifact(report, root, "v116_competition_manifest.json", json.dumps(manifest[:1800], indent=2, ensure_ascii=False), "v116_manifest", "v116 Cyber Sprint frontier/transposition/morse/pcapng/static manifest", 1120, "v116_competition", rel)
    report["v116_competition"] = {
        "enabled": True,
        "version": "v116-cybersprint-frontier",
        "runtime_ms": int((time.time()-started)*1000),
        "findings": len(rows),
        "manifest_items": len(manifest),
        "budget_ms": V116_FILE_BUDGET_MS,
        "budget_exhausted": not _budget(started),
    }
    return report


def apply(mod) -> None:
    old_analyze = getattr(mod, "analyze_file", None)
    def analyze_file(pid, path, root, i=1, total=1):
        p=Path(path); r=Path(root)
        if os.environ.get("SLOPER_V116_FAST_ONLY", "0") == "1":
            report = {"name": p.name, "path": str(p), "flags": [], "verified_flags": [], "artifacts": [], "transformations": []}
        else:
            report = old_analyze(pid, path, root, i, total) if old_analyze else {"flags": [], "artifacts": []}
            if not isinstance(report, dict):
                report = {"error": "previous analyzer returned non-dict", "flags": [], "artifacts": []}
        try: rel=str(p.relative_to(r))
        except Exception: rel=p.name
        try: profile=_profile_for_project(mod, str(pid))
        except Exception: profile={}
        try:
            return extra_analyze_v116(p, r, report, profile, rel)
        except Exception as e:
            report.setdefault("v116_competition", {})["error"] = repr(e)
            return report
    mod.analyze_file = analyze_file
    mod.sl116_rect_transpositions = _rect_transpositions
    mod.sl116_morse_decode = _morse_decode
    mod.sl116_frontier_payloads = _frontier_payloads
    try:
        @mod.app.get("/api/v116_status")
        def v116_status():
            return {"ok": True, "version": "v116-cybersprint-frontier", "extractors": ["rect-transposition", "morse-password-zip", "carved-ooxml", "pcapng", "pyc-static", "binary-static"], "budget_ms": V116_FILE_BUDGET_MS}
    except Exception:
        pass
