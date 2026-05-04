"""Final tournament workflow layer for CTF SLOPER.

This module is intentionally small compared with the legacy solver.  It wraps
the existing v93-v104 pipeline with a few high-value, bounded CTF workflows and
then builds a cleaner evidence map for the UI.  It does not hardcode challenge
answers; all promotions come from decoded/extracted artifacts.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import html
import io
import json
import lzma
import quopri
import re
import struct
import tarfile
import time
import urllib.parse
import zipfile
import zlib
from pathlib import Path
from typing import Any

from .health import agent_crash
from . import v93_reasoned as core
from . import v100_ctf_player as v100
from .artifact_hub import compact_hub


SEMANTIC_RE = re.compile(
    r"ctf|flag|secret|hidden|cyber|sprint|calc|archive|password|pass|key|token|"
    r"rakt|slapt|veliav|v[eė]liav|atsak|answer|solve|winner|lab|l4b",
    re.I,
)
BRACE_RE = re.compile(r"(?<![A-Za-z0-9_])\{([A-Za-z0-9][A-Za-z0-9_\-:+./=]{3,160})\}")
NATO = {
    "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e", "foxtrot": "f", "golf": "g",
    "hotel": "h", "india": "i", "juliett": "j", "juliet": "j", "kilo": "k", "lima": "l", "mike": "m",
    "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r", "sierra": "s", "tango": "t",
    "uniform": "u", "victor": "v", "whiskey": "w", "xray": "x", "x-ray": "x", "yankee": "y", "zulu": "z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
    "eight": "8", "nine": "9",
    "underscore": "_", "under": "_", "dash": "-", "hyphen": "-", "minus": "-", "plus": "+", "dot": ".",
    "period": ".", "slash": "/", "lbrace": "{", "rbrace": "}", "leftbrace": "{", "rightbrace": "}",
    "openbrace": "{", "closebrace": "}", "braceopen": "{", "braceclose": "}",
}


def _txt(blob: bytes | str) -> str:
    if isinstance(blob, str):
        return blob
    return bytes(blob or b"").decode("utf-8", "ignore")


def _signal(text: str) -> int:
    text = str(text or "")
    score = core.text_quality(text[:12000])
    if core.STRICT_RE.search(text):
        score += 500
    if BRACE_RE.search(text):
        score += 160
    if SEMANTIC_RE.search(text):
        score += 90
    if v100.LEETSPEAK_TOKEN_RE.search(text) or v100.LEET_WORD_RE.search(text):
        score += 45
    return score


def _interesting(text: str, threshold: int = 135) -> bool:
    if not text:
        return False
    if core.STRICT_RE.search(text) or BRACE_RE.search(text):
        return True
    return _signal(text) >= threshold


def _emit_text(report: dict, root: Path, name: str, text: str, kind: str, note: str, score: int, family: str = "final") -> dict | None:
    if not text:
        return None
    art = core.artifact(root, report, name, text[:1_000_000], kind, note, score, family)
    apath = art.get("path") if art else None
    core.scan_text(report, text, "CTF SLOPER final workflow", apath, note, score + 80, allow_wrap=True)
    v100.scan_alt_formats(report, text, "CTF SLOPER final workflow", apath, note, score + 40)
    v100.preserve_unconfirmed_strict(report, text, "CTF SLOPER final workflow", apath, note, score)
    return art


def _decode_brainfuck(src: str, limit_steps: int = 220000, limit_out: int = 20000) -> str:
    code = [c for c in src if c in "><+-.,[]"]
    if len(code) < 8:
        return ""
    jump: dict[int, int] = {}
    stack: list[int] = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]" and stack:
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    tape = [0] * 60000
    ptr = ip = steps = 0
    out: list[str] = []
    while 0 <= ip < len(code) and steps < limit_steps and len(out) < limit_out:
        c = code[ip]
        if c == ">":
            ptr = (ptr + 1) % len(tape)
        elif c == "<":
            ptr = (ptr - 1) % len(tape)
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == "[" and tape[ptr] == 0 and ip in jump:
            ip = jump[ip]
        elif c == "]" and tape[ptr] != 0 and ip in jump:
            ip = jump[ip]
        ip += 1
        steps += 1
    return "".join(out)


def _keyboard_shift(text: str, direction: int) -> str:
    rows = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
    mapping: dict[str, str] = {}
    for row in rows:
        for i, ch in enumerate(row):
            j = i + direction
            if 0 <= j < len(row):
                mapping[ch] = row[j]
                mapping[ch.upper()] = row[j].upper()
    return "".join(mapping.get(c, c) for c in text)


def _pack_bits(bits: str, msb_first: bool = True) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if not msb_first:
            chunk = chunk[::-1]
        out.append(int(chunk, 2))
    return bytes(out)


def _polybius(text: str) -> str:
    chars = "abcdefghiklmnopqrstuvwxyz"
    out = []
    for a, b in re.findall(r"([1-5])\D*([1-5])", text):
        idx = (int(a) - 1) * 5 + (int(b) - 1)
        if 0 <= idx < len(chars):
            out.append(chars[idx])
    return "".join(out)


def _a1z26(text: str) -> str:
    vals = [int(x) for x in re.findall(r"(?<![A-Za-z0-9])(?:[1-9]|1[0-9]|2[0-6])(?![A-Za-z0-9])", text[:400000])]
    if len(vals) < 4:
        return ""
    return "".join(chr(96 + v) for v in vals if 1 <= v <= 26)


def _decode_bacon_bits(bits: str) -> list[str]:
    bits = re.sub(r"[^01]", "", bits)
    if len(bits) < 25:
        return []
    alphabets = ["abcdefghiklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"]
    outs: list[str] = []
    for alpha in alphabets:
        for inv in (False, True):
            chars: list[str] = []
            for i in range(0, len(bits) - 4, 5):
                chunk = bits[i:i + 5]
                if inv:
                    chunk = "".join("1" if c == "0" else "0" for c in chunk)
                idx = int(chunk, 2)
                if idx < len(alpha):
                    chars.append(alpha[idx])
            val = "".join(chars)
            if val and val not in outs:
                outs.append(val)
    return outs[:8]


def _columnar_decrypt(cipher: str, key: str) -> str:
    cipher = re.sub(r"[^A-Za-z0-9_{}+\-]", "", cipher)
    key = re.sub(r"[^A-Za-z0-9]", "", key).upper()
    cols = len(key)
    if cols < 2 or cols > 18 or len(cipher) < cols * 2:
        return ""
    rows = (len(cipher) + cols - 1) // cols
    short = rows * cols - len(cipher)
    order = sorted(range(cols), key=lambda i: (key[i], i))
    col_lens = [rows] * cols
    for c in range(cols - short, cols):
        if 0 <= c < cols:
            col_lens[c] = rows - 1
    columns: dict[int, str] = {}
    pos = 0
    for c in order:
        ln = max(0, col_lens[c])
        columns[c] = cipher[pos:pos + ln]
        pos += ln
    out: list[str] = []
    for r in range(rows):
        for c in range(cols):
            col = columns.get(c, "")
            if r < len(col):
                out.append(col[r])
    return "".join(out)


def _iter_url_layers(text: str, rounds: int = 6) -> list[str]:
    vals: list[str] = []
    cur = str(text or "")
    for _ in range(rounds):
        nxt = html.unescape(urllib.parse.unquote_plus(cur))
        if nxt == cur:
            break
        vals.append(nxt)
        cur = nxt
    return vals or [cur]


def _bytes_preview(data: bytes, limit: int = 6000) -> str:
    text = bytes(data[:limit]).decode("utf-8", "ignore")
    if not text.strip():
        text = "\n".join(core.printable_strings(data[:120000], 5, 180))
    return text


def _try_decompress(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if not data:
        return out
    attempts: list[tuple[str, Any]] = [
        ("gzip", gzip.decompress),
        ("bzip2", bz2.decompress),
        ("xz", lzma.decompress),
        ("zlib", zlib.decompress),
    ]
    for name, fn in attempts:
        try:
            val = fn(data)
            if val and val != data:
                out.append((name, val))
        except Exception:
            pass
    return out


def _decode_base64_variants(data: bytes) -> list[tuple[str, bytes]]:
    if not data or len(data) > 25_000_000:
        return []
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    sample = text[:5000]
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-\r\n\t ]+", sample or ""):
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    compact = re.sub(r"\s+", "", text)
    variants = [
        ("base64_compact", compact),
        ("base64_reverse_text", compact[::-1]),
    ]
    if lines:
        variants.extend([
            ("base64_reverse_each_line", "".join(ln[::-1] for ln in lines)),
            ("base64_reverse_line_order", "".join(reversed(lines))),
            ("base64_reverse_lines_and_order", "".join(ln[::-1] for ln in reversed(lines))),
        ])
    out: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for name, value in variants:
        if len(value) < 16:
            continue
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        for decoder_name, decoder in [("std", base64.b64decode), ("url", base64.urlsafe_b64decode)]:
            try:
                blob = decoder(padded)
            except Exception:
                continue
            for suffix, candidate in [("", blob), ("_reverse_bytes", blob[::-1])]:
                if len(candidate) < 4 or candidate in seen:
                    continue
                seen.add(candidate)
                out.append((name + "_" + decoder_name + suffix, candidate))
    return out


def _payload_rank(data: bytes) -> int:
    if not data:
        return 0
    rank = _signal(_bytes_preview(data, 12000))
    magics = [b"PK\x03\x04", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"%PDF", b"SQLite format 3\x00", b"\x1f\x8b\x08", b"BZh", b"\xfd7zXZ\x00"]
    if any(data.startswith(m) for m in magics):
        rank += 140
    off = data.find(b"PK\x03\x04")
    if 0 <= off < 96:
        rank += 110
    if re.search(rb"ctf[_-]?cs\{[^}]{1,160}\}|\{[A-Za-z0-9_+\-:/=]{6,160}\}", data[:250000]):
        rank += 600
    return rank


def _next_onion_payload(data: bytes) -> tuple[str, bytes, dict[str, Any]] | None:
    raw = bytes(data or b"")
    if not raw:
        return None
    if raw.startswith(b"PK\x03\x04") or zipfile.is_zipfile(io.BytesIO(raw)):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                infos = [zi for zi in zf.infolist() if not zi.is_dir()]
                if not infos:
                    return None
                # Onion tasks usually hide the next layer in the largest member.
                ranked = sorted(infos, key=lambda zi: (zi.file_size, zi.compress_size), reverse=True)
                for zi in ranked[:6]:
                    try:
                        child = zf.read(zi)
                    except RuntimeError:
                        continue
                    if child:
                        return "zip_member", child, {"member": zi.filename, "size": zi.file_size, "compress_size": zi.compress_size}
        except Exception:
            pass
    for name, child in _try_decompress(raw):
        if child:
            return name, child, {"size": len(child)}
    candidates: list[tuple[int, str, bytes]] = []
    for name, child in _decode_base64_variants(raw):
        if not child:
            continue
        off = child.find(b"PK\x03\x04")
        if 0 <= off < 96:
            child = child[off:]
            name += "_strip_to_zip"
        candidates.append((_payload_rank(child), name, child))
    if candidates:
        _rank, name, child = max(candidates, key=lambda x: x[0])
        if _rank >= 120 or child.startswith((b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"SQLite format 3\x00")):
            return name, child, {"rank": _rank, "size": len(child)}
    # Single-byte transform rescue for small-ish final layers.
    if len(raw) <= 4_000_000:
        for key in range(256):
            child = bytes(b ^ key for b in raw[:2_000_000])
            if child.startswith((b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"SQLite format 3\x00")) or core.STRICT_RE.search(_txt(child[:200000])):
                return f"xor_{key:02x}", child, {"key": key, "size": len(child)}
    return None


def final_text_workflow_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """More CTF-style text routes: mixed bits, word channels, keyboard shifts and esolangs."""
    if not data or len(data) > 5_000_000:
        return []
    text = _txt(data[:2_000_000])
    if not text.strip():
        return []
    arts: list[dict] = []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(method: str, value: bytes | str, note: str, base_score: int = 820) -> None:
        txt = _txt(value).strip("\x00")
        if not txt:
            return
        key = (method, txt[:300])
        if key in seen:
            return
        seen.add(key)
        score = base_score + min(_signal(txt), 260)
        rows.append({"method": method, "score": score, "note": note, "preview": txt[:1200]})
        if _interesting(txt, 110):
            art = _emit_text(report, root, f"final_{core.safe_name(method)}.txt", txt, "final_text_transform", note, score, "final_text")
            if art:
                arts.append(art)

    # Iterative unescape/URL/quoted-printable layers preserve the exact braces.
    cur = text
    for i in range(4):
        nxts: list[tuple[str, str]] = []
        try:
            u = urllib.parse.unquote_plus(cur)
            if u != cur:
                nxts.append((f"url_decode_round_{i+1}", u))
        except Exception:
            pass
        try:
            h = html.unescape(cur)
            if h != cur:
                nxts.append((f"html_unescape_round_{i+1}", h))
        except Exception:
            pass
        try:
            q = quopri.decodestring(cur.encode("utf-8", "ignore")).decode("utf-8", "ignore")
            if q and q != cur:
                nxts.append((f"quoted_printable_round_{i+1}", q))
        except Exception:
            pass
        if not nxts:
            break
        for name, val in nxts:
            add(name, val, f"Iterative {name} produced readable evidence.", 830)
        cur = nxts[0][1]

    groups8 = re.findall(r"(?<![01])([01]{8})(?![01])", text)
    if len(groups8) >= 4:
        add("mixed_delimiter_binary_groups", bytes(int(g, 2) for g in groups8[:40000]), "8-bit binary groups decoded despite labels/mixed delimiters.", 900)
    hex_bytes = re.findall(r"(?:\\x|0x)?([0-9a-fA-F]{2})(?![0-9a-fA-F])", text[:300000])
    if len(hex_bytes) >= 4:
        try:
            add("hex_byte_stream", bytes(int(x, 16) for x in hex_bytes[:60000]), "Hex byte stream decoded with optional 0x/\\x markers.", 850)
        except Exception:
            pass
    bits = re.sub(r"[^01]", "", text)
    if 32 <= len(bits) <= 500000:
        for off in range(8):
            chunk = bits[off:]
            if len(chunk) >= 32:
                add(f"continuous_bits_offset_{off}_msb", _pack_bits(chunk, True), f"Continuous bitstream packed from offset {off} MSB-first.", 780)
                add(f"continuous_bits_offset_{off}_lsb", _pack_bits(chunk, False), f"Continuous bitstream packed from offset {off} LSB-first.", 760)
        for idx, bacon in enumerate(_decode_bacon_bits(bits)):
            add(f"bacon_from_binary_bits_{idx}", bacon, "Bacon 5-bit decode from binary-like stream.", 820)

    # Binary bits from case, punctuation and whitespace are common plain-sight misc tricks.
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 32:
        case_bits = "".join("1" if c.isupper() else "0" for c in letters[:120000])
        add("case_bits_msb", _pack_bits(case_bits, True), "Upper/lowercase channel decoded as bits.", 790)
        add("case_bits_lsb", _pack_bits(case_bits, False), "Upper/lowercase channel decoded as reversed-bit bytes.", 770)
    ws_bits = "".join("1" if c == "\t" else "0" for c in text if c in " \t")
    if 32 <= len(ws_bits) <= 300000 and "\t" in text:
        add("space_tab_bits_msb", _pack_bits(ws_bits, True), "Space/tab stream decoded as bits.", 800)
        add("space_tab_bits_lsb", _pack_bits(ws_bits, False), "Space/tab stream decoded as reversed-bit bytes.", 780)

    nums = [int(x, 0) for x in re.findall(r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{1,4}|0b[01]{1,8}|\d{1,5})(?![A-Za-z0-9])", text[:400000])[:12000]]
    if len(nums) >= 4:
        for off in (0, 1, 32, 48, 64, 65, 97, 100, 128, 255, 1000):
            raw = bytes((n - off) & 255 for n in nums if 0 <= n - off <= 255)
            if len(raw) >= 4:
                add(f"number_stream_minus_{off}", raw, f"Numeric stream decoded as byte values minus {off}.", 820)
        a1 = "".join(chr(96 + n) for n in nums if 1 <= n <= 26)
        if len(a1) >= 4:
            add("a1z26_numbers", a1, "Numbers 1-26 decoded as A1Z26 text.", 800)
    poly = _polybius(text)
    if len(poly) >= 4:
        add("polybius_11_55", poly, "Polybius coordinate pairs decoded.", 800)

    words = re.findall(r"[A-Za-z0-9_{}\-:+./=]{2,80}", text)
    nato_words = [NATO[w.lower()] for w in words if w.lower() in NATO]
    if len(nato_words) >= 4:
        add("nato_spelling_words", "".join(nato_words), "NATO/spelling words normalized to letters and digits.", 850)
    ab_words = [w for w in re.findall(r"\b[AaBb]\b", text)]
    if len(ab_words) >= 5:
        for idx, bacon in enumerate(_decode_bacon_bits("".join("1" if w.lower() == "b" else "0" for w in ab_words))):
            add(f"bacon_from_ab_words_{idx}", bacon, "Bacon A/B word stream decoded.", 840)
    if len(words) >= 5:
        for n in range(2, 10):
            add(f"every_{n}_word", " ".join(words[n-1::n])[:120000], f"Every {n}th word extracted.", 700)
            add(f"every_{n}_word_reverse", " ".join(words[::-1][n-1::n])[:120000], f"Every {n}th word from reversed word order.", 690)
        key_candidates = ["KEY", "SECRET", "CTF", "CYBER", "SPRINT", "FLAG", "PASSWORD", "Raktas", "Slaptas"]
        key_candidates.extend([w for w in words if 2 <= len(w) <= 14 and w.isalpha()])
        cipher_chunks = []
        for chunk in re.findall(r"[A-Za-z0-9_{}+\-]{18,4000}", text):
            if sum(c.isalpha() for c in chunk) >= 12:
                cipher_chunks.append(chunk)
        seen_keys: set[str] = set()
        for key in key_candidates[:80]:
            k = key.upper()
            if k in seen_keys:
                continue
            seen_keys.add(k)
            for ci, cipher in enumerate(cipher_chunks[:6]):
                plain = _columnar_decrypt(cipher, k)
                if plain and _interesting(plain, 90):
                    add(f"columnar_{core.safe_name(k)}_{ci}", plain, f"Keyed columnar transposition decrypt attempt using key {k}.", 850)
    compact_chars = re.sub(r"\s+", "", text)
    if 16 <= len(compact_chars) <= 200000:
        for n in range(2, 9):
            add(f"every_{n}_char", compact_chars[n-1::n], f"Every {n}th non-whitespace character extracted.", 690)

    for direction, label in [(-1, "left"), (1, "right")]:
        shifted = _keyboard_shift(text[:200000], direction)
        if shifted != text[:200000]:
            add(f"keyboard_shift_{label}", shifted, f"QWERTY keyboard shift {label} corrected.", 760)

    if len(re.sub(r"[^><+\-.,\[\]]", "", text)) >= 12:
        bf = _decode_brainfuck(text)
        if bf:
            add("brainfuck_output", bf, "Brainfuck-like program executed with bounded interpreter.", 860)

    if "begin " in text and re.search(r"^M", text, re.M):
        out = bytearray()
        for line in text.splitlines():
            try:
                if line and not line.startswith(("begin", "end")):
                    out.extend(binascii.a2b_uu(line))
            except Exception:
                pass
        if out:
            add("uuencode_decode", bytes(out), "UUencoded lines decoded.", 860)

    if rows:
        rows = sorted(rows, key=lambda x: int(x.get("score", 0) or 0), reverse=True)[:220]
        art = core.artifact(root, report, "final_text_workflow_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "final_text_workflow_manifest", "Bounded text workflow manifest: bit streams, word/char routes, keyboard shifts and esolang attempts.", 760, "final_text")
        if art:
            arts.append(art)
    return [a for a in arts if a]


def _decode_number_sequence(vals: list[int], limit: int = 12000) -> dict[str, str]:
    vals = [int(v) for v in vals[:limit]]
    out: dict[str, str] = {}
    if not vals:
        return out
    seqs: dict[str, list[int]] = {
        "low": [v & 255 for v in vals],
        "mod95": [32 + (v % 95) for v in vals],
        "mod26_lower": [97 + (v % 26) for v in vals],
    }
    if len(vals) >= 2:
        seqs["diff_low"] = [(vals[i] - vals[i - 1]) & 255 for i in range(1, len(vals))]
        seqs["diff_mod95"] = [32 + ((vals[i] - vals[i - 1]) % 95) for i in range(1, len(vals))]
        seqs["xor_prev"] = [(vals[i] ^ vals[i - 1]) & 255 for i in range(1, len(vals))]
    for name, seq in seqs.items():
        text = bytes(seq).decode("utf-8", "ignore")
        if text:
            out[name] = text
        rev = bytes(reversed(seq)).decode("utf-8", "ignore")
        if rev:
            out[name + "_reverse"] = rev
        try:
            for bname, btxt in core.decode_bit_channels(seq, limit=12).items():
                if btxt:
                    out[name + "_" + bname] = btxt
        except Exception:
            pass
    return out


def _decode_symbol_sequence(seq: list[str], limit: int = 8000) -> dict[str, str]:
    seq = [s for s in seq[:limit] if s]
    vals = sorted(set(seq))
    out: dict[str, str] = {}
    if not (2 <= len(vals) <= 7 and len(seq) >= 8):
        return out
    out["letters"] = "".join(s[0] for s in seq if s)
    idx = {v: i for i, v in enumerate(vals)}
    digits = [idx[s] for s in seq]
    for v in vals:
        bits = [1 if s == v else 0 for s in seq]
        for lsb in (False, True):
            text = _pack_bits("".join("1" if b else "0" for b in bits), not lsb).decode("utf-8", "ignore")
            if text:
                out[f"bit_presence_{core.safe_name(v)}_{'lsb' if lsb else 'msb'}"] = text
    base = len(vals)
    for group in range(2, 9):
        bs: list[int] = []
        for i in range(0, len(digits) - group + 1, group):
            val = 0
            for d in digits[i:i + group]:
                val = val * base + d
            if 0 <= val <= 255:
                bs.append(val)
        if len(bs) >= 3:
            out[f"base{base}_group{group}"] = bytes(bs).decode("utf-8", "ignore")
    return out


def final_time_log_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Timestamp/module/level sequence extractor for log-anomaly CTFs."""
    if not data or len(data) > 12_000_000:
        return []
    text = _txt(data[:12_000_000])
    if "T" not in text or "Z" not in text or not re.search(r"\b(?:INFO|WARN|DEBUG|ERROR)\b", text):
        return []
    rows: list[dict[str, Any]] = []
    parsed: list[dict[str, Any]] = []
    last_abs: int | None = None
    line_re = re.compile(r"(\d{4}-\d\d-\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z\s+([A-Za-z0-9_.:-]+)\s+([A-Za-z]+)\s*(.*)")
    for idx, line in enumerate(text.splitlines()[:40000]):
        m = line_re.search(line)
        if not m:
            continue
        _date, hh, mm, ss, usec, module, level, msg = m.groups()
        abs_s = int(hh) * 3600 + int(mm) * 60 + int(ss)
        delta = None if last_abs is None else abs_s - last_abs
        last_abs = abs_s
        parsed.append({"idx": idx, "h": int(hh), "m": int(mm), "s": int(ss), "usec": int((usec or "0")[:6] or 0), "abs": abs_s, "delta": delta, "module": module, "level": level.upper(), "msg": msg.strip(), "line": line})
    if len(parsed) < 12:
        return []
    arts: list[dict] = []

    def add(method: str, val: str, note: str, score: int = 900) -> None:
        if not val:
            return
        if len(rows) < 1200:
            rows.append({"method": method, "score": score, "preview": val[:900], "note": note})
        if len(arts) < 90 and _interesting(val, 115):
            art = _emit_text(report, root, f"final_time_{core.safe_name(method)}.txt", val, "final_time_log_channel", note, score, "final_time")
            if art:
                arts.append(art)

    subsets = {
        "all": parsed,
        "backwards": [r for r in parsed if r.get("delta") is not None and int(r["delta"]) < 0],
        "forward_jumps": [r for r in parsed if r.get("delta") is not None and int(r["delta"]) > 1],
        "non_core": [r for r in parsed if str(r["module"]).upper() != "CORE"],
        "warn": [r for r in parsed if r["level"] == "WARN"],
        "debug": [r for r in parsed if r["level"] == "DEBUG"],
        "info": [r for r in parsed if r["level"] == "INFO"],
        "time_messages": [r for r in parsed if "time" in str(r["msg"]).lower() or "delay" in str(r["msg"]).lower() or "drift" in str(r["msg"]).lower()],
    }
    for name, sub in subsets.items():
        if len(sub) < 4:
            continue
        add(f"{name}_module_sequence", "".join(str(r["module"])[0] for r in sub if r.get("module")), f"First letters of modules for {name} log rows.", 760)
        add(f"{name}_level_sequence", "".join(str(r["level"])[0] for r in sub if r.get("level")), f"First letters of levels for {name} log rows.", 740)
        add(f"{name}_message_sequence", "".join(str(r["msg"] or " ")[:1] for r in sub), f"First letters of messages for {name} log rows.", 740)
        for field, vals in {
            "idx": [r["idx"] for r in sub],
            "idx1": [r["idx"] + 1 for r in sub],
            "seconds": [r["s"] for r in sub],
            "minute_second": [r["m"] * 60 + r["s"] for r in sub],
            "absolute_seconds": [r["abs"] for r in sub],
            "delta": [int(r["delta"] or 0) for r in sub],
        }.items():
            for meth, val in _decode_number_sequence(vals).items():
                add(f"{name}_{field}_{meth}", val, f"Numeric log channel {field}/{meth} for {name} rows.", 820)
        for field in ("module", "level", "msg"):
            seq = [str(r[field]).split()[0] if field == "msg" else str(r[field]) for r in sub]
            for meth, val in _decode_symbol_sequence(seq).items():
                add(f"{name}_{field}_{meth}", val, f"Symbol log channel {field}/{meth} for {name} rows.", 800)
    rows.append({"parsed_rows": len(parsed), "subsets": {k: len(v) for k, v in subsets.items()}, "note": "Time log workflow preserves timestamp/module/level/message channels even when no final flag is automatic."})
    art = core.artifact(root, report, "final_time_log_workflow.json", json.dumps(rows[:700], indent=2, ensure_ascii=False), "final_time_log_manifest", "Final time/log workflow manifest with sequence channels and previews.", 890, "final_time")
    if art:
        arts.append(art)
    return [a for a in arts if a]


def _natural_key(name: str) -> list[Any]:
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", name)]


def final_archive_workflow_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Archive metadata/order channels plus explicit comments as first-class artifacts."""
    raw = bytes(data or b"")
    if not raw or len(raw) > 140_000_000:
        return []
    arts: list[dict] = []
    rows: list[dict[str, Any]] = []

    def emit_channel(method: str, text: str, note: str, score: int = 840) -> None:
        if not text:
            return
        rows.append({"method": method, "score": score, "preview": text[:900], "note": note})
        if _interesting(text, 95):
            art = _emit_text(report, root, f"{method}.txt", text, "final_archive_channel", note, score, "final_archive")
            if art:
                arts.append(art)

    def name_channels(names: list[str], sizes: list[int], mtimes: list[int], modes: list[int], prefix: str) -> None:
        if not names:
            return
        ordered = sorted(names, key=_natural_key)
        stems = [Path(n).stem for n in ordered]
        bases = [Path(n).name for n in ordered]
        emit_channel(prefix + "_names_joined", "\n".join(ordered), "Archive member names joined for review.", 680)
        emit_channel(prefix + "_stems_concat", "".join(stems), "Archive member stems concatenated in natural order.", 820)
        emit_channel(prefix + "_first_chars", "".join((Path(n).name or " ")[0] for n in ordered if Path(n).name), "First char of each member name in natural order.", 820)
        emit_channel(prefix + "_last_chars", "".join((Path(n).stem or " ")[-1] for n in ordered if Path(n).stem), "Last char of each member stem in natural order.", 800)
        for label, vals in [("size_low", sizes), ("mtime_low", mtimes), ("mode_low", modes)]:
            if len(vals) >= 4:
                raw_seq = bytes(v & 255 for v in vals[:5000])
                emit_channel(prefix + "_" + label, _txt(raw_seq), f"Archive {label.replace('_', ' ')} byte channel.", 820)
        # Filename metadata can be real in CTFs, but keep it visible as evidence rather than silent noise.
        for n in bases[:300]:
            v100.preserve_unconfirmed_strict(report, n, "CTF SLOPER final archive filename metadata", None, "Filename/member-name evidence preserved for human review.", 700)

    try:
        if zipfile.is_zipfile(io.BytesIO(raw)) or raw.startswith(b"PK\x03\x04") or b"PK\x03\x04" in raw[:4096]:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                infos = zf.infolist()
                names = [i.filename for i in infos]
                sizes = [int(i.file_size or 0) for i in infos]
                mtimes = []
                modes = []
                for i in infos:
                    try:
                        y, mo, d, hh, mm, ss = i.date_time
                        mtimes.append((ss + mm * 60 + hh * 3600 + d + mo + y) & 255)
                    except Exception:
                        mtimes.append(0)
                    modes.append((int(i.external_attr or 0) >> 16) & 255)
                rows.append({"archive": "zip", "members": len(infos), "has_archive_comment": bool(zf.comment)})
                if zf.comment:
                    ctext = "\n".join(_iter_url_layers(zf.comment.decode("utf-8", "replace"), 8))
                    emit_channel("zip_archive_comment_decoded", ctext, "ZIP archive comment decoded through iterative URL layers.", 940)
                for idx, info in enumerate(infos[:700]):
                    if info.comment:
                        ctext = "\n".join(_iter_url_layers(info.comment.decode("utf-8", "replace"), 8))
                        emit_channel(f"zip_member_comment_{idx:03d}", ctext, f"ZIP per-file comment decoded for {info.filename}.", 910)
                name_channels(names, sizes, mtimes, modes, "zip")
    except Exception as e:
        rows.append({"zip_error": repr(e)})
        agent_crash("final archive zip workflow", e, report)

    try:
        fileobj = io.BytesIO(raw)
        with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
            members = tf.getmembers()[:800]
            rows.append({"archive": "tar", "members": len(members)})
            name_channels([m.name for m in members], [int(m.size or 0) for m in members], [int(m.mtime or 0) for m in members], [int(m.mode or 0) for m in members], "tar")
    except Exception:
        pass

    sigs = {
        "zip": b"PK\x03\x04",
        "gzip": b"\x1f\x8b\x08",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
        "pdf": b"%PDF",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff",
        "sqlite": b"SQLite format 3\x00",
        "elf": b"\x7fELF",
        "pe": b"MZ",
        "rar": b"Rar!\x1a\x07",
        "7z": b"7z\xbc\xaf\x27\x1c",
    }
    magic_hits = []
    for name, sig in sigs.items():
        start = 0
        while True:
            idx = raw.find(sig, start)
            if idx < 0 or len(magic_hits) >= 160:
                break
            magic_hits.append({"kind": name, "offset": idx})
            start = idx + 1
    if magic_hits:
        rows.append({"embedded_magic_offsets": magic_hits[:160]})
    if rows:
        art = core.artifact(root, report, "final_archive_workflow_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "final_archive_workflow_manifest", "Final archive workflow: comments, filename/order channels, byte channels and embedded magic offsets.", 840, "final_archive")
        if art:
            arts.append(art)
    return [a for a in arts if a]


def final_recursive_onion_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Bounded ZIP/base64/compression onion peeler for deep archive-chain CTFs."""
    raw = bytes(data or b"")
    if not raw or len(raw) > 80_000_000:
        return []
    if not (raw.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"x\x9c", b"x\xda")) or zipfile.is_zipfile(io.BytesIO(raw))):
        return []
    arts: list[dict] = []
    steps: list[dict[str, Any]] = []
    cur = raw
    started = time.time()
    last_signal = ""
    max_steps = 360
    max_seconds = 18.0
    for depth in range(max_steps):
        preview = _bytes_preview(cur, 5000)
        if _interesting(preview, 90):
            last_signal = preview[:4000]
            if len(arts) < 32 and (depth < 3 or depth % 25 == 0 or core.STRICT_RE.search(preview) or BRACE_RE.search(preview) or _signal(preview) > 260):
                art = _emit_text(report, root, f"final_onion_signal_depth_{depth:03d}.txt", preview, "final_onion_signal", f"Readable or semantic payload at onion depth {depth}.", 980, "final_onion")
                if art:
                    arts.append(art)
        nxt = _next_onion_payload(cur)
        if not nxt:
            steps.append({"depth": depth, "action": "stop", "size": len(cur), "rank": _payload_rank(cur), "preview": preview[:700]})
            break
        action, child, meta = nxt
        steps.append({"depth": depth, "action": action, "input_size": len(cur), "output_size": len(child), **(meta or {})})
        cur = child
        if len(cur) > 100_000_000 or time.time() - started > max_seconds:
            steps.append({"depth": depth + 1, "action": "budget_stop", "size": len(cur), "elapsed": round(time.time() - started, 3)})
            break
    else:
        steps.append({"depth": max_steps, "action": "max_depth_stop", "size": len(cur)})

    if len(steps) >= 2:
        manifest = {
            "steps": steps,
            "final_size": len(cur),
            "elapsed": round(time.time() - started, 3),
            "note": "Recursive onion workflow follows ZIP members, compressed payloads, base64, reversed-line base64 and byte-reversal layers. Last payload is saved for manual review.",
        }
        art = core.artifact(root, report, "final_recursive_onion_manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False), "final_recursive_onion_manifest", "Deep archive/onion chain manifest with each transform step.", 1040, "final_onion")
        if art:
            arts.append(art)
        suffix = ".bin"
        if cur.startswith(b"PK\x03\x04"):
            suffix = ".zip"
        elif cur.startswith(b"\x89PNG"):
            suffix = ".png"
        elif cur.startswith(b"\xff\xd8\xff"):
            suffix = ".jpg"
        elif cur.startswith(b"%PDF"):
            suffix = ".pdf"
        elif cur.startswith(b"SQLite format 3\x00"):
            suffix = ".sqlite"
        payload_art = core.artifact(root, report, "final_recursive_onion_last_payload" + suffix, cur[:25_000_000], "final_recursive_onion_payload", "Last payload reached by the bounded onion workflow. Open/download this if no flag was auto-promoted.", 1030, "final_onion")
        if payload_art:
            arts.append(payload_art)
        final_preview = _bytes_preview(cur, 20000)
        if final_preview and final_preview != last_signal:
            art = _emit_text(report, root, "final_recursive_onion_last_preview.txt", final_preview, "final_recursive_onion_preview", "Readable strings/preview from the last onion payload.", 1000, "final_onion")
            if art:
                arts.append(art)
    return [a for a in arts if a]


def _ipv4(pkt: bytes) -> int | None:
    tries = []
    if len(pkt) >= 14 and pkt[12:14] == b"\x08\x00":
        tries.append(14)
    tries.extend([0, 4, 14, 16, 20])
    seen = set()
    for off in tries:
        if off in seen or len(pkt) < off + 20:
            continue
        seen.add(off)
        first = pkt[off]
        ihl = (first & 15) * 4
        if (first >> 4) == 4 and ihl >= 20 and len(pkt) >= off + ihl:
            total = struct.unpack_from("!H", pkt, off + 2)[0]
            if ihl <= total <= len(pkt) - off + 32:
                return off
    return None


def _dns_names(payload: bytes) -> list[str]:
    out: list[str] = []
    if len(payload) < 12:
        return out
    try:
        qd = struct.unpack_from("!H", payload, 4)[0]
        an = struct.unpack_from("!H", payload, 6)[0]
    except Exception:
        return out

    def read_name(pos: int, depth: int = 0) -> tuple[str, int]:
        labels: list[str] = []
        start = pos
        jumped = False
        while pos < len(payload) and depth < 8:
            ln = payload[pos]
            if ln == 0:
                pos += 1
                break
            if ln & 0xC0 == 0xC0 and pos + 1 < len(payload):
                ptr = ((ln & 0x3F) << 8) | payload[pos + 1]
                sub, _ = read_name(ptr, depth + 1)
                if sub:
                    labels.append(sub)
                pos += 2
                jumped = True
                break
            if ln > 63 or pos + 1 + ln > len(payload):
                break
            lab = payload[pos + 1:pos + 1 + ln].decode("latin1", "ignore")
            if lab:
                labels.append(lab)
            pos += 1 + ln
        return ".".join(labels), (pos if not jumped else start + 2)

    pos = 12
    for _ in range(min(qd, 80)):
        name, pos = read_name(pos)
        if name:
            out.append(name)
        pos += 4
        if pos >= len(payload):
            break
    for _ in range(min(an, 120)):
        name, pos = read_name(pos)
        if name:
            out.append(name)
        if pos + 10 > len(payload):
            break
        typ, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", payload, pos)
        pos += 10
        rdata = payload[pos:pos + rdlen]
        pos += rdlen
        if typ == 16 and rdata:
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                txt = rdata[i:i + ln].decode("latin1", "ignore")
                i += ln
                if txt:
                    out.append(txt)
    return out[:500]


def final_pcap_workflow_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 35_000_000 or data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return []
    arts: list[dict] = []
    dns_labels: list[str] = []
    http_chunks: list[str] = []
    payload_strings: list[str] = []
    ipids: list[int] = []
    rows: list[dict[str, Any]] = []
    try:
        packets = list(core.pcap_packets(data))[:12000]
    except Exception:
        packets = []
    for pkt in packets:
        eth = _ipv4(pkt)
        if eth is None:
            continue
        ihl = (pkt[eth] & 15) * 4
        proto = pkt[eth + 9]
        ipid = struct.unpack_from("!H", pkt, eth + 4)[0]
        ipids.append(ipid)
        p0 = eth + ihl
        payload = b""
        sport = dport = 0
        if proto == 17 and len(pkt) >= p0 + 8:
            sport, dport, ulen, _chk = struct.unpack_from("!HHHH", pkt, p0)
            payload = pkt[p0 + 8:p0 + max(8, min(ulen, len(pkt) - p0))]
            if sport == 53 or dport == 53:
                dns_labels.extend(_dns_names(payload))
        elif proto == 6 and len(pkt) >= p0 + 20:
            sport, dport = struct.unpack_from("!HH", pkt, p0)
            doff = (pkt[p0 + 12] >> 4) * 4
            if doff >= 20:
                payload = pkt[p0 + doff:]
        elif proto == 1 and len(pkt) >= p0 + 8:
            payload = pkt[p0 + 8:]
        if payload:
            s = payload.decode("latin1", "ignore")
            for m in re.finditer(r"[ -~]{5,1000}", s):
                chunk = m.group(0)
                if _interesting(chunk, 80) or re.search(r"GET |POST |HTTP/|Host:|Cookie:|token=|data=|q=", chunk, re.I):
                    payload_strings.append(chunk)
            if re.search(rb"HTTP/|GET |POST |Host:", payload, re.I):
                http_chunks.append(s[:4000])
                body = payload.split(b"\r\n\r\n", 1)[-1]
                if body.startswith(b"\x1f\x8b"):
                    try:
                        http_chunks.append(gzip.decompress(body).decode("utf-8", "ignore"))
                    except Exception:
                        pass
                elif body.startswith((b"\x78\x9c", b"\x78\xda", b"\x78\x01")):
                    try:
                        http_chunks.append(zlib.decompress(body).decode("utf-8", "ignore"))
                    except Exception:
                        pass
        if len(rows) < 500:
            rows.append({"ipid": ipid, "proto": proto, "sport": sport, "dport": dport, "payload": len(payload)})

    if dns_labels:
        labels_text = "\n".join(dict.fromkeys(dns_labels))
        joined = "".join(label.split(".")[0] for label in dns_labels if label)
        art = _emit_text(report, root, "final_pcap_dns_labels.txt", labels_text + "\n\nJOINED_FIRST_LABELS:\n" + joined, "final_pcap_dns_labels", "DNS labels/TXT records extracted and joined for covert channels.", 900, "final_pcap")
        if art:
            arts.append(art)
    if http_chunks or payload_strings:
        text = "\n\n---HTTP---\n".join(http_chunks[:120]) + "\n\n---PAYLOAD STRINGS---\n" + "\n".join(payload_strings[:700])
        art = _emit_text(report, root, "final_pcap_http_payloads.txt", text, "final_pcap_payloads", "HTTP/payload printable chunks, including decoded compressed HTTP bodies where possible.", 900, "final_pcap")
        if art:
            arts.append(art)
    if len(ipids) >= 4:
        variants: dict[str, str] = {}
        seqs = {
            "ipid_low": [x & 255 for x in ipids],
            "ipid_high": [(x >> 8) & 255 for x in ipids],
            "ipid_be": [b for x in ipids for b in ((x >> 8) & 255, x & 255)],
            "ipid_le": [b for x in ipids for b in (x & 255, (x >> 8) & 255)],
        }
        for name, vals in seqs.items():
            text = bytes(vals[:20000]).decode("utf-8", "ignore")
            variants[name] = text[:2000]
            if _interesting(text, 90):
                art = _emit_text(report, root, f"final_pcap_{name}.txt", text, "final_pcap_ipid_channel", f"IP ID covert byte channel {name}.", 910, "final_pcap")
                if art:
                    arts.append(art)
            try:
                for bname, btxt in core.decode_bit_channels(vals, limit=20).items():
                    variants[name + "_" + bname] = btxt[:2000]
                    if _interesting(btxt, 90):
                        art = _emit_text(report, root, f"final_pcap_{name}_{core.safe_name(bname)}.txt", btxt, "final_pcap_ipid_bit_channel", f"IP ID bit-channel variant {name}/{bname}.", 930, "final_pcap")
                        if art:
                            arts.append(art)
            except Exception:
                pass
        manifest = {"packets": len(packets), "rows": rows[:500], "ipid_variants": variants, "dns_count": len(dns_labels), "http_chunks": len(http_chunks), "payload_strings": len(payload_strings)}
        art = core.artifact(root, report, "final_pcap_workflow.json", json.dumps(manifest, indent=2, ensure_ascii=False), "final_pcap_workflow_manifest", "Final PCAP workflow: DNS/HTTP/payload/IPID channels for human review.", 850, "final_pcap")
        if art:
            arts.append(art)
    return [a for a in arts if a]


def final_document_db_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Pure-Python document/database fallback for PDF and SQLite artifacts."""
    raw = bytes(data or b"")
    if not raw or len(raw) > 80_000_000:
        return []
    path = Path(str(report.get("path", "")))
    ext = path.suffix.lower()
    arts: list[dict] = []

    if raw.startswith(b"%PDF") or ext == ".pdf":
        chunks: list[str] = []
        head = raw[:4_000_000].decode("latin1", "ignore")
        for m in re.finditer(r"\(([^()\r\n]{4,500})\)", head):
            chunks.append(m.group(1).encode("latin1", "ignore").decode("unicode_escape", "ignore"))
            if len(chunks) >= 1200:
                break
        for m in re.finditer(r"<([0-9A-Fa-f\s]{8,2000})>", head):
            try:
                b = bytes.fromhex(re.sub(r"\s+", "", m.group(1)))
                t = b.decode("utf-8", "ignore")
                if _interesting(t, 60):
                    chunks.append(t)
            except Exception:
                pass
            if len(chunks) >= 1400:
                break
        for sm in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw[:12_000_000], re.S):
            blob = sm.group(1).strip(b"\r\n")
            for fn in (zlib.decompress,):
                try:
                    t = fn(blob).decode("utf-8", "ignore")
                    if _interesting(t, 55):
                        chunks.append(t[:5000])
                except Exception:
                    pass
            if len(chunks) >= 1500:
                break
        if chunks:
            art = _emit_text(report, root, "final_pdf_text_extract.txt", "\n".join(chunks), "final_pdf_text_extract", "Pure-Python PDF text/hex/deflate stream extraction for manual review.", 880, "final_document")
            if art:
                arts.append(art)
        manifest = {"size": len(raw), "objects": len(re.findall(rb"\bobj\b", raw[:12_000_000])), "streams": len(re.findall(rb"\bstream\b", raw[:12_000_000])), "note": "If no flag appears, inspect final_pdf_text_extract and use pdfinfo/pdftotext/qpdf from Tools."}
        art = core.artifact(root, report, "final_pdf_manifest.json", json.dumps(manifest, indent=2), "final_pdf_manifest", "PDF object/stream summary for workflow routing.", 720, "final_document")
        if art:
            arts.append(art)

    if raw.startswith(b"SQLite format 3\x00") or ext in {".sqlite", ".db", ".sqlite3"}:
        rows: list[dict[str, Any]] = []
        text_dump: list[str] = []
        try:
            import sqlite3
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            tables = [r["name"] for r in conn.execute("select name from sqlite_master where type='table' order by name").fetchall()]
            rows.append({"tables": tables})
            for table in tables[:60]:
                if table.startswith("sqlite_"):
                    continue
                try:
                    schema = conn.execute("select sql from sqlite_master where type='table' and name=?", (table,)).fetchone()
                    if schema and schema[0]:
                        text_dump.append(f"-- schema {table}\n{schema[0]}")
                    cols = [r["name"] for r in conn.execute(f"pragma table_info({json.dumps(table)})").fetchall()]
                    for rr in conn.execute(f"select * from {json.dumps(table)} limit 250").fetchall():
                        vals = []
                        for c in rr.keys():
                            v = rr[c]
                            if isinstance(v, bytes):
                                vals.append(v.decode("utf-8", "ignore"))
                            else:
                                vals.append(str(v))
                        text_dump.append(f"{table}: " + " | ".join(vals))
                except Exception as e:
                    rows.append({"table": table, "error": repr(e)})
            conn.close()
        except Exception as e:
            rows.append({"sqlite_error": repr(e)})
            # Fallback: printable strings still often recover deleted/hidden rows.
            text_dump.extend(re.findall(r"[ -~]{5,400}", raw[:10_000_000].decode("latin1", "ignore")))
        if text_dump:
            art = _emit_text(report, root, "final_sqlite_dump.txt", "\n".join(text_dump[:5000]), "final_sqlite_dump", "SQLite schema/table/text fallback dump.", 900, "final_database")
            if art:
                arts.append(art)
        art = core.artifact(root, report, "final_sqlite_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "final_sqlite_manifest", "SQLite fallback manifest with table/schema errors if any.", 760, "final_database")
        if art:
            arts.append(art)
    return [a for a in arts if a]


def final_image_color_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Lightweight visual/color-order channels for image stego tasks."""
    raw = bytes(data or b"")
    if not raw or len(raw) > 45_000_000 or not raw.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")):
        return []
    try:
        from PIL import Image, ImageOps, ImageEnhance, ImageChops  # type: ignore
    except Exception as e:
        agent_crash("final image color import", e, report)
        return []
    arts: list[dict] = []
    rows: list[dict[str, Any]] = []
    try:
        img = Image.open(io.BytesIO(raw))
        img.load()
        rgba = img.convert("RGBA")
        w, h = rgba.size
        max_pixels = 520000
        step = max(1, int(((w * h) / max_pixels) ** 0.5))
        pixels: list[tuple[int, int, int, int, int, int]] = []
        for y in range(0, h, step):
            for x in range(0, w, step):
                r, g, b, a = rgba.getpixel((x, y))
                pixels.append((x, y, r, g, b, a))
                if len(pixels) >= max_pixels:
                    break
            if len(pixels) >= max_pixels:
                break
        rows.append({"size": [w, h], "sample_step": step, "sampled_pixels": len(pixels), "mode": img.mode})

        def emit_bytes(method: str, vals: list[int], note: str, score: int = 870) -> None:
            if len(vals) < 4:
                return
            blob = bytes(v & 255 for v in vals[:500000])
            text = blob.decode("utf-8", "ignore")
            rows.append({"method": method, "score": score, "preview": text[:900], "bytes": len(blob), "note": note})
            if _interesting(text, 70):
                art = _emit_text(report, root, f"final_image_{core.safe_name(method)}.txt", text, "final_image_color_channel", note, score, "final_image")
                if art:
                    arts.append(art)
            try:
                for bname, btxt in core.decode_bit_channels(list(blob[:160000]), limit=14).items():
                    if _interesting(btxt, 80):
                        art = _emit_text(report, root, f"final_image_{core.safe_name(method)}_{core.safe_name(bname)}.txt", btxt, "final_image_bit_channel", f"{note} Bit-channel variant {bname}.", score + 40, "final_image")
                        if art:
                            arts.append(art)
            except Exception:
                pass

        # Raw sampled channel streams.
        emit_bytes("row_rgb_sampled", [c for _x, _y, r, g, b, _a in pixels for c in (r, g, b)], "Sampled row-major RGB bytes.")
        emit_bytes("row_bgr_sampled", [c for _x, _y, r, g, b, _a in pixels for c in (b, g, r)], "Sampled row-major BGR bytes.")
        emit_bytes("alpha_sampled", [a for _x, _y, _r, _g, _b, a in pixels], "Sampled alpha-channel bytes.")
        transparent = [(x, y, r, g, b, a) for x, y, r, g, b, a in pixels if a < 255]
        if transparent:
            emit_bytes("transparent_rgb_sampled", [c for _x, _y, r, g, b, _a in transparent for c in (r, g, b)], "RGB bytes from transparent/semi-transparent sampled pixels.", 920)
        non_transparent = [(x, y, r, g, b, a) for x, y, r, g, b, a in pixels if a >= 255]
        if non_transparent and len(non_transparent) != len(pixels):
            emit_bytes("opaque_rgb_sampled", [c for _x, _y, r, g, b, _a in non_transparent for c in (r, g, b)], "RGB bytes from opaque sampled pixels.", 880)

        # Hue/brightness order is common in color-strip and rainbow puzzles.
        def hue_key(px: tuple[int, int, int, int, int, int]) -> tuple[int, int, int, int, int]:
            x, y, r, g, b, a = px
            mx, mn = max(r, g, b), min(r, g, b)
            if mx == mn:
                hue = 0
            elif mx == r:
                hue = (60 * (g - b) // max(1, mx - mn)) % 360
            elif mx == g:
                hue = 120 + (60 * (b - r) // max(1, mx - mn))
            else:
                hue = 240 + (60 * (r - g) // max(1, mx - mn))
            sat = mx - mn
            return (hue, -sat, mx, y, x)

        unique: dict[tuple[int, int, int, int], tuple[int, int, int, int, int, int]] = {}
        for px in pixels:
            unique.setdefault(px[2:6], px)
            if len(unique) >= 120000:
                break
        color_pixels = list(unique.values()) if len(unique) >= 8 else pixels[:120000]
        for label, ordered in [
            ("hue_sorted_rgb", sorted(color_pixels, key=hue_key)),
            ("brightness_sorted_rgb", sorted(color_pixels, key=lambda p: (p[2] + p[3] + p[4], p[1], p[0]))),
            ("coordinate_diagonal_rgb", sorted(pixels[:120000], key=lambda p: (p[0] + p[1], p[1], p[0]))),
            ("coordinate_column_rgb", sorted(pixels[:120000], key=lambda p: (p[0], p[1]))),
        ]:
            emit_bytes(label, [c for _x, _y, r, g, b, _a in ordered for c in (r, g, b)], f"Image color channel ordered by {label.replace('_', ' ')}.", 910)

        # Save a compact visual review sheet that humans can inspect first.
        try:
            thumb = rgba.copy()
            thumb.thumbnail((520, 520))
            panels = [thumb.convert("RGB")]
            panels.append(ImageOps.invert(thumb.convert("RGB")))
            panels.append(ImageEnhance.Contrast(thumb.convert("RGB")).enhance(2.8))
            gray = ImageOps.grayscale(thumb)
            panels.append(gray.convert("RGB"))
            sheet = Image.new("RGB", (thumb.width * len(panels), thumb.height), (16, 22, 18))
            for i, panel in enumerate(panels):
                sheet.paste(panel.resize(thumb.size), (i * thumb.width, 0))
            buf = io.BytesIO()
            sheet.save(buf, format="PNG")
            art = core.artifact(root, report, "final_image_visual_review_sheet.png", buf.getvalue(), "final_image_visual_review", "Visual review sheet: original, invert, contrast and grayscale. Put this near Open First for human solving.", 1080, "final_image")
            if art:
                arts.append(art)
        except Exception:
            pass
    except Exception as e:
        agent_crash("final image color workflow", e, report)
        rows.append({"error": repr(e)})
    if rows:
        art = core.artifact(root, report, "final_image_color_workflow.json", json.dumps(rows[:500], indent=2, ensure_ascii=False), "final_image_color_manifest", "Final image workflow: color-order streams, alpha/transparent channels and visual review sheet.", 900, "final_image")
        if art:
            arts.append(art)
    return [a for a in arts if a]


def _printable_ratio_bytes(data: bytes, limit: int = 500000) -> float:
    sample = bytes(data[:limit])
    if not sample:
        return 0.0
    good = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    return good / max(1, len(sample))


def final_safe_archive_child_agent(old_agent: Any):
    def wrapped(report: dict, root: Path, data: bytes) -> list[dict]:
        raw = bytes(data or b"")
        if not raw:
            return []
        # Legacy v100 can spend minutes running recursive decode graphs over
        # gzip-wrapped raw disk images. Keep the useful child evidence, but do
        # not feed low-printable binary dumps into broad text decoders.
        is_compressed = raw.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"))
        if is_compressed:
            children = _try_decompress(raw)
            if children:
                arts: list[dict] = []
                rows: list[dict[str, Any]] = []
                for cname, child in children[:3]:
                    ratio = _printable_ratio_bytes(child)
                    strings = "\n".join(core.printable_strings(child[:2_000_000], 5, 900))
                    rows.append({"child": cname, "size": len(child), "printable_ratio": round(ratio, 4), "strings_preview": strings[:1200]})
                    if strings:
                        art = _emit_text(report, root, f"final_safe_{cname}_child_strings.txt", strings, "final_safe_archive_child_strings", "Safe strings from decompressed archive child; broad decode graph skipped for binary/disk-like payload.", 905, "final_archive")
                        if art:
                            arts.append(art)
                    if child.find(b"PK\x03\x04") >= 0 or child.find(b"word/document.xml") >= 0 or child.find(b"[Content_Types].xml") >= 0:
                        hits = []
                        for sig in (b"PK\x03\x04", b"word/document.xml", b"docProps/", b"[Content_Types].xml", b"%PDF", b"SQLite format 3\x00"):
                            off = child.find(sig)
                            if off >= 0:
                                hits.append({"signature": sig.decode("latin1", "ignore"), "offset": off})
                        rows[-1]["embedded_hits"] = hits
                    # If it is actually readable text, the old agent remains useful.
                    if ratio > 0.72 and len(child) <= 1_200_000 and callable(old_agent):
                        try:
                            arts.extend(old_agent(report, root, raw) or [])
                        except Exception as e:
                            agent_crash("final safe archive old_agent text child", e, report)
                        break
                art = core.artifact(root, report, "final_safe_archive_child_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "final_safe_archive_child_manifest", "Safe archive-child manifest. Binary disk-like children do not enter broad recursive decode graphs.", 930, "final_archive")
                if art:
                    arts.append(art)
                return [a for a in arts if a]
        if callable(old_agent):
            return old_agent(report, root, data) or []
        return []
    return wrapped


def final_binary_quick_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Bounded binary/reversing route for ELF/PE/opaque binaries.

    The legacy universal route is still valuable for text and containers, but
    broad recursive decoders can spend a very long time on ordinary ELF bytes.
    This route keeps the CTF-relevant reversing evidence: strings, imports,
    static bytes, stack arrays and transform candidates.
    """
    arts: list[dict] = []
    try:
        core.ensure(report)
        safe_calls: list[tuple[str, Any, int]] = [
            ("final_bin_context", getattr(core, "v96_context_agent", None), 4),
            ("final_bin_static_strings", getattr(core, "v95_static_strings_agent", None), 4),
            ("final_bin_static", getattr(core, "v96_binary_static_reasoning_agent", None), 5),
        ]
        if getattr(core, "v74", None):
            safe_calls.extend([
                ("final_bin_array_transform", getattr(core.v74, "array_transform_agent", None), 6),
                ("final_bin_elf_stack_array", getattr(core.v74, "binary_elf_stack_array_agent", None), 7),
                ("final_bin_strings", getattr(core.v74, "strings_agent", None), 4),
            ])
        for name, fn, budget in safe_calls:
            if callable(fn):
                core.call_agent(report, root, data, name, fn, arts, budget)
        # Short semantic preview for humans even when no transform solves it.
        strings = re.findall(rb"[\x20-\x7e]{4,}", data[:3_000_000])
        interesting = []
        for s in strings[:6000]:
            t = s.decode("latin1", "ignore")
            if SEMANTIC_RE.search(t) or core.STRICT_RE.search(t) or BRACE_RE.search(t):
                interesting.append(t)
                if len(interesting) >= 300:
                    break
        if interesting:
            art = _emit_text(report, root, "final_binary_semantic_strings.txt", "\n".join(interesting), "final_binary_semantic_strings", "Bounded semantic strings from binary for manual reversing review.", 850, "final_reversing")
            if art:
                arts.append(art)
    except Exception as e:
        agent_crash("final binary quick", e, report)
    return [a for a in arts if a]


def _project_root(reports: list[dict]) -> Path | None:
    for r in reports or []:
        try:
            p = Path(str(r.get("path") or ""))
            parts = list(p.parts)
            if "files" in parts:
                idx = len(parts) - 1 - parts[::-1].index("files")
                return Path(*parts[:idx])
        except Exception:
            continue
    return None


def _artifact_dict(root: Path, rel_name: str, content: str | bytes, kind: str, note: str, score: int) -> dict | None:
    try:
        outdir = root / "generated" / "sloper_final" / "project"
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / core.safe_name(rel_name)
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(bytes(content))
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
        return {"kind": kind, "name": p.name, "path": str(p), "url": "/api/raw?path=" + str(p), "source": "CTF SLOPER final", "score": score, "note": note, "exists": True, "size": p.stat().st_size, "file": "project"}
    except Exception:
        return None


def final_project_multifile(summary: dict, reports: list[dict], meta: dict) -> None:
    root = _project_root(reports)
    files: list[tuple[str, Path, bytes]] = []
    for r in reports or []:
        try:
            p = Path(str(r.get("path") or ""))
            if p.exists() and p.is_file() and p.stat().st_size <= 2_000_000:
                files.append((str(r.get("name") or p.name), p, p.read_bytes()))
        except Exception:
            continue
    if not root or not (2 <= len(files) <= 160):
        return
    rows: list[dict[str, Any]] = []
    found: list[dict[str, Any]] = []
    seen_flags = {str(x.get("flag") if isinstance(x, dict) else x) for x in summary.get("flags", []) or []}

    def record(label: str, blob: bytes, score: int) -> None:
        text = _txt(blob[:1_000_000])
        row = {"method": label, "size": len(blob), "signal": _signal(text), "preview": text[:500]}
        rows.append(row)
        if not _interesting(text, 90):
            return
        art = _artifact_dict(root, "final_project_" + core.safe_name(label) + ".txt", text[:1_000_000], "final_project_multifile", "Project-level multi-file transform output.", score)
        if art:
            summary.setdefault("artifacts", []).append(art)
        for m in core.STRICT_RE.finditer(text):
            flag = m.group(0)
            if flag not in seen_flags:
                item = {"flag": flag, "file": "project", "score": score + 120, "why": "Final project-level multi-file workflow reconstructed a strict flag.", "source": label, "artifact": art.get("path") if art else ""}
                summary.setdefault("flags", []).append(item)
                found.append(item)
                seen_flags.add(flag)
        for m in BRACE_RE.finditer(text):
            body = m.group(1)
            cand = {"value": "{" + body + "}", "body": body, "score": score, "bucket": "final_project_multifile", "why_not_promoted": "Bare-brace project-level evidence kept for human review.", "artifact": art.get("path") if art else "", "wrapped_if_required": f"ctf_cs{{{body.lower()}}}"}
            summary.setdefault("unconfirmed_evidence", []).append(cand)

    ordered = sorted(files, key=lambda x: _natural_key(x[0]))
    if 2 <= len(ordered) <= 160:
        record("concat_natural_sort", b"".join(b for _, _, b in ordered), 900)
        record("concat_reverse_natural_sort", b"".join(b for _, _, b in reversed(ordered)), 880)
        record("concat_by_mtime", b"".join(b for _, _, b in sorted(files, key=lambda x: x[1].stat().st_mtime)), 880)
        record("filenames_first_chars", "".join(n[0] for n, _, _ in ordered if n).encode(), 820)
        record("filenames_stems_concat", "".join(Path(n).stem for n, _, _ in ordered).encode(), 820)
        record("file_sizes_lowbytes", bytes(len(b) & 255 for _, _, b in ordered), 820)
    for i in range(min(len(files), 60)):
        for j in range(i + 1, min(len(files), 60)):
            n1, _, a = files[i]
            n2, _, b = files[j]
            if not a or not b:
                continue
            m = min(len(a), len(b))
            if m >= 4:
                record(f"pair_xor_{n1}_{n2}", bytes(x ^ y for x, y in zip(a[:m], b[:m])), 920)
            for first, second, label in ((a, b, "ab"), (b, a, "ba")):
                inter = bytearray()
                for k in range(max(len(first), len(second))):
                    if k < len(first):
                        inter.append(first[k])
                    if k < len(second):
                        inter.append(second[k])
                record(f"interleave_{label}_{n1}_{n2}", bytes(inter), 900)
            if len(rows) > 260:
                break
        if len(rows) > 260:
            break
    if rows:
        art = _artifact_dict(root, "final_project_multifile_manifest.json", json.dumps({"methods": rows[:320], "found": found[:40]}, indent=2, ensure_ascii=False), "final_project_multifile_manifest", "Manifest of final project-level concat/interleave/XOR/name/size channels.", 860)
        if art:
            summary.setdefault("artifacts", []).append(art)
    if found:
        summary.setdefault("workflow_evidence", []).extend(found)


def _statement_text(meta: dict, reports: list[dict]) -> str:
    parts: list[str] = []
    for key in ("statement", "description", "prompt", "readme", "notes", "challenge_text"):
        val = meta.get(key) if isinstance(meta, dict) else ""
        if val:
            parts.append(str(val)[:30000])
    for r in reports or []:
        try:
            p = Path(str(r.get("path") or ""))
            name = (str(r.get("name") or p.name)).lower()
            if not p.exists() or not p.is_file() or p.stat().st_size > 200_000:
                continue
            if any(t in name for t in ("readme", "statement", "task", "uzdu", "uždu", "apras", "apraš", "info", "hint")) or p.suffix.lower() in {".txt", ".md"}:
                parts.append(p.read_text(encoding="utf-8", errors="ignore")[:20000])
        except Exception:
            continue
    return "\n".join(parts)


def _wrap_allowed_from_statement(text: str) -> bool:
    low = text.lower()
    return any(t in low for t in ("ctf_cs", "ctf cs", "veliav", "vėliav", "flag format", "formatas", "wrapper", "apgaub"))


def _strong_token_body(body: str) -> bool:
    body = str(body or "").strip()
    low = body.lower()
    if not (5 <= len(body) <= 96):
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+\-:.]{4,95}", body):
        return False
    if low in {"example", "sample", "test", "flag", "placeholder", "answer_here", "vietos_pavadinimas", "rastas_tekstas"}:
        return False
    if v100._generated_body(body):
        return False
    has_letter = bool(re.search(r"[A-Za-z]", body))
    has_digit = bool(re.search(r"\d", body))
    has_shape = any(ch in body for ch in "_+-:.") or has_digit
    if not (has_letter and has_shape):
        return False
    if low.count("http") or low.startswith(("xml", "xmlns", "schema", "version", "encoding")):
        return False
    return True


def final_promote_artifact_body_candidates(summary: dict, reports: list[dict], meta: dict) -> None:
    """Promote high-signal extracted tokens when the statement says to wrap.

    This keeps the solver logical: an Office custom property, carved text file,
    decoded payload, SQLite row, PDF metadata field, etc. is meaningful evidence;
    a raw random strings dump is not enough by itself.
    """
    artifacts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
    if not artifacts:
        return
    statement = _statement_text(meta or {}, reports or [])
    wrap_allowed = _wrap_allowed_from_statement(statement)
    existing = {str(x.get("flag") if isinstance(x, dict) else x) for x in summary.get("flags", []) or []}
    unconfirmed_seen = {str(x.get("value") or x.get("flag") or x.get("candidate") or "") for x in summary.get("unconfirmed_evidence", []) or [] if isinstance(x, dict)}
    high_signal_terms = re.compile(
        r"final_|decode|decoded|decompress|extract|carve|office|docx|docprops|custom|xml|sqlite|pdf|"
        r"payload|comment|metadata|hidden|lsb|pcap|dns|http|archive|localzip|strings|transform|"
        r"array|stack|elf|pe|binary|reverse|reversing|xor|rol|ror",
        re.I,
    )
    skip_terms = re.compile(r"manifest|contact_sheet|visual_review|thumbnail|bitplane|histogram|entropy", re.I)
    token_added = 0
    flag_added = 0
    for art in sorted(artifacts, key=lambda a: int(a.get("score", 0) or 0), reverse=True)[:700]:
        try:
            blob = " ".join(str(art.get(k, "")) for k in ("name", "kind", "note", "source", "method", "path", "file"))
            if skip_terms.search(blob) and not core.STRICT_RE.search(blob):
                continue
            if not high_signal_terms.search(blob):
                continue
            p = Path(str(art.get("path") or ""))
            if not p.exists() or not p.is_file() or p.stat().st_size <= 0 or p.stat().st_size > 1_500_000:
                continue
            raw = p.read_bytes()[:350_000]
            text = _txt(raw)
            if not text.strip():
                continue
            score_base = max(740, min(980, int(art.get("score", 0) or 0) + 60))
            for m in core.STRICT_RE.finditer(text):
                flag = m.group(0)
                body = m.group(1)
                if body.lower() in {"example", "sample", "test", "flag", "placeholder", "answer_here", "vietos_pavadinimas", "rastas_tekstas"} or v100._generated_body(body):
                    continue
                if flag in existing:
                    continue
                item = {
                    "flag": flag,
                    "file": art.get("file") or art.get("source_file") or "",
                    "score": score_base + 120,
                    "why": "Strict flag appears inside a high-signal decoded/extracted artifact.",
                    "source": art.get("kind") or art.get("name") or "artifact_body",
                    "artifact": str(p),
                    "bucket": "confirmed",
                }
                summary.setdefault("flags", []).append(item)
                summary.setdefault("workflow_evidence", []).append(item)
                existing.add(flag)
                flag_added += 1
            for m in BRACE_RE.finditer(text):
                body = m.group(1)
                if not (wrap_allowed and _strong_token_body(body)):
                    continue
                wrapped = f"ctf_cs{{{body}}}"
                if wrapped in existing:
                    continue
                item = {
                    "flag": wrapped,
                    "file": art.get("file") or art.get("source_file") or "",
                    "score": score_base + 90,
                    "why": "Bare-brace answer body appears in a high-signal artifact, and task context indicates ctf_cs wrapper.",
                    "source": art.get("kind") or art.get("name") or "artifact_body",
                    "artifact": str(p),
                    "bucket": "likely_wrapped",
                }
                summary.setdefault("flags", []).append(item)
                summary.setdefault("workflow_evidence", []).append(item)
                existing.add(wrapped)
                flag_added += 1
            for m in re.finditer(r"(?<![A-Za-z0-9])([A-Za-z0-9][A-Za-z0-9_+\-:.]{4,95})(?![A-Za-z0-9])", text):
                body = m.group(1)
                if not _strong_token_body(body):
                    continue
                wrapped = f"ctf_cs{{{body}}}"
                if token_added < 120 and wrapped not in unconfirmed_seen:
                    ev = {
                        "value": body,
                        "wrapped_if_required": wrapped,
                        "bucket": "artifact_body_token",
                        "score": score_base,
                        "file": art.get("file") or art.get("source_file") or "",
                        "artifact": str(p),
                        "why_not_promoted": "Strong token found in a high-signal decoded/extracted artifact; kept for human review.",
                        "source": art.get("kind") or art.get("name") or "artifact_body",
                    }
                    summary.setdefault("unconfirmed_evidence", []).append(ev)
                    unconfirmed_seen.add(wrapped)
                    token_added += 1
                wrap_shape = ("_" in body or "+" in body or (body.count("-") == 0 and bool(re.search(r"[A-Za-z]\d|\d[A-Za-z]", body))))
                if wrap_allowed and wrap_shape and token_added < 120 and wrapped not in existing:
                    item = {
                        "flag": wrapped,
                        "file": art.get("file") or art.get("source_file") or "",
                        "score": score_base + 80,
                        "why": "Task context indicates ctf_cs wrapper, and the body was extracted from a high-signal artifact.",
                        "source": art.get("kind") or art.get("name") or "artifact_body",
                        "artifact": str(p),
                        "bucket": "likely_wrapped",
                    }
                    summary.setdefault("flags", []).append(item)
                    summary.setdefault("workflow_evidence", []).append(item)
                    existing.add(wrapped)
                    flag_added += 1
        except Exception as e:
            agent_crash("final artifact body promotion", e, None)


def final_enrich_summary(summary: dict, reports: list[dict], meta: dict) -> dict:
    final_project_multifile(summary, reports, meta or {})
    final_promote_artifact_body_candidates(summary, reports, meta or {})
    flags = summary.get("flags", []) or []
    artifacts = [a for a in summary.get("artifacts", []) or [] if isinstance(a, dict)]
    workflow = [e for e in summary.get("workflow_evidence", []) or [] if isinstance(e, dict)]
    unconfirmed = [e for e in summary.get("unconfirmed_evidence", []) or [] if isinstance(e, dict)]

    clean_flags: list[dict[str, Any]] = []
    seen_final: set[str] = set()
    for item in flags:
        raw = item.get("flag") if isinstance(item, dict) else str(item)
        blob = json.dumps(item, ensure_ascii=False)[:800] if isinstance(item, dict) else str(item)
        flag = core.normalize_flag(str(raw or ""), blob, allow_wrap=False)
        if not flag:
            continue
        body = core.STRICT_RE.fullmatch(flag).group(1)
        low = body.lower()
        if low in {"...", "example", "sample", "test", "flag", "placeholder", "answer_here", "vietos_pavadinimas", "rastas_tekstas"}:
            continue
        if v100._generated_body(body):
            continue
        if flag in seen_final:
            continue
        seen_final.add(flag)
        row = dict(item) if isinstance(item, dict) else {"flag": flag}
        row["flag"] = flag
        row.setdefault("score", 760)
        clean_flags.append(row)
    summary["flags"] = sorted(clean_flags, key=lambda x: int(x.get("score", 0) or 0), reverse=True)[:120]
    flags = summary["flags"]

    exact_from_unconfirmed: list[dict[str, Any]] = []
    for item in unconfirmed[:800]:
        val = str(item.get("flag") or item.get("value") or item.get("candidate") or "")
        for m in core.STRICT_RE.finditer(val):
            body = m.group(1)
            if body.lower() in {"...", "example", "sample", "test", "flag", "placeholder"} or v100._generated_body(body):
                continue
            exact_from_unconfirmed.append({
                "flag": m.group(0),
                "file": item.get("file", ""),
                "score": int(item.get("score", 650) or 650),
                "why": item.get("why") or item.get("why_not_promoted") or "Strict-looking flag preserved from unconfirmed evidence for review.",
                "source": item.get("bucket", "unconfirmed_evidence"),
                "artifact": item.get("artifact", ""),
                "bucket": "unconfirmed_strict",
            })
    summary["unconfirmed_strict_flags"] = exact_from_unconfirmed[:200]

    candidate_paths = {str(x.get("artifact") or "") for x in workflow + unconfirmed + exact_from_unconfirmed if isinstance(x, dict) and x.get("artifact")}
    evidence_paths = {str(x.get("artifact") or "") for x in workflow if isinstance(x, dict) and x.get("artifact")}
    visual_terms = ("visual", "image", "png", "jpg", "jpeg", "contact", "bitplane", "palette", "alpha", "lsb", "canvas", "ascii", "reconstruct", "piet", "qr", "ocr", "threshold", "rotate", "flip")
    transform_terms = ("final_", "v102", "v101", "v100", "v99", "v96", "multistep", "decode", "decompress", "carve", "extract", "xor", "array", "columnar", "rail", "rot", "pcap", "dns", "http", "zip", "archive", "office", "docx", "sqlite")
    queue: list[dict[str, Any]] = []
    seen = set()
    for a in artifacts:
        blob = " ".join(str(a.get(k, "")) for k in ("name", "kind", "source", "note", "path", "file")).lower()
        apath = str(a.get("path") or "")
        score = int(a.get("score", 0) or 0)
        reasons: list[str] = []
        priority = 0
        if apath in evidence_paths:
            priority += 150
            reasons.append("direct workflow evidence")
        if apath in candidate_paths:
            priority += 120
            reasons.append("candidate/fragment source")
        if any(t in blob for t in visual_terms):
            priority += 110
            reasons.append("visual/manual-review artifact")
        if any(t in blob for t in transform_terms):
            priority += 70
            reasons.append("logical transform output")
        if "final_" in blob:
            priority += 95
            reasons.append("final workflow artifact")
        if priority <= 0:
            continue
        key = apath or str(a.get("name") or id(a))
        if key in seen:
            continue
        seen.add(key)
        item = dict(a)
        item["open_first"] = True
        item["human_priority"] = priority + min(score, 300)
        item["priority_reason"] = "; ".join(dict.fromkeys(reasons))
        queue.append(item)
    queue = sorted(queue, key=lambda x: (int(x.get("human_priority", 0) or 0), int(x.get("score", 0) or 0)), reverse=True)[:180]
    summary["final_open_queue"] = queue
    old_priority = [a for a in summary.get("priority_artifacts", []) or [] if isinstance(a, dict)]
    by_key = set()
    merged = []
    for a in queue + old_priority:
        key = str(a.get("path") or a.get("name") or id(a))
        if key in by_key:
            continue
        by_key.add(key)
        merged.append(a)
    summary["priority_artifacts"] = merged[:180]
    summary["human_review_artifacts"] = merged[:180]

    lanes = {
        "submit": {"priority": 100, "title": "Submit / verify", "count": len(flags), "why": "Strict ctf_cs flags and unconfirmed strict flags are separated from fragments."},
        "open_first": {"priority": 98, "title": "Open First artifacts", "count": len(queue), "why": "Visuals, transform outputs and evidence sources ranked for human review."},
        "visual": {"priority": 92, "title": "Visual / reconstruction", "count": sum(1 for a in queue if any(t in str(a).lower() for t in visual_terms)), "why": "Manual-eye artifacts can solve tasks even without auto-submission."},
        "archive": {"priority": 88, "title": "Archive / carving", "count": sum(1 for a in artifacts if re.search(r"zip|tar|archive|carve|office|docx|xlsx|pdf|sqlite", str(a), re.I)), "why": "Nested children, comments, filenames, local headers and carved payloads."},
        "network": {"priority": 86, "title": "PCAP / network", "count": sum(1 for a in artifacts if re.search(r"pcap|dns|http|icmp|udp|tcp|ipid", str(a), re.I)), "why": "Payloads, protocol strings and scalar covert fields."},
        "reversing": {"priority": 84, "title": "Reversing / binary", "count": sum(1 for a in artifacts if re.search(r"array|binary|elf|pe|constraint|strings|rodata|xor|rol|ror", str(a), re.I)), "why": "Static strings, constants, transforms and constraint outputs."},
        "fragments": {"priority": 82, "title": "Fragments / leetspeak", "count": len(unconfirmed), "why": "Bare braces, leetspeak and alternate formats preserved for human choice."},
    }
    summary["final_workflow_map"] = lanes
    actions = summary.setdefault("sloper93_next_actions", [])
    actions.insert(0, {"priority": 140, "step": "Start with Final Open Queue", "why": f"{len(queue)} artifacts are ranked by evidence and manual usefulness; visual reconstructions and transform outputs are promoted above raw noise."})
    if exact_from_unconfirmed:
        actions.insert(0, {"priority": 138, "step": "Review unconfirmed strict-looking flags", "why": f"{len(exact_from_unconfirmed)} strict-looking tokens were preserved even when not promoted. They may be true if the workflow context makes sense."})
    if unconfirmed:
        actions.insert(0, {"priority": 130, "step": "Review fragments and alternate formats", "why": "Bare {...}, leetspeak, TSG/UID and non-wrapper answers are preserved with copy buttons."})
    try:
        hub = compact_hub(summary)
        hub.setdefault("groups", {})["start_here"] = merged[:50]
        hub.setdefault("counts", {})["open_first"] = len(merged[:50])
        summary["final_artifact_hub"] = hub
        summary["sloper93_artifact_hub"] = hub
    except Exception:
        pass
    return summary


def install(mod: Any) -> Any:
    try:
        if not getattr(v100, "_final_safe_archive_child_installed", False):
            v100.archive_child_multistep_agent = final_safe_archive_child_agent(getattr(v100, "archive_child_multistep_agent", None))
            v100._final_safe_archive_child_installed = True
    except Exception as e:
        agent_crash("final install safe archive child", e, None)
    old_run = core.run_file_fast
    old_summary = core.build_summary

    def run_file_fast_final(mod_obj: Any, report: dict, root: Path, data: bytes) -> list[dict]:
        try:
            path = Path(str(report.get("path", "")))
            kind_hint = report.get("kind") or core.kind_for(mod_obj, path, data)
            suffix = path.suffix.lower()
            binary_quick = (
                kind_hint == "generic"
                and len(data) <= 80_000_000
                and (
                    data.startswith((b"\x7fELF", b"MZ"))
                    or suffix in {"", ".bin", ".elf", ".exe", ".dll", ".so", ".wasm", ".class", ".jar"}
                    or core.printable_ratio(data[:200000]) < 0.45
                )
                and not zipfile.is_zipfile(io.BytesIO(data[:200000]))
            )
        except Exception:
            kind_hint = report.get("kind") or "generic"
            binary_quick = False
        if binary_quick:
            report["kind"] = kind_hint
            arts = final_binary_quick_agent(report, root, data) or []
        else:
            arts = old_run(mod_obj, report, root, data) or []
        try:
            kind = report.get("kind") or core.kind_for(mod_obj, Path(report.get("path", "")), data)
            if kind in {"text", "generic"} and len(data) <= 5_000_000:
                core.call_agent(report, root, data, "final_text_workflow", final_text_workflow_agent, arts, 7)
            if kind in {"text", "generic"} and len(data) <= 12_000_000:
                core.call_agent(report, root, data, "final_time_log_workflow", final_time_log_agent, arts, 7)
            if kind in {"archive", "generic"} and len(data) <= 140_000_000 and (data.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ")) or zipfile.is_zipfile(io.BytesIO(data))):
                core.call_agent(report, root, data, "final_archive_workflow", final_archive_workflow_agent, arts, 8)
                core.call_agent(report, root, data, "final_recursive_onion", final_recursive_onion_agent, arts, 9)
            if kind == "pcap" or data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
                core.call_agent(report, root, data, "final_pcap_workflow", final_pcap_workflow_agent, arts, 8)
            if kind == "image" or data.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")):
                core.call_agent(report, root, data, "final_image_color_workflow", final_image_color_agent, arts, 7)
            if Path(str(report.get("path", ""))).suffix.lower() in {".pdf", ".sqlite", ".sqlite3", ".db"} or data.startswith((b"%PDF", b"SQLite format 3\x00")):
                core.call_agent(report, root, data, "final_document_db", final_document_db_agent, arts, 7)
            report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
        except Exception as e:
            agent_crash("final run_file_fast", e, report)
        return arts

    def build_summary_final(reports: list[dict], meta: dict, project_flags: list[dict], project_artifacts: list[dict]) -> dict:
        try:
            summary = old_summary(reports, meta, project_flags, project_artifacts)
        except Exception as e:
            agent_crash("final old build_summary", e, None)
            summary = {"flags": [], "artifacts": [], "workflow_evidence": [], "unconfirmed_evidence": []}
        try:
            return final_enrich_summary(summary, reports or [], meta or {})
        except Exception as e:
            agent_crash("final summary enrichment", e, None)
            return summary

    core.run_file_fast = run_file_fast_final
    core.build_summary = build_summary_final
    mod.sl_final_run_file_fast = lambda report, root, data: run_file_fast_final(mod, report, root, data)
    mod.sl93_run_file_fast = mod.sl_final_run_file_fast
    mod.project_summary = lambda reports, meta: build_summary_final(reports or [], meta or {}, [], [])
    mod.APP_TITLE = "CTF SLOPER FINAL"
    return mod
