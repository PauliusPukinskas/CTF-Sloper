"""v114 competition hardening layer.

This module layers additional bounded, local-only extractors on top of v113:
- recursive binary payload frontier with explicit provenance chains;
- office ZIP text normalization for docx/xlsx/pptx XML text fragments;
- SQLite text-table extraction;
- PNG ancillary/zTXt chunk extraction and bit-plane preview artifacts;
- WAV PCM LSB extraction;
- single-byte XOR rescue for hidden text/payloads;
- richer manifest artifacts for live competition triage.

It never executes uploaded challenge files and never contacts the network.
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
import os
import quopri
import re
import sqlite3
import struct
import tarfile
import time
import wave
import zipfile
import zlib
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from .fast_lane_v110 import scan_text, _safe_text, _profile_for_project
try:
    from .competition_v113 import _append_flags, _artifact, _zip_members, _tar_members, MAX_MEMBER_BYTES, MAX_EXTRA_BYTES, MAX_IMAGE_PIXELS
except Exception:  # pragma: no cover - defensive when imported standalone
    MAX_MEMBER_BYTES = int(os.environ.get("SLOPER_V114_MAX_MEMBER_BYTES", "2500000"))
    MAX_EXTRA_BYTES = int(os.environ.get("SLOPER_V114_MAX_EXTRA_BYTES", "7000000"))
    MAX_IMAGE_PIXELS = int(os.environ.get("SLOPER_V114_MAX_IMAGE_PIXELS", "1400000"))

    def _append_flags(report: dict[str, Any], rows: list[dict[str, Any]], rel: str) -> None:
        report.setdefault("verified_flags", []).extend(rows)
        report.setdefault("findings", []).extend(rows)
        for r in rows:
            f = r.get("flag") if isinstance(r, dict) else None
            if f and f not in report.setdefault("flags", []):
                report["flags"].append(f)

    def _artifact(report: dict[str, Any], root: Path, name: str, data: bytes | str, kind: str, note: str, score: int, source: str, rel: str) -> dict[str, Any]:
        art_dir = root / "artifacts_v114"
        art_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:160] or "artifact.txt"
        path = art_dir / safe
        if isinstance(data, bytes):
            path.write_bytes(data[:MAX_MEMBER_BYTES])
            size = min(len(data), MAX_MEMBER_BYTES)
        else:
            path.write_text(str(data)[:1_000_000], encoding="utf-8", errors="replace")
            size = min(len(str(data).encode("utf-8", "ignore")), 1_000_000)
        row = {"name": safe, "kind": kind, "source": source, "file": rel, "path": str(path), "score": score, "size": size, "note": note, "exists": True, "evidence_version": "v114"}
        report.setdefault("artifacts", []).append(row)
        return row

    def _zip_members(raw: bytes) -> list[tuple[str, bytes, str]]:
        return []

    def _tar_members(raw: bytes) -> list[tuple[str, bytes]]:
        return []

V114_MAX_FRONTIER_NODES = int(os.environ.get("SLOPER_V114_MAX_FRONTIER_NODES", "180"))
V114_MAX_FRONTIER_DEPTH = int(os.environ.get("SLOPER_V114_MAX_FRONTIER_DEPTH", "6"))
V114_MAX_XOR_BYTES = int(os.environ.get("SLOPER_V114_MAX_XOR_BYTES", "1200000"))
V114_MAX_SQL_ROWS = int(os.environ.get("SLOPER_V114_MAX_SQL_ROWS", "2000"))
PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
FLAGISH_RE = re.compile(rb"(?is)(?:[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}|\{[^{}\r\n]{3,220}\})")
XML_TEXT_TAG_RE = re.compile(r">([^<>]{2,})<")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{24,})(?![A-Za-z0-9+/=_-])")
HEX_RE = re.compile(r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{16,})(?![A-Fa-f0-9])")
BIN_RE = re.compile(r"(?<![01])((?:[01][\s_-]*){32,})(?![01])")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data[:8192] + str(len(data)).encode()).hexdigest()[:16]


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    data = raw[:5000]
    good = sum(1 for b in data if b in b"\t\n\r" or 32 <= b <= 126)
    return good / max(1, len(data))


def _interesting_bytes(raw: bytes) -> bool:
    if not raw:
        return False
    head = raw[:250_000]
    if FLAGISH_RE.search(head):
        return True
    if any(head.startswith(m) for m in (b"PK\x03\x04", b"\x89PNG\r\n\x1a\n", b"%PDF", b"SQLite format 3\x00", b"RIFF")):
        return True
    if _printable_ratio(head) >= 0.42 and any(x in head.lower() for x in (b"ctf", b"flag", b"secret", b"slapt", b"rakt", b"key")):
        return True
    return False


def _dedupe_key(label: str, data: bytes) -> str:
    return hashlib.sha256(label.encode() + b"\0" + data[:4096] + str(len(data)).encode()).hexdigest()


def _scan_blob(label: str, blob: bytes, profile: dict[str, Any], rel: str, boost: int = 180) -> list[dict[str, Any]]:
    # The v114 frontier performs recursion itself; keep the inner fast scan shallow
    # so hard-mode does not multiply into an exponential decoder tree.
    scan_profile = dict(profile or {})
    scan_profile["max_depth"] = min(1, int(scan_profile.get("max_depth", 1) or 1))
    scan_profile["max_artifacts"] = min(180, int(scan_profile.get("max_artifacts", 180) or 180))
    rows = scan_text(_safe_text(blob), profile=scan_profile, raw=blob)
    out: list[dict[str, Any]] = []
    for row in rows[:100]:
        if not isinstance(row, dict):
            continue
        nr = dict(row)
        src = str(nr.get("source") or "input")
        nr["source"] = f"{label}->{src}" if src and src != label else label
        nr["file"] = rel
        nr["score"] = int(nr.get("score", 0) or 0) + boost
        nr.setdefault("sources", []).append(label)
        nr["evidence_version"] = "v114"
        out.append(nr)
    return out


def _decompress_candidates(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if not data or len(data) > MAX_EXTRA_BYTES:
        return out
    attempts = [
        ("gzip", gzip.decompress),
        ("bz2", bz2.decompress),
        ("xz", lzma.decompress),
        ("zlib", lambda b: zlib.decompress(b)),
        ("zlib_raw", lambda b: zlib.decompress(b, -zlib.MAX_WBITS)),
    ]
    for name, fn in attempts:
        try:
            val = fn(data)
            if val and val != data:
                out.append((name, val[:MAX_MEMBER_BYTES]))
        except Exception:
            pass
    return out


def _text_decode_candidates(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    text = _safe_text(data, limit=1_000_000)
    if not text.strip():
        return out
    for label, val in (
        ("url_unquote", unquote_plus(text)),
        ("html_unescape", html.unescape(text)),
    ):
        if val and val != text:
            out.append((label, val.encode("utf-8", "ignore")[:MAX_MEMBER_BYTES]))
    try:
        qp = quopri.decodestring(text.encode("utf-8", "ignore"))
        if qp and qp != data:
            out.append(("quoted_printable", qp[:MAX_MEMBER_BYTES]))
    except Exception:
        pass
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 16:
        if len(compact) % 2 == 0 and re.fullmatch(r"[A-Fa-f0-9]+", compact):
            try:
                out.append(("hex_whole", bytes.fromhex(compact)[:MAX_MEMBER_BYTES]))
            except Exception:
                pass
        if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            pad = "=" * ((4 - len(compact) % 4) % 4)
            for alt, name in ((None, "base64_whole"), (b"-_", "base64url_whole")):
                try:
                    out.append((name, base64.b64decode((compact + pad).encode(), altchars=alt, validate=False)[:MAX_MEMBER_BYTES]))
                except Exception:
                    pass
        if re.fullmatch(r"[A-Z2-7=]+", compact.upper()):
            try:
                out.append(("base32_whole", base64.b32decode(compact.upper().encode(), casefold=True)[:MAX_MEMBER_BYTES]))
            except Exception:
                pass
    for i, tok in enumerate(B64_RE.findall(text)[:80]):
        pad = "=" * ((4 - len(tok) % 4) % 4)
        for alt, name in ((None, "base64_token"), (b"-_", "base64url_token")):
            try:
                child = base64.b64decode((tok + pad).encode(), altchars=alt, validate=False)
                if _interesting_bytes(child) or _printable_ratio(child) > 0.45:
                    out.append((f"{name}_{i}", child[:MAX_MEMBER_BYTES]))
            except Exception:
                pass
    for i, tok in enumerate(HEX_RE.findall(text)[:80]):
        if len(tok) % 2:
            continue
        try:
            child = bytes.fromhex(tok)
            if _interesting_bytes(child) or _printable_ratio(child) > 0.45:
                out.append((f"hex_token_{i}", child[:MAX_MEMBER_BYTES]))
        except Exception:
            pass
    for i, tok in enumerate(BIN_RE.findall(text)[:40]):
        bits = re.sub(r"[^01]", "", tok)
        if len(bits) >= 32:
            try:
                child = bytes(int(bits[j:j+8], 2) for j in range(0, len(bits) - 7, 8))
                out.append((f"binary_bits_{i}", child[:MAX_MEMBER_BYTES]))
            except Exception:
                pass
    return out


def _xor_candidates(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if not data or len(data) > V114_MAX_XOR_BYTES:
        return out
    # Do not brute-force obvious structured binary containers here; specialized
    # extractors handle them and XOR on compressed/database bytes produces huge noise.
    if data.startswith((b"SQLite format 3\x00", b"RIFF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"%PDF")):
        return out
    # Only XOR small/text-ish blobs or blobs already containing brace-like signal.
    if len(data) > 250_000 and not FLAGISH_RE.search(data[:250_000]):
        return out
    # Try every single-byte key, but only keep outputs with clear CTF signal or file magic.
    for key in range(1, 256):
        child = bytes(b ^ key for b in data)
        if _interesting_bytes(child):
            out.append((f"xor_{key:02x}", child[:MAX_MEMBER_BYTES]))
            if len(out) >= 12:
                break
    return out


def _container_candidates(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for name, child, pwd in _zip_members(data):
        out.append((f"zip:{name}:pwd={pwd}", child[:MAX_MEMBER_BYTES]))
    for name, child in _tar_members(data):
        out.append((f"tar:{name}", child[:MAX_MEMBER_BYTES]))
    return out


def _payload_frontier(raw: bytes, profile: dict[str, Any], rel: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[tuple[str, bytes]]]:
    rows: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    interesting_payloads: list[tuple[str, bytes]] = []
    max_depth = min(V114_MAX_FRONTIER_DEPTH, max(2, int(profile.get("max_depth", 4) or 4) if isinstance(profile, dict) else 4))
    max_nodes = min(V114_MAX_FRONTIER_NODES, max(80, int(profile.get("max_artifacts", 1000) or 1000) if isinstance(profile, dict) else 1000))
    q: deque[tuple[str, bytes, int]] = deque([("input", raw[:MAX_EXTRA_BYTES], 0)])
    seen: set[str] = set()
    processed = 0
    while q and processed < max_nodes:
        label, blob, depth = q.popleft()
        if not blob:
            continue
        key = _dedupe_key(label, blob)
        if key in seen:
            continue
        seen.add(key)
        processed += 1
        structured_binary = blob.startswith((b"SQLite format 3\x00", b"RIFF", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"%PDF"))
        scan_this = (not structured_binary) and (_printable_ratio(blob) >= 0.20 or FLAGISH_RE.search(blob[:250_000]) or len(blob) < 4096)
        got = _scan_blob(label, blob, profile, rel, boost=max(60, 220 - depth * 22)) if scan_this else []
        rows.extend(got)
        is_interesting = bool(got) or _interesting_bytes(blob)
        if is_interesting and label != "input":
            interesting_payloads.append((label, blob[:MAX_MEMBER_BYTES]))
        manifest.append({
            "label": label,
            "depth": depth,
            "size": len(blob),
            "flags": [r.get("flag") for r in got[:5]],
            "interesting": is_interesting,
            "printable_ratio": round(_printable_ratio(blob), 3),
        })
        if depth >= max_depth:
            continue
        children: list[tuple[str, bytes]] = []
        children.extend(_container_candidates(blob))
        children.extend(_decompress_candidates(blob))
        children.extend(_text_decode_candidates(blob))
        if depth <= 2:
            children.extend(_xor_candidates(blob))
        child_seen: set[str] = set()
        for cname, child in children[:120]:
            if not child or len(child) < 2:
                continue
            ckey = hashlib.sha256(child[:4096] + str(len(child)).encode()).hexdigest()
            if ckey in child_seen:
                continue
            child_seen.add(ckey)
            q.append((f"{label}->{cname}", child[:MAX_MEMBER_BYTES], depth + 1))
    return rows, manifest, interesting_payloads[:80]


def _office_texts_from_zip(raw: bytes) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not raw or not zipfile.is_zipfile(io.BytesIO(raw)):
        return out
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            office_like = any(n.startswith(("word/", "xl/", "ppt/")) for n in names) or "[Content_Types].xml" in names
            if not office_like:
                return out
            for name in names[:300]:
                low = name.lower()
                if not low.endswith((".xml", ".rels")):
                    continue
                if not low.startswith(("word/", "xl/", "ppt/", "docprops/")):
                    continue
                try:
                    xml = zf.read(name)[:MAX_MEMBER_BYTES].decode("utf-8", "ignore")
                except Exception:
                    continue
                pieces = [html.unescape(re.sub(r"\s+", " ", p)).strip() for p in XML_TEXT_TAG_RE.findall(xml)]
                text = "\n".join(p for p in pieces if p)
                if text:
                    out.append((f"office_xml_text:{name}", text[:1_000_000]))
    except Exception:
        pass
    return out


def _sqlite_texts(path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        raw = path.read_bytes()[:32]
    except Exception:
        return out
    if not raw.startswith(b"SQLite format 3\x00"):
        return out
    conn = None
    try:
        uri = f"file:{path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=1.0)
        conn.execute("PRAGMA query_only=ON")
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 80")]
        for t in tables:
            # Quote identifier safely by doubling quotes.
            tq = '"' + t.replace('"', '""') + '"'
            cols_info = list(conn.execute(f"PRAGMA table_info({tq})"))
            cols = [c[1] for c in cols_info if str(c[2]).lower() in ("text", "varchar", "char", "clob", "")]
            if not cols:
                cols = [c[1] for c in cols_info[:12]]
            if not cols:
                continue
            col_expr = ", ".join('"' + c.replace('"', '""') + '"' for c in cols[:12])
            try:
                rows = conn.execute(f"SELECT {col_expr} FROM {tq} LIMIT {V114_MAX_SQL_ROWS}").fetchall()
            except Exception:
                continue
            text = "\n".join(" | ".join(str(x) for x in row if x is not None) for row in rows)
            if text.strip():
                out.append((f"sqlite:{t}", text[:1_000_000]))
    except Exception:
        pass
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
    return out


def _png_chunks(raw: bytes) -> list[tuple[str, bytes, dict[str, Any]]]:
    out: list[tuple[str, bytes, dict[str, Any]]] = []
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return out
    pos = 8
    idx = 0
    while pos + 12 <= len(raw) and idx < 220:
        idx += 1
        try:
            ln = struct.unpack(">I", raw[pos:pos+4])[0]
            ctype = raw[pos+4:pos+8]
            data = raw[pos+8:pos+8+ln]
        except Exception:
            break
        if pos + 12 + ln > len(raw):
            break
        typ = ctype.decode("latin1", "ignore")
        if typ in {"tEXt", "iTXt"} and data:
            out.append((f"png_chunk:{typ}:{idx}", data[:MAX_MEMBER_BYTES], {"type": typ, "size": ln}))
        elif typ == "zTXt" and data:
            nul = data.find(b"\x00")
            if nul >= 0 and nul + 2 < len(data):
                comp = data[nul+2:]
                try:
                    out.append((f"png_chunk:zTXt:{idx}", zlib.decompress(comp)[:MAX_MEMBER_BYTES], {"type": typ, "size": ln}))
                except Exception:
                    pass
        elif typ not in {"IHDR", "IDAT", "IEND", "PLTE"} and data and (FLAGISH_RE.search(data) or _printable_ratio(data) > 0.5):
            out.append((f"png_chunk:{typ}:{idx}", data[:MAX_MEMBER_BYTES], {"type": typ, "size": ln}))
        pos += 12 + ln
        if typ == "IEND":
            break
    return out


def _wav_lsb_channels(path: Path) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        with wave.open(str(path), "rb") as wf:
            nch = wf.getnchannels()
            sw = wf.getsampwidth()
            nframes = min(wf.getnframes(), 600_000)
            frames = wf.readframes(nframes)
    except Exception:
        return out
    if not frames or sw not in (1, 2, 3, 4):
        return out
    samples: list[int] = []
    step = sw
    for i in range(0, len(frames) - step + 1, step):
        samples.append(frames[i] & 1)
    if len(samples) < 32:
        return out

    def pack(bits: list[int], reverse: bool = False) -> bytes:
        b = bytearray()
        n = len(bits) - len(bits) % 8
        for i in range(0, n, 8):
            chunk = bits[i:i+8]
            if reverse:
                chunk = list(reversed(chunk))
            val = 0
            for bit in chunk:
                val = (val << 1) | (bit & 1)
            b.append(val)
        return bytes(b)

    for off in range(8):
        bits = samples[off:]
        if len(bits) >= 32:
            for rev, suffix in ((False, "msb"), (True, "lsb")):
                data = pack(bits, rev)[:MAX_MEMBER_BYTES]
                if FLAGISH_RE.search(data) or b"ctf" in data.lower() or b"flag" in data.lower():
                    out.append((f"wav_lsb_offset_{off}_{suffix}_ch{nch}_w{sw}", data))
    return out[:24]


def _image_bitplane_artifacts(path: Path, root: Path, report: dict[str, Any], rel: str) -> list[dict[str, Any]]:
    arts: list[dict[str, Any]] = []
    try:
        from PIL import Image
    except Exception:
        return arts
    try:
        im = Image.open(path)
        im.load()
        if im.width * im.height > MAX_IMAGE_PIXELS:
            im.thumbnail((1200, 1200))
        rgba = im.convert("RGBA")
    except Exception:
        return arts
    channels = [("r", 0), ("g", 1), ("b", 2), ("a", 3)]
    pix = list(rgba.getdata())
    for cname, idx in channels:
        for bit in (0, 1):
            try:
                plane = Image.new("L", rgba.size)
                vals = [255 if ((px[idx] >> bit) & 1) else 0 for px in pix]
                plane.putdata(vals)
                bio = io.BytesIO()
                plane.save(bio, format="PNG")
                arts.append(_artifact(report, root, f"v114_bitplane_{cname}{bit}_{path.stem}.png", bio.getvalue(), "image_bitplane_preview", f"visual bit-plane preview channel={cname} bit={bit}", 640 + bit * 10, f"image_bitplane:{cname}{bit}", rel))
            except Exception:
                continue
    return arts


def extra_analyze_v114(path: Path, root: Path, report: dict[str, Any], profile: dict[str, Any], rel: str) -> dict[str, Any]:
    started = time.time()
    try:
        raw = path.read_bytes()[:MAX_EXTRA_BYTES]
    except Exception as e:
        report.setdefault("v114_competition", {})["error"] = repr(e)
        return report

    rows: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    payloads_written = 0

    frontier_rows, frontier_manifest, payloads = _payload_frontier(raw, profile, rel)
    rows.extend(frontier_rows)
    manifest.extend({**m, "extractor": "payload_frontier"} for m in frontier_manifest[:600])
    for label, payload in payloads[:30]:
        if payloads_written >= 30:
            break
        if _interesting_bytes(payload):
            _artifact(report, root, f"v114_payload_{_sha(payload)}.bin", payload, "decoded_payload", "interesting decoded payload with preserved transform chain", 780, label, rel)
            payloads_written += 1

    for label, text in _office_texts_from_zip(raw):
        data = text.encode("utf-8", "ignore")
        got = _scan_blob(label, data, profile, rel, boost=260)
        rows.extend(got)
        manifest.append({"extractor": "office_text", "label": label, "size": len(data), "flags": [r.get("flag") for r in got[:5]]})
        if got or any(x in text.lower() for x in ("flag", "ctf", "secret", "rakt", "slapt")):
            _artifact(report, root, f"v114_{re.sub(r'[^A-Za-z0-9_.-]+','_', label)}.txt", text, "office_text", "normalized office XML visible text", 790, label, rel)

    for label, text in _sqlite_texts(path):
        data = text.encode("utf-8", "ignore")
        got = _scan_blob(label, data, profile, rel, boost=280)
        rows.extend(got)
        manifest.append({"extractor": "sqlite", "label": label, "size": len(data), "flags": [r.get("flag") for r in got[:5]]})
        _artifact(report, root, f"v114_{re.sub(r'[^A-Za-z0-9_.-]+','_', label)}.txt", text, "sqlite_text", "SQLite text/table dump", 800, label, rel)

    for label, data, meta in _png_chunks(raw):
        got = _scan_blob(label, data, profile, rel, boost=260)
        rows.extend(got)
        manifest.append({"extractor": "png_chunk", "label": label, "meta": meta, "flags": [r.get("flag") for r in got[:5]]})
        if got or _interesting_bytes(data):
            _artifact(report, root, f"v114_{re.sub(r'[^A-Za-z0-9_.-]+','_', label)}.bin", data, "png_chunk", "PNG ancillary/compressed chunk extraction", 760, label, rel)

    for label, data in _wav_lsb_channels(path):
        got = _scan_blob(label, data, profile, rel, boost=300)
        rows.extend(got)
        manifest.append({"extractor": "wav_lsb", "label": label, "flags": [r.get("flag") for r in got[:5]]})
        if got:
            _artifact(report, root, f"v114_{label}_{_sha(data)}.txt", _safe_text(data)[:20000], "wav_lsb_text", "WAV PCM LSB decoded bytes", 820, label, rel)

    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}:
        previews = _image_bitplane_artifacts(path, root, report, rel)
        if previews:
            manifest.append({"extractor": "image_bitplane_previews", "count": len(previews), "flags": []})

    _append_flags(report, rows, rel)
    if manifest:
        _artifact(report, root, "v114_competition_manifest.json", json.dumps(manifest[:1000], indent=2, ensure_ascii=False), "v114_manifest", "v114 extractor manifest with payload frontier and specialized parsers", 820, "v114_competition", rel)
    report["v114_competition"] = {
        "enabled": True,
        "version": "v114-frontier-specialized-extractors",
        "runtime_ms": int((time.time() - started) * 1000),
        "extra_findings": len(rows),
        "manifest_items": len(manifest),
        "payloads_written": payloads_written,
        "extractors": sorted({str(m.get("extractor")) for m in manifest if isinstance(m, dict)}),
        "limits": {
            "max_frontier_nodes": V114_MAX_FRONTIER_NODES,
            "max_frontier_depth": V114_MAX_FRONTIER_DEPTH,
            "max_extra_bytes": MAX_EXTRA_BYTES,
            "max_member_bytes": MAX_MEMBER_BYTES,
        },
    }
    return report


def apply(mod) -> None:
    old_analyze = getattr(mod, "analyze_file", None)

    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"flags": [], "artifacts": []}
        if not isinstance(report, dict):
            report = {"error": "previous analyzer returned non-dict", "flags": [], "artifacts": []}
        p = Path(path)
        r = Path(root)
        try:
            rel = str(p.relative_to(r))
        except Exception:
            rel = p.name
        try:
            profile = _profile_for_project(mod, str(pid))
        except Exception:
            profile = {}
        try:
            return extra_analyze_v114(p, r, report, profile, rel)
        except Exception as e:  # keep v113 result even if v114 breaks
            report.setdefault("v114_competition", {})["error"] = repr(e)
            return report

    mod.analyze_file = analyze_file
    mod.sl114_payload_frontier = _payload_frontier
    mod.sl114_office_texts_from_zip = _office_texts_from_zip
    mod.sl114_sqlite_texts = _sqlite_texts
    mod.sl114_png_chunks = _png_chunks
    mod.sl114_wav_lsb_channels = _wav_lsb_channels

    try:
        @mod.app.get("/api/v114_status")
        def v114_status():
            return {
                "ok": True,
                "version": "v114-frontier-specialized-extractors",
                "extractors": ["payload-frontier", "office-xml-text", "sqlite", "png-chunks", "wav-lsb", "xor-rescue", "image-bitplane-previews"],
                "limits": {"max_frontier_nodes": V114_MAX_FRONTIER_NODES, "max_frontier_depth": V114_MAX_FRONTIER_DEPTH, "max_extra_bytes": MAX_EXTRA_BYTES},
            }
    except Exception:
        pass
