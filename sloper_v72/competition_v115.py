"""v115 competition expansion layer.

Adds more CTF-practical extractors on top of v114 without executing challenge files:
- deep image LSB byte extraction with channel/order/bit variants;
- PDF stream/string/hex extraction, including FlateDecode streams;
- JPEG/GIF metadata and comment extraction;
- classic PCAP packet payload/string extraction;
- dynamic ZIP password retry using local strings/filenames/common CTF words;
- URL/data URI and base85/base58/uu/quoted-printable token rescue;
- per-file operator playbook artifacts and bounded runtime manifests.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import io
import json
import os
import quopri
import re
import struct
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

from .fast_lane_v110 import scan_text, _safe_text, _profile_for_project
try:
    from .competition_v113 import _append_flags, _artifact, MAX_MEMBER_BYTES, MAX_EXTRA_BYTES, MAX_IMAGE_PIXELS
except Exception:  # pragma: no cover
    MAX_MEMBER_BYTES = int(os.environ.get("SLOPER_V115_MAX_MEMBER_BYTES", "2500000"))
    MAX_EXTRA_BYTES = int(os.environ.get("SLOPER_V115_MAX_EXTRA_BYTES", "7000000"))
    MAX_IMAGE_PIXELS = int(os.environ.get("SLOPER_V115_MAX_IMAGE_PIXELS", "1400000"))
    def _append_flags(report: dict[str, Any], rows: list[dict[str, Any]], rel: str) -> None:
        report.setdefault("verified_flags", []).extend(rows)
        for r in rows:
            f = r.get("flag") if isinstance(r, dict) else None
            if f and f not in report.setdefault("flags", []):
                report["flags"].append(f)
    def _artifact(report: dict[str, Any], root: Path, name: str, data: bytes | str, kind: str, note: str, score: int, source: str, rel: str) -> dict[str, Any]:
        d = root / "artifacts_v115"; d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:160] or "artifact.bin"
        p = d / safe
        if isinstance(data, bytes):
            p.write_bytes(data[:MAX_MEMBER_BYTES]); size = min(len(data), MAX_MEMBER_BYTES)
        else:
            p.write_text(str(data)[:1_000_000], encoding="utf-8", errors="replace"); size = min(len(str(data).encode()), 1_000_000)
        row = {"name": safe, "kind": kind, "source": source, "file": rel, "path": str(p), "score": score, "size": size, "note": note, "exists": True, "evidence_version": "v115"}
        report.setdefault("artifacts", []).append(row); return row

V115_MAX_LSB_BYTES = int(os.environ.get("SLOPER_V115_MAX_LSB_BYTES", "900000"))
V115_MAX_PCAP_PACKETS = int(os.environ.get("SLOPER_V115_MAX_PCAP_PACKETS", "400"))
V115_MAX_ZIP_PWDS = int(os.environ.get("SLOPER_V115_MAX_ZIP_PASSWORDS", "120"))
V115_FILE_BUDGET_MS = int(os.environ.get("SLOPER_V115_FILE_BUDGET_MS", "3500"))
FLAGISH_RE = re.compile(rb"(?is)(?:[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}|\{[^{}\r\n]{3,220}\})")
PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{20,})(?![A-Za-z0-9+/=_-])")
B85_RE = re.compile(r"(?<![!-u])([!-u]{24,})(?![!-u])")
DATA_URI_RE = re.compile(r"data:([^;,\s]+)?(;base64)?,([A-Za-z0-9+/=_%\-\.]+)", re.I)
PDF_STREAM_RE = re.compile(rb"(<<[^>]{0,1200}>>\s*)?stream\r?\n(.*?)\r?\nendstream", re.S)
PDF_LITERAL_RE = re.compile(rb"\((?:\\.|[^\\)]){2,800}\)")
PDF_HEX_RE = re.compile(rb"<([0-9A-Fa-f\s]{8,4000})>")
COMMON_WORDS = [
    "", "ctf", "flag", "sloper", "nksc", "cybersprint", "sprint", "cyber", "secret", "password", "pass",
    "admin", "root", "kodas", "raktas", "slaptas", "slaptazodis", "veliava", "vėliava", "lietuva", "venona",
    "challenge", "solver", "hidden", "forensics", "stego", "misc", "re", "crypto", "1234", "12345", "0000",
]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data[:8192] + str(len(data)).encode()).hexdigest()[:16]


def _budget(start: float) -> bool:
    if not start or start <= 0:
        return True
    return (time.time() - start) * 1000 < V115_FILE_BUDGET_MS


def _interesting(raw: bytes) -> bool:
    if not raw:
        return False
    head = raw[:200_000]
    low = head.lower()
    if FLAGISH_RE.search(head):
        return True
    if any(x in low for x in (b"ctf", b"flag", b"secret", b"slapt", b"rakt", b"password", b"key")) and len(PRINTABLE_RE.findall(head[:4000])) > 0:
        return True
    if head.startswith((b"PK\x03\x04", b"%PDF", b"\x89PNG", b"SQLite format 3\x00", b"RIFF")):
        return True
    return False


def _scan(label: str, blob: bytes | str, profile: dict[str, Any], rel: str, boost: int = 330) -> list[dict[str, Any]]:
    raw = blob.encode("utf-8", "ignore") if isinstance(blob, str) else bytes(blob or b"")
    scan_profile = dict(profile or {})
    scan_profile["max_depth"] = min(2, int(scan_profile.get("max_depth", 2) or 2))
    scan_profile["max_artifacts"] = min(260, int(scan_profile.get("max_artifacts", 260) or 260))
    rows = scan_text(_safe_text(raw), profile=scan_profile, raw=raw)
    out: list[dict[str, Any]] = []
    for row in rows[:140]:
        if not isinstance(row, dict):
            continue
        nr = dict(row)
        src = str(nr.get("source") or "input")
        nr["source"] = f"{label}->{src}" if src and src != label else label
        nr["file"] = rel
        nr["score"] = int(nr.get("score", 0) or 0) + boost
        nr.setdefault("sources", []).append(label)
        nr["evidence_version"] = "v115"
        nr.setdefault("chain", [label, src] if src and src != label else [label])
        out.append(nr)
    return out


def _printable_text(raw: bytes, limit: int = 900_000) -> str:
    parts = [m.group(0).decode("utf-8", "ignore") for m in PRINTABLE_RE.finditer(raw[:limit])]
    return "\n".join(parts[:5000])


def _zip_dynamic(raw: bytes, rel: str) -> list[tuple[str, bytes, str]]:
    out: list[tuple[str, bytes, str]] = []
    if not raw.startswith(b"PK") and b"PK\x03\x04" not in raw[:128]:
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return out
    base_tokens = set(COMMON_WORDS)
    base_tokens.add(Path(rel).stem)
    base_tokens.add(Path(rel).name)
    for s in re.findall(rb"[A-Za-z0-9_@!#.$%+\-]{3,32}", raw[:200_000]):
        try:
            t = s.decode("utf-8", "ignore").strip()
            if 3 <= len(t) <= 32:
                base_tokens.add(t)
        except Exception:
            pass
    variants: list[bytes | None] = [None]
    for w in list(base_tokens)[:V115_MAX_ZIP_PWDS]:
        vals = {w, w.lower(), w.upper(), w.capitalize(), w + "!", w + "123", w + "2026"}
        for v in vals:
            if v:
                variants.append(v.encode("utf-8", "ignore"))
    seen = set()
    try:
        for info in zf.infolist()[:120]:
            if info.is_dir() or info.file_size > MAX_MEMBER_BYTES * 4:
                continue
            for pwd in variants[:V115_MAX_ZIP_PWDS]:
                label = pwd.decode("utf-8", "ignore") if pwd else "none"
                key = (info.filename, label)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    data = zf.read(info, pwd=pwd)[:MAX_MEMBER_BYTES]
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


def _decode_token_rescue(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen = set()
    def add(label: str, data: bytes):
        if not data or len(data) < 4:
            return
        key = hashlib.sha1(data[:4096] + str(len(data)).encode()).hexdigest()
        if key in seen:
            return
        seen.add(key)
        if _interesting(data) or len(PRINTABLE_RE.findall(data[:3000])) > 0:
            out.append((label, data[:MAX_MEMBER_BYTES]))

    for i, m in enumerate(DATA_URI_RE.finditer(text[:1_500_000])):
        enc = m.group(2); payload = m.group(3)
        try:
            if enc:
                add(f"data_uri_b64_{i}", base64.b64decode(payload + "=" * ((4 - len(payload) % 4) % 4)))
            else:
                add(f"data_uri_url_{i}", unquote_plus(payload).encode())
        except Exception:
            pass
    for i, tok in enumerate(B64_RE.findall(text[:1_000_000])[:120]):
        val = tok.strip()
        try:
            add(f"b64_token_{i}", base64.b64decode(val + "=" * ((4 - len(val) % 4) % 4)))
        except Exception:
            try: add(f"b64url_token_{i}", base64.urlsafe_b64decode(val + "=" * ((4 - len(val) % 4) % 4)))
            except Exception: pass
    for i, tok in enumerate(B85_RE.findall(text[:500_000])[:40]):
        try: add(f"base85_token_{i}", base64.b85decode(tok.encode()))
        except Exception:
            try: add(f"ascii85_token_{i}", base64.a85decode(tok.encode()))
            except Exception: pass
    try:
        qp = quopri.decodestring(text[:500_000].encode("utf-8", "ignore"))
        if qp and qp != text[:len(qp)].encode("utf-8", "ignore"):
            add("quoted_printable_document", qp)
    except Exception:
        pass
    if "begin " in text and re.search(r"^M", text, re.M):
        buff = bytearray()
        for line in text.splitlines()[:20000]:
            try:
                if line and not line.startswith(("begin", "end")):
                    buff.extend(binascii.a2b_uu(line))
            except Exception:
                pass
        add("uuencoded_document", bytes(buff))
    return out[:120]


def _pdf_extract(raw: bytes) -> list[tuple[str, bytes]]:
    if not raw.startswith(b"%PDF") and b"%PDF" not in raw[:1024]:
        return []
    out: list[tuple[str, bytes]] = []
    for idx, m in enumerate(PDF_STREAM_RE.finditer(raw[:MAX_EXTRA_BYTES])):
        hdr = m.group(1) or b""
        data = m.group(2).strip(b"\r\n")[:MAX_MEMBER_BYTES]
        out.append((f"pdf_stream_{idx}_raw", data))
        if b"FlateDecode" in hdr or data[:2] in (b"x\x9c", b"x\xda", b"x\x01"):
            for wbits, name in ((zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "rawdeflate")):
                try:
                    out.append((f"pdf_stream_{idx}_{name}", zlib.decompress(data, wbits)[:MAX_MEMBER_BYTES]))
                    break
                except Exception:
                    pass
    lit_parts = []
    for m in PDF_LITERAL_RE.finditer(raw[:MAX_EXTRA_BYTES]):
        s = m.group(0)[1:-1]
        s = s.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\n", b"\n").replace(b"\\r", b"\r")
        lit_parts.append(s)
    if lit_parts:
        out.append(("pdf_literal_strings", b"\n".join(lit_parts)[:MAX_MEMBER_BYTES]))
    hex_parts = []
    for m in PDF_HEX_RE.finditer(raw[:MAX_EXTRA_BYTES]):
        token = re.sub(rb"\s+", b"", m.group(1))
        if len(token) % 2:
            token += b"0"
        try:
            val = bytes.fromhex(token.decode())
            if len(val) >= 3:
                hex_parts.append(val)
        except Exception:
            pass
    if hex_parts:
        out.append(("pdf_hex_strings", b"\n".join(hex_parts)[:MAX_MEMBER_BYTES]))
    return out[:80]


def _jpeg_gif_metadata(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if raw.startswith(b"\xff\xd8"):
        i = 2; n = len(raw)
        while i + 4 <= n and len(out) < 80:
            if raw[i] != 0xFF:
                i += 1; continue
            while i < n and raw[i] == 0xFF: i += 1
            if i >= n: break
            marker = raw[i]; i += 1
            if marker in (0xD9, 0xDA): break
            if i + 2 > n: break
            ln = int.from_bytes(raw[i:i+2], "big"); i += 2
            seg = raw[i:i+max(0, ln-2)]; i += max(0, ln-2)
            if marker == 0xFE or 0xE0 <= marker <= 0xEF:
                out.append((f"jpeg_marker_ff{marker:02x}", seg[:MAX_MEMBER_BYTES]))
    if raw.startswith((b"GIF87a", b"GIF89a")):
        i = 13
        while i < len(raw) - 2 and len(out) < 80:
            if raw[i] == 0x21 and raw[i+1] in (0xFE, 0xFF):
                label = "gif_comment" if raw[i+1] == 0xFE else "gif_application"
                i += 2
                chunks = []
                while i < len(raw):
                    sz = raw[i]; i += 1
                    if sz == 0: break
                    chunks.append(raw[i:i+sz]); i += sz
                if chunks: out.append((f"{label}_{len(out)}", b"".join(chunks)[:MAX_MEMBER_BYTES]))
            else:
                i += 1
    return out


def _pcap_payloads(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if len(raw) < 24:
        return out
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1": endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4": endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1": endian = "<"
    elif magic == b"\xa1\xb2\x3c\x4d": endian = ">"
    else: return out
    pos = 24
    merged = bytearray()
    for idx in range(V115_MAX_PCAP_PACKETS):
        if pos + 16 > len(raw): break
        try:
            _ts, _us, incl, orig = struct.unpack(endian + "IIII", raw[pos:pos+16])
        except Exception:
            break
        pos += 16
        if incl <= 0 or incl > 10_000_000 or pos + incl > len(raw): break
        pkt = raw[pos:pos+incl]; pos += incl
        merged.extend(pkt + b"\n")
        # Common packet payload offsets; safe heuristic only.
        for off in (0, 14, 16, 20, 34, 42, 54):
            if len(pkt) > off + 4:
                chunk = pkt[off:]
                if _interesting(chunk):
                    out.append((f"pcap_packet_{idx}_offset_{off}", chunk[:MAX_MEMBER_BYTES]))
    if merged:
        out.append(("pcap_all_packets_strings", _printable_text(bytes(merged)).encode()[:MAX_MEMBER_BYTES]))
    return out[:80]


def _deep_image_lsb(path: Path, start: float) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        from PIL import Image
    except Exception:
        return out
    try:
        im = Image.open(path); im.load()
        if im.width * im.height > MAX_IMAGE_PIXELS:
            im.thumbnail((1200, 1200))
        rgba = im.convert("RGBA")
        pix = list(rgba.getdata())
    except Exception:
        return out
    orders = [
        ("rgb", [0,1,2]), ("bgr", [2,1,0]), ("rgba", [0,1,2,3]), ("argb", [3,0,1,2]),
        ("r", [0]), ("g", [1]), ("b", [2]), ("a", [3]),
    ]
    def pack(bits: list[int], reverse: bool) -> bytes:
        bb = bytearray(); n = min(len(bits) - len(bits) % 8, V115_MAX_LSB_BYTES * 8)
        for j in range(0, n, 8):
            chunk = bits[j:j+8]
            if reverse: chunk = list(reversed(chunk))
            v = 0
            for bit in chunk: v = (v << 1) | (bit & 1)
            bb.append(v)
        return bytes(bb)
    for pname, pdata in (("normal", pix), ("reverse", list(reversed(pix)))):
        for bit in (0, 1):
            for oname, idxs in orders:
                if not _budget(start): return out
                bits = [((px[i] >> bit) & 1) for px in pdata for i in idxs]
                if len(bits) < 32: continue
                for rev, suffix in ((False, "msb"), (True, "lsb")):
                    data = pack(bits, rev)
                    if _interesting(data):
                        out.append((f"image_lsb_{pname}_{oname}_bit{bit}_{suffix}", data[:MAX_MEMBER_BYTES]))
    return out[:60]


def _operator_playbook(report: dict[str, Any], root: Path, rel: str, manifest: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
    if not manifest:
        return
    kinds = sorted({str(m.get("extractor")) for m in manifest if isinstance(m, dict)})
    lines = [
        f"# v115 operator notes for `{rel}`", "",
        f"Findings from v115: **{len(rows)}**", "",
        "## Extractors that produced evidence", "",
    ]
    for k in kinds:
        lines.append(f"- {k}")
    lines += ["", "## Top candidate chains", ""]
    for r in rows[:15]:
        lines.append(f"- `{r.get('flag') or r.get('preferred_flag')}` via `{r.get('source')}` score={r.get('score')}")
    lines += ["", "## Manual fallback checklist", "", "- Inspect high-score artifacts first, not every generated file.", "- For images: open v115 LSB text payloads and v114 bit-plane PNG previews.", "- For PDFs/office files: check extracted XML/stream artifacts before OCR.", "- For archives: verify dynamic password hits and member names."]
    _artifact(report, root, f"v115_operator_playbook_{Path(rel).stem}.md", "\n".join(lines), "v115_operator_playbook", "human triage guide generated from extractor evidence", 900, "v115_playbook", rel)


def extra_analyze_v115(path: Path, root: Path, report: dict[str, Any], profile: dict[str, Any], rel: str) -> dict[str, Any]:
    started = time.time()
    try:
        raw = path.read_bytes()[:MAX_EXTRA_BYTES]
    except Exception as e:
        report.setdefault("v115_competition", {})["error"] = repr(e)
        return report
    rows: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []

    def handle(label: str, data: bytes, extractor: str, boost: int = 340, write_if: bool = True):
        nonlocal rows, manifest
        if not data:
            return
        got = _scan(label, data, profile, rel, boost=boost)
        rows.extend(got)
        manifest.append({"extractor": extractor, "label": label, "size": len(data), "flags": [g.get("flag") for g in got[:5]]})
        if write_if and (got or _interesting(data)):
            ext = ".txt" if data and sum(1 for b in data[:2000] if b in b"\t\n\r" or 32 <= b <= 126) / max(1, min(len(data), 2000)) > 0.65 else ".bin"
            payload = _safe_text(data)[:100000] if ext == ".txt" else data
            _artifact(report, root, f"v115_{re.sub(r'[^A-Za-z0-9_.-]+','_',label)}_{_sha(data)}{ext}", payload, f"v115_{extractor}", "v115 extracted payload with explicit transform/source label", 820, label, rel)

    text = _safe_text(raw)
    for label, data in _decode_token_rescue(text):
        if not _budget(started): break
        handle(label, data, "token_rescue", 360)
    for name, data, pwd in _zip_dynamic(raw, rel):
        if not _budget(started): break
        handle(f"zip_dynamic:{name}:pwd={pwd}", data, "zip_dynamic_password", 390)
    for label, data in _pdf_extract(raw):
        if not _budget(started): break
        handle(label, data, "pdf_extract", 370)
    for label, data in _jpeg_gif_metadata(raw):
        if not _budget(started): break
        handle(label, data, "image_metadata", 350)
    for label, data in _pcap_payloads(raw):
        if not _budget(started): break
        handle(label, data, "pcap_payload", 360)
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff"}:
        for label, data in _deep_image_lsb(path, started):
            if not _budget(started): break
            handle(label, data, "deep_image_lsb", 430)

    _append_flags(report, rows, rel)
    if manifest:
        _artifact(report, root, "v115_competition_manifest.json", json.dumps(manifest[:1200], indent=2, ensure_ascii=False), "v115_manifest", "v115 extractor manifest: PDF/JPEG/GIF/PCAP/deep-LSB/token/dynamic ZIP evidence", 910, "v115_competition", rel)
        _operator_playbook(report, root, rel, manifest, rows)
    report["v115_competition"] = {
        "enabled": True,
        "version": "v115-broad-extractor-triage",
        "runtime_ms": int((time.time() - started) * 1000),
        "extra_findings": len(rows),
        "manifest_items": len(manifest),
        "extractors": sorted({str(m.get("extractor")) for m in manifest if isinstance(m, dict)}),
        "budget_ms": V115_FILE_BUDGET_MS,
        "budget_exhausted": not _budget(started),
    }
    return report


def apply(mod) -> None:
    old_analyze = getattr(mod, "analyze_file", None)
    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"flags": [], "artifacts": []}
        if not isinstance(report, dict):
            report = {"error": "previous analyzer returned non-dict", "flags": [], "artifacts": []}
        p = Path(path); r = Path(root)
        try: rel = str(p.relative_to(r))
        except Exception: rel = p.name
        try: profile = _profile_for_project(mod, str(pid))
        except Exception: profile = {}
        try:
            return extra_analyze_v115(p, r, report, profile, rel)
        except Exception as e:
            report.setdefault("v115_competition", {})["error"] = repr(e)
            return report
    mod.analyze_file = analyze_file
    mod.sl115_pdf_extract = _pdf_extract
    mod.sl115_jpeg_gif_metadata = _jpeg_gif_metadata
    mod.sl115_pcap_payloads = _pcap_payloads
    mod.sl115_deep_image_lsb = _deep_image_lsb
    mod.sl115_zip_dynamic = _zip_dynamic
    try:
        @mod.app.get("/api/v115_status")
        def v115_status():
            return {"ok": True, "version": "v115-broad-extractor-triage", "extractors": ["deep-image-lsb", "pdf-streams", "jpeg-gif-metadata", "pcap-payloads", "dynamic-zip-passwords", "token-rescue"], "budget_ms": V115_FILE_BUDGET_MS}
    except Exception:
        pass
