"""v113 competition solver extensions.

Adds bounded, file-aware extractors on top of the v110/v112 recursive fast lane:
archives, office documents, image LSB channels, whitespace/case channels, and
structured evidence artifacts.  All work is local and bounded.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

from .fast_lane_v110 import scan_text, _safe_text, _profile_for_project

MAX_EXTRA_BYTES = int(os.environ.get("SLOPER_V113_MAX_EXTRA_BYTES", "6000000"))
MAX_MEMBER_BYTES = int(os.environ.get("SLOPER_V113_MAX_MEMBER_BYTES", "2500000"))
MAX_IMAGE_PIXELS = int(os.environ.get("SLOPER_V113_MAX_IMAGE_PIXELS", "1200000"))
COMMON_ZIP_PASSWORDS = [b"", b"ctf", b"flag", b"password", b"secret", b"sloper", b"nksc", b"cybersprint", b"venona"]

PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data[:8192] + str(len(data)).encode()).hexdigest()[:16]


def _append_flags(report: dict[str, Any], rows: list[dict[str, Any]], rel: str) -> None:
    if not rows:
        return
    seen = {str(x).lower() for x in report.get("flags", []) or []}
    verified = report.setdefault("verified_flags", [])
    findings = report.setdefault("findings", [])
    decoders = report.setdefault("decoders", [])
    chain_results = report.setdefault("chain_results", [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        flag = str(row.get("flag") or "").strip()
        if not flag:
            continue
        row.setdefault("file", rel)
        row.setdefault("status", "candidate")
        row.setdefault("evidence_version", "v113")
        key = flag.lower()
        if key not in seen:
            report.setdefault("flags", []).append(flag)
            seen.add(key)
        verified.append(row)
        findings.append(row)
        decoders.append(row)
        chain_results.append(row)


def _artifact(report: dict[str, Any], root: Path, name: str, data: bytes | str, kind: str, note: str, score: int, source: str, rel: str) -> dict[str, Any]:
    art_dir = root / "artifacts_v113"
    art_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:140] or "artifact.txt"
    path = art_dir / safe
    if isinstance(data, bytes):
        path.write_bytes(data[:MAX_MEMBER_BYTES])
        size = min(len(data), MAX_MEMBER_BYTES)
    else:
        text = str(data)
        path.write_text(text[:1_000_000], encoding="utf-8", errors="replace")
        size = min(len(text.encode("utf-8", "ignore")), 1_000_000)
    row = {"name": safe, "kind": kind, "source": source, "file": rel, "path": str(path), "score": score, "size": size, "note": note, "exists": True, "evidence_version": "v113"}
    report.setdefault("artifacts", []).append(row)
    return row


def _scan_blob(label: str, blob: bytes, profile: dict[str, Any], rel: str, score_boost: int = 0) -> list[dict[str, Any]]:
    rows = scan_text(_safe_text(blob), profile=profile, raw=blob)
    out: list[dict[str, Any]] = []
    for row in rows[:80]:
        if not isinstance(row, dict):
            continue
        nr = dict(row)
        src = str(nr.get("source") or "input")
        nr["source"] = f"{label}->{src}" if src and src != label else label
        nr["file"] = rel
        nr["score"] = int(nr.get("score", 0) or 0) + score_boost
        nr.setdefault("sources", []).append(label)
        out.append(nr)
    return out


def _zip_members(raw: bytes) -> list[tuple[str, bytes, str]]:
    out: list[tuple[str, bytes, str]] = []
    if not raw or len(raw) < 4:
        return out
    bio = io.BytesIO(raw)
    try:
        if not zipfile.is_zipfile(bio):
            return out
        bio.seek(0)
        with zipfile.ZipFile(bio) as zf:
            for info in zf.infolist()[:80]:
                if info.is_dir() or info.file_size > MAX_MEMBER_BYTES * 4:
                    continue
                got = False
                for pwd in COMMON_ZIP_PASSWORDS:
                    try:
                        data = zf.read(info, pwd=pwd or None)[:MAX_MEMBER_BYTES]
                        out.append((info.filename, data, (pwd.decode(errors="ignore") if pwd else "none")))
                        got = True
                        break
                    except RuntimeError:
                        continue
                    except Exception:
                        break
                if not got:
                    continue
    except Exception:
        return out
    return out


def _tar_members(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
            for m in tf.getmembers()[:80]:
                if not m.isfile() or m.size > MAX_MEMBER_BYTES * 4:
                    continue
                f = tf.extractfile(m)
                if not f:
                    continue
                out.append((m.name, f.read(MAX_MEMBER_BYTES)))
    except Exception:
        pass
    return out


def _case_and_space_channels(text: str) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []

    def pack(bits: str, reverse_bits: bool = False) -> bytes:
        b = bytearray()
        for i in range(0, len(bits) - 7, 8):
            chunk = bits[i:i+8]
            if reverse_bits:
                chunk = chunk[::-1]
            b.append(int(chunk, 2))
        return bytes(b)

    letters = [c for c in text[:900000] if c.isalpha()]
    if len(letters) >= 32:
        bits = "".join("1" if c.isupper() else "0" for c in letters)
        for off in range(8):
            b = bits[off:]
            if len(b) >= 32:
                out.append((f"case_bits_offset_{off}_msb", pack(b, False)))
                out.append((f"case_bits_offset_{off}_lsb", pack(b, True)))
    spaces = [c for c in text[:900000] if c in " \t"]
    if len(spaces) >= 32 and "\t" in spaces:
        bits = "".join("1" if c == "\t" else "0" for c in spaces)
        for off in range(8):
            b = bits[off:]
            if len(b) >= 32:
                out.append((f"space_tab_bits_offset_{off}_msb", pack(b, False)))
                out.append((f"space_tab_bits_offset_{off}_lsb", pack(b, True)))
    zw = [c for c in text[:900000] if c in "\u200b\u200c\u200d\ufeff"]
    if len(zw) >= 32:
        bits = "".join("1" if c in "\u200c\u200d" else "0" for c in zw)
        for off in range(8):
            b = bits[off:]
            if len(b) >= 32:
                out.append((f"zero_width_bits_offset_{off}_msb", pack(b, False)))
                out.append((f"zero_width_bits_offset_{off}_lsb", pack(b, True)))
    return [(n, d) for n, d in out if d and (b"{" in d or len(PRINTABLE_RE.findall(d[:2000])) > 0)]


def _image_lsb_channels(path: Path) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        from PIL import Image
    except Exception:
        return out
    try:
        im = Image.open(path)
        im.load()
        if im.width * im.height > MAX_IMAGE_PIXELS:
            im.thumbnail((1200, 1200))
        rgba = im.convert("RGBA")
        data = list(rgba.getdata())
    except Exception:
        return out

    def pack(bits: list[int], reverse_bits: bool = False) -> bytes:
        b = bytearray()
        n = len(bits) - (len(bits) % 8)
        for i in range(0, n, 8):
            chunk = bits[i:i+8]
            if reverse_bits:
                chunk = list(reversed(chunk))
            val = 0
            for bit in chunk:
                val = (val << 1) | (bit & 1)
            b.append(val)
        return bytes(b)

    channels = {"r": 0, "g": 1, "b": 2, "a": 3}
    combos = [("rgb", [0, 1, 2]), ("rgba", [0, 1, 2, 3]), ("alpha", [3])]
    for name, idxs in combos:
        bits = [(px[i] & 1) for px in data for i in idxs]
        if len(bits) >= 32:
            out.append((f"image_lsb_{name}_msb", pack(bits, False)))
            out.append((f"image_lsb_{name}_lsb", pack(bits, True)))
    for cname, idx in channels.items():
        bits = [(px[idx] & 1) for px in data]
        if len(bits) >= 32:
            out.append((f"image_lsb_{cname}_msb", pack(bits, False)))
            out.append((f"image_lsb_{cname}_lsb", pack(bits, True)))
    return [(n, d[:MAX_MEMBER_BYTES]) for n, d in out if d and (b"{" in d or b"ctf" in d.lower() or b"flag" in d.lower())]


def _string_layers(raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    strings = b"\n".join(PRINTABLE_RE.findall(raw[:MAX_EXTRA_BYTES])[:6000])
    if strings and strings != raw[:len(strings)]:
        out.append(("printable_strings", strings))
    # Data URI / embedded base64 rescue.
    text = raw[:MAX_EXTRA_BYTES].decode("latin1", "ignore")
    for i, tok in enumerate(re.findall(r"base64,([A-Za-z0-9+/=_-]{24,})", text)[:40]):
        try:
            pad = "=" * ((4 - len(tok) % 4) % 4)
            out.append((f"data_uri_base64_{i}", base64.b64decode((tok + pad).encode(), validate=False)[:MAX_MEMBER_BYTES]))
        except Exception:
            pass
    return out


def extra_analyze(path: Path, root: Path, report: dict[str, Any], profile: dict[str, Any], rel: str) -> dict[str, Any]:
    started = time.time()
    try:
        raw = path.read_bytes()[:MAX_EXTRA_BYTES]
    except Exception:
        return report
    manifest: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []

    def scan_and_record(label: str, blob: bytes, kind: str, note: str, write: bool = False) -> None:
        nonlocal all_rows
        if not blob:
            return
        rows = _scan_blob(label, blob[:MAX_MEMBER_BYTES], profile, rel, score_boost=120)
        if rows:
            all_rows.extend(rows)
            preview = _safe_text(blob[:20000])[:4000]
            if write:
                _artifact(report, root, f"{label}_{_sha(blob)}.txt", preview or blob[:20000], kind, note, 760, label, rel)
        manifest.append({"label": label, "kind": kind, "size": len(blob), "flags": [r.get("flag") for r in rows[:5]], "note": note})

    # Archive and office-document style containers.
    for name, data, pwd in _zip_members(raw):
        label = f"zip:{name}"
        scan_and_record(label, data, "archive_member", f"ZIP member extracted; password={pwd}", write=bool(name.lower().endswith(('.txt','.xml','.json','.html','.js','.csv','.md'))))
        # nested one-level zip/tar/string scan
        for n2, d2, pwd2 in _zip_members(data):
            scan_and_record(f"{label}->zip:{n2}", d2, "nested_archive_member", f"nested ZIP member; password={pwd2}", write=False)
        for n2, d2 in _tar_members(data):
            scan_and_record(f"{label}->tar:{n2}", d2, "nested_archive_member", "nested TAR member", write=False)
    for name, data in _tar_members(raw):
        scan_and_record(f"tar:{name}", data, "archive_member", "TAR member extracted", write=bool(name.lower().endswith(('.txt','.json','.html','.js','.csv','.md'))))

    # Text hidden channels.
    text = raw.decode("utf-8", "ignore")
    for name, data in _case_and_space_channels(text):
        scan_and_record(name, data, "text_hidden_channel", "case/space/zero-width hidden bit channel", write=True)

    # Image LSB channels.
    for name, data in _image_lsb_channels(path):
        scan_and_record(name, data, "image_lsb_channel", "least-significant-bit channel extracted from image", write=True)

    # String extraction and embedded payloads.
    for name, data in _string_layers(raw):
        scan_and_record(name, data, "string_layer", "printable string/data URI extraction", write=False)

    _append_flags(report, all_rows, rel)
    if manifest:
        _artifact(report, root, "v113_competition_manifest.json", json.dumps(manifest[:500], indent=2, ensure_ascii=False), "v113_manifest", "Competition extractor manifest", 700, "v113_competition", rel)
    report["v113_competition"] = {
        "enabled": True,
        "runtime_ms": int((time.time() - started) * 1000),
        "extra_findings": len(all_rows),
        "extractors": sorted({m["kind"] for m in manifest}),
        "manifest_items": len(manifest),
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
            return extra_analyze(p, r, report, profile, rel)
        except Exception as e:
            report.setdefault("v113_competition", {})["error"] = repr(e)
            return report

    mod.analyze_file = analyze_file

    try:
        @mod.app.get("/api/v113_status")
        def v113_status():
            return {
                "ok": True,
                "version": "v113-competition-extractors",
                "extractors": ["zip", "tar", "office-zip", "image-lsb", "case-bits", "space-tab-bits", "zero-width-bits", "string-layers"],
                "limits": {"max_extra_bytes": MAX_EXTRA_BYTES, "max_member_bytes": MAX_MEMBER_BYTES, "max_image_pixels": MAX_IMAGE_PIXELS},
            }
    except Exception:
        pass
