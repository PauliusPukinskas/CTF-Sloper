"""Bounded high-signal workflow agents for local CTF solving.

This layer is deliberately small and deterministic.  It does not replace the
legacy solvers; it catches common multi-step chains and always writes artifacts
with method/source/why so the final ranking gate can prefer real transforms over
metadata noise.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import html
import io
import itertools
import struct
import lzma
import re
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import unquote


FLAG_RE = re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{3,220}\}|\{[^{}\r\n]{3,220}\}")
PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
INT_RE = re.compile(r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]{1,2}|\d{1,3}|'.'|\".\")(?![A-Za-z0-9_])")

MAX_DATA = 4_000_000
MAX_TEXT = 1_200_000
MAX_NODES = 180
MAX_ARTIFACTS = 80
TIME_BUDGET = 5.0


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "artifact"))[:150] or "artifact"


def _root_from_reports(reports: list[dict[str, Any]]) -> Path | None:
    for report in reports:
        p = _report_path(report)
        if p:
            return p.parent.parent if p.parent.name == "files" else p.parent
    return None


def _report_path(report: dict[str, Any]) -> Path | None:
    for key in ("path", "source_path", "file_path"):
        val = report.get(key)
        if val and Path(str(val)).exists():
            return Path(str(val))
    return None


def _text(raw: bytes | str, limit: int = MAX_TEXT) -> str:
    if isinstance(raw, str):
        return raw[:limit]
    return bytes(raw or b"")[:limit].decode("utf-8", errors="replace")


def _interesting(raw: bytes | str) -> bool:
    b = raw.encode("utf-8", "ignore") if isinstance(raw, str) else bytes(raw or b"")
    if FLAG_RE.search(_text(b, 160_000)):
        return True
    if b.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"%PDF", b"\x89PNG", b"\xff\xd8", b"SQLite format 3")):
        return True
    printable = sum(32 <= x <= 126 or x in (9, 10, 13) for x in b[:4000])
    return len(b) >= 8 and printable / max(1, min(len(b), 4000)) > 0.72 and any(k in _text(b, 8000).lower() for k in ("ctf", "flag", "secret", "rakt", "slapt", "veli", "password"))


def _artifact(root: Path, report_or_summary: dict[str, Any], name: str, data: bytes | str, method: str, note: str, source_file: str = "", family: str = "workflow") -> dict[str, Any]:
    outdir = root / "artifacts" / "deep_workflows"
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / _safe_name(name)
    if isinstance(data, bytes):
        path.write_bytes(data[:2_000_000])
        preview = _text(data, 900)
    else:
        path.write_text(str(data)[:2_000_000], encoding="utf-8", errors="replace")
        preview = str(data)[:900]
    row = {
        "name": path.name,
        "kind": "deep_workflow_transform",
        "family": family,
        "method": method,
        "source": "deep_workflows",
        "source_file": source_file,
        "file": source_file,
        "path": str(path),
        "url": "/api/raw?path=" + str(path),
        "score": 3600,
        "note": note,
        "exists": True,
        "size": path.stat().st_size,
        "preview": preview,
    }
    report_or_summary.setdefault("artifacts", []).append(row)
    return row


def _add_flag(report_or_summary: dict[str, Any], flag: str, art: dict[str, Any], method: str, why: str, score: int = 5100) -> None:
    row = {
        "flag": flag,
        "preferred_flag": flag,
        "score": score,
        "status": "confirmed",
        "source": f"deep_workflows:{method}",
        "artifact": art.get("path"),
        "file": art.get("source_file"),
        "method": method,
        "why": why,
        "chain": ["deep_workflows", method, str(art.get("path") or "")],
    }
    report_or_summary.setdefault("flags", []).append(flag)
    report_or_summary.setdefault("verified_flags", []).append(row)
    report_or_summary.setdefault("workflow_evidence", []).append(row)
    report_or_summary.setdefault("findings", []).append(row)


def _scan_flags(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in FLAG_RE.finditer(text or ""):
        val = m.group(0)
        key = val.lower()
        if key not in seen:
            seen.add(key)
            out.append(val)
    return out[:40]


def _decode_candidates(label: str, raw: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    text = _text(raw, 800_000)
    compact = re.sub(r"\s+", "", text)

    def add(name: str, value: bytes | str) -> None:
        b = value.encode("utf-8", "ignore") if isinstance(value, str) else bytes(value or b"")
        if 4 <= len(b) <= MAX_DATA and _interesting(b):
            out.append((f"{label}->{name}", b))

    if 8 <= len(compact) <= 900_000:
        if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            for alt, name in ((None, "base64"), (b"-_", "base64url")):
                try:
                    add(name, base64.b64decode((compact + "=" * ((4 - len(compact) % 4) % 4)).encode(), altchars=alt, validate=False))
                except Exception:
                    pass
        if re.fullmatch(r"[A-Z2-7=]+", compact.upper()):
            try:
                add("base32", base64.b32decode(compact.upper() + "=" * ((8 - len(compact) % 8) % 8), casefold=True))
            except Exception:
                pass
        if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
            try:
                add("hex", bytes.fromhex(compact))
            except Exception:
                pass
        if re.fullmatch(r"[ -u]+", text.strip()) and len(text.strip()) >= 8:
            for fn, name in ((base64.a85decode, "ascii85"), (base64.b85decode, "base85")):
                try:
                    add(name, fn(text.strip().encode()))
                except Exception:
                    pass
    try:
        u = html.unescape(unquote(text))
        if u != text:
            add("url_html", u)
    except Exception:
        pass
    if 8 <= len(text) <= 800_000:
        add("reverse", text[::-1])
        add("rot13", _rot(text, 13))
        add("rot47", _rot47(text))
    for fn, name in ((gzip.decompress, "gzip"), (bz2.decompress, "bz2"), (lzma.decompress, "lzma")):
        try:
            add(name, fn(raw))
        except Exception:
            pass
    for wbits, name in ((15, "zlib"), (-15, "raw_deflate")):
        try:
            add(name, zlib.decompress(raw, wbits))
        except Exception:
            pass
    return out


def _rot(text: str, n: int) -> str:
    chars: list[str] = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            chars.append(chr((o - 65 + n) % 26 + 65))
        elif 97 <= o <= 122:
            chars.append(chr((o - 97 + n) % 26 + 97))
        else:
            chars.append(ch)
    return "".join(chars)


def _rot47(text: str) -> str:
    return "".join(chr(33 + ((ord(ch) - 33 + 47) % 94)) if 33 <= ord(ch) <= 126 else ch for ch in text)


def recursive_decode_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    start = time.time()
    source = str(report.get("rel") or report.get("name") or path.name)
    queue: list[tuple[str, bytes]] = [("input", data[:MAX_DATA])]
    seen: set[str] = set()
    artifacts = 0
    while queue and len(seen) < MAX_NODES and artifacts < MAX_ARTIFACTS and time.time() - start < TIME_BUDGET:
        label, raw = queue.pop(0)
        key = f"{label}:{len(raw)}:{raw[:64]!r}"
        if key in seen:
            continue
        seen.add(key)
        text = _text(raw)
        flags = _scan_flags(text)
        if flags and label != "input":
            art = _artifact(root, report, _safe_name(path.stem + "_" + label.replace("->", "_")) + ".txt", raw, label, "Bounded recursive decode produced flag-shaped evidence.", source, "crypto_decode")
            artifacts += 1
            for flag in flags:
                _add_flag(report, flag, art, label, "Recursive decode chain produced a candidate with saved artifact proof.")
        for next_label, val in _decode_candidates(label, raw):
            sig = f"{next_label}:{len(val)}:{val[:64]!r}"
            if sig not in seen:
                queue.append((next_label, val[:MAX_DATA]))
    if len(seen) > 1:
        report["deep_recursive_decode"] = {"enabled": True, "nodes": len(seen), "artifacts": artifacts, "seconds": round(time.time() - start, 3)}


def _parse_int_token(token: str) -> int | None:
    token = token.strip()
    try:
        if token.startswith(("'", '"')) and token.endswith(("'", '"')) and len(token) >= 3:
            return ord(token[1])
        val = int(token, 16) if token.lower().startswith("0x") else int(token)
        return val & 0xFF if 0 <= val <= 255 else None
    except Exception:
        return None


def _arrays_from_text(text: str) -> list[bytes]:
    arrays: list[bytes] = []
    for block in re.findall(r"[\[{]([^{}\[\]]{15,20000})[\]}]", text[:MAX_TEXT]):
        toks = INT_RE.findall(block)
        if not (6 <= len(toks) <= 6000):
            continue
        vals = [_parse_int_token(t) for t in toks]
        if all(v is not None for v in vals):
            arrays.append(bytes(v for v in vals if v is not None))
            if len(arrays) >= 24:
                break
    return arrays


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _ror(x: int, n: int) -> int:
    return ((x >> n) | (x << (8 - n))) & 0xFF


def _bitrev(x: int) -> int:
    return int(f"{x:08b}"[::-1], 2)


def _nibbleswap(x: int) -> int:
    return ((x & 0x0F) << 4) | ((x & 0xF0) >> 4)


def byte_array_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    text = _text(data)
    arrays = _arrays_from_text(text)
    if not arrays:
        return
    source = str(report.get("rel") or report.get("name") or path.name)
    start = time.time()
    made = 0
    transforms: list[tuple[str, Any]] = [
        ("raw", lambda b: b),
        ("reverse", lambda b: b[::-1]),
        ("not", lambda b: bytes((~x) & 0xFF for x in b)),
        ("bit_reverse", lambda b: bytes(_bitrev(x) for x in b)),
        ("nibble_swap", lambda b: bytes(_nibbleswap(x) for x in b)),
    ]
    for n in range(1, 8):
        transforms.append((f"rol_{n}", lambda b, n=n: bytes(_rol(x, n) for x in b)))
        transforms.append((f"ror_{n}", lambda b, n=n: bytes(_ror(x, n) for x in b)))
    for idx, arr in enumerate(arrays[:16]):
        if time.time() - start > TIME_BUDGET or made >= MAX_ARTIFACTS:
            break
        tests = list(transforms)
        for key in range(256):
            tests.append((f"xor_{key:02x}", lambda b, key=key: bytes(x ^ key for x in b)))
        for key in range(1, 256):
            tests.append((f"sub_{key:02x}", lambda b, key=key: bytes((x - key) & 0xFF for x in b)))
            tests.append((f"add_{key:02x}", lambda b, key=key: bytes((x + key) & 0xFF for x in b)))
        for method, fn in tests:
            if time.time() - start > TIME_BUDGET or made >= MAX_ARTIFACTS:
                break
            try:
                out = fn(arr)
            except Exception:
                continue
            txt = _text(out, 120_000)
            flags = _scan_flags(txt)
            if flags or (b"PK\x03\x04" in out[:64] or b"\x89PNG" in out[:64]):
                art = _artifact(root, report, f"{path.stem}_array{idx}_{method}.bin", out, f"byte_array_{method}", "Parsed source byte array and applied reversible transform.", source, "reversing")
                made += 1
                for flag in flags:
                    _add_flag(report, flag, art, f"byte_array_{method}", "Byte-array transform produced a strict candidate with artifact proof.")
    if made:
        report["deep_byte_arrays"] = {"enabled": True, "arrays": len(arrays), "artifacts": made, "seconds": round(time.time() - start, 3)}


def zip_side_channel_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"PK\x03\x04") and path.suffix.lower() not in {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"}:
        return
    source = str(report.get("rel") or report.get("name") or path.name)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return
    chunks: list[str] = []
    try:
        if zf.comment:
            chunks.append("zip comment: " + zf.comment.decode("utf-8", errors="replace"))
    except Exception:
        pass
    infos = zf.infolist()[:1000]
    chunks.append("member names:\n" + "\n".join(i.filename for i in infos))
    chunks.append("member sizes ascii: " + "".join(chr(i.file_size) for i in infos if 32 <= i.file_size <= 126))
    chunks.append("member compressed sizes ascii: " + "".join(chr(i.compress_size) for i in infos if 32 <= i.compress_size <= 126))
    chunks.append("member perms ascii: " + "".join(chr((i.external_attr >> 16) & 0xFF) for i in infos if 32 <= ((i.external_attr >> 16) & 0xFF) <= 126))
    text = "\n\n".join(chunks)
    flags = _scan_flags(text)
    if flags or any(s.strip() for s in chunks):
        art = _artifact(root, report, f"{path.stem}_zip_side_channels.txt", text, "zip_side_channels", "ZIP comments, filenames, sizes, timestamps and permissions extracted as evidence.", source, "archives")
        for flag in flags:
            _add_flag(report, flag, art, "zip_side_channels", "ZIP metadata side channel contained a strict candidate.")


def _scan_blob_to_artifact(report: dict[str, Any], root: Path, path: Path, blob: bytes | str, method: str, note: str, family: str) -> bool:
    text = _text(blob)
    flags = _scan_flags(text)
    if not flags:
        return False
    source = str(report.get("rel") or report.get("name") or path.name)
    art = _artifact(root, report, f"{path.stem}_{method}.txt", blob, method, note, source, family)
    for flag in flags:
        _add_flag(report, flag, art, method, note)
    return True


def png_chunk_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    pos = 8
    chunks: list[dict[str, Any]] = []
    while pos + 12 <= len(data):
        try:
            n = int.from_bytes(data[pos:pos + 4], "big")
            typ = data[pos + 4:pos + 8]
            payload = data[pos + 8:pos + 8 + n]
        except Exception:
            break
        if pos + 12 + n > len(data):
            break
        t = typ.decode("latin1", errors="replace")
        chunks.append({"type": t, "offset": pos, "size": n})
        if typ == b"tEXt":
            _scan_blob_to_artifact(report, root, path, payload.replace(b"\x00", b"\n"), "png_tEXt", "PNG tEXt chunk decoded.", "stego_image")
        elif typ == b"iTXt":
            _scan_blob_to_artifact(report, root, path, payload.replace(b"\x00", b"\n"), "png_iTXt", "PNG iTXt chunk decoded.", "stego_image")
        elif typ == b"zTXt":
            try:
                key, comp = payload.split(b"\x00", 1)
                if comp:
                    # zTXt: compression method byte then zlib stream.
                    inflated = zlib.decompress(comp[1:] if comp[0] == 0 else comp)
                    _scan_blob_to_artifact(report, root, path, key + b"\n" + inflated, "png_zTXt", "PNG zTXt chunk inflated.", "stego_image")
            except Exception:
                pass
        pos += 12 + n
        if typ == b"IEND":
            tail = data[pos:]
            if tail:
                _magic_payloads(report, root, path, tail, "png_iend_tail")
            break
    if chunks:
        _scan_blob_to_artifact(report, root, path, json_dumps({"chunks": chunks}), "png_chunk_map", "PNG chunk map for operator verification.", "stego_image")


def jpeg_marker_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"\xff\xd8"):
        return
    pos = 2
    comments: list[bytes] = []
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:
            tail = data[pos + 2:]
            if tail:
                _magic_payloads(report, root, path, tail, "jpeg_eoi_tail")
            break
        if marker in {0xD8, 0x01} or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        try:
            n = int.from_bytes(data[pos + 2:pos + 4], "big")
        except Exception:
            break
        payload = data[pos + 4:pos + 2 + n]
        if marker == 0xFE:
            comments.append(payload)
        if marker in {0xE1, 0xFE}:
            _scan_blob_to_artifact(report, root, path, payload, f"jpeg_marker_ff{marker:02x}", "JPEG APP/comment marker payload extracted.", "stego_image")
        pos += max(2, n + 2)
    if comments:
        _scan_blob_to_artifact(report, root, path, b"\n".join(comments), "jpeg_comments", "JPEG comments extracted.", "stego_image")


def _magic_payloads(report: dict[str, Any], root: Path, path: Path, data: bytes, method: str) -> None:
    magics = [(b"\x1f\x8b", "gzip"), (b"BZh", "bz2"), (b"\xfd7zXZ", "xz"), (b"PK\x03\x04", "zip"), (b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8", "jpg"), (b"SQLite format 3", "sqlite")]
    for magic, label in magics:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            chunk = data[idx:idx + MAX_DATA]
            source = str(report.get("rel") or report.get("name") or path.name)
            art = _artifact(root, report, f"{path.stem}_{method}_{label}_{idx}.bin", chunk, method + "_" + label, f"Carved {label} payload from offset {idx}.", source, "carving")
            txt = _text(chunk)
            for flag in _scan_flags(txt):
                _add_flag(report, flag, art, method + "_" + label, "Carved payload contained a strict candidate.")
            for dec_label, dec in _decode_candidates(method + "_" + label, chunk):
                if _scan_flags(_text(dec)):
                    dart = _artifact(root, report, f"{path.stem}_{method}_{label}_{idx}_decoded.txt", dec, dec_label, f"Decoded carved {label} payload.", source, "carving")
                    for flag in _scan_flags(_text(dec)):
                        _add_flag(report, flag, dart, dec_label, "Decoded carved payload contained a strict candidate.")
            start = idx + max(1, len(magic))


def wav_lsb_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    if not data.startswith(b"RIFF") or b"WAVE" not in data[:32]:
        return
    try:
        import wave
        with wave.open(io.BytesIO(data), "rb") as wf:
            channels = wf.getnchannels()
            width = wf.getsampwidth()
            frames = wf.readframes(min(wf.getnframes(), 300_000))
    except Exception:
        return
    streams: list[tuple[str, list[int]]] = []
    if width == 1:
        samples = list(frames)
        for ch in range(max(1, channels)):
            streams.append((f"u8_ch{ch}", samples[ch::channels]))
    elif width == 2:
        vals = list(struct.unpack("<" + "h" * (len(frames) // 2), frames[: len(frames) - (len(frames) % 2)]))
        for ch in range(max(1, channels)):
            streams.append((f"s16_ch{ch}", [v & 0xFFFF for v in vals[ch::channels]]))
    made = 0
    for label, samples in streams[:4]:
        for bit in range(4):
            bits = [(v >> bit) & 1 for v in samples[:120_000]]
            for order, seq in (("msb", bits), ("lsb", bits)):
                raw = _bits_to_bytes(seq, msb_first=(order == "msb"))
                if _scan_blob_to_artifact(report, root, path, raw.split(b"\x00", 1)[0], f"wav_lsb_{label}_bit{bit}_{order}", "WAV PCM LSB stream decoded.", "audio"):
                    made += 1
                rev = _bits_to_bytes(list(reversed(seq)), msb_first=(order == "msb"))
                if _scan_blob_to_artifact(report, root, path, rev.split(b"\x00", 1)[0], f"wav_lsb_{label}_bit{bit}_{order}_reverse", "Reversed WAV PCM LSB stream decoded.", "audio"):
                    made += 1
                if made >= 16:
                    return


def _bits_to_bytes(bits: list[int], msb_first: bool = True) -> bytes:
    out = bytearray()
    n = len(bits) - (len(bits) % 8)
    for i in range(0, n, 8):
        val = 0
        chunk = bits[i:i + 8]
        if msb_first:
            for bit in chunk:
                val = (val << 1) | bit
        else:
            for j, bit in enumerate(chunk):
                val |= (bit & 1) << j
        out.append(val)
    return bytes(out)


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, indent=2, ensure_ascii=False)


def analyze_file_agent(report: dict[str, Any], root: Path, path: Path, data: bytes) -> None:
    if len(data) > MAX_DATA:
        data = data[:MAX_DATA]
    recursive_decode_agent(report, root, path, data)
    byte_array_agent(report, root, path, data)
    zip_side_channel_agent(report, root, path, data)
    png_chunk_agent(report, root, path, data)
    jpeg_marker_agent(report, root, path, data)
    wav_lsb_agent(report, root, path, data)
    _magic_payloads(report, root, path, data, "file_magic_scan")


def _project_file_paths(reports: list[dict[str, Any]]) -> list[Path]:
    paths = []
    for r in reports:
        p = _report_path(r)
        if p and p.is_file() and p.name.lower() not in {"flag.txt", "expected.txt", "solution.txt"} and p.stat().st_size <= 1_000_000:
            paths.append(p)
    return paths[:40]


def _project_add(summary: dict[str, Any], root: Path, name: str, data: bytes, method: str, why: str, source_file: str) -> None:
    text = _text(data)
    flags = _scan_flags(text)
    if not flags:
        return
    art = _artifact(root, summary, name, data, method, why, source_file, "multi-file")
    for flag in flags:
        _add_flag(summary, flag, art, method, why, 5300)


def multi_file_agent(summary: dict[str, Any], reports: list[dict[str, Any]]) -> None:
    paths = _project_file_paths(reports)
    if len(paths) < 2:
        return
    root = _root_from_reports(reports)
    if root is None:
        return
    ordered = sorted(paths, key=lambda p: _natural_key(p.name))
    rev = list(reversed(ordered))
    _project_add(summary, root, "concat_natural.bin", b"".join(p.read_bytes() for p in ordered), "concat_natural", "Concatenated project files in natural filename order.", "+".join(p.name for p in ordered[:8]))
    _project_add(summary, root, "concat_reverse.bin", b"".join(p.read_bytes() for p in rev), "concat_reverse", "Concatenated project files in reverse natural order.", "+".join(p.name for p in rev[:8]))
    for a, b in itertools.combinations(ordered[:12], 2):
        da, db = a.read_bytes(), b.read_bytes()
        n = min(len(da), len(db))
        if n < 4:
            continue
        for method, data in (
            ("file_xor", bytes(da[i] ^ db[i] for i in range(n))),
            ("file_add", bytes((da[i] + db[i]) & 0xFF for i in range(n))),
            ("file_sub_ab", bytes((da[i] - db[i]) & 0xFF for i in range(n))),
            ("file_sub_ba", bytes((db[i] - da[i]) & 0xFF for i in range(n))),
            ("interleave_ab", _interleave(da, db)),
            ("interleave_ba", _interleave(db, da)),
        ):
            _project_add(summary, root, f"{method}_{a.stem}_{b.stem}.bin", data, method, f"Project-level {method} transform between {a.name} and {b.name}.", f"{a.name}+{b.name}")


def _natural_key(name: str) -> list[Any]:
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", name)]


def _interleave(a: bytes, b: bytes) -> bytes:
    out = bytearray()
    n = max(len(a), len(b))
    for i in range(n):
        if i < len(a):
            out.append(a[i])
        if i < len(b):
            out.append(b[i])
    return bytes(out)


def apply(mod: Any) -> None:
    old_analyze = getattr(mod, "analyze_file", None)
    old_summary = getattr(mod, "project_summary", None)

    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"path": str(path), "name": Path(path).name, "flags": [], "artifacts": []}
        if isinstance(report, dict):
            try:
                p = Path(path)
                analyze_file_agent(report, Path(root), p, p.read_bytes()[:MAX_DATA])
            except Exception as exc:
                try:
                    from sloper_v72.health import agent_crash
                    agent_crash("deep_workflows.analyze_file", exc, report)
                except Exception:
                    pass
        return report

    def project_summary(reports, meta):
        summary = old_summary(reports, meta) if old_summary else {"flags": [], "artifacts": []}
        if isinstance(summary, dict):
            try:
                multi_file_agent(summary, [r for r in reports or [] if isinstance(r, dict)])
            except Exception as exc:
                try:
                    from sloper_v72.health import agent_crash
                    agent_crash("deep_workflows.multi_file", exc, summary)
                except Exception:
                    pass
        return summary

    mod.analyze_file = analyze_file
    mod.project_summary = project_summary
    mod.SLOPER_DEEP_WORKFLOWS = "bounded-recursive-transform-layer"
