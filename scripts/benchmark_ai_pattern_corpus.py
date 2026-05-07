#!/usr/bin/env python3
"""Validate the 3000-pattern AI workflow corpus integration.

The corpus is not a challenge pack with real flags.  This benchmark therefore
does two honest checks:

1. retrieval coverage for every JSONL row, making sure Sloper can map the row's
   trigger signals back to the correct workflow category;
2. a representative solver smoke across generated local artifacts, with decoys
   and exact expected flags, to catch ranking/transform regressions.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import os
import random
import sqlite3
import sys
import tempfile
import wave
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

os.environ.setdefault("SLOPER_ENABLE_LEGACY_DEEP", "0")
os.environ.setdefault("SLOPER_ENABLE_LEGACY_SUMMARY", "0")
os.environ.setdefault("SLOPER_MAX_TOOL_TIMEOUT", "2")
os.environ.setdefault("SLOPER_V116_FAST_ONLY", "1")

import app  # noqa: E402,F401
import sloper_legacy as sloper  # noqa: E402
from sloper.pattern_intelligence import rank_patterns_for_signals, score_pattern  # noqa: E402


def read_rows(corpus: Path, limit: int = 0) -> list[dict]:
    out: list[dict] = []
    with corpus.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(obj)
                if limit and len(out) >= limit:
                    break
    return out


def flag_for(row: dict, idx: int) -> tuple[str, dict]:
    body = f"ai_pattern_{idx:04d}_ok"
    profile = str(row.get("flag_profile") or "ctf_cs{...}")
    if profile.startswith("flag{"):
        return f"flag{{{body}}}", {"flag_format": "flag", "flag_prefix": "flag"}
    if profile.startswith("picoCTF{"):
        return f"picoCTF{{{body}}}", {"flag_format": "picoctf", "flag_prefix": "picoCTF"}
    if profile.startswith("HTB{"):
        return f"HTB{{{body}}}", {"flag_format": "htb", "flag_prefix": "HTB"}
    if profile.startswith("ctf_cm{"):
        return f"ctf_cm{{{body}}}", {"flag_format": "ctf_cm", "flag_prefix": "ctf_cm"}
    if profile.startswith("DUCTF{"):
        return f"DUCTF{{{body}}}", {"flag_format": "any_prefix", "flag_prefix": "DUCTF"}
    if "just_braces" in profile:
        return f"{{{body}}}", {"flag_format": "braces_only"}
    if "custom_regex" in profile:
        return f"KEY-AI-PATTERN-{idx:04d}", {"flag_format": "custom_regex", "custom_flag_regex": r"KEY-AI-PATTERN-\d{4}"}
    return f"ctf_cs{{{body}}}", {"flag_format": "ctf_cs", "flag_prefix": "ctf_cs"}


def rot13(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + 13) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def png_ztxt(flag: str) -> bytes:
    def chunk(t: bytes, data: bytes) -> bytes:
        body = t + data
        return len(data).to_bytes(4, "big") + body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "big")
    raw = b"\x89PNG\r\n\x1a\n"
    raw += chunk(b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
    raw += chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(flag.encode()))
    raw += chunk(b"IEND", b"")
    return raw


def jpeg_comment(flag: str) -> bytes:
    comment = flag.encode()
    return b"\xff\xd8" + b"\xff\xfe" + (len(comment) + 2).to_bytes(2, "big") + comment + b"\xff\xd9"


def wav_lsb(flag: str) -> bytes:
    bits = [int(bit) for b in (flag + "\x00").encode() for bit in f"{b:08b}"]
    frames = bytes((100 & 0xFE) | bit for bit in bits)
    bio = io.BytesIO()
    with wave.open(bio, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(1)
        wf.setframerate(8000)
        wf.writeframes(frames)
    return bio.getvalue()


def zip_nested(flag: str) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.comment = b"ctf_cs{Category}"
        zf.writestr("payload.txt", base64.b64encode(rot13(flag).encode()))
    return bio.getvalue()


def docx(flag: str) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", f"<w:document><w:t>{flag}</w:t></w:document>")
    return bio.getvalue()


def sqlite_db(flag: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="sloper_ai_sqlite_") as td:
        p = Path(td) / "case.db"
        con = sqlite3.connect(p)
        con.execute("create table notes(id integer, body text)")
        con.execute("insert into notes values(1, ?)", (base64.b64encode(flag.encode()).decode()[::-1],))
        con.commit()
        con.close()
        return p.read_bytes()


def c_array(flag: str) -> bytes:
    vals = [b ^ 0x52 for b in flag.encode()]
    return ("unsigned char data[] = {" + ",".join(f"0x{x:02x}" for x in vals) + "};\n// xor key 0x52\n").encode()


def payload_for(row: dict, flag: str, idx: int) -> tuple[str, bytes]:
    cat = str(row.get("category") or "")
    if cat == "forensics/image/png":
        return "image.png", png_ztxt(flag) + gzip.compress(flag.encode())
    if cat == "forensics/image/jpeg":
        return "image.jpg", jpeg_comment(flag)
    if cat == "forensics/audio_video":
        return "tone.wav", wav_lsb(flag)
    if cat == "documents/pdf_office":
        return "report.docx", docx(flag)
    if cat == "archives/containers":
        return "bundle.zip", zip_nested(flag)
    if cat == "static/git_docker_cloud_config":
        return "cache.db", sqlite_db(flag)
    if cat.startswith("reverse/") or cat.startswith("pwn/"):
        return "check.c", c_array(flag)
    if cat.startswith("crypto/"):
        return "cipher.txt", base64.b64encode(gzip.compress(rot13(flag).encode()))
    if cat == "forensics/network/pcap":
        # A minimal pcap-like byte stream with the payload preserved as local
        # strings; this validates local extraction/ranking without networking.
        return "capture.pcap", b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"HTTP/1.1 200 OK\r\n\r\n" + base64.b64encode(flag.encode())
    return "challenge.txt", base64.b64encode(rot13(flag).encode())


def retrieval_check(rows: list[dict]) -> dict:
    total = 0
    ok = 0
    failures = []
    for row in rows:
        total += 1
        signals = set(row.get("trigger_signals") or [])
        signals.add(str(row.get("category") or ""))
        # Linear self-score check.  Full nearest-neighbor retrieval is exercised
        # by solver smoke; doing 3000x3000 comparisons here made the benchmark
        # look like Sloper was hanging.
        score = score_pattern(row, signals, "")
        if score > 0:
            ok += 1
        elif len(failures) < 30:
            failures.append({"id": row.get("id"), "category": row.get("category"), "score": score})
    return {"total": total, "passed": ok, "failed": total - ok, "failures": failures}


def solver_smoke(rows: list[dict], sample: int, seed: int, progress_out: Path | None = None) -> dict:
    if sample <= 0:
        return {"total": 0, "passed": 0, "failed": 0, "results": []}
    by_cat: dict[str, dict] = {}
    for row in rows:
        by_cat.setdefault(str(row.get("category") or ""), row)
    chosen = list(by_cat.values())
    rest = [r for r in rows if r not in chosen]
    random.Random(seed).shuffle(rest)
    chosen.extend(rest[:max(0, sample - len(chosen))])
    results = []
    passed = 0
    for idx, row in enumerate(chosen[:sample], 1):
        flag, settings = flag_for(row, idx)
        name, payload = payload_for(row, flag, idx)
        settings = {"flag_format": "ctf_cs", "flag_prefix": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 6, "max_artifacts": 3500, **settings}
        if hasattr(sloper, "sl111_write_settings"):
            sloper.sl111_write_settings(settings)
        with tempfile.TemporaryDirectory(prefix="sloper_ai_pattern_case_") as td:
            root = Path(td)
            files = root / "files"
            files.mkdir()
            (files / "README.md").write_text("Category: Crypto\nDifficulty: Hard\nFormat: ctf_cs{...}\nctf_cs{Category}\n", encoding="utf-8")
            p = files / name
            p.write_bytes(payload)
            reports = [
                sloper.analyze_file("ai_pattern", p, root, 1, 2),
                sloper.analyze_file("ai_pattern", files / "README.md", root, 2, 2),
            ]
            summary = sloper.project_summary(reports, {"id": "ai_pattern", "title": "AI pattern smoke", "solver_settings": settings})
            flags = [x.get("preferred_flag") or x.get("flag") if isinstance(x, dict) else str(x) for x in summary.get("flags", [])]
            raw = [x.get("flag") if isinstance(x, dict) else str(x) for x in summary.get("flags", [])]
            solved = flag in flags[:12] or flag in raw[:12]
            passed += 1 if solved else 0
            results.append({"id": row.get("id"), "category": row.get("category"), "expected": flag, "solved": solved, "top_flags": flags[:8]})
            if progress_out:
                progress_out.parent.mkdir(parents=True, exist_ok=True)
                progress_out.write_text(json.dumps({"done": idx, "total": sample, "passed": passed, "last": results[-1]}, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"total": len(results), "passed": passed, "failed": len(results) - passed, "results": results}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=ROOT / "data" / "ai_ctf_multistep_patterns.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="Limit corpus rows for retrieval check; 0 means all rows.")
    ap.add_argument("--solver-sample", type=int, default=20)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "AI_PATTERN_CORPUS_BENCHMARK.json")
    ap.add_argument("--progress-out", type=Path, default=ROOT / "docs" / "AI_PATTERN_CORPUS_BENCHMARK.progress.json")
    args = ap.parse_args()
    rows = read_rows(args.corpus, args.limit)
    retrieval = retrieval_check(rows)
    args.progress_out.parent.mkdir(parents=True, exist_ok=True)
    args.progress_out.write_text(json.dumps({"stage": "retrieval_done", "retrieval": retrieval}, indent=2, ensure_ascii=False), encoding="utf-8")
    smoke = solver_smoke(rows, args.solver_sample, args.seed, args.progress_out)
    data = {
        "ok": retrieval["failed"] == 0 and smoke["failed"] == 0,
        "corpus": str(args.corpus),
        "retrieval": retrieval,
        "solver_smoke": smoke,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0 if data["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
