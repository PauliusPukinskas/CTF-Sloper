#!/usr/bin/env python3
"""Local regression benchmark for CTF SLOPER.

v114 checks competition evidence ranking, decoy suppression, recursive decoding,
archives, office docs, SQLite, PNG chunks, WAV LSB, image LSB, and hidden text channels.  It does not execute challenge
binaries or touch the network.
"""
from __future__ import annotations

import base64
import gzip
import io
import json
import os
import sys
import subprocess
import tempfile
import time
import zipfile
import sqlite3
import wave
import zlib
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

os.environ.setdefault("SLOPER_ENABLE_LEGACY_DEEP", "0")
os.environ.setdefault("SLOPER_ENABLE_LEGACY_SUMMARY", "0")
os.environ.setdefault("SLOPER_MAX_TOOL_TIMEOUT", "2")

import app  # noqa: E402,F401
import sloper_legacy as sloper  # noqa: E402
from sloper.bench_runner import python_cmd, run_json_file_worker, write_json  # noqa: E402


def b64(x: bytes) -> bytes:
    return base64.b64encode(x)


def rot13_text(s: str) -> str:
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


def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def zip_bytes(name: str, data: bytes) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, data)
    return bio.getvalue()


def nested_zip_case() -> bytes:
    inner = zip_bytes("deep/flag.txt", b64(rot13_text("ctf_cs{zip_nested_real_16}").encode()))
    return zip_bytes("layer1.bin", inner)


def whitespace_case() -> bytes:
    payload = b"ctf_cs{space_tab_hidden_17}"
    bits = "".join(f"{b:08b}" for b in payload)
    return ("cover\n" + "".join("\t" if bit == "1" else " " for bit in bits)).encode()


def case_bits_case() -> bytes:
    payload = b"ctf_cs{case_bits_hidden_18}"
    bits = "".join(f"{b:08b}" for b in payload)
    chars = []
    alpha = "abcdefghijklmnopqrstuvwxyz"
    for i, bit in enumerate(bits):
        ch = alpha[i % len(alpha)]
        chars.append(ch.upper() if bit == "1" else ch)
    return ("noise " + "".join(chars)).encode()


def image_lsb_case() -> bytes:
    try:
        from PIL import Image
    except Exception:
        return b"ctf_cs{image_lsb_skipped_19}"
    payload = b"ctf_cs{image_lsb_rgb_19}\x00"
    bits = [int(x) for b in payload for x in f"{b:08b}"]
    w, h = 96, 32
    px = []
    it = iter(bits)
    for _ in range(w * h):
        vals = []
        for base in (120, 121, 122):
            bit = next(it, 0)
            vals.append((base & 0xFE) | bit)
        px.append(tuple(vals))
    im = Image.new("RGB", (w, h))
    im.putdata(px)
    bio = io.BytesIO()
    im.save(bio, format="PNG")
    return bio.getvalue()


def decoy_case() -> bytes:
    return b"ctf_cs{fake_example_ignore_me}\n" + b64(gzip.compress(b"real answer: ctf_cs{real_after_decoy_20}"))


def docx_xml_case() -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document><w:body><w:t>ctf_cs{docx_xml_text_21}</w:t></w:body></w:document>")
    return bio.getvalue()


def sqlite_case() -> bytes:
    with tempfile.TemporaryDirectory(prefix="sloper_sqlite_case_") as td:
        p = Path(td) / "case.db"
        con = sqlite3.connect(p)
        con.execute("create table notes(id integer, body text)")
        con.execute("insert into notes values(1, 'operator note ctf_cs{sqlite_table_22}')")
        con.commit(); con.close()
        return p.read_bytes()


def png_ztxt_case() -> bytes:
    def chunk(t: bytes, data: bytes) -> bytes:
        import struct
        body = t + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)
    raw = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
    raw += chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(b"ctf_cs{png_ztxt_23}"))
    raw += chunk(b"IEND", b"")
    return raw


def wav_lsb_case() -> bytes:
    payload = b"ctf_cs{wav_lsb_24}\x00"
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    frames = bytes((100 & 0xFE) | bit for bit in bits)
    bio = io.BytesIO()
    with wave.open(bio, "wb") as wf:
        wf.setnchannels(1); wf.setsampwidth(1); wf.setframerate(8000); wf.writeframes(frames)
    return bio.getvalue()


def frontier_nested_case() -> bytes:
    return base64.b64encode(zlib.compress(b"ctf_cs{frontier_nested_25}"))


def xor_rescue_case() -> bytes:
    return bytes(b ^ 0x42 for b in b"ctf_cs{xor_rescue_26}")


CASES = [
    {"case": "plain_ctf_cs", "data": b"notes: ctf_cs{bench_plain_01}\n", "expected": "ctf_cs{bench_plain_01}", "settings": {"flag_format": "ctf_cs", "attack_preset": "quick", "difficulty": "easy", "max_depth": 1}},
    {"case": "base64_ctf_cs", "data": b64(b"ctf_cs{bench_base64_02}"), "expected": "ctf_cs{bench_base64_02}", "settings": {"flag_format": "ctf_cs", "attack_preset": "balanced", "difficulty": "medium", "max_depth": 2}},
    {"case": "hex_ctf_cs", "data": b"prefix " + b"ctf_cs{bench_hex_03}".hex().encode(), "expected": "ctf_cs{bench_hex_03}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "url_ctf_cs", "data": b"%63%74%66%5F%63%73%7Bbench_url_04%7D", "expected": "ctf_cs{bench_url_04}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "rot13_ctf_cs", "data": b"pgs_pf{orapu_ebg13_05}", "expected": "ctf_cs{bench_rot13_05}", "settings": {"flag_format": "ctf_cs"}},
    {"case": "ctf_cm_selected", "data": b"answer: ctf_cm{bench_custom_prefix_06}", "expected": "ctf_cm{bench_custom_prefix_06}", "settings": {"flag_format": "ctf_cm", "flag_prefix": "ctf_cm"}},
    {"case": "flag_selected", "data": b"flag{bench_flag_prefix_07}", "expected": "flag{bench_flag_prefix_07}", "settings": {"flag_format": "flag", "flag_prefix": "flag"}},
    {"case": "braces_only_selected", "data": b"hidden {bench_bare_braces_08}", "expected": "{bench_bare_braces_08}", "settings": {"flag_format": "braces_only"}},
    {"case": "custom_regex_selected", "data": b"ticket KEY-BENCH-09 accepted", "expected": "KEY-BENCH-09", "settings": {"flag_format": "custom_regex", "custom_flag_regex": r"KEY-[A-Z0-9-]+"}},
    {"case": "multistep_base64_rot13", "data": b64(rot13_text("ctf_cs{multi_step_10}").encode()), "expected": "ctf_cs{multi_step_10}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 4, "max_artifacts": 2500}},
    {"case": "multistep_base64_hex", "data": b64(b"ctf_cs{hex_inside_11}".hex().encode()), "expected": "ctf_cs{hex_inside_11}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 4}},
    {"case": "url_base64_rot13", "data": quote(base64.b64encode(rot13_text("ctf_cs{url_b64_rot_12}").encode()).decode()).encode(), "expected": "ctf_cs{url_b64_rot_12}", "settings": {"flag_format": "ctf_cs", "max_depth": 4}},
    {"case": "gzip_base64", "data": b64(gzip.compress(b"ctf_cs{gzip_b64_13}")), "expected": "ctf_cs{gzip_b64_13}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "max_depth": 4}},
    {"case": "single_byte_xor", "data": xor(b"ctf_cs{xor_42_14}", 42), "expected": "ctf_cs{xor_42_14}", "settings": {"flag_format": "ctf_cs", "attack_preset": "balanced", "max_depth": 2}},
    {"case": "base32", "data": base64.b32encode(b"ctf_cs{base32_15}"), "expected": "ctf_cs{base32_15}", "settings": {"flag_format": "ctf_cs", "max_depth": 2}},
    {"case": "nested_zip_base64_rot13", "data": nested_zip_case, "expected": "ctf_cs{zip_nested_real_16}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 5}},
    {"case": "space_tab_hidden", "data": whitespace_case, "expected": "ctf_cs{space_tab_hidden_17}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "max_depth": 3}},
    {"case": "case_bits_hidden", "data": case_bits_case, "expected": "ctf_cs{case_bits_hidden_18}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "max_depth": 3}},
    {"case": "image_lsb_rgb", "data": image_lsb_case, "expected": "ctf_cs{image_lsb_rgb_19}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 3}, "suffix": ".png"},
    {"case": "decoy_demoted_real_promoted", "data": decoy_case, "expected": "ctf_cs{real_after_decoy_20}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "hard", "max_depth": 4}, "not_top": "ctf_cs{fake_example_ignore_me}"},
    {"case": "docx_xml_text", "data": docx_xml_case, "expected": "ctf_cs{docx_xml_text_21}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 5}, "suffix": ".docx"},
    {"case": "sqlite_table", "data": sqlite_case, "expected": "ctf_cs{sqlite_table_22}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "forensics", "max_depth": 5}, "suffix": ".db"},
    {"case": "png_ztxt", "data": png_ztxt_case, "expected": "ctf_cs{png_ztxt_23}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "stego", "max_depth": 5}, "suffix": ".png"},
    {"case": "wav_lsb", "data": wav_lsb_case, "expected": "ctf_cs{wav_lsb_24}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "stego", "max_depth": 5}, "suffix": ".wav"},
    {"case": "frontier_nested_zlib_base64", "data": frontier_nested_case, "expected": "ctf_cs{frontier_nested_25}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "multi_step", "max_depth": 5}},
    {"case": "xor_rescue", "data": xor_rescue_case, "expected": "ctf_cs{xor_rescue_26}", "settings": {"flag_format": "ctf_cs", "attack_preset": "deep", "difficulty": "hard", "max_depth": 4}},
]



# Run very expensive visual image benchmark last so PIL memory/cache state cannot
# affect document/container cases during normal validation.
CASES = [c for c in CASES if c["case"] != "image_lsb_rgb"] + [c for c in CASES if c["case"] == "image_lsb_rgb"]

def set_settings(settings: dict) -> None:
    # Write a full baseline so one benchmark case cannot leak max_depth,
    # max_artifacts, or attack preset into the next case.
    baseline = {
        "flag_format": "ctf_cs",
        "flag_prefix": "ctf_cs",
        "custom_flag_regex": "",
        "attack_preset": "balanced",
        "difficulty": "medium",
        "max_depth": 2,
        "max_artifacts": 800,
    }
    full = {**baseline, **(settings or {})}
    if hasattr(sloper, "sl111_write_settings"):
        sloper.sl111_write_settings(full)


def case_data(case: dict) -> bytes:
    data = case["data"]
    return data() if callable(data) else data


def run_case(case: dict) -> dict:
    set_settings(case.get("settings", {}))
    with tempfile.TemporaryDirectory(prefix="sloper_bench_") as td:
        root = Path(td)
        files = root / "files"
        files.mkdir()
        suffix = case.get("suffix", ".bin")
        path = files / f"{case['case']}{suffix}"
        path.write_bytes(case_data(case))
        meta = {"id": "bench", "title": "benchmark", "solver_settings": case.get("settings", {})}
        start = time.perf_counter()
        report = sloper.analyze_file("bench", path, root, 1, 1)
        summary = sloper.project_summary([report], meta)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        found = [item.get("flag") if isinstance(item, dict) else str(item) for item in summary.get("flags", []) or []]
        preferred = [item.get("preferred_flag") or item.get("flag") if isinstance(item, dict) else str(item) for item in summary.get("preferred_flags", []) or []]
        expected = case["expected"]
        ok = expected in found or expected in preferred
        not_top_ok = True
        if case.get("not_top") and (found or preferred):
            top = (preferred or found)[0]
            not_top_ok = top != case["not_top"]
        return {
            "case": case["case"],
            "expected": expected,
            "ok": bool(ok and not_top_ok),
            "elapsed_ms": elapsed_ms,
            "settings": case.get("settings", {}),
            "top_flags": found[:8],
            "preferred": preferred[:8],
            "not_top_ok": not_top_ok,
            "fast_lane": report.get("v110_fast_lane", {}),
            "competition": report.get("v113_competition", {}),
            "evidence": summary.get("v113_evidence", {}),
        }


def _run_case_worker(idx: int) -> dict:
    return _run_case_chunk([idx])[0]


def _run_case_chunk(indices: list[int]) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="sloper_bench_worker_") as td:
        outp = Path(td) / "result.json"
        cmd = python_cmd(Path(__file__).resolve(), "--case-indices", ",".join(str(i) for i in indices), "--worker-out", str(outp))
        worker_timeout = int(os.environ.get("SLOPER_BENCH_WORKER_TIMEOUT", "20"))
        ok, data, err = run_json_file_worker(cmd, ROOT, worker_timeout, outp)
    if ok and isinstance(data, list):
        return data
    return [{"case": CASES[i]["case"], "expected": CASES[i].get("expected"), "ok": False, "elapsed_ms": 0, "error": err or "worker failed"} for i in indices]


def main() -> int:
    worker_out = None
    if "--worker-out" in sys.argv:
        worker_out = Path(sys.argv[sys.argv.index("--worker-out") + 1])
    if "--case-indices" in sys.argv:
        raw = sys.argv[sys.argv.index("--case-indices") + 1]
        indices = [int(x) for x in raw.split(",") if x.strip()]
        rows = [run_case(CASES[i]) for i in indices]
        if worker_out:
            write_json(worker_out, rows)
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    if "--case-index" in sys.argv:
        idx = int(sys.argv[sys.argv.index("--case-index") + 1])
        row = run_case(CASES[idx])
        if worker_out:
            write_json(worker_out, row)
        print(json.dumps(row, ensure_ascii=False))
        return 0

    # Chunked subprocess mode is the default: much faster than one process per
    # case, but resets state often enough that a pathological case cannot poison
    # the rest of the benchmark. Set SLOPER_BENCH_IN_PROCESS=1 for debugging.
    in_process = os.environ.get("SLOPER_BENCH_IN_PROCESS", "0") == "1"
    results = []
    progress_path = Path(os.environ.get("SLOPER_BENCH_PROGRESS", "docs/BENCHMARK_PROGRESS.json"))
    if in_process:
        for idx, case in enumerate(CASES):
            print(f"[benchmark] {idx + 1}/{len(CASES)} {case['case']}", file=sys.stderr, flush=True)
            results.append(run_case(case))
            write_json(progress_path, {"done": len(results), "total": len(CASES), "last_case": case["case"], "results": results})
    else:
        chunk = int(os.environ.get("SLOPER_BENCH_CHUNK", "1"))
        for start in range(0, len(CASES), chunk):
            indices = list(range(start, min(start + chunk, len(CASES))))
            names = ", ".join(CASES[i]["case"] for i in indices)
            print(f"[benchmark] {indices[0] + 1}-{indices[-1] + 1}/{len(CASES)} {names}", file=sys.stderr, flush=True)
            results.extend(_run_case_chunk(indices))
            write_json(progress_path, {"done": len(results), "total": len(CASES), "last_case": names, "results": results})
    ok = sum(1 for r in results if r["ok"])
    max_ms = max((r["elapsed_ms"] for r in results), default=0)
    out = {"ok": ok == len(results), "passed": ok, "total": len(results), "max_elapsed_ms": max_ms, "results": results}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    Path("docs/BENCHMARK_RESULTS_v115.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    Path("docs/BENCHMARK_RESULTS_v114.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    Path("docs/BENCHMARK_RESULTS_v113.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    # Keep the v112 file updated enough for existing docs/scripts.
    Path("docs/BENCHMARK_RESULTS_v112.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
