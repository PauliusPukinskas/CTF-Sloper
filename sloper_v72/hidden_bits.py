
"""CTF SLOPER v72 zero-width and whitespace bit-channel solvers."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
from .health import agent_crash

ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"

def text_score(txt: str) -> int:
    txt = str(txt or "")
    score = int(sum(1 for c in txt if 32 <= ord(c) < 127 or c in "\r\n\t") / max(1, len(txt)) * 100)
    low = txt.lower()
    for w in ["ctf_cs{", "flag{", "secret", "password", "token", "cyber", "sprint", "raktas", "slapta"]:
        if w in low:
            score += 150
    if "{" in txt and "}" in txt:
        score += 80
    return score

def bits_to_text(bits: str) -> List[Dict[str, Any]]:
    bits = "".join(c for c in str(bits) if c in "01")
    out = []
    for offset in range(8):
        usable = bits[offset:]
        raw = bytearray()
        for i in range(0, len(usable) - 7, 8):
            try:
                raw.append(int(usable[i:i+8], 2))
            except Exception:
                pass
        if raw:
            txt = bytes(raw).decode("utf-8", "ignore")
            if txt.strip():
                out.append({"offset": offset, "endian": "msb", "text": txt[:200000], "hex_head": bytes(raw[:64]).hex(), "score": text_score(txt)})
        raw = bytearray()
        for i in range(0, len(usable) - 7, 8):
            try:
                raw.append(int(usable[i:i+8][::-1], 2))
            except Exception:
                pass
        if raw:
            txt = bytes(raw).decode("utf-8", "ignore")
            if txt.strip():
                out.append({"offset": offset, "endian": "lsb", "text": txt[:200000], "hex_head": bytes(raw[:64]).hex(), "score": text_score(txt)})
    return sorted(out, key=lambda x: x.get("score", 0), reverse=True)

def decode_zero_width(text: str) -> List[Dict[str, Any]]:
    text = str(text or "")
    maps = [
        {"\u200b": "0", "\u200c": "1"},
        {"\u200c": "0", "\u200d": "1"},
        {"\u200b": "0", "\u200d": "1"},
        {"\u2060": "0", "\ufeff": "1"},
    ]
    present = [c for c in text if c in ZERO_WIDTH_CHARS]
    if not present:
        return []
    results = []
    for mp in maps:
        bits = "".join(mp[c] for c in text if c in mp)
        if len(bits) >= 8:
            for item in bits_to_text(bits):
                item.update({"method": "zero_width", "chars": len(present), "bit_len": len(bits)})
                results.append(item)
    return sorted(results, key=lambda x: x.get("score", 0), reverse=True)[:80]

def decode_whitespace_bits(text: str) -> List[Dict[str, Any]]:
    text = str(text or "")
    variants = []
    bits = "".join("0" if c == " " else "1" for c in text if c in " \t")
    if len(bits) >= 8:
        variants.append(("space_tab_all_space0_tab1", bits))
        variants.append(("space_tab_all_tab0_space1", bits.translate(str.maketrans("01", "10"))))

    trailing = []
    for line in text.splitlines():
        tail = line[len(line.rstrip(" \t")):]
        trailing.extend("0" if c == " " else "1" for c in tail)
    if len(trailing) >= 8:
        bits = "".join(trailing)
        variants.append(("trailing_space0_tab1", bits))
        variants.append(("trailing_tab0_space1", bits.translate(str.maketrans("01", "10"))))

    blank = "".join("1" if not line.strip() else "0" for line in text.splitlines())
    if len(blank) >= 8 and "1" in blank:
        variants.append(("blank_line_channel", blank))

    results = []
    for name, bits in variants:
        for item in bits_to_text(bits):
            item.update({"method": name, "bit_len": len(bits)})
            results.append(item)
    return sorted(results, key=lambda x: x.get("score", 0), reverse=True)[:100]

def safe_name(mod, name: str) -> str:
    try:
        return mod.safe(name)
    except Exception:
        import re
        return re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "file"))[:160] or "file"

def scan_flags(mod, report: dict, text: str, source: str, artifact: str | None = None, score: int = 330) -> None:
    try:
        if hasattr(mod, "sl70_scan_text_for_flags"):
            mod.sl70_scan_text_for_flags(report, str(text or ""), source=source, artifact=artifact, score=score)
            return
    except Exception as e:
        agent_crash("legacy sl70_scan_text_for_flags", e, report)
    try:
        if hasattr(mod, "vf_primary_flags"):
            for flag in mod.vf_primary_flags(str(text or ""), limit=20, scan_limit=600000):
                report.setdefault("flags", [])
                if flag not in report["flags"]:
                    report["flags"].append(flag)
    except Exception as e:
        agent_crash("legacy vf_primary_flags", e, report)

def write_artifact(mod, root, report: dict, name: str, content, kind: str, score: int, note: str):
    try:
        root = Path(root)
        outdir = root / "generated" / "sloper72" / safe_name(mod, report.get("name", "file"))
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / safe_name(mod, name)
        if isinstance(content, (bytes, bytearray)):
            p.write_bytes(content)
            text = bytes(content[:800000]).decode("utf-8", "ignore")
        else:
            p.write_text(str(content), encoding="utf-8", errors="ignore")
            text = str(content)
        art = {
            "kind": kind,
            "name": p.name,
            "path": str(p),
            "url": "/api/raw?path=" + str(p),
            "source": "CTF SLOPER v72",
            "score": int(score),
            "note": note,
            "exists": True,
            "size": p.stat().st_size,
            "file": report.get("rel", ""),
        }
        report.setdefault("artifacts", []).append(art)
        report.setdefault("transformations", []).append(art)
        scan_flags(mod, report, text, "SLOPER v72 artifact", str(p), score)
        return art
    except Exception as e:
        agent_crash("v72 write_artifact", e, report)
        return None

def zero_width_whitespace_agent(mod, report: dict, root, data):
    try:
        text = data[:2_000_000].decode("utf-8", "ignore") if isinstance(data, bytes) else str(data)
        artifacts = []
        zw = decode_zero_width(text)
        if zw:
            art = write_artifact(mod, root, report, "zero_width_decode_candidates.json", json.dumps(zw, indent=2, ensure_ascii=False), "sloper72_zero_width_decode", 430, "Zero-width Unicode hidden-bit decode candidates.")
            if art:
                artifacts.append(art)
            for item in zw[:20]:
                scan_flags(mod, report, item.get("text", ""), "SLOPER v72 zero-width", art.get("path") if art else None, 420)
        ws = decode_whitespace_bits(text)
        if ws:
            art = write_artifact(mod, root, report, "whitespace_bits_decode_candidates.json", json.dumps(ws, indent=2, ensure_ascii=False), "sloper72_whitespace_bits_decode", 430, "Whitespace hidden-bit decode candidates.")
            if art:
                artifacts.append(art)
            for item in ws[:20]:
                scan_flags(mod, report, item.get("text", ""), "SLOPER v72 whitespace bits", art.get("path") if art else None, 420)
        if artifacts:
            report.setdefault("next_steps", []).insert(0, {"priority": 99, "step": "Open v72 zero-width/whitespace artifacts.", "why": "Hidden Unicode/whitespace bit channels were decoded into artifacts and scanned for flags."})
        return artifacts
    except Exception as e:
        agent_crash("v72 zero_width_whitespace_agent", e, report)
        return []
