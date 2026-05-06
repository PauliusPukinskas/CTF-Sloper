
"""CTF SLOPER v72 artifact hub utilities."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List

def compact_hub(summary: Dict[str, Any]) -> Dict[str, Any]:
    artifacts: List[dict] = summary.get("artifacts", []) or []
    flags = summary.get("flags", []) or []
    wrappers = summary.get("flag_wrapping_helpers", []) or []
    groups = {
        "start_here": [],
        "transforms": [],
        "visual": [],
        "crypto_decode": [],
        "archives": [],
        "network": [],
        "reversing": [],
        "misc": [],
    }
    for a in artifacts:
        text = (a.get("kind", "") + " " + a.get("name", "") + " " + a.get("note", "")).lower()
        if any(k in text for k in ["contact_sheet", "bitplane", "png", "image", "visual", "lsb", "palette"]):
            groups["visual"].append(a)
        elif any(k in text for k in ["decode", "crypto", "xor", "classic", "vigenere", "whitespace", "zero_width"]):
            groups["crypto_decode"].append(a)
        elif any(k in text for k in ["zip", "tar", "gzip", "archive", "carve", "embedded"]):
            groups["archives"].append(a)
        elif any(k in text for k in ["pcap", "tcp", "udp", "icmp", "dns", "http"]):
            groups["network"].append(a)
        elif any(k in text for k in ["elf", "binary", "rodata", "constant_array", "transform_graph", "revers"]):
            groups["reversing"].append(a)
        elif any(k in text for k in ["transform", "child", "generated"]):
            groups["transforms"].append(a)
        else:
            groups["misc"].append(a)
    groups["start_here"] = sorted(artifacts, key=lambda x: int(x.get("score", 0) or 0), reverse=True)[:20]
    return {
        "flags": flags[:20],
        "wrappers": wrappers[:20],
        "groups": {k: v[:60] for k, v in groups.items()},
        "counts": {k: len(v) for k, v in groups.items()},
    }
