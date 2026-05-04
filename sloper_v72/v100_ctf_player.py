"""CTF SLOPER v102 evidence-workflow layer.

This module deliberately wraps the stable v93-v99 pipeline instead of growing
app.py or editing the legacy monolith.  The goal is practical CTF solving:
follow real transformation chains, surface alternate flag formats, and make
generated artifacts easier to inspect.
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


ALT_FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_])((?:uid|tsg|t5g|7sg|flag|ctf|cyber|sprint)\{"
    r"([A-Za-z0-9][A-Za-z0-9_\-:+./=]{3,140})\})",
    re.I,
)
BRACED_BODY_RE = re.compile(r"(?<![A-Za-z0-9_])\{([A-Za-z0-9][A-Za-z0-9_\-:+./=]{3,140})\}")
LEETSPEAK_TOKEN_RE = re.compile(r"\b[a-z0-9]+(?:[_\-][a-z0-9]+){1,9}\b", re.I)
LEET_WORD_RE = re.compile(r"\b(?=[a-z0-9]*[03457189])[a-z0-9]{5,48}\b", re.I)


def _prefix_norm(prefix: str) -> str:
    low = str(prefix or "").lower()
    return low.translate(str.maketrans({"5": "s", "7": "t", "0": "o", "$": "s"}))


def _report_statement(report: dict) -> str:
    return (str(report.get("statement", "")) + " " + str(report.get("task", ""))).lower()


def _explicit_ctf_cs(report: dict) -> bool:
    text = _report_statement(report)
    if re.search(r"(do not|don't|without|no|neprid|ne\s+)\s*(?:add\s*)?ctf[_ ]?cs|ctf[_ ]?cs\s*(?:wrapper|apvalkal)", text):
        return False
    return "ctf_cs" in text or "ctf cs" in text


def _weak_metadata_source(source: str, why: str = "") -> bool:
    text = (str(source or "") + " " + str(why or "")).lower()
    return bool(re.search(r"metadata|member name|file name|filename|zip names|tar names|manifest|path|comment evidence", text))


def _statement_requests_filename(report: dict) -> bool:
    text = _report_statement(report)
    return bool(re.search(r"file\s*name|filename|member\s*name|archive\s*name|failo\s+pavadin|pavadinim|vard", text, re.I))


def _statement_says_filename_decoy(report: dict) -> bool:
    text = _report_statement(report)
    return bool(re.search(
        r"(?:file\s*name|filename|member\s*name|archive\s*name|failo\s+pavadin|pavadinim|vard).{0,80}"
        r"(?:decoy|fake|netik|klaid|ignore|nesvarb|red\s*herring)|"
        r"(?:decoy|fake|netik|klaid|ignore|nesvarb|red\s*herring).{0,80}"
        r"(?:file\s*name|filename|member\s*name|archive\s*name|failo\s+pavadin|pavadinim|vard)",
        text,
        re.I,
    ))


def _generated_body(body: str) -> bool:
    low = str(body or "").strip().strip("{}").lower()
    if re.search(r"^(?:ctf_)?sloper|^tmp_|^generated$|^benchmark|^project_", low):
        return True
    if re.search(r"^v\d+_(?:cybersprint|multistep|pattern|benchmark|local|work|artifact|context)", low):
        return True
    if re.search(r"^(?:rel|path|file|tmp|generated|benchmark_runs|cybersprint(?:_local)?)_", low):
        return True
    if re.search(r"^\d{1,3}_.+(?:category|difficulty|format|task)|category_.+difficulty_.+format|^statement_|^text_head_|^zip_local_\d+_|^decode_the_local_artifact_final_format_is$", low):
        return True
    if re.fullmatch(r"(?:25)*7b[a-z0-9_\-:+./=]{3,160}(?:25)*7d", low):
        return True
    if re.match(r"^(?:25)*7b[a-z0-9_\-:+./=]{3,160}$", low) or re.search(r"(?:25)*7d$", low):
        return True
    if any(x in low for x in ("benchmark_runs", "cybersprint_local", "sloper_v", "v100_cybersprint_local")):
        return True
    return False


def _noise_body_v100(body: str, source: str = "") -> bool:
    low = str(body or "").strip().strip("{}").lower()
    src = str(source or "").lower()
    if not low:
        return True
    if re.search(r"(?:^|[_-])u00[0-9a-f]{2}|(?:^|[_-])x[0-9a-f]{2}", low):
        return True
    if re.fullmatch(r"byte[_-]?array[_-](?:minus|plus|add|sub|xor|rol|ror|not|reverse)[a-z0-9_-]*", low):
        return True
    if re.fullmatch(r"(?:binary|decimal|octal|latin|utf|ascii|generic)[_-]?(?:bytes?|text|decode|decoded|candidate|payload|strings|ok)?", low):
        return True
    if re.fullmatch(r"(?:input|offset|candidate|payload|strings|decode|decoded|unwrapped|wrapper)[_-]?[a-z0-9_-]{0,24}", low):
        return True
    if re.fullmatch(r"[a-z]{1,4}\d{0,3}_ok", low) and not re.search(r"(calc|flag|secret|cyber|sprint|steg|pwn|rev|heap|shell|admin|pass|key)", low + " " + src):
        return True
    if re.fullmatch(r"[a-z0-9]{1,5}_ok", low) and not re.search(r"(calc|flag|secret|cyber|sprint|steg|pwn|rev|heap|shell|admin|pass|key)", low + " " + src):
        return True
    if "-" in low and len(low) < 14 and not re.search(r"(cwe|calc|flag|secret|cyber|sprint|steg|pwn|rev|heap|shell|admin|pass|key)", low):
        return True
    toks = [t for t in re.split(r"[_-]+", low) if t]
    if len(toks) == 2 and toks[-1] == "ok" and len(toks[0]) >= 8 and not re.search(r"\d", toks[0]):
        vowels = sum(1 for ch in toks[0] if ch in "aeiouy")
        if vowels / max(1, len(toks[0])) < 0.22:
            return True
    if re.search(r"(?:^|[_-])(?:minus|plus|offset|byte|array|candidate|generic|decoded)(?:[_-]|$)", low):
        return True
    return False


def _family(kind: str, subdir: str = "") -> str:
    text = (str(kind or "") + " " + str(subdir or "")).lower()
    if any(x in text for x in ("flag", "answer", "priority_chain", "multistep_hit")):
        return "start_here"
    if any(x in text for x in ("image", "lsb", "piet", "visual", "png", "jpg", "palette", "tile")):
        return "visual_image"
    if any(x in text for x in ("zip", "tar", "gzip", "bz2", "xz", "archive", "carve", "openxml", "container")):
        return "archives_carves"
    if any(x in text for x in ("pcap", "packet", "dns", "http", "icmp", "tcp", "udp")):
        return "pcap_network"
    if any(x in text for x in ("rev", "binary", "pyc", "array", "dword", "double", "elf", "pe")):
        return "reversing_binary"
    if any(x in text for x in ("decode", "crypto", "base", "rot", "xor", "morse", "rail", "transposition", "chain")):
        return "crypto_decode"
    if any(x in text for x in ("audio", "wav", "media", "document", "pdf", "office")):
        return "documents_audio"
    return "misc"


def add_answer_candidate(report: dict, value: str, body: str, source: str, artifact: str | None, why: str, score: int, bucket: str) -> None:
    core.ensure(report)
    body = str(body or "").strip().strip("{}")
    if _generated_body(body):
        return
    review_hint = source + " " + why + " exact braced leetspeak answer candidate"
    reviewish = bool(
        str(bucket or "").lower().startswith(("v102", "leetspeak", "bare", "alternate"))
        and 5 <= len(body) <= 120
        and (re.search(r"[03457189]", body) or "_" in body or "-" in body or BRACED_BODY_RE.search("{" + body + "}"))
    )
    if not reviewish and not core.body_quality(body, review_hint):
        return
    item = {
        "value": value,
        "body": body,
        "candidate": value,
        "bucket": bucket,
        "score": int(score),
        "source": source,
        "artifact": artifact or "",
        "why": why,
        "source_file": report.get("rel", ""),
        "submit_as_is": not _explicit_ctf_cs(report),
        "wrapped_if_required": f"ctf_cs{{{body.lower()}}}",
    }
    targets = [report.setdefault("answer_candidates", []), report.setdefault("candidate_flags", [])]
    for target in targets:
        key = (str(item.get("value", "")).lower(), item.get("artifact", ""), item.get("bucket", ""))
        existing = {
            (str(x.get("value") or x.get("candidate") or "").lower(), x.get("artifact", ""), x.get("bucket", ""))
            for x in target if isinstance(x, dict)
        }
        if key not in existing:
            target.append(dict(item))
    evidence = report.setdefault("unconfirmed_evidence", [])
    ev_key = (item["value"].lower(), item["artifact"], item["bucket"])
    existing_ev = {
        (str(x.get("value") or x.get("candidate") or "").lower(), x.get("artifact", ""), x.get("bucket", ""))
        for x in evidence if isinstance(x, dict)
    }
    if ev_key not in existing_ev:
        ev = dict(item)
        ev["confirmed"] = False
        ev["why_not_promoted"] = "Preserved for human review. It is not a final flag unless the workflow evidence is strong enough."
        evidence.append(ev)


def add_alt_candidate(report: dict, value: str, body: str, source: str, artifact: str | None, why: str, score: int) -> str | None:
    core.ensure(report)
    body = str(body or "").strip().strip("{}")
    if _generated_body(body):
        return None
    if not core.body_quality(body, source + " " + why + " alternate flag uid tsg leetspeak"):
        return None
    item = {
        "value": value,
        "body": body,
        "bucket": "alternate_format",
        "score": int(score),
        "source": source,
        "artifact": artifact or "",
        "why": why,
        "source_file": report.get("rel", ""),
    }
    bucket = report.setdefault("alternate_flag_candidates", [])
    key = (item["value"].lower(), item["artifact"], item["source"])
    if key not in {(str(x.get("value", "")).lower(), x.get("artifact", ""), x.get("source", "")) for x in bucket if isinstance(x, dict)}:
        bucket.append(item)
    add_answer_candidate(report, value, body, source, artifact, why, score, "alternate_format")
    if _explicit_ctf_cs(report) and not _weak_metadata_source(source, why):
        return core.add_flag(
            report,
            body,
            source,
            artifact,
            why + " Alternate/organizer prefix was extracted and wrapped because the task declares ctf_cs{...}.",
            score + 35,
            allow_wrap=True,
        )
    return None


def scan_braced_and_leetspeak_candidates(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 720) -> list[str]:
    s = str(text or "")
    out: list[str] = []
    for m in BRACED_BODY_RE.finditer(s[:1_500_000]):
        before = s[max(0, m.start() - 12):m.start()].lower()
        if re.search(r"(ctf_cs|uid|tsg|t5g|7sg|flag|ctf|cyber|sprint)\s*$", before):
            continue
        body = m.group(1)
        add_answer_candidate(report, "{" + body + "}", body, source, artifact, why + " Bare {body} token preserved as an answer candidate.", score, "bare_braced")
        if _explicit_ctf_cs(report) and not _weak_metadata_source(source, why):
            f = core.add_flag(report, body, source, artifact, why + " Bare {body} token wrapped because the task explicitly declares ctf_cs{...}.", score + 45, allow_wrap=True)
            if f:
                out.append(f)
    # Bare leetspeak phrases should be visible, but not promoted unless the
    # challenge explicitly requests ctf_cs wrapping.
    if re.search(r"flag|answer|atsak|rastas|text|decode|extract|hidden|secret|slapta|raktas|ctf", source + " " + why + " " + _report_statement(report), re.I):
        for m in LEETSPEAK_TOKEN_RE.finditer(s[:300_000]):
            tok = m.group(0)
            low = tok.lower()
            if low.startswith(("v93_", "v94_", "v95_", "v96_", "v97_", "v99_", "v100_")):
                continue
            if not re.search(r"[03457189]", low) and not core.SEMANTIC_HINTS.search(low):
                continue
            add_answer_candidate(report, tok, tok, source, artifact, why + " Leetspeak/underscore phrase preserved as a possible non-wrapper answer.", score - 60, "leetspeak_phrase")
            if _explicit_ctf_cs(report) and not _weak_metadata_source(source, why):
                f = core.add_flag(report, tok, source, artifact, why + " Leetspeak phrase wrapped because the task explicitly declares ctf_cs{...}.", score, allow_wrap=True)
                if f:
                    out.append(f)
    return list(dict.fromkeys(out))


def _url_decode_layers(text: str, rounds: int = 3) -> list[str]:
    vals = [str(text or "")]
    cur = vals[0]
    for _ in range(rounds):
        try:
            nxt = urllib.parse.unquote_plus(cur)
        except Exception:
            break
        if nxt == cur or nxt in vals:
            break
        vals.append(nxt)
        cur = nxt
    return vals


def scan_alt_formats(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 760) -> list[str]:
    out: list[str] = []
    seen_text = set()
    for s in _url_decode_layers(str(text or "")):
        if s in seen_text:
            continue
        seen_text.add(s)
        for m in ALT_FLAG_RE.finditer(s[:1_500_000]):
            full, body = m.group(1), m.group(2)
            prefix = full.split("{", 1)[0]
            norm = _prefix_norm(prefix)
            if norm in {"uid", "tsg", "flag", "ctf", "cyber", "sprint"}:
                f = add_alt_candidate(report, full, body, source, artifact, why + f" Found {prefix}{{...}} alternate flag token.", score)
                if f:
                    out.append(f)
        out += scan_braced_and_leetspeak_candidates(report, s, source, artifact, why, score - 20)
    return out


def preserve_unconfirmed_strict(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 680) -> None:
    for m in core.STRICT_RE.finditer(str(text or "")[:1_000_000]):
        add_answer_candidate(
            report,
            m.group(0),
            m.group(1),
            source,
            artifact,
            why + " Strict-looking token preserved for review but not treated as final evidence.",
            score,
            "unconfirmed_strict",
        )


MORSE_V100 = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H",
    "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P",
    "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}

NATO_V100 = {
    "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D", "echo": "E", "foxtrot": "F",
    "golf": "G", "hotel": "H", "india": "I", "juliett": "J", "juliet": "J", "kilo": "K",
    "lima": "L", "mike": "M", "november": "N", "oscar": "O", "papa": "P", "quebec": "Q",
    "romeo": "R", "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W",
    "xray": "X", "x-ray": "X", "yankee": "Y", "zulu": "Z",
}


def _bytes_to_text(blob: bytes) -> str:
    return bytes(blob or b"").decode("utf-8", "ignore")


def _printable_ratio(blob: bytes) -> float:
    b = bytes(blob or b"")
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in b"\r\n\t") / len(b)


def _scan_blob(report: dict, root: Path, name: str, blob: bytes | str, kind: str, why: str, score: int = 820, subdir: str = "v100") -> list[dict]:
    art = core.artifact(root, report, name, blob, kind, why, score, subdir)
    return [art] if art else []


def _decode_bacon(text: str) -> str:
    groups = re.findall(r"[ABab]{5}", text)
    out = []
    for g in groups[:2000]:
        n = 0
        for ch in g.upper():
            n = (n << 1) | (1 if ch == "B" else 0)
        if 0 <= n < 26:
            out.append(chr(ord("A") + n))
    return "".join(out)


def _morse_decode(text: str) -> str:
    toks = re.split(r"(\s*/\s*|\s+)", text.strip())
    out = []
    for tok in toks[:5000]:
        t = tok.strip()
        if not t:
            continue
        if "/" in t:
            out.append(" ")
        elif re.fullmatch(r"[.\-]+", t):
            out.append(MORSE_V100.get(t, ""))
    return "".join(out)


def _decode_nato(text: str) -> str:
    words = re.findall(r"[A-Za-z]+(?:-[A-Za-z]+)?", text.lower())
    out = [NATO_V100[w] for w in words if w in NATO_V100]
    return "".join(out) if len(out) >= 4 else ""


def _columnar_decrypt(cipher: str, key: str) -> str:
    c = re.sub(r"[^A-Za-z0-9_{}]", "", cipher)
    k = re.sub(r"[^A-Za-z0-9]", "", key).upper()
    if len(k) < 2 or len(k) > 16 or len(c) < len(k) * 2:
        return ""
    cols = len(k)
    rows = (len(c) + cols - 1) // cols
    short = rows * cols - len(c)
    order = sorted(range(cols), key=lambda i: (k[i], i))
    col_lens = [rows] * cols
    for idx in (order[-short:] if short else []):
        col_lens[idx] -= 1
    pos = 0
    grid = [""] * cols
    for idx in order:
        n = col_lens[idx]
        grid[idx] = c[pos:pos + n]
        pos += n
    out = []
    for r in range(rows):
        for col in grid:
            if r < len(col):
                out.append(col[r])
    return "".join(out)


def _phrase_to_ctf(report: dict, text: str, source: str, artifact: str | None, why: str, score: int) -> None:
    raw = re.sub(r"[^A-Za-z0-9]+", " ", str(text or "")).strip()
    low = raw.lower()
    for prefix in ("ctf cs ", "ctf_cs "):
        if low.startswith(prefix):
            body = re.sub(r"[^a-z0-9]+", "_", low[len(prefix):]).strip("_")
            if body:
                core.add_flag(report, body, source, artifact, why + " Normalized decoded CTF CS phrase.", score, allow_wrap=True)
    compact = re.sub(r"[^a-z0-9]+", "", low)
    ctfcs_pos = compact.find("ctfcs")
    if ctfcs_pos >= 0 and len(compact) - ctfcs_pos > 8:
        body = compact[ctfcs_pos + 5:]
        if body:
            core.add_flag(report, body, source, artifact, why + " Normalized decoded compact ctfcs phrase.", score, allow_wrap=True)


def _v102_caesar(text: str, shift: int) -> str:
    out = []
    for ch in str(text or ""):
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _v102_atbash(text: str) -> str:
    out = []
    for ch in str(text or ""):
        if "a" <= ch <= "z":
            out.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            out.append(chr(90 - (ord(ch) - 65)))
        else:
            out.append(ch)
    return "".join(out)


def _v102_rot47(text: str) -> str:
    out = []
    for ch in str(text or ""):
        o = ord(ch)
        out.append(chr(33 + ((o + 14) % 94)) if 33 <= o <= 126 else ch)
    return "".join(out)


def _v102_rail_decrypt(cipher: str, rails: int) -> str:
    c = str(cipher or "")
    if rails < 2 or len(c) < rails * 2:
        return ""
    pattern = []
    row = 0
    step = 1
    for _ in c:
        pattern.append(row)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    counts = [pattern.count(r) for r in range(rails)]
    chunks = []
    pos = 0
    for n in counts:
        chunks.append(list(c[pos:pos + n]))
        pos += n
    out = []
    curs = [0] * rails
    for r in pattern:
        out.append(chunks[r][curs[r]])
        curs[r] += 1
    return "".join(out)


def _v102_score_text(text: str) -> int:
    s = str(text or "")
    if not s:
        return 0
    low = s.lower()
    score = 0
    if core.STRICT_RE.search(s):
        score += 500
    if ALT_FLAG_RE.search(s) or BRACED_BODY_RE.search(s):
        score += 230
    if re.search(r"(flag|answer|secret|hidden|slapta|atsak|raktas|cyber|sprint)", low):
        score += 120
    if re.search(r"[a-z0-9]+[_-][a-z0-9]+", low):
        score += 70
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t") / max(1, len(s))
    score += int(printable * 100)
    if len(s) > 20 and printable > 0.88:
        score += 50
    if len(re.findall(r"[A-Za-z]{3,}", s)) >= 2:
        score += 35
    return score


def _v102_try_decompress(blob: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    if not blob or len(blob) > 8_000_000:
        return out
    trials = [
        ("gzip", lambda b: gzip.decompress(b)),
        ("zlib", lambda b: zlib.decompress(b)),
        ("raw_deflate", lambda b: zlib.decompress(b, -15)),
        ("bzip2", lambda b: bz2.decompress(b)),
        ("xz_lzma", lambda b: lzma.decompress(b)),
    ]
    for name, fn in trials:
        try:
            val = fn(blob)
        except Exception:
            continue
        if val and len(val) <= 20_000_000:
            out.append((name, val))
    return out


def _v102_base58_decode(token: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in token:
        if ch not in alphabet:
            raise ValueError("not base58")
        n = n * 58 + alphabet.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(token) - len(token.lstrip("1"))
    return b"\x00" * pad + raw


def _v102_bits_to_bytes(bits: str, lsb: bool = False) -> bytes:
    clean = re.sub(r"[^01]", "", bits)
    return bytes(int((clean[i:i + 8][::-1] if lsb else clean[i:i + 8]), 2) for i in range(0, len(clean) - 7, 8))


def _v102_candidate_blobs(text: str) -> list[tuple[str, bytes | str, str]]:
    s = str(text or "")
    compact = re.sub(r"\s+", "", s)
    out: list[tuple[str, bytes | str, str]] = []

    if re.fullmatch(r"[0-9a-fA-F]{8,}", compact) and len(compact) % 2 == 0:
        try:
            out.append(("hex_compact", bytes.fromhex(compact), "hex bytes from compact text"))
        except Exception:
            pass
    for m in re.finditer(r"(?i)(?:hex|bytes?|payload|data|ascii|ord|codes?)\D{0,80}((?:0x[0-9a-f]{1,2}|[0-9a-f]{2})(?:[\s,;:_-]+(?:0x[0-9a-f]{1,2}|[0-9a-f]{2})){5,800})", s):
        toks = re.findall(r"0x[0-9a-fA-F]{1,2}|[0-9a-fA-F]{2}", m.group(1))
        try:
            out.append(("hex_labeled", bytes(int(t, 16) for t in toks), "labeled hex byte list"))
        except Exception:
            pass

    nums = re.findall(r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?![A-Za-z0-9])", s)
    if 6 <= len(nums) <= 2000:
        vals = []
        for n in nums:
            v = int(n, 16) if n.lower().startswith("0x") else int(n)
            if 0 <= v <= 255:
                vals.append(v)
        if len(vals) >= 6:
            out.append(("decimal_or_hex_bytes", bytes(vals), "decimal/hex byte sequence"))

    if re.search(r"\boctal\b|0o[0-7]", s, re.I):
        octs = re.findall(r"0o[0-7]{1,3}|(?<![0-9])[0-7]{3}(?![0-9])", s, re.I)
        vals = []
        for tok in octs[:2000]:
            v = int(tok[2:] if tok.lower().startswith("0o") else tok, 8)
            if 0 <= v <= 255:
                vals.append(v)
        if len(vals) >= 5:
            out.append(("octal_bytes", bytes(vals), "octal byte sequence"))

    bits = re.sub(r"[^01]", "", s) if re.fullmatch(r"[01\s,;:_-]{32,}", s.strip()) else ""
    if len(bits) >= 32:
        out.append(("binary_bits_msb", _v102_bits_to_bytes(bits, False), "binary bits packed MSB-first"))
        out.append(("binary_bits_lsb", _v102_bits_to_bytes(bits, True), "binary bits packed LSB-first"))
    groups8 = re.findall(r"(?<![01])([01]{8})(?![01])", s)
    if len(groups8) >= 4:
        out.append(("binary_grouped_msb", bytes(int(g, 2) for g in groups8[:20000]), "8-bit binary groups MSB-first"))
        out.append(("binary_grouped_lsb", bytes(int(g[::-1], 2) for g in groups8[:20000]), "8-bit binary groups LSB-first"))

    for tok in re.findall(r"[A-Za-z0-9+/=_-]{8,3000}", s):
        if tok.lower().startswith(("ctf_cs", "http", "file")):
            continue
        token_variants = [(tok, "")]
        if len(tok) >= 12:
            token_variants.append((tok[::-1], "reversed_"))
        for token, prefix in token_variants:
            pad4 = "=" * (-len(token) % 4)
            pad8 = "=" * (-len(token) % 8)
            decoders = [
                (prefix + "base64_token", lambda t=token: base64.b64decode(t + pad4, validate=False)),
                (prefix + "base64url_token", lambda t=token: base64.urlsafe_b64decode(t + pad4)),
                (prefix + "base32_token", lambda t=token: base64.b32decode(t + pad8, casefold=True)),
                (prefix + "ascii85_token", lambda t=token: base64.a85decode(t.encode(), adobe=False)),
                (prefix + "base85_token", lambda t=token: base64.b85decode(t.encode())),
                (prefix + "base58_token", lambda t=token: _v102_base58_decode(t)),
            ]
            for name, fn in decoders:
                try:
                    blob = fn()
                except Exception:
                    continue
                if blob and (
                    core.STRICT_RE.search(_bytes_to_text(blob))
                    or b"{" in blob
                    or _printable_ratio(blob) > 0.72
                    or bool(_v102_try_decompress(blob[:8_000_000]))
                ):
                    out.append((name, blob, f"{name} decoded from token"))

    decoded_layers = []
    for u in _url_decode_layers(s, 5):
        try:
            h = html.unescape(u)
        except Exception:
            h = u
        for val, label in ((u, "url_decode"), (h, "html_unescape")):
            if val != s and val not in decoded_layers:
                decoded_layers.append(val)
                out.append((label, val, label.replace("_", " ")))
    for comment in re.findall(r"<!--(.*?)-->", s, re.S)[:60]:
        out.append(("html_comment", comment, "HTML comment content"))
    for q in re.findall(r"(?i)(?:quoted-printable|qp)\D{0,40}([A-Za-z0-9=+/%_\-{}\s]{12,2000})", s)[:20]:
        try:
            out.append(("quoted_printable", quopri.decodestring(q).decode("utf-8", "replace"), "quoted-printable decode"))
        except Exception:
            pass
    if re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", s):
        try:
            out.append(("unicode_escape", s.encode("utf-8", "replace").decode("unicode_escape"), "Python/C-style unicode escape decode"))
        except Exception:
            pass
    zws = "".join(ch for ch in s if ch in "\u200b\u200c\u200d\ufeff")
    if len(zws) >= 8:
        maps = [
            ("\u200b\u200c", {"\u200b": "0", "\u200c": "1", "\u200d": "", "\ufeff": ""}),
            ("\u200b\u200d", {"\u200b": "0", "\u200d": "1", "\u200c": "", "\ufeff": ""}),
            ("\u200c\u200d", {"\u200c": "0", "\u200d": "1", "\u200b": "", "\ufeff": ""}),
        ]
        for label, mp in maps:
            bits2 = "".join(mp.get(ch, "") for ch in zws)
            if len(bits2) >= 8:
                out.append((f"zero_width_bits_{label.encode('unicode_escape').decode()}", _v102_bits_to_bytes(bits2, False), "zero-width Unicode bit channel"))
                out.append((f"zero_width_bits_lsb_{label.encode('unicode_escape').decode()}", _v102_bits_to_bytes(bits2, True), "zero-width Unicode bit channel LSB-packed"))
    trailing = []
    for line in s.splitlines():
        m = re.search(r"([ \t]+)$", line)
        if m:
            trailing.extend("1" if ch == "\t" else "0" for ch in m.group(1))
    if len(trailing) >= 8:
        tb = "".join(trailing)
        out.append(("trailing_whitespace_bits_msb", _v102_bits_to_bytes(tb, False), "trailing space/tab bit channel"))
        out.append(("trailing_whitespace_bits_lsb", _v102_bits_to_bytes(tb, True), "trailing space/tab bit channel LSB-packed"))
    a1_source = s.split(":", 1)[1] if ":" in s else s
    a1z_nums = re.findall(r"(?<!\d)(?:[1-9]|1\d|2[0-6])(?!\d)", a1_source)
    if 4 <= len(a1z_nums) <= 500 and re.search(r"a1z26|letter|numbers?|skai", s, re.I):
        out.append(("a1z26_letters", "".join(chr(96 + int(n)) for n in a1z_nums), "A1Z26 number-to-letter decode"))
    return out[:120]


def _v102_emit_candidate(report: dict, root: Path, arts: list[dict], name: str, payload: bytes | str, method: str, why: str, score: int) -> bool:
    text = _bytes_to_text(payload) if isinstance(payload, (bytes, bytearray)) else str(payload)
    blob = bytes(payload) if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", "replace")
    useful = _v102_score_text(text) >= 170 or _printable_ratio(blob[:4096]) > 0.78
    if not useful and method not in {"sha256_phrase"}:
        return False
    art = core.artifact(root, report, name, payload, "v102_logical_preflight", why, score, "v102_preflight")
    apath = art.get("path") if art else None
    if art:
        arts.append(art)
    before = (
        len(report.get("flags", []) or []),
        len(report.get("answer_candidates", []) or []),
        len(report.get("alternate_flag_candidates", []) or []),
        len(report.get("unconfirmed_evidence", []) or []),
    )
    source = f"SLOPER v102 logical preflight / {method}"
    core.scan_text(report, text, source, apath, why, score, allow_wrap=None)
    scan_alt_formats(report, text, source, apath, why, score - 10)
    preserve_unconfirmed_strict(report, text, source, apath, why, score - 80)
    _phrase_to_ctf(report, text, source, apath, why, score - 20)
    if re.search(r"\bsha\s*-?256\b|hash\s+of|sha256\s+of", _report_statement(report), re.I):
        phrase = text.strip()
        if 4 <= len(phrase) <= 500 and "\x00" not in phrase:
            digest = hashlib.sha256(phrase.encode("utf-8", "replace")).hexdigest()
            add_answer_candidate(report, digest, digest, source, apath, why + " Challenge asks for SHA-256/hash of the decoded phrase.", score + 25, "v102_hash_answer")
    after = (
        len(report.get("flags", []) or []),
        len(report.get("answer_candidates", []) or []),
        len(report.get("alternate_flag_candidates", []) or []),
        len(report.get("unconfirmed_evidence", []) or []),
    )
    hit = after != before or bool(core.STRICT_RE.search(text) or ALT_FLAG_RE.search(text) or BRACED_BODY_RE.search(text))
    if hit:
        report.setdefault("workflow_evidence", []).append({
            "flag": (core.STRICT_RE.search(text).group(0) if core.STRICT_RE.search(text) else ""),
            "source": source,
            "artifact": apath or "",
            "score": score,
            "why": why + " This transformation produced flag-like or answer-like evidence.",
            "file": report.get("rel", report.get("name", "")),
        })
        report.setdefault("sloper102_preflight_hits", []).append({
            "method": method,
            "artifact": apath or "",
            "score": score,
            "why": why,
            "preview": text[:400],
        })
    return hit


def v102_logical_preflight_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 5_000_000:
        return []
    text = _bytes_to_text(data[:2_000_000])
    if not text.strip():
        return []
    start = time.time()
    arts: list[dict] = []
    steps: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()

    def add_step(method: str, why: str, hit: bool, artifact: str = "") -> None:
        steps.append({
            "priority": 120 if hit else 40,
            "step": method,
            "why": why,
            "hit": hit,
            "artifact": artifact,
            "source_file": report.get("rel", report.get("name", "")),
        })

    def emit(name: str, payload: bytes | str, method: str, why: str, score: int = 900, depth: int = 0) -> None:
        if time.time() - start > 3.8 or len(arts) >= 36:
            return
        preview = _bytes_to_text(payload) if isinstance(payload, (bytes, bytearray)) else str(payload)
        sig = hashlib.sha1((method + "\0" + preview[:5000]).encode("utf-8", "replace")).hexdigest()
        if sig in seen_payloads:
            return
        seen_payloads.add(sig)
        before_art = len(arts)
        hit = _v102_emit_candidate(report, root, arts, name, payload, method, why, score)
        apath = arts[-1].get("path", "") if len(arts) > before_art and arts[-1] else ""
        add_step(method, why, hit, apath)
        blob = bytes(payload) if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", "replace")
        for dname, child in _v102_try_decompress(blob)[:4]:
            emit(f"{name}.{dname}.txt", child, f"{method}+{dname}", why + f" Then decompressed as {dname}.", score + 30, depth + 1)
        if depth < 3 and len(arts) < 32:
            child_text = preview if isinstance(preview, str) else _bytes_to_text(blob)
            for cname, child, cwhy in _v102_candidate_blobs(child_text)[:18]:
                emit(f"{name}.{cname}.txt", child, f"{method}+{cname}", why + f" Then {cwhy}.", score + 20, depth + 1)

    # First expose obvious original evidence without letting it be the only reason
    # to stop routing.  Strict visible flags can be decoys, but the user must see them.
    preserve_unconfirmed_strict(report, text, "SLOPER v102 logical preflight / visible text", "", "Visible strict-looking token in original input.", 700)
    scan_alt_formats(report, text, "SLOPER v102 logical preflight / visible text", "", "Visible alternate/bare answer token in original input.", 690)

    for name, payload, why in _v102_candidate_blobs(text):
        emit(f"{name}.txt", payload, name, why, 930)

    plainish = re.sub(r"\s+", " ", text)
    if len(plainish) <= 120_000:
        for shift in range(1, 26):
            decoded = _v102_caesar(plainish, shift)
            if _v102_score_text(decoded) >= 230 or "ctf" in decoded.lower() or "{" in decoded:
                emit(f"rot_{shift}.txt", decoded, f"rot_{shift}", f"Caesar/ROT-{shift} decode of the text.", 870)
        atb = _v102_atbash(plainish)
        if _v102_score_text(atb) >= 230:
            emit("atbash.txt", atb, "atbash", "Atbash substitution decode.", 850)
        r47 = _v102_rot47(plainish)
        if _v102_score_text(r47) >= 230:
            emit("rot47.txt", r47, "rot47", "ROT47 printable ASCII decode.", 850)

    cipher_tokens = []
    whole = re.sub(r"[^A-Za-z0-9_{}]", "", text)
    if 12 <= len(whole) <= 2000:
        cipher_tokens.append(("whole", whole))
    for idx, tok in enumerate(re.findall(r"[A-Za-z0-9_{}]{12,2000}", text)[:60]):
        if tok not in {v for _, v in cipher_tokens}:
            cipher_tokens.append((f"token_{idx}", tok))
    key_words = []
    for key in ["KEY", "SECRET", "PASSWORD", "FLAG", "CYBER", "SPRINT", "CTF"] + re.findall(r"[A-Za-z][A-Za-z0-9]{1,15}", _report_statement(report) + " " + text[:2000]):
        k = key.upper()
        if 2 <= len(k) <= 16 and k not in key_words:
            key_words.append(k)
    for label, tok in cipher_tokens[:30]:
        if time.time() - start > 3.8:
            break
        for rails in range(2, 8):
            out = _v102_rail_decrypt(tok, rails)
            if _v102_score_text(out) >= 210 or "ctf" in out.lower() or "{" in out:
                emit(f"rail_{rails}_{label}.txt", out, f"rail_{rails}", f"Rail fence decrypt with {rails} rails on {label}.", 865)
        for key in key_words[:80]:
            out = _columnar_decrypt(tok, key)
            if _v102_score_text(out) >= 210 or "ctf" in out.lower() or "{" in out:
                emit(f"columnar_{key}_{label}.txt", out, f"columnar_{key}", f"Columnar transposition candidate using key {key} on {label}.", 875)

    for m in LEETSPEAK_TOKEN_RE.finditer(text[:400_000]):
        tok = m.group(0)
        low = tok.lower()
        if re.search(r"[03457189]", low) or core.SEMANTIC_HINTS.search(low):
            add_answer_candidate(report, tok, tok, "SLOPER v102 logical preflight / leetspeak", "", "Leetspeak or semantic token preserved for human review.", 760, "v102_leetspeak_token")
    for m in LEET_WORD_RE.finditer(text[:400_000]):
        tok = m.group(0)
        add_answer_candidate(report, tok, tok, "SLOPER v102 logical preflight / leetspeak word", "", "Single leetspeak word preserved because the event may use non-wrapper answers.", 735, "v102_leetspeak_word")

    hit_count = len(report.get("sloper102_preflight_hits", []) or [])
    report["sloper102_preflight"] = {
        "version": "v102",
        "seconds": round(time.time() - start, 3),
        "steps": steps[:80],
        "hits": (report.get("sloper102_preflight_hits", []) or [])[:40],
        "artifact_count": len(arts),
        "note": "Fast logical routing: byte encodings, base decodes, compression chains, ROT/rail/columnar, alternate wrappers, and leetspeak review tokens before heavy legacy agents.",
    }
    report["sloper102_preflight_solved"] = bool(hit_count and (report.get("flags") or report.get("answer_candidates") or report.get("alternate_flag_candidates")))
    if time.time() - start > 3.8:
        report.setdefault("agent_health", []).append({
            "agent": "v102_logical_preflight",
            "file": report.get("rel", report.get("name", "")),
            "time": round(time.time() - start, 3),
            "error": "Preflight stopped at its time budget; heavy agents may continue if needed.",
        })
    return [a for a in arts if a]


def _v102_simple_text_route(report: dict, data: bytes, kind: str) -> bool:
    if kind not in {"text", "generic"} or len(data) > 1_500_000:
        return False
    rel = str(report.get("rel") or report.get("name") or report.get("path") or "").lower()
    if re.search(r"\.(png|jpg|jpeg|gif|bmp|webp|wav|mp3|flac|ogg|pcap|pcapng|zip|7z|rar|tar|gz|bz2|xz|pdf|docx|xlsx|pptx|sqlite|db|exe|dll|elf|class|jar|apk|pyc)$", rel):
        return False
    return True


def _v102_can_stop_after_preflight(report: dict, data: bytes, kind: str) -> bool:
    if not _v102_simple_text_route(report, data, kind):
        return False
    hits = report.get("sloper102_preflight_hits", []) or []
    if not hits:
        return False
    # Do not stop on raw visible strict tokens alone.  Stop only when a true
    # transformation or alternate-format analysis produced evidence.
    transform_hits = [
        h for h in hits
        if isinstance(h, dict) and not re.search(r"visible text", str(h.get("method", "") + " " + h.get("why", "")), re.I)
    ]
    if not transform_hits:
        return False
    text = _bytes_to_text(data[:200_000])
    looks_like_container = bool(re.search(r"PK\x03\x04|%PDF-|IHDR|IEND|pcap|sqlite|MZ|ELF", text, re.I))
    if looks_like_container:
        return False
    return True


def _v102_image_dimensions(data: bytes) -> tuple[int, int, str] | None:
    try:
        Image = __import__("PIL.Image", fromlist=["Image"])
        img = Image.open(io.BytesIO(data))
        return int(img.size[0]), int(img.size[1]), str(img.mode)
    except Exception:
        return None


def _v102_archive_should_fast(data: bytes) -> bool:
    raw = bytes(data or b"")
    if not raw.startswith(b"PK\x03\x04"):
        return False
    if len(raw) > 1_000_000:
        return True
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()
            if len(infos) > 120:
                return True
            media_ext = re.compile(r"\.(?:png|jpe?g|gif|webp|bmp|tiff?|wav|mp3|flac|ogg|mp4|mov|avi)$", re.I)
            if any(media_ext.search(info.filename or "") for info in infos):
                return True
    except Exception:
        return True
    return False


def v102_large_image_triage_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 60_000_000:
        return []
    try:
        Image = __import__("PIL.Image", fromlist=["Image"])
        ImageOps = __import__("PIL.ImageOps", fromlist=["ImageOps"])
        img = Image.open(io.BytesIO(data))
        w, h = img.size
        mode = img.mode
    except Exception:
        return []
    arts: list[dict] = []
    meta_rows: list[dict[str, Any]] = [{"width": w, "height": h, "mode": mode, "bytes": len(data)}]

    def add_text_art(name: str, text: str, note: str, score: int = 820) -> None:
        art = core.artifact(root, report, name, text, "v102_large_image_triage", note, score, "v102_image")
        if art:
            arts.append(art)
            core.scan_text(report, text, "SLOPER v102 large image triage", art.get("path"), note, score, allow_wrap=True)
            scan_alt_formats(report, text, "SLOPER v102 large image triage", art.get("path"), note, score)

    raw = bytes(data)
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        off = 8
        chunks = []
        while off + 12 <= len(raw) and len(chunks) < 400:
            try:
                ln = int.from_bytes(raw[off:off + 4], "big")
                typ = raw[off + 4:off + 8].decode("latin1", "replace")
                body = raw[off + 8:off + 8 + ln]
                chunks.append({"offset": off, "type": typ, "size": ln})
                if typ in {"tEXt", "iTXt", "zTXt"} or any(b in body.lower() for b in (b"ctf", b"flag", b"{", b"secret")):
                    text = body.decode("utf-8", "replace")
                    if typ == "zTXt" and b"\x00" in body:
                        try:
                            text = body.split(b"\x00", 2)[0].decode("utf-8", "replace") + "\n" + zlib.decompress(body.split(b"\x00", 2)[-1][1:]).decode("utf-8", "replace")
                        except Exception:
                            pass
                    add_text_art(f"png_chunk_{typ}_{len(chunks)}.txt", text, f"PNG {typ} chunk text/bytes surfaced from a large image.", 900)
                off = off + 12 + ln
                if typ == "IEND":
                    tail = raw[off:]
                    if tail:
                        meta_rows.append({"png_tail_after_iend": len(tail)})
                        for dname, child in _v102_try_decompress(tail)[:4]:
                            art = core.artifact(root, report, f"png_iend_tail_{dname}.bin", child, "v102_png_iend_tail", f"Payload after PNG IEND decompressed as {dname}.", 950, "v102_image")
                            if art:
                                arts.append(art)
                                text = _bytes_to_text(child[:200000])
                                core.scan_text(report, text, "SLOPER v102 PNG IEND tail", art.get("path"), f"Payload after PNG IEND decompressed as {dname}.", 950, allow_wrap=True)
                                scan_alt_formats(report, text, "SLOPER v102 PNG IEND tail", art.get("path"), f"Payload after PNG IEND decompressed as {dname}.", 950)
                    break
            except Exception:
                break
        meta_rows.append({"png_chunks": chunks[:120]})

    try:
        thumb = img.convert("RGBA")
        thumb.thumbnail((512, 512))
        bio = io.BytesIO()
        thumb.save(bio, format="PNG")
        art = core.artifact(root, report, "large_image_thumbnail.png", bio.getvalue(), "v102_large_image_thumbnail", "Fast thumbnail for human visual review; full image is intentionally not decoded through slow legacy image sweeps.", 880, "v102_image")
        if art:
            arts.append(art)
        contact_parts = []
        rgba = img.convert("RGBA")
        rgba.thumbnail((256, 256))
        for ch_name, channel in zip(("R", "G", "B", "A"), rgba.split()):
            contact_parts.append((ch_name, ImageOps.autocontrast(channel.convert("L"))))
        sheet = Image.new("RGB", (256 * 2, 256 * 2), (0, 0, 0))
        for idx, (_, part) in enumerate(contact_parts):
            part = part.resize((256, 256))
            sheet.paste(part.convert("RGB"), ((idx % 2) * 256, (idx // 2) * 256))
        bio = io.BytesIO()
        sheet.save(bio, format="PNG")
        art = core.artifact(root, report, "large_image_channel_contact.png", bio.getvalue(), "v102_large_image_contact_sheet", "Autocontrasted RGBA channel contact sheet for fast human review.", 940, "v102_image")
        if art:
            arts.append(art)
    except Exception as e:
        meta_rows.append({"preview_error": repr(e)})

    try:
        sample = []
        for idx, px in enumerate(img.convert("RGBA").getdata()):
            if idx >= 180_000:
                break
            sample.append(px)
        chan_orders = {"R": (0,), "G": (1,), "B": (2,), "A": (3,), "RGB": (0, 1, 2), "BGR": (2, 1, 0)}
        hits = 0
        for cname, chans in chan_orders.items():
            if hits >= 10:
                break
            for bit in range(2):
                bits = []
                for p in sample:
                    for ch in chans:
                        bits.append((p[ch] >> bit) & 1)
                        if len(bits) >= 65536:
                            break
                    if len(bits) >= 65536:
                        break
                for packing in ("msb", "lsb"):
                    out = bytearray()
                    for i in range(0, len(bits) - 7, 8):
                        chunk = bits[i:i + 8]
                        out.append((sum(b << j for j, b in enumerate(chunk))) if packing == "lsb" else int("".join(str(b) for b in chunk), 2))
                    blob = bytes(out).split(b"\x00", 1)[0]
                    if b"ctf" in blob.lower() or b"{" in blob or _printable_ratio(blob[:2000]) > 0.80:
                        art = core.artifact(root, report, f"sampled_lsb_{cname}_bit{bit}_{packing}.txt", blob[:32768], "v102_sampled_lsb", f"Sampled first 180k pixels, {cname} bit {bit}, {packing} packing.", 900, "v102_image")
                        if art:
                            arts.append(art)
                            core.scan_text(report, _bytes_to_text(blob), "SLOPER v102 sampled large-image LSB", art.get("path"), f"Sampled large-image LSB {cname} bit {bit} {packing}.", 900, allow_wrap=True)
                            scan_alt_formats(report, _bytes_to_text(blob), "SLOPER v102 sampled large-image LSB", art.get("path"), f"Sampled large-image LSB {cname} bit {bit} {packing}.", 900)
                            hits += 1
    except Exception as e:
        meta_rows.append({"sampled_lsb_error": repr(e)})

    add_text_art("large_image_triage.json", json.dumps(meta_rows, indent=2, ensure_ascii=False), "Large image triage metadata, PNG chunks, trailer info and preview artifact list.", 860)
    report.setdefault("sloper102_route", {
        "mode": "large_image_triage",
        "why": "Large image skipped legacy exhaustive image sweeps to avoid UI/project hangs. Fast thumbnail, channel contact, PNG chunk/tail scan and sampled LSB artifacts were generated instead.",
        "next": "Open large_image_channel_contact.png and sampled_lsb artifacts first; rerun deeper external stego tools manually if visual evidence suggests it.",
    })
    return [a for a in arts if a]


def v102_binary_triage_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if not raw or len(raw) > 80_000_000:
        return []
    arts: list[dict] = []
    magic = raw[:16].hex(" ")
    kind = "ELF" if raw.startswith(b"\x7fELF") else ("PE/MZ" if raw.startswith(b"MZ") else "binary")
    strings = []
    for m in re.finditer(rb"[\x20-\x7e]{4,240}", raw[:8_000_000]):
        s = m.group(0).decode("utf-8", "replace")
        if len(strings) < 4000:
            strings.append(s)
        if len(strings) >= 4000:
            break
    string_text = "\n".join(strings)
    art = core.artifact(
        root,
        report,
        "v102_binary_strings.txt",
        string_text,
        "v102_binary_strings",
        f"Fast {kind} printable string triage. Legacy deep binary sweep was skipped to prevent hangs.",
        900,
        "v102_binary",
    )
    if art:
        arts.append(art)
        core.scan_text(report, string_text, "SLOPER v102 binary string triage", art.get("path"), "Fast binary strings scanned for real flag/evidence.", 900, allow_wrap=True)
        scan_alt_formats(report, string_text, "SLOPER v102 binary string triage", art.get("path"), "Fast binary strings scanned for alternate/bare evidence.", 880)
    rows: list[dict[str, Any]] = [{
        "kind": kind,
        "bytes": len(raw),
        "magic": magic,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "strings": len(strings),
    }]
    if raw.startswith(b"\x7fELF") and len(raw) >= 64:
        try:
            cls = "64-bit" if raw[4] == 2 else "32-bit"
            endian = "little" if raw[5] == 1 else "big"
            rows.append({"elf_class": cls, "endian": endian, "entry_hint": raw[24:32].hex(" ")})
        except Exception:
            pass
    if raw.startswith(b"MZ"):
        try:
            peoff = int.from_bytes(raw[0x3C:0x40], "little")
            rows.append({"pe_header_offset": peoff, "pe_signature": raw[peoff:peoff + 4].hex(" ") if 0 <= peoff < len(raw) else ""})
        except Exception:
            pass
    # Cheap transform windows: many rev/PWN tasks hide a transformed flag in a
    # static byte table or rodata window.  Work on chunks, cap aggressively.
    hits = 0
    transforms: list[tuple[str, Any]] = [
        ("xor_52", lambda b: bytes(x ^ 0x52 for x in b)),
        ("xor_42", lambda b: bytes(x ^ 0x42 for x in b)),
        ("xor_ff", lambda b: bytes(x ^ 0xFF for x in b)),
        ("sub_1", lambda b: bytes((x - 1) & 255 for x in b)),
        ("add_1", lambda b: bytes((x + 1) & 255 for x in b)),
        ("bit_reverse", lambda b: bytes(_bitrev(x) for x in b)),
    ]
    for off in range(0, min(len(raw), 3_000_000), 4096):
        if hits >= 12:
            break
        chunk = raw[off:off + 4096]
        for name, fn in transforms:
            out = fn(chunk)
            txt = _bytes_to_text(out)
            if core.STRICT_RE.search(txt) or "ctf_cs{" in txt.lower() or re.search(r"\{[a-z0-9_:+./=-]{5,80}\}", txt, re.I):
                art = core.artifact(root, report, f"binary_window_{off:08x}_{name}.bin", out, "v102_binary_window_transform", f"Fast binary window transform {name} at offset {off}.", 930, "v102_binary")
                if art:
                    arts.append(art)
                    core.scan_text(report, txt, "SLOPER v102 binary transform", art.get("path"), f"Binary window transform {name} at offset {off}.", 930, allow_wrap=True)
                    scan_alt_formats(report, txt, "SLOPER v102 binary transform", art.get("path"), f"Binary window transform {name} at offset {off}.", 920)
                    hits += 1
    rows.append({"window_transform_hits": hits})
    art = core.artifact(root, report, "v102_binary_triage.json", json.dumps(rows, indent=2, ensure_ascii=False), "v102_binary_triage", "Fast binary triage metadata and bounded transform summary.", 860, "v102_binary")
    if art:
        arts.append(art)
    report.setdefault("sloper102_route", {
        "mode": "binary_fast_triage",
        "why": "Binary/ELF/PE file used fast triage instead of legacy deep sweeps to avoid project hangs.",
        "next": "Open v102_binary_strings.txt and binary_window transform artifacts. Use local reversing tools manually if no final flag appears.",
    })
    return [a for a in arts if a]


def v102_archive_triage_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if not raw or len(raw) > 120_000_000:
        return []
    arts: list[dict] = []
    rows: list[dict[str, Any]] = []

    def scan_child(label: str, blob: bytes, score: int = 900) -> None:
        if not blob:
            return
        safe_label = core.safe_name(label)[-120:] or "member"
        if len(blob) <= 4_000_000:
            art = core.artifact(root, report, f"archive_child_{safe_label}.bin", blob, "v102_archive_child", f"Bounded extraction of archive member {label}.", score, "v102_archive")
            if art:
                arts.append(art)
                txt = _bytes_to_text(blob[:500_000])
                core.scan_text(report, txt, "SLOPER v102 archive child", art.get("path"), f"Archive member {label} scanned as content evidence.", score, allow_wrap=True)
                scan_alt_formats(report, txt, "SLOPER v102 archive child", art.get("path"), f"Archive member {label} scanned as content evidence.", score)
                for dname, child in _v102_try_decompress(blob)[:3]:
                    dart = core.artifact(root, report, f"archive_child_{safe_label}_{dname}.bin", child, "v102_archive_child_decompressed", f"Archive member {label} decompressed as {dname}.", score + 20, "v102_archive")
                    if dart:
                        arts.append(dart)
                        dtxt = _bytes_to_text(child[:500_000])
                        core.scan_text(report, dtxt, "SLOPER v102 archive child decompressed", dart.get("path"), f"Archive member {label} decompressed as {dname}.", score + 20, allow_wrap=True)
                        scan_alt_formats(report, dtxt, "SLOPER v102 archive child decompressed", dart.get("path"), f"Archive member {label} decompressed as {dname}.", score + 20)

    try:
        if raw.startswith(b"PK\x03\x04") or b"PK\x03\x04" in raw[:4096]:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                infos = zf.infolist()
                rows.append({"archive": "zip", "members": len(infos), "comment": zf.comment.decode("utf-8", "replace") if zf.comment else ""})
                if zf.comment:
                    ctext = "\n".join(_url_decode_layers(zf.comment.decode("utf-8", "replace"), 5))
                    art = core.artifact(root, report, "zip_archive_comment.txt", ctext, "v102_zip_archive_comment", "ZIP archive comment decoded and scanned.", 940, "v102_archive")
                    if art:
                        arts.append(art)
                        core.scan_text(report, ctext, "SLOPER v102 ZIP archive comment", art.get("path"), "ZIP archive comment scanned as content evidence.", 940, allow_wrap=True)
                        scan_alt_formats(report, ctext, "SLOPER v102 ZIP archive comment", art.get("path"), "ZIP archive comment scanned as content evidence.", 940)
                total_read = 0
                for idx, info in enumerate(infos[:500]):
                    row = {
                        "idx": idx,
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed": info.compress_size,
                        "comment": info.comment.decode("utf-8", "replace") if info.comment else "",
                    }
                    rows.append(row)
                    if _statement_requests_filename(report) and not _statement_says_filename_decoy(report):
                        core.scan_text(report, info.filename, "SLOPER v102 filename requested", None, "Task asks for archive member filename evidence.", 850, allow_wrap=True)
                    preserve_unconfirmed_strict(report, info.filename, "SLOPER v102 archive filename metadata", None, "Archive filename metadata kept for review.", 680)
                    scan_alt_formats(report, info.filename, "SLOPER v102 archive filename metadata", None, "Archive filename metadata kept for review.", 680)
                    if info.comment:
                        ctext = "\n".join(_url_decode_layers(info.comment.decode("utf-8", "replace"), 5))
                        core.scan_text(report, ctext, "SLOPER v102 ZIP per-file comment", None, "ZIP per-file comment scanned.", 910, allow_wrap=True)
                        scan_alt_formats(report, ctext, "SLOPER v102 ZIP per-file comment", None, "ZIP per-file comment scanned.", 910)
                    if info.is_dir() or info.file_size > 8_000_000 or total_read > 30_000_000:
                        continue
                    try:
                        blob = zf.read(info)
                    except Exception as e:
                        row["read_error"] = repr(e)
                        continue
                    total_read += len(blob)
                    if idx < 180 or core.STRICT_RE.search(_bytes_to_text(blob[:10000])) or b"{" in blob[:10000]:
                        scan_child(info.filename, blob, 910)
    except Exception as e:
        rows.append({"archive_error": repr(e)})

    if rows:
        art = core.artifact(root, report, "v102_archive_triage_manifest.json", json.dumps(rows[:700], indent=2, ensure_ascii=False), "v102_archive_triage_manifest", "Bounded archive triage manifest: members, comments, extracted children and metadata.", 900, "v102_archive")
        if art:
            arts.append(art)
    report.setdefault("sloper102_route", {
        "mode": "archive_fast_triage",
        "why": "Large or suspicious archive used bounded triage instead of legacy recursive sweeps to prevent hangs.",
        "next": "Open v102_archive_triage_manifest.json and archive_child artifacts; extracted children are scanned and downloadable.",
    })
    return [a for a in arts if a]


def text_pattern_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 4_000_000:
        return []
    text = _bytes_to_text(data[:2_000_000])
    arts: list[dict] = []
    candidates: list[tuple[str, bytes | str, str, str]] = []
    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[0-9a-fA-F]{8,}", compact) and len(compact) % 2 == 0:
        try:
            candidates.append(("hex_ascii", bytes.fromhex(compact), "hex_decode", "Hex ASCII bytes decoded."))
        except Exception:
            pass
    nums = re.findall(r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?![A-Za-z0-9])", text)
    if 6 <= len(nums) <= 5000:
        vals = []
        for n in nums:
            v = int(n, 16) if n.lower().startswith("0x") else int(n)
            if 0 <= v <= 255:
                vals.append(v)
        if len(vals) >= 6:
            candidates.append(("number_bytes", bytes(vals), "number_bytes", "Decimal/hex byte list decoded."))
    if re.fullmatch(r"[01\s]{32,}", text.strip()):
        bits = re.sub(r"[^01]", "", text)
        if len(bits) >= 8:
            candidates.append(("binary_bytes", bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8)), "binary_bytes", "Binary bit string packed as bytes."))
    groups8 = re.findall(r"(?<![01])([01]{8})(?![01])", text)
    if len(groups8) >= 4:
        try:
            candidates.append(("binary_grouped_bytes", bytes(int(g, 2) for g in groups8[:20000]), "binary_bytes", "Grouped 8-bit binary bytes decoded, allowing labels and mixed delimiters."))
        except Exception:
            pass
    if re.fullmatch(r"[ABab\s]+", text.strip()) and len(re.findall(r"[ABab]{5}", text)) >= 3:
        candidates.append(("bacon_decode", _decode_bacon(text), "bacon", "Bacon A/B groups decoded."))
    nato = _decode_nato(text)
    if nato:
        candidates.append(("nato_words", nato, "nato", "NATO phonetic words converted to letters."))
    if re.fullmatch(r"[.\-/\s]+", text.strip()) and len(re.findall(r"[.\-]+", text)) >= 3:
        candidates.append(("morse_decode", _morse_decode(text), "morse", "Morse tokens decoded."))
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if 4 <= len(lines) <= 400:
        firsts = "".join(ln.lstrip()[0] for ln in lines if ln.lstrip())
        lasts = "".join(ln.rstrip()[-1] for ln in lines if ln.rstrip())
        candidates.append(("acrostic_first_chars", firsts, "acrostic", "First character of each non-empty line."))
        candidates.append(("acrostic_last_chars", lasts, "acrostic", "Last character of each non-empty line."))
    statement_words = re.findall(r"[A-Za-z][A-Za-z0-9_]{1,15}", _report_statement(report) + " " + text[:1000])
    keys = []
    for key in ["KEY", "SECRET", "CTF", "CYBER", "SPRINT", "FLAG", "PASSWORD"] + statement_words:
        k = key.upper()
        if 2 <= len(k) <= 16 and k not in keys:
            keys.append(k)
    cipher_sources = []
    whole_cipherish = re.sub(r"[^A-Za-z0-9_{}]", "", text)
    if 12 <= len(whole_cipherish) <= 5000:
        cipher_sources.append(("whole", whole_cipherish))
    for idx, tok in enumerate(re.findall(r"[A-Za-z0-9_{}]{12,5000}", text)):
        if tok not in {v for _, v in cipher_sources}:
            cipher_sources.append((f"token{idx}", tok))
    for src_label, cipherish in cipher_sources[:40]:
        for key in keys[:80]:
            plain = _columnar_decrypt(cipherish, key)
            if plain and ("ctf" in plain.lower() or "{" in plain or core.STRICT_RE.search(plain)):
                candidates.append((f"columnar_{key}_{src_label}", plain, "columnar", f"Columnar transposition candidate using key {key} on {src_label}."))
    for name, payload, kind, why in candidates[:40]:
        arts += _scan_blob(report, root, f"{name}.txt", payload, f"v100_{kind}", why, 860, "v100_text")
        txt = _bytes_to_text(payload) if isinstance(payload, (bytes, bytearray)) else str(payload)
        _phrase_to_ctf(report, txt, "SLOPER v100 text pattern", arts[-1].get("path") if arts else None, why, 820)
        scan_alt_formats(report, txt, "SLOPER v100 text pattern", arts[-1].get("path") if arts else None, why, 820)
    return [a for a in arts if a]


def _ror(v: int, n: int) -> int:
    n &= 7
    return ((v >> n) | ((v << (8 - n)) & 255)) & 255


def _rol(v: int, n: int) -> int:
    n &= 7
    return (((v << n) & 255) | (v >> (8 - n))) & 255


def _bitrev(v: int) -> int:
    return int(f"{v:08b}"[::-1], 2)


def _extract_byte_arrays(text: str) -> list[list[int]]:
    arrays: list[list[int]] = []
    for m in re.finditer(r"[\[{](.{8,25000}?)[\]}]", text, re.S):
        vals = []
        for tok in re.findall(r"0x[0-9a-fA-F]{1,2}|'(?:\\.|[^'])'|\"(?:\\.|[^\"])\"|\b\d{1,3}\b", m.group(1)):
            if tok.startswith(("'", '"')):
                body = tok[1:-1]
                vals.extend(body.encode("utf-8", "ignore")[:4])
            else:
                v = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                if 0 <= v <= 255:
                    vals.append(v)
        if 5 <= len(vals) <= 4096:
            arrays.append(vals)
    hexes = re.findall(r"0x[0-9a-fA-F]{1,2}|\b\d{1,3}\b", text)
    if 6 <= len(hexes) <= 4096:
        vals = []
        for tok in hexes:
            v = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
            if 0 <= v <= 255:
                vals.append(v)
        if len(vals) >= 6:
            arrays.append(vals)
    return arrays[:24]


def source_reverse_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 5_000_000:
        return []
    text = _bytes_to_text(data[:2_000_000])
    arts: list[dict] = []
    # Source literals that hide base encodings.
    for tok in re.findall(r"[A-Za-z0-9+/=_-]{12,300}", text):
        variants: list[tuple[str, bytes]] = []
        try:
            variants.append(("base64_literal", base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False)))
        except Exception:
            pass
        try:
            variants.append(("base32_literal", base64.b32decode(tok + "=" * (-len(tok) % 8), casefold=True)))
        except Exception:
            pass
        for name, blob in variants:
            if b"ctf" in blob.lower() or b"{" in blob:
                arts += _scan_blob(report, root, f"{name}.txt", blob, "v100_source_literal_decode", "Decoded encoded literal from source/text.", 900, "v100_reverse")
    # Explicit constraints such as input[i] ^ 0x21 == 0x42.
    slots: dict[int, int] = {}
    for m in re.finditer(r"input\s*\[\s*(\d+)\s*\]\s*\)*\s*([\^+\-*])\s*(0x[0-9a-fA-F]+|\d+)\s*\)*\s*==\s*(0x[0-9a-fA-F]+|\d+)", text):
        i = int(m.group(1)); op = m.group(2)
        k = int(m.group(3), 16) if m.group(3).lower().startswith("0x") else int(m.group(3))
        rhs = int(m.group(4), 16) if m.group(4).lower().startswith("0x") else int(m.group(4))
        val = None
        if op == "^":
            val = rhs ^ k
        elif op == "+":
            val = (rhs - k) & 255
        elif op == "-":
            val = (rhs + k) & 255
        elif op == "*" and k % 2:
            try:
                val = (rhs * pow(k, -1, 256)) & 255
            except Exception:
                val = None
        if val is not None and 0 <= i < 8192:
            slots[i] = val & 255
    if slots:
        blob = bytes(slots.get(i, 0x3f) for i in range(max(slots) + 1))
        arts += _scan_blob(report, root, "v100_constraints_solution.txt", blob, "v100_constraints_solution", "Solved source input[i] byte equations.", 960, "v100_reverse")
    arrays = _extract_byte_arrays(text)
    clue_keys = {int(x, 16) for x in re.findall(r"xor(?:\s+key)?\D{0,12}(0x[0-9a-fA-F]{1,2})", text, re.I)}
    for x in re.findall(r"xor(?:\s+key)?\D{0,12}\b(\d{1,3})\b", text, re.I):
        clue_keys.add(int(x) & 255)
    transforms: list[tuple[str, Any]] = [("identity", lambda b: b), ("reverse", lambda b: bytes(reversed(b))), ("not", lambda b: bytes((~x) & 255 for x in b)), ("bit_reverse", lambda b: bytes(_bitrev(x) for x in b)), ("nibble_swap", lambda b: bytes(((x << 4) | (x >> 4)) & 255 for x in b))]
    for k in sorted(clue_keys):
        transforms.append((f"xor_{k:02x}", lambda b, kk=k: bytes(x ^ kk for x in b)))
    for k in range(1, 16):
        transforms.append((f"add_{k}", lambda b, kk=k: bytes((x + kk) & 255 for x in b)))
        transforms.append((f"sub_{k}", lambda b, kk=k: bytes((x - kk) & 255 for x in b)))
    for n in range(1, 8):
        transforms.append((f"ror_{n}", lambda b, nn=n: bytes(_ror(x, nn) for x in b)))
        transforms.append((f"rol_{n}", lambda b, nn=n: bytes(_rol(x, nn) for x in b)))
    for idx, vals in enumerate(arrays):
        raw = bytes(vals)
        for name, fn in transforms[:80]:
            out = fn(raw)
            if b"ctf" in out.lower() or b"{" in out or core.STRICT_RE.search(_bytes_to_text(out)):
                arts += _scan_blob(report, root, f"array_{idx}_{name}.txt", out, "v100_array_transform", f"Byte/int array transform {name}.", 930, "v100_reverse")
    # Runtime string construction: parts=["ctf_","cs{...}"]
    lits = re.findall(r"['\"]([^'\"]{1,80})['\"]", text)
    if 2 <= len(lits) <= 80:
        joined = "".join(lits)
        if "ctf" in joined.lower() or "{" in joined:
            arts += _scan_blob(report, root, "joined_string_literals.txt", joined, "v100_runtime_string_join", "Joined short source string literals.", 900, "v100_reverse")
    return [a for a in arts if a]


def image_hidden_channels_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 15_000_000:
        return []
    try:
        Image = __import__("PIL.Image", fromlist=["Image"])
        img = Image.open(io.BytesIO(data))
        w, h = img.size
        if w * h > 2_000_000:
            return []
        rgba = img.convert("RGBA")
    except Exception:
        return []
    arts: list[dict] = []
    pix = list(rgba.getdata())
    alpha = bytes([p[3] for p in pix])
    if any(32 <= b < 127 for b in alpha[:200]):
        arts += _scan_blob(report, root, "alpha_channel_bytes.txt", alpha.split(b"\x00", 1)[0] or alpha[:4096], "v100_alpha_channel_bytes", "Raw alpha channel values as bytes.", 900, "v100_image")
    transparent = bytearray()
    transparent_channels = [bytearray(), bytearray(), bytearray()]
    for r, g, b, a in pix[:500000]:
        if a == 0:
            transparent.extend([r, g, b])
            transparent_channels[0].append(r)
            transparent_channels[1].append(g)
            transparent_channels[2].append(b)
    if transparent:
        arts += _scan_blob(report, root, "transparent_pixels_rgb.txt", bytes(transparent[:65536]).split(b"\x00", 1)[0], "v100_transparent_rgb", "RGB bytes from fully transparent pixels.", 900, "v100_image")
        for label, channel_blob in zip(("R", "G", "B"), transparent_channels):
            if channel_blob:
                arts += _scan_blob(report, root, f"transparent_pixels_{label}.txt", bytes(channel_blob[:65536]).split(b"\x00", 1)[0], "v100_transparent_rgb_channel", f"{label} channel bytes from fully transparent pixels.", 910, "v100_image")
    try:
        if img.mode == "P":
            idx = bytes(list(img.getdata())[:200000])
            arts += _scan_blob(report, root, "palette_indices_bytes.txt", idx.split(b"\x00", 1)[0] or idx[:65536], "v100_palette_indices", "Palette pixel indices read as bytes.", 900, "v100_image")
    except Exception:
        pass
    orders = {
        "row": range(w * h),
        "reverse_row": range(w * h - 1, -1, -1),
    }
    if w * h <= 250000:
        col = [y * w + x for x in range(w) for y in range(h)]
        orders["column"] = col
        orders["reverse_column"] = list(reversed(col))
    chan_orders = {"R": (0,), "G": (1,), "B": (2,), "A": (3,), "RGB": (0, 1, 2), "BGR": (2, 1, 0), "RGBA": (0, 1, 2, 3), "ARGB": (3, 0, 1, 2)}
    hits = 0
    for oname, coords in orders.items():
        coord_iter = list(coords) if not isinstance(coords, range) else coords
        for cname, chans in chan_orders.items():
            for bit in range(4):
                bits = []
                limit = 65536
                for idx in coord_iter:
                    p = pix[idx]
                    for ch in chans:
                        bits.append((p[ch] >> bit) & 1)
                        if len(bits) >= limit:
                            break
                    if len(bits) >= limit:
                        break
                for packing in ("msb", "lsb"):
                    out = bytearray()
                    for i in range(0, len(bits) - 7, 8):
                        chunk = bits[i:i+8]
                        if packing == "msb":
                            v = 0
                            for b in chunk:
                                v = (v << 1) | b
                        else:
                            v = sum(b << j for j, b in enumerate(chunk))
                        out.append(v)
                    blob = bytes(out).split(b"\x00", 1)[0]
                    if b"ctf" in blob.lower() or b"{" in blob:
                        arts += _scan_blob(report, root, f"lsb_{oname}_{cname}_bit{bit}_{packing}.txt", blob[:32768], "v100_lsb_matrix", f"LSB extraction {oname} {cname} bit {bit} {packing}.", 920, "v100_image")
                        hits += 1
                        if hits >= 24:
                            return [a for a in arts if a]
    return [a for a in arts if a]


def raw_zip_local_header_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if b"PK\x03\x04" not in raw or len(raw) > 50_000_000:
        return []
    arts: list[dict] = []
    rows = []
    off = 0
    while len(rows) < 80:
        off = raw.find(b"PK\x03\x04", off)
        if off < 0 or off + 30 > len(raw):
            break
        try:
            sig, ver, flags, method, mt, md, crc, csize, usize, nlen, elen = struct.unpack_from("<IHHHHHIIIHH", raw, off)
            name = raw[off + 30:off + 30 + nlen].decode("utf-8", "replace")
            start = off + 30 + nlen + elen
            comp = raw[start:start + csize] if csize else raw[start:]
            if method == 0:
                blob = comp
            elif method == 8:
                blob = zlib.decompress(comp, -15)
            else:
                blob = b""
            if blob:
                art = core.artifact(root, report, f"zip_local_{len(rows):02d}_{Path(name).name or 'member'}.bin", blob, "v100_zip_local_member", f"Recovered ZIP local header member {name}.", 940, "v100_archive")
                if art:
                    arts.append(art)
                rows.append({"offset": off, "name": name, "method": method, "size": len(blob), "artifact": art.get("path") if art else ""})
            off = max(start + max(csize, 1), off + 4)
        except Exception:
            off += 4
    if rows:
        a = core.artifact(root, report, "v100_zip_local_header_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_zip_local_manifest", "Recovered members from raw ZIP local headers.", 900, "v100_archive")
        if a:
            arts.append(a)
    return arts


def known_prefix_xor_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if not (8 <= len(raw) <= 2_000_000):
        return []
    prefixes = [b"ctf_cs{", b"CTF{", b"flag{", b"FLAG{"]
    arts: list[dict] = []
    for pref in prefixes:
        for key_len in range(1, 33):
            key: list[int | None] = [None] * key_len
            ok = True
            for i, pb in enumerate(pref):
                j = i % key_len
                kb = raw[i] ^ pb
                if key[j] is not None and key[j] != kb:
                    ok = False
                    break
                key[j] = kb
            if not ok or any(k is None for k in key):
                continue
            kbytes = bytes(int(k or 0) for k in key)
            out = bytes(b ^ kbytes[i % key_len] for i, b in enumerate(raw))
            printable = sum(1 for c in out if 32 <= c < 127 or c in b"\r\n\t") / max(1, len(out))
            if printable >= 0.85 and (b"ctf" in out.lower() or b"{" in out):
                arts += _scan_blob(report, root, f"known_prefix_xor_key{key_len}.txt", out[:200000], "v100_known_prefix_xor", f"Repeating-key XOR recovered from known prefix {pref.decode('ascii', 'ignore')}.", 940, "v100_reverse")
                if len(arts) >= 8:
                    return [a for a in arts if a]
    return [a for a in arts if a]


def pcap_scalar_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if len(raw) < 40 or len(raw) > 30_000_000 or raw[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return []
    le = raw[:4] == b"\xd4\xc3\xb2\xa1"
    endian = "<" if le else ">"
    off = 24
    fields: dict[str, bytearray] = {
        "ipid_low": bytearray(),
        "ipid_high": bytearray(),
        "ipid_be": bytearray(),
        "ipid_le": bytearray(),
        "ttl": bytearray(),
        "length_low": bytearray(),
        "length_high": bytearray(),
        "src_last_octet": bytearray(),
        "dst_last_octet": bytearray(),
        "timestamp_low": bytearray(),
        "delta_low": bytearray(),
        "udp_src_low": bytearray(),
        "udp_dst_low": bytearray(),
        "icmp_type": bytearray(),
        "icmp_code": bytearray(),
    }
    payloads: list[bytes] = []
    packet_rows: list[dict[str, Any]] = []
    last_ts: int | None = None

    def ipv4_offset(pkt: bytes) -> int | None:
        tries: list[int] = []
        if len(pkt) >= 14 and pkt[12:14] == b"\x08\x00":
            tries.append(14)
        tries += [0, 4, 14, 16, 20]
        seen_offsets = set()
        for eth in tries:
            if eth in seen_offsets:
                continue
            seen_offsets.add(eth)
            if len(pkt) < eth + 20:
                continue
            first = pkt[eth]
            ihl = (first & 15) * 4
            if (first >> 4) != 4 or ihl < 20 or len(pkt) < eth + ihl:
                continue
            total = struct.unpack_from("!H", pkt, eth + 2)[0]
            if total < ihl or total > len(pkt) - eth + 32:
                continue
            return eth
        return None

    def add_variant_artifacts(name: str, blob: bytes, note: str) -> None:
        if not blob:
            return
        variants: list[tuple[str, bytes, str]] = [(name, blob, note), (name.replace(".txt", "_reverse.txt"), blob[::-1], note + " Reverse order.")]
        if len(blob) >= 2:
            variants.append((name.replace(".txt", "_diff.txt"), bytes((blob[i] - blob[i - 1]) & 255 for i in range(1, len(blob))), note + " Adjacent differences."))
            variants.append((name.replace(".txt", "_xor_prev.txt"), bytes(blob[i] ^ blob[i - 1] for i in range(1, len(blob))), note + " XOR with previous byte."))
        if any(b in blob.lower() for b in (b"ctf", b"flag", b"uid", b"tsg")) or b"{" in blob or _printable_ratio(blob[:4000]) >= 0.55:
            for vname, vblob, vnote in variants[:4]:
                arts.extend(_scan_blob(report, root, vname, vblob[:200000], "v101_pcap_scalar", vnote, 930, "v101_pcap"))

    while off + 16 <= len(raw) and len(fields["ipid_low"]) < 40000:
        try:
            ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII", raw, off)
        except Exception:
            break
        off += 16
        pkt = raw[off:off + incl]
        off += incl
        if len(pkt) < 20:
            continue
        eth = ipv4_offset(pkt)
        if eth is None:
            continue
        ihl = (pkt[eth] & 15) * 4
        total = struct.unpack_from("!H", pkt, eth + 2)[0]
        ipid = struct.unpack_from("!H", pkt, eth + 4)[0]
        proto = pkt[eth + 9]
        src = pkt[eth + 12:eth + 16]
        dst = pkt[eth + 16:eth + 20]
        ts = int(ts_sec) * 1_000_000 + int(ts_usec)
        fields["ipid_low"].append(ipid & 255)
        fields["ipid_high"].append((ipid >> 8) & 255)
        fields["ipid_be"].extend(struct.pack("!H", ipid))
        fields["ipid_le"].extend(struct.pack("<H", ipid))
        fields["ttl"].append(pkt[eth + 8])
        fields["length_low"].append(total & 255)
        fields["length_high"].append((total >> 8) & 255)
        if len(src) == 4:
            fields["src_last_octet"].append(src[-1])
        if len(dst) == 4:
            fields["dst_last_octet"].append(dst[-1])
        fields["timestamp_low"].append(ts & 255)
        if last_ts is not None:
            fields["delta_low"].append((ts - last_ts) & 255)
        last_ts = ts
        payload_start = eth + ihl
        if proto == 17 and len(pkt) >= payload_start + 8:
            sport, dport, ulen, _chk = struct.unpack_from("!HHHH", pkt, payload_start)
            fields["udp_src_low"].append(sport & 255)
            fields["udp_dst_low"].append(dport & 255)
            payload = pkt[payload_start + 8:payload_start + max(8, min(ulen, len(pkt) - payload_start))]
            if payload:
                payloads.append(payload)
        elif proto == 1 and len(pkt) >= payload_start + 8:
            fields["icmp_type"].append(pkt[payload_start])
            fields["icmp_code"].append(pkt[payload_start + 1])
            payloads.append(pkt[payload_start + 8:])
        elif proto == 6 and len(pkt) >= payload_start + 20:
            data_off = (pkt[payload_start + 12] >> 4) * 4
            if data_off >= 20 and len(pkt) > payload_start + data_off:
                payloads.append(pkt[payload_start + data_off:])
        if len(packet_rows) < 600:
            packet_rows.append({"ipid": ipid, "ttl": pkt[eth + 8], "length": total, "proto": proto, "src": ".".join(map(str, src)), "dst": ".".join(map(str, dst))})
    arts: list[dict] = []
    matrix = {
        "packet_count": len(packet_rows),
        "fields": {k: {"count": len(v), "hex_head": bytes(v[:96]).hex(), "text_head": _bytes_to_text(bytes(v[:200]))} for k, v in fields.items() if v},
        "packets": packet_rows[:200],
        "note": "PCAP scalar/covert matrix: inspect IP ID, TTL, lengths, timestamps, src/dst octets, UDP/ICMP/TCP payloads and byte variants.",
    }
    a = core.artifact(root, report, "v101_pcap_covert_matrix.json", json.dumps(matrix, indent=2, ensure_ascii=False), "v101_pcap_covert_matrix", "Packet scalar fields extracted for human review and decode variants.", 900, "v101_pcap")
    if a:
        arts.append(a)
    for field_name, seq in fields.items():
        add_variant_artifacts(f"pcap_{field_name}.txt", bytes(seq), f"PCAP {field_name.replace('_', ' ')} byte sequence.")
    if payloads:
        joined = b"\n".join(p for p in payloads if p)[:1_000_000]
        add_variant_artifacts("pcap_joined_payloads.txt", joined, "Joined TCP/UDP/ICMP payload bytes.")
    return [a for a in arts if a]


def time_anomaly_deep_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    text = _bytes_to_text(bytes(data[:4_000_000] or b""))
    lines = text.splitlines()
    if len(lines) < 20 or ":" not in text:
        return []
    time_re = re.compile(r"(?:(\d{4})[-/](\d{2})[-/](\d{2})[ T])?(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))?")
    rows = []
    last: int | None = None
    for idx, line in enumerate(lines[:160000]):
        m = time_re.search(line)
        if not m:
            continue
        h, mi, sec = int(m.group(4)), int(m.group(5)), int(m.group(6))
        usec = int((m.group(7) or "0").ljust(6, "0")[:6])
        t = ((h * 60 + mi) * 60 + sec) * 1_000_000 + usec
        delta = None if last is None else t - last
        last = t
        toks = re.findall(r"\b[A-Z][A-Z0-9_]{1,12}\b", line)
        module = toks[0] if toks else ""
        level = toks[1] if len(toks) > 1 else ""
        suspicious = delta is not None and (delta < 0 or abs(delta) > 2_000_000)
        if suspicious or re.search(r"anomaly|drift|delay|skew|rollback|time", line, re.I):
            rows.append({"idx": idx, "h": h, "m": mi, "s": sec, "usec": usec, "delta": delta or 0, "module": module, "level": level, "line": line[:240]})
    if len(rows) < 3:
        return []
    modules = {v: i for i, v in enumerate(sorted({r["module"] for r in rows if r["module"]}))}
    levels = {v: i for i, v in enumerate(sorted({r["level"] for r in rows if r["level"]}))}

    def vals_to_texts(vals: list[int], label: str) -> dict[str, str]:
        out = {f"{label}_raw": bytes([v & 255 for v in vals]).decode("utf-8", "ignore")}
        out[f"{label}_reverse"] = bytes([v & 255 for v in vals[::-1]]).decode("utf-8", "ignore")
        out[f"{label}_mod95"] = "".join(chr(32 + (int(v) % 95)) for v in vals)
        out[f"{label}_mod26"] = "".join(chr(ord("a") + (int(v) % 26)) for v in vals)
        if len(vals) >= 2:
            out[f"{label}_diff_mod95"] = "".join(chr(32 + (((vals[i] - vals[i - 1]) & 255) % 95)) for i in range(1, len(vals)))
            out[f"{label}_xor_prev"] = bytes([(vals[i] ^ vals[i - 1]) & 255 for i in range(1, len(vals))]).decode("utf-8", "ignore")
        return out

    decoded: dict[str, str] = {}
    sequences: dict[str, list[int]] = {
        "seconds": [int(r["s"]) for r in rows],
        "minutes": [int(r["m"]) for r in rows],
        "line_indices": [int(r["idx"]) for r in rows],
        "delta_abs_low": [abs(int(r["delta"])) & 255 for r in rows],
        "module_ids": [modules.get(r["module"], 0) for r in rows],
        "level_ids": [levels.get(r["level"], 0) for r in rows],
    }
    for label, vals in sequences.items():
        decoded.update(vals_to_texts(vals, label))
        try:
            for method, txt in core.decode_sequence([int(v) & 255 for v in vals]).items():
                decoded[f"{label}_{method}"] = txt
        except Exception:
            pass
    # CTF logs often encode symbols as module/level alphabets.  Decode grouped
    # base-N values using sorted symbol order, plus a reverse-symbol pass.
    for label, vals in (("module_ids", sequences["module_ids"]), ("level_ids", sequences["level_ids"])):
        base = max(vals) + 1 if vals else 0
        if 2 <= base <= 6:
            for group in range(2, 7):
                nums = []
                for i in range(0, len(vals) - group + 1, group):
                    n = 0
                    for v in vals[i:i + group]:
                        n = n * base + v
                    nums.append(n)
                if nums:
                    decoded.update(vals_to_texts(nums, f"{label}_base{base}_group{group}"))
            rev_vals = [(base - 1 - v) for v in vals]
            for group in range(2, 7):
                nums = []
                for i in range(0, len(rev_vals) - group + 1, group):
                    n = 0
                    for v in rev_vals[i:i + group]:
                        n = n * base + v
                    nums.append(n)
                if nums:
                    decoded.update(vals_to_texts(nums, f"{label}_revbase{base}_group{group}"))
    interesting = {}
    arts: list[dict] = []
    for name, txt in decoded.items():
        if not txt:
            continue
        if any(x in txt.lower() for x in ("ctf", "flag", "uid", "tsg", "cyber", "sprint")) or "{" in txt or _printable_ratio(txt.encode("utf-8", "ignore")[:300]) > 0.72:
            interesting[name] = txt[:4000]
            core.scan_text(report, txt, "SLOPER v101 time anomaly deep", None, f"Time anomaly deep sequence {name}.", 830, allow_wrap=True)
            scan_alt_formats(report, txt, "SLOPER v101 time anomaly deep", None, f"Time anomaly deep sequence {name}.", 830)
    payload = {
        "rows": rows[:1500],
        "module_map": modules,
        "level_map": levels,
        "sequence_counts": {k: len(v) for k, v in sequences.items()},
        "interesting_decodes": interesting,
        "note": "Review the decoded variants and anomaly rows when no final flag is found; time/order channels often need human pattern recognition.",
    }
    a = core.artifact(root, report, "v101_time_anomaly_deep.json", json.dumps(payload, indent=2, ensure_ascii=False), "v101_time_anomaly_deep", "Timestamp anomaly sequences expanded into raw/reverse/diff/xor/base-N decode variants for human review.", 920, "v101_time")
    if a:
        arts.append(a)
    return arts


def project_multifile_evidence_v100(reports: list[dict], meta: dict) -> list[dict[str, Any]]:
    files: list[tuple[str, Path, bytes]] = []
    for r in reports or []:
        try:
            p = Path(str(r.get("path") or ""))
            if p.exists() and p.is_file() and p.stat().st_size <= 5_000_000:
                files.append((str(r.get("name") or p.name), p, p.read_bytes()))
        except Exception:
            continue
    out: list[dict[str, Any]] = []
    seen = set()

    def record(blob: bytes, source: str, file_hint: str = "") -> None:
        text = _bytes_to_text(blob[:1_000_000])
        variants = [
            ("raw", text),
            ("whitespace-normalized", re.sub(r"\s+", "", text)),
            ("line-joined", "".join(line.strip() for line in text.splitlines())),
        ]
        for variant_name, candidate_text in variants:
            for m in core.STRICT_RE.finditer(candidate_text):
                flag = m.group(0)
                if flag in seen:
                    continue
                seen.add(flag)
                out.append({
                    "flag": flag,
                    "source": source,
                    "artifact": "",
                    "why": f"Project-level multi-file workflow reconstructed a strict flag ({variant_name}).",
                    "score": 940 if variant_name != "raw" else 930,
                    "file": file_hint,
                })

    ordered = sorted(files, key=lambda x: [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", x[0])])
    if 2 <= len(ordered) <= 80:
        record(b"".join(b for _, _, b in ordered), "SLOPER v100 concat natural sort", "project")
        record(b"".join(b for _, _, b in reversed(ordered)), "SLOPER v100 concat reverse natural sort", "project")
    for i in range(min(len(files), 40)):
        for j in range(i + 1, min(len(files), 40)):
            n1, _, a = files[i]
            n2, _, b = files[j]
            if not a or not b:
                continue
            m = min(len(a), len(b))
            if m >= 4:
                record(bytes(x ^ y for x, y in zip(a[:m], b[:m])), "SLOPER v100 file pair XOR", f"{n1}+{n2}")
                record(bytes((x + y) & 255 for x, y in zip(a[:m], b[:m])), "SLOPER v100 file pair ADD", f"{n1}+{n2}")
                record(bytes((x - y) & 255 for x, y in zip(a[:m], b[:m])), "SLOPER v100 file pair SUB", f"{n1}+{n2}")
                record(bytes((y - x) & 255 for x, y in zip(a[:m], b[:m])), "SLOPER v100 file pair SUB reverse", f"{n2}+{n1}")
            for first, second, label in ((a, b, "AB"), (b, a, "BA")):
                inter = bytearray()
                for k in range(max(len(first), len(second))):
                    if k < len(first):
                        inter.append(first[k])
                    if k < len(second):
                        inter.append(second[k])
                record(bytes(inter), f"SLOPER v100 file interleave {label}", f"{n1}+{n2}")
    # Cross-file clue/password ZIP workflow.
    clue_text = "\n".join(_bytes_to_text(b[:20000]) for n, p, b in files if p.suffix.lower() in {".txt", ".md"} or len(b) < 30000)
    words = set(re.findall(r"[A-Za-z0-9_!@#$%^&*+\-=]{3,40}", clue_text + "\n" + str((meta or {}).get("statement", ""))))
    for name, path, blob in files:
        if not zipfile.is_zipfile(io.BytesIO(blob)):
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for pwd in [None] + [w.encode("utf-8", "ignore") for w in sorted(words)[:200]]:
                    try:
                        for info in zf.infolist()[:80]:
                            data = zf.read(info, pwd=pwd)
                            record(data, "SLOPER v100 project ZIP clue extraction", name)
                    except Exception:
                        continue
        except Exception:
            continue
    return out


def archive_child_multistep_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Walk nested archive/compression children and decode each child as a CTF step.

    Existing archive agents extract members, but many hard tasks put an encoded
    payload inside the extracted member.  This agent explicitly feeds children
    through the bounded priority decode graph and records the chain.
    """
    core.ensure(report)
    raw = bytes(data or b"")
    if not raw or len(raw) > 80_000_000:
        return []
    q: list[tuple[str, bytes, int]] = [("input", raw, 0)]
    seen: set[tuple[int, bytes]] = set()
    rows: list[dict[str, Any]] = []
    arts: list[dict] = []
    nodes = 0
    while q and nodes < 90:
        label, blob, depth = q.pop(0)
        if depth > 5 or not blob:
            continue
        key = (len(blob), blob[:64])
        if key in seen:
            continue
        seen.add(key)
        nodes += 1
        rows.append({"chain": label, "size": len(blob), "magic": blob[:12].hex()})
        if len(blob) <= 2_000_000:
            text = blob.decode("utf-8", "ignore")
            core.scan_text(report, text, "SLOPER v100 archive child", None, f"Archive child chain {label} text scan.", 850, allow_wrap=True)
            scan_alt_formats(report, text, "SLOPER v100 archive child", None, f"Archive child chain {label}.", 850)
            if text.strip():
                try:
                    core.priority_chain_agent(report, root, blob)
                    if not report.get("flags"):
                        core.multistep_decode_agent(report, root, blob)
                except Exception as e:
                    agent_crash("v100 archive child decode graph", e, report)
                if depth < 5:
                    clean = re.sub(r"\s+", "", text)
                    rev_lines = "\n".join(line[::-1] for line in text.splitlines())
                    for vname, sval in (("base64", clean), ("reverse_base64", clean[::-1]), ("reverse_each_line_base64", re.sub(r"\s+", "", rev_lines))):
                        if 12 <= len(sval) <= 2_000_000 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", sval):
                            try:
                                child = base64.b64decode(sval + "=" * (-len(sval) % 4), validate=False)
                            except Exception:
                                continue
                            if child and child != blob:
                                q.append((label + " -> " + vname, child, depth + 1))
        if depth >= 5:
            continue
        try:
            if blob.startswith(b"PK\x03\x04"):
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    for info in zf.infolist()[:80]:
                        if info.is_dir() or info.file_size > 25_000_000:
                            continue
                        try:
                            child = zf.read(info)
                        except RuntimeError:
                            continue
                        q.append((label + " -> zip:" + info.filename, child, depth + 1))
                        # Member names are useful breadcrumbs, but they are also
                        # a common benchmark/decoy source.  Preserve them as
                        # unconfirmed candidates unless the statement asks for
                        # filenames explicitly.  Real ZIP comments are content
                        # evidence, so decode URL layers and scan them strongly.
                        if _statement_requests_filename(report):
                            core.scan_text(report, info.filename, "SLOPER v101 filename requested", None, "Task asks for filename/member-name evidence.", 850, allow_wrap=True)
                        preserve_unconfirmed_strict(report, info.filename, "SLOPER v101 zip filename metadata", None, "ZIP member filename metadata.", 700)
                        scan_alt_formats(report, info.filename, "SLOPER v101 zip filename metadata", None, "ZIP member filename preserved as unconfirmed metadata candidate.", 700)
                        comment = info.comment.decode("utf-8", "ignore") if info.comment else ""
                        if comment.strip():
                            layers = _url_decode_layers(comment, 5)
                            ca = core.artifact(
                                root,
                                report,
                                f"zip_comment_{nodes}_{core.safe_name(info.filename or 'member')}.txt",
                                "\n\n".join(f"--- layer {i} ---\n{txt}" for i, txt in enumerate(layers)),
                                "v101_zip_comment",
                                "ZIP per-file comment decoded through URL layers and scanned as content evidence.",
                                910,
                                "v101_archive",
                            )
                            cpath = ca.get("path") if ca else None
                            for txt in layers:
                                core.scan_text(report, txt, "SLOPER v101 zip comment", cpath, "ZIP comment content scanned after iterative URL decoding.", 910, allow_wrap=True)
                                scan_alt_formats(report, txt, "SLOPER v101 zip comment", cpath, "ZIP comment content scanned after iterative URL decoding.", 910)
        except Exception as e:
            rows[-1]["zip_error"] = type(e).__name__ + ": " + str(e)[:120]
        for cname, fn in (
            ("gzip", gzip.decompress),
            ("bz2", bz2.decompress),
            ("xz", lzma.decompress),
        ):
            try:
                if (cname == "gzip" and blob.startswith(b"\x1f\x8b")) or (cname == "bz2" and blob.startswith(b"BZh")) or (cname == "xz" and blob.startswith(b"\xfd7zXZ\x00")):
                    child = fn(blob)
                    if child:
                        q.append((label + " -> " + cname, child, depth + 1))
            except Exception:
                pass
        try:
            if blob.startswith((b"\x78\x9c", b"\x78\xda", b"\x78\x01")):
                child = zlib.decompress(blob)
                if child:
                    q.append((label + " -> zlib", child, depth + 1))
        except Exception:
            pass
        try:
            bio = io.BytesIO(blob)
            if tarfile.is_tarfile(bio):
                bio.seek(0)
                with tarfile.open(fileobj=bio) as tf:
                    for member in tf.getmembers()[:80]:
                        if not member.isfile() or member.size > 25_000_000:
                            continue
                        fh = tf.extractfile(member)
                        if fh:
                            q.append((label + " -> tar:" + member.name, fh.read(), depth + 1))
                            if _statement_requests_filename(report):
                                core.scan_text(report, member.name, "SLOPER v101 filename requested", None, "Task asks for TAR filename/member-name evidence.", 850, allow_wrap=True)
                            preserve_unconfirmed_strict(report, member.name, "SLOPER v101 tar filename metadata", None, "TAR member filename metadata.", 700)
                            scan_alt_formats(report, member.name, "SLOPER v101 tar filename metadata", None, "TAR member filename preserved as unconfirmed metadata candidate.", 700)
        except Exception:
            pass
    if rows:
        a = core.artifact(root, report, "v100_archive_child_workflow.json", json.dumps(rows[:220], indent=2, ensure_ascii=False), "v100_archive_child_workflow", "Nested archive/compression children were fed into bounded decode chains.", 930, "v100_archive")
        if a:
            arts.append(a)
    return arts


def zip_password_chain_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    raw = bytes(data or b"")
    if not raw.startswith(b"PK\x03\x04") or len(raw) > 90_000_000:
        return []
    core.ensure(report)
    text = _report_statement(report) + " " + str(report.get("name", ""))
    base_words = [
        "ctf", "cyber", "sprint", "cybersprint", "flag", "password", "secret",
        "hidden", "slapta", "raktas", "archyvas", "archive", "zip",
    ]
    tokens = re.findall(r"[A-Za-z0-9_@#.$+\-]{3,40}", text)
    candidates: list[str] = []
    for tok in base_words + tokens:
        for val in (tok, tok.lower(), tok.upper(), tok.capitalize()):
            if val and val not in candidates:
                candidates.append(val)
    rows: list[dict[str, Any]] = []
    arts: list[dict] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()[:80]
            encrypted = [i for i in infos if (i.flag_bits & 1)]
            if not encrypted:
                return []
            for info in encrypted[:12]:
                if info.file_size > 20_000_000:
                    continue
                for pwd in candidates[:160]:
                    try:
                        child = zf.read(info, pwd=pwd.encode("utf-8"))
                    except Exception:
                        continue
                    rows.append({"member": info.filename, "password": pwd, "size": len(child)})
                    a = core.artifact(root, report, "v100_zip_pwd_" + core.safe_name(info.filename), child, "v100_zip_password_child", f"ZIP member {info.filename} decrypted with password candidate '{pwd}'.", 970, "v100_archive")
                    if a:
                        arts.append(a)
                    archive_child_multistep_agent(report, root, child)
                    break
    except Exception as e:
        agent_crash("v100 zip_password_chain_agent", e, report)
    if rows:
        a = core.artifact(root, report, "v100_zip_password_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_zip_password_manifest", "Clue-derived ZIP password attempts that succeeded.", 900, "v100_archive")
        if a:
            arts.insert(0, a)
    return arts


def text_alt_and_chain_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    if not data or len(data) > 5_000_000:
        return []
    txt = data[:2_000_000].decode("utf-8", "ignore")
    hits = scan_alt_formats(report, txt, "SLOPER v100 alternate format", None, "Direct text scan for UID/TSG/T5G/FLAG alternate prefixes.", 870)
    # Common CTF trick: HTML/URL/quoted-printable wrapping around alternate flags.
    variants: list[tuple[str, str]] = []
    try:
        variants.append(("url_decode", urllib.parse.unquote_plus(txt)))
    except Exception:
        pass
    try:
        variants.append(("html_unescape", html.unescape(txt)))
    except Exception:
        pass
    try:
        if "=" in txt:
            variants.append(("quoted_printable", quopri.decodestring(txt.encode("utf-8", "ignore")).decode("utf-8", "ignore")))
    except Exception:
        pass
    for name, val in variants:
        if val and val != txt:
            hits += scan_alt_formats(report, val, "SLOPER v100 alternate format decode", None, f"{name} exposed alternate-format evidence.", 900)
            core.scan_text(report, val, "SLOPER v100 alternate format decode", None, f"{name} exposed flag evidence.", 900, allow_wrap=True)
    if not hits:
        return []
    payload = {"hits": hits, "alternate": report.get("alternate_flag_candidates", [])[-40:]}
    a = core.artifact(root, report, "v100_alternate_flag_formats.json", json.dumps(payload, indent=2, ensure_ascii=False), "v100_alternate_flag_formats", "UID/TSG/T5G/FLAG-style tokens normalized with evidence.", 910, "v100_text")
    return [a] if a else []


def xor_container_chain_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Detect XOR-obfuscated containers and immediately continue solving.

    Generic XOR over all keys is noisy.  This agent only accepts a key when the
    decoded bytes start with a real container/compression signature, which is a
    high-confidence CTF step.
    """
    raw = bytes(data or b"")
    if not (4 <= len(raw) <= 5_000_000):
        return []
    sigs = (
        ("gzip", b"\x1f\x8b\x08"),
        ("bz2", b"BZh"),
        ("xz", b"\xfd7zXZ\x00"),
        ("zip", b"PK\x03\x04"),
        ("zlib", b"\x78\x9c"),
        ("zlib", b"\x78\xda"),
        ("zlib", b"\x78\x01"),
    )
    rows: list[dict[str, Any]] = []
    arts: list[dict] = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in raw)
        kind = next((name for name, sig in sigs if dec.startswith(sig)), "")
        if not kind:
            continue
        rows.append({"key": key, "kind": kind, "size": len(dec)})
        a = core.artifact(root, report, f"v100_xor_{key:02x}_{kind}.bin", dec[:25_000_000], "v100_xor_container", f"Single-byte XOR key 0x{key:02x} produced {kind} magic bytes.", 940, "v100_multistep")
        if a:
            arts.append(a)
        child = dec
        if kind in {"gzip", "bz2", "xz", "zlib"}:
            child = core.decompress_one(kind, dec) or b""
            if child:
                da = core.artifact(root, report, f"v100_xor_{key:02x}_{kind}_decoded.bin", child[:25_000_000], "v100_xor_container_decoded", f"XOR key 0x{key:02x} then {kind} decompression.", 980, "v100_multistep")
                if da:
                    arts.append(da)
        if child:
            text = child[:2_000_000].decode("utf-8", "ignore")
            core.scan_text(report, text, "SLOPER v100 XOR container", a.get("path") if a else None, f"XOR key 0x{key:02x} revealed {kind} child data.", 980, allow_wrap=True)
            scan_alt_formats(report, text, "SLOPER v100 XOR container", a.get("path") if a else None, f"XOR key 0x{key:02x} revealed {kind} child data.", 980)
            archive_child_multistep_agent(report, root, child)
        break
    if rows:
        m = core.artifact(root, report, "v100_xor_container_manifest.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_xor_container_manifest", "XOR keys that turned opaque input into real container/compression magic.", 920, "v100_multistep")
        if m:
            arts.insert(0, m)
    return arts


def _asciiish8(v: int) -> bytes:
    for order in ("big", "little"):
        b = int(v).to_bytes(8, order, signed=False)
        if sum(32 <= x < 127 for x in b) >= 6 and sum(chr(x).isalpha() for x in b if 32 <= x < 127) >= 4:
            return b
    return b""


def pwn_static_flag_value_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Recover simple static PWN printf('%lx') style values from immediates.

    A common beginner-to-intermediate pwn/rev pattern stores two 64-bit
    immediates and prints their XOR as a hex answer.  This does not guess the
    answer from strings: it only fires when the binary itself mentions a hex
    print path and two nearby MOVABS constants explain the value.
    """
    raw = bytes(data or b"")
    if not raw.startswith(b"\x7fELF") or len(raw) > 15_000_000:
        return []
    if b"%lx" not in raw and b"%llx" not in raw and b"FLAG" not in raw.upper():
        return []
    immediates: list[tuple[int, int, bytes]] = []
    for pat in (b"\x48\xb8", b"\x48\xb9", b"\x48\xba", b"\x48\xbb", b"\x49\xb8", b"\x49\xb9", b"\x49\xba", b"\x49\xbb"):
        for m in re.finditer(re.escape(pat) + b"(.{8})", raw, re.S):
            chunk = m.group(1)
            val = int.from_bytes(chunk, "little", signed=False)
            if val not in {0, 1, 0xffffffffffffffff, 0x7fffffffffffffff, 0x8000000000000000}:
                immediates.append((m.start(), val, chunk))
    rows: list[dict[str, Any]] = []
    arts: list[dict] = []
    for i, (oa, a, _) in enumerate(immediates[:260]):
        aa = _asciiish8(a)
        if not aa:
            continue
        for ob, b, _ in immediates[i + 1:i + 80]:
            if abs(ob - oa) > 8192:
                continue
            if _asciiish8(b):
                continue
            body = f"{a ^ b:016x}"
            if not re.search(r"[a-f]", body):
                continue
            flag = core.add_flag(
                report,
                body,
                "SLOPER v100 pwn static flag value",
                None,
                "ELF contains %lx-style output and nearby MOVABS constants; XOR of printable seed and mask yields the submitted hex body.",
                1030,
                allow_wrap=True,
            )
            if flag:
                report.setdefault("flags", []).append({
                    "flag": flag,
                    "source": "SLOPER v100 pwn static flag value",
                    "score": 1030,
                    "why": "ELF contains %lx-style output and nearby MOVABS constants; XOR of printable seed and mask yields the submitted hex body.",
                    "artifact": "",
                })
            rows.append({"offset_a": oa, "offset_b": ob, "ascii_seed": aa.decode("latin1", "ignore"), "value_hex": body, "flag": flag or f"ctf_cs{{{body}}}"})
            break
        if rows:
            break
    if rows:
        a = core.artifact(root, report, "v100_pwn_static_flag_values.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_pwn_static_flag_values", "Static PWN hex flag values derived from nearby 64-bit immediates and %lx output.", 980, "v100_reversing")
        if a:
            arts.append(a)
    return arts


def double_table_ascii_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Decode numeric-table leaks where doubles store char-pairs divided by index."""
    raw = bytes(data or b"")
    if len(raw) < 8 * 5 or len(raw) > 20_000_000:
        return []
    rows: list[dict[str, Any]] = []
    arts: list[dict] = []
    max_scan = min(len(raw) - 8 * 5, 4_000_000)
    seen: set[str] = set()
    for off in range(0, max_scan, 8):
        vals: list[float] = []
        pos = off
        while pos + 8 <= len(raw) and len(vals) < 48:
            try:
                v = struct.unpack_from("<d", raw, pos)[0]
            except Exception:
                break
            if v != v or abs(v) > 1_000_000_000:
                break
            if abs(v) < 1e-12:
                break
            vals.append(v)
            pos += 8
        if len(vals) < 5:
            continue
        blob = bytearray()
        for i, v in enumerate(vals, 1):
            n = int(v * i) & 0xffff
            blob.extend(n.to_bytes(2, "little"))
        text = bytes(blob).decode("latin1", "ignore")
        parts = re.split(r"[\x00\r\n\t]+", text)
        for part in parts:
            clean = "".join(ch for ch in part if 32 <= ord(ch) < 127).strip("_ -")
            if len(clean) < 8 or clean.lower() in seen:
                continue
            if not re.search(r"[_0-9]", clean) or not re.search(r"[A-Za-z]", clean):
                continue
            if not core.body_quality(clean, "SLOPER v100 double table ascii numeric leak anomaly"):
                continue
            seen.add(clean.lower())
            flag = core.add_flag(
                report,
                clean,
                "SLOPER v100 double table ascii",
                None,
                "A contiguous double table decoded as int(value*index) little-endian character pairs.",
                1010,
                allow_wrap=True,
            )
            if flag:
                report.setdefault("flags", []).append({
                    "flag": flag,
                    "source": "SLOPER v100 double table ascii",
                    "score": 1010,
                    "why": "A contiguous double table decoded as int(value*index) little-endian character pairs.",
                    "artifact": "",
                })
            rows.append({"offset": off, "candidate": clean, "flag": flag or "", "pairs": min(len(vals), 48)})
            if len(rows) >= 8:
                break
        if len(rows) >= 8:
            break
    if rows:
        a = core.artifact(root, report, "v100_double_table_ascii.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_double_table_ascii", "Numeric-table reversing leak decoded into candidate text.", 970, "v100_reversing")
        if a:
            arts.append(a)
    return arts


def high_signal_artifact_candidate_agent(report: dict, root: Path, data: bytes) -> list[dict]:
    """Promote candidates from explicit high-signal workflow artifacts.

    This is intentionally narrow.  It does not scan every JSON file; it only
    trusts artifacts whose own method says they are visual OCR/FIGlet/answer
    reconstruction hints.  That keeps random string dumps out of Final Flags
    while preserving a real CTF workflow breadcrumb.
    """
    core.ensure(report)
    rows: list[dict[str, Any]] = []
    for art in list(report.get("artifacts", []) or [])[-400:]:
        if not isinstance(art, dict):
            continue
        path = str(art.get("path") or "")
        name = Path(path).name.lower()
        kind_note = (str(art.get("kind", "")) + " " + str(art.get("note", "")) + " " + name).lower()
        if not path or not Path(path).exists():
            continue
        if not (
            "ascii_art_ocr_hints" in name
            or ("figlet" in kind_note and "candidate" in kind_note)
            or ("ocr" in kind_note and "hint" in kind_note and "candidate" in kind_note)
        ):
            continue
        try:
            payload = json.loads(Path(path).read_text("utf-8", "ignore")[:200_000])
        except Exception:
            continue
        entries = payload if isinstance(payload, list) else payload.get("candidates", []) if isinstance(payload, dict) else []
        for item in entries:
            if not isinstance(item, dict):
                continue
            cand = str(item.get("candidate") or item.get("value") or item.get("body") or "").strip().strip("{}")
            why = str(item.get("why") or "High-signal visual/FIGlet reconstruction artifact proposed this candidate.")
            if not core.body_quality(cand, "SLOPER v100 high signal artifact candidate FIGlet OCR visual reconstruction " + why):
                continue
            flag = core.add_flag(
                report,
                cand,
                "SLOPER v100 high-signal artifact candidate",
                path,
                why + " Candidate came from a generated workflow artifact, not from a broad raw strings scan.",
                int(item.get("score", 900) or 900) + 420,
                allow_wrap=True,
            )
            if flag:
                report.setdefault("flags", []).append({
                    "flag": flag,
                    "source": "SLOPER v100 high-signal artifact candidate",
                    "score": int(item.get("score", 900) or 900) + 420,
                    "why": why + " Candidate came from a generated workflow artifact, not from a broad raw strings scan.",
                    "artifact": path,
                })
                rows.append({"artifact": path, "candidate": cand, "flag": flag, "why": why})
    if rows:
        a = core.artifact(root, report, "v100_high_signal_artifact_candidates.json", json.dumps(rows, indent=2, ensure_ascii=False), "v100_high_signal_artifact_candidates", "Final candidates promoted from explicit visual/FIGlet/OCR workflow hints.", 960, "v100_review")
        return [a] if a else []
    return []


def call_legacy_v99(mod: Any, report: dict, root: Path, data: bytes) -> list[dict]:
    """Run real v99 workflow-sprint agents from the legacy module in stable mode."""
    if not hasattr(mod, "v99_enhance_report"):
        return []
    before = len(report.get("artifacts", []))
    mod.v99_enhance_report(root, report, data)
    return report.get("artifacts", [])[before:]


def install(mod: Any) -> Any:
    old_body_quality = core.body_quality

    def body_quality_v100(body: str, source: str = "") -> bool:
        if _generated_body(body):
            return False
        if re.fullmatch(r"[0-9a-f]{16}", str(body or "").strip().strip("{}").lower()) and re.search(r"pwn|%lx|printf|movabs|static flag value|xor of printable seed", source, re.I):
            return True
        if re.search(r"compact ctfcs phrase", source, re.I):
            low = str(body or "").strip().strip("{}").lower()
            if 5 <= len(low) <= 90 and re.search(r"[a-z]", low):
                return True
        if re.search(r"array|constraint|source literal|runtime string|file pair|interleave|zip local|zip comment|pcap scalar|palette|alpha|transparent|lsb|morse|bacon|nato|columnar|binary_bytes|hex_decode|number_bytes|decimal|octal|v102 logical preflight|known prefix|known_prefix", source, re.I):
            low = str(body or "").strip().strip("{}").lower()
            if 6 <= len(low) <= 90 and "_" in low and low.endswith("_ok") and re.search(r"[a-z]", low):
                return True
        if _noise_body_v100(body, source):
            return False
        if re.search(r"double table ascii|numeric leak", source, re.I):
            low = str(body or "").strip().strip("{}").lower()
            if 8 <= len(low) <= 80 and "_" in low and re.search(r"[a-z]", low) and re.search(r"\d", low):
                return True
        if re.search(r"figlet|ascii art|ocr|visual reconstruction", source, re.I):
            low = str(body or "").strip().strip("{}").lower()
            if 8 <= len(low) <= 80 and "_" in low and re.search(r"[a-z]", low) and re.search(r"\d", low):
                return True
        return old_body_quality(body, source)

    core.body_quality = body_quality_v100

    def wants_wrapper_v100(report: dict) -> bool:
        # v100 fixes a long-standing over-wrap bug: "flag format" alone is not
        # enough to force ctf_cs{}.  Preserve raw {body}/TSG/UID answers unless
        # the statement explicitly names ctf_cs.
        return _explicit_ctf_cs(report)

    core.wants_wrapper = wants_wrapper_v100

    old_scan = core.scan_text

    def scan_text_v100(report: dict, text: str, source: str, artifact: str | None, why: str, score: int = 760, allow_wrap: bool | None = None) -> list[str]:
        old_allow = False if _weak_metadata_source(source, why) else allow_wrap
        out = old_scan(report, text, source, artifact, why, score, old_allow)
        out += scan_alt_formats(report, text, source, artifact, why, score + 20)
        return list(dict.fromkeys(out))

    core.scan_text = scan_text_v100

    old_artifact = core.artifact

    def artifact_v100(root: Path, report: dict, name: str, content: bytes | str, kind: str, note: str, score: int = 400, subdir: str = "v93") -> dict | None:
        art = old_artifact(root, report, name, content, kind, note, score, subdir)
        if art:
            family = _family(kind, subdir)
            art.setdefault("family", family)
            art.setdefault("method", kind)
            art.setdefault("source_file", report.get("rel", ""))
            art.setdefault("parent", report.get("path", ""))
            art.setdefault("ui_group", family)
            if isinstance(content, str):
                art.setdefault("preview", content[:700])
                text = content
            elif isinstance(content, (bytes, bytearray)):
                text = bytes(content[:1_000_000]).decode("utf-8", "ignore")
                art.setdefault("preview", bytes(content[:700]).decode("utf-8", "ignore"))
            else:
                text = ""
            if text and "manifest" not in kind.lower() and "manifest" not in str(name).lower():
                core.scan_text(report, text, f"SLOPER v100 artifact {kind}", art.get("path", ""), note, score + 150, allow_wrap=True)
        return art

    core.artifact = artifact_v100

    old_run = core.run_file_fast

    def demote_wrapped_without_ctf(report: dict) -> None:
        keep = []
        moved = []
        evidence = report.get("workflow_evidence", []) or []
        banned_flags: set[str] = set()
        filename_banned: set[str] = set()
        file_stems = set()
        for val in (report.get("name", ""), Path(str(report.get("path", ""))).name, Path(str(report.get("path", ""))).stem):
            clean = re.sub(r"[^a-z0-9]+", "_", str(val or "").lower()).strip("_")
            if clean:
                file_stems.add(clean)
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            flag = str(ev.get("flag", ""))
            mflag = core.STRICT_RE.fullmatch(flag)
            if not mflag:
                continue
            body = mflag.group(1).lower()
            why = str(ev.get("why", "")).lower()
            weak_meta = _weak_metadata_source(str(ev.get("source", "")), why)
            metadata_text = (str(ev.get("source", "")) + " " + why).lower()
            wrapped = ("wrapped" in why or "task declares ctf" in why or
                       "single clean extracted token" in why or "strong underscore token" in why)
            looks_like_filename = any(body == stem for stem in file_stems)
            if looks_like_filename:
                banned_flags.add(flag)
                filename_banned.add(flag)
            elif weak_meta and "zip comment" not in metadata_text and not _statement_requests_filename(report):
                banned_flags.add(flag)
            elif weak_meta and wrapped:
                banned_flags.add(flag)
            elif (not _explicit_ctf_cs(report)) and wrapped:
                banned_flags.add(flag)
        for flag in sorted(banned_flags):
            m = core.STRICT_RE.fullmatch(flag or "")
            if m and flag not in filename_banned:
                ev = next((e for e in evidence if isinstance(e, dict) and e.get("flag") == flag), {})
                add_answer_candidate(report, m.group(1), m.group(1), "SLOPER v100 wrapper demotion", ev.get("artifact", ""), "Wrapper was demoted because evidence was weak metadata or the task did not explicitly require ctf_cs.", 780, "demoted_wrapper")
                moved.append(flag)
            elif m:
                moved.append(flag)
        for item in report.get("flags", []) or []:
            flag = item.get("flag") if isinstance(item, dict) else str(item)
            if flag in banned_flags:
                continue
            keep.append(item)
        if moved:
            report["flags"] = keep
            report["workflow_evidence"] = [e for e in evidence if not (isinstance(e, dict) and e.get("flag") in banned_flags)]

    def run_file_fast_v100(mod_obj: Any, report: dict, root: Path, data: bytes) -> list[dict]:
        arts: list[dict] = []
        kind = report.get("kind") or core.kind_for(mod_obj, Path(report.get("path", "")), data)
        image_dims = _v102_image_dimensions(data) if kind == "image" and len(data) <= 60_000_000 else None
        large_image = bool(image_dims and image_dims[0] * image_dims[1] > 2_000_000)
        archive_fast = bool(kind == "archive" and _v102_archive_should_fast(data))
        binary_fast = bool(
            (((data.startswith(b"\x7fELF") or data.startswith(b"MZ")) and len(data) > 500_000) or (kind == "generic" and len(data) > 2_000_000))
            and not data.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x89PNG", b"\xff\xd8"))
        )
        if kind in {"text", "generic"} and len(data) <= 5_000_000:
            core.call_agent(report, root, data, "v102_logical_preflight", v102_logical_preflight_agent, arts, 4)
        if large_image:
            core.call_agent(report, root, data, "v102_large_image_triage", v102_large_image_triage_agent, arts, 6)
            demote_wrapped_without_ctf(report)
            report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
            return arts
        if archive_fast:
            core.call_agent(report, root, data, "v102_archive_triage", v102_archive_triage_agent, arts, 12)
            core.call_agent(report, root, data, "v100_raw_zip_local_headers", raw_zip_local_header_agent, arts, 6)
            demote_wrapped_without_ctf(report)
            report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
            return arts
        if binary_fast:
            core.call_agent(report, root, data, "v102_binary_triage", v102_binary_triage_agent, arts, 8)
            core.call_agent(report, root, data, "v100_pwn_static_flag_value", pwn_static_flag_value_agent, arts, 5)
            core.call_agent(report, root, data, "v100_double_table_ascii", double_table_ascii_agent, arts, 5)
            if len(data) <= 2_000_000:
                core.call_agent(report, root, data, "v100_known_prefix_xor", known_prefix_xor_agent, arts, 4)
            demote_wrapped_without_ctf(report)
            report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
            return arts
        if _v102_can_stop_after_preflight(report, data, kind):
            report.setdefault("sloper102_route", {
                "mode": "fast_solved_text",
                "why": "A logical transformation produced answer evidence on a small text task, so heavy legacy sweeps were skipped to keep the workflow readable.",
                "next": "Open the v102_preflight artifact, verify the transform, then run Deep/legacy agents only if the evidence is not convincing.",
                "deep_sweep_available": True,
            })
            demote_wrapped_without_ctf(report)
            report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
            return arts
        arts += old_run(mod_obj, report, root, data) or []
        demote_wrapped_without_ctf(report)
        if kind in {"generic", "text"} and len(data) <= 20_000_000:
            core.call_agent(report, root, data, "v100_double_table_ascii", double_table_ascii_agent, arts, 5)
            core.call_agent(report, root, data, "v100_pwn_static_flag_value", pwn_static_flag_value_agent, arts, 5)
        if kind in {"text", "generic"} and len(data) <= 5_000_000 and not report.get("flags"):
            core.call_agent(report, root, data, "v100_xor_container", xor_container_chain_agent, arts, 5)
            core.call_agent(report, root, data, "v100_priority_chain_retry", core.priority_chain_agent, arts, 5)
            if not report.get("flags"):
                core.call_agent(report, root, data, "v100_multistep_retry", core.multistep_decode_agent, arts, 8)
        if kind in {"text", "generic"} and len(data) <= 5_000_000:
            core.call_agent(report, root, data, "v101_time_anomaly_deep", time_anomaly_deep_agent, arts, 5)
            core.call_agent(report, root, data, "v100_text_patterns", text_pattern_agent, arts, 4)
            core.call_agent(report, root, data, "v100_source_reverse", source_reverse_agent, arts, 5)
            core.call_agent(report, root, data, "v100_known_prefix_xor", known_prefix_xor_agent, arts, 4)
            core.call_agent(report, root, data, "v100_alt_formats", text_alt_and_chain_agent, arts, 4)
        if kind in {"image", "generic"} and len(data) <= 15_000_000:
            core.call_agent(report, root, data, "v100_image_hidden_channels", image_hidden_channels_agent, arts, 8)
        if kind in {"archive", "generic", "text"} and len(data) <= 90_000_000:
            core.call_agent(report, root, data, "v100_raw_zip_local_headers", raw_zip_local_header_agent, arts, 6)
            core.call_agent(report, root, data, "v100_archive_child_multistep", archive_child_multistep_agent, arts, 8)
            core.call_agent(report, root, data, "v100_zip_password_chain", zip_password_chain_agent, arts, 8)
        if kind in {"pcap", "generic"} and len(data) <= 30_000_000:
            core.call_agent(report, root, data, "v100_pcap_scalar", pcap_scalar_agent, arts, 5)
        # v99 patch-note agents live in sloper_legacy.py and were hooked to the
        # older rb_enhance_report path.  Stable v93/v97 AutoSolve skipped them,
        # so run them here with the same bounded dispatcher and health logging.
        if len(data) <= 100_000_000:
            core.call_agent(report, root, data, "v99_workflow_sprint_agents", lambda r, rt, d: call_legacy_v99(mod_obj, r, rt, d), arts, 15)
            core.call_agent(report, root, data, "v100_high_signal_artifact_candidates", high_signal_artifact_candidate_agent, arts, 4)
        demote_wrapped_without_ctf(report)
        report["flags"] = core.sanitize_flag_items(report.get("flags", []), report)
        return arts

    core.run_file_fast = run_file_fast_v100
    mod.sl100_run_file_fast = lambda report, root, data: run_file_fast_v100(mod, report, root, data)
    mod.sl93_run_file_fast = mod.sl100_run_file_fast

    old_summary = core.build_summary

    def build_summary_v100(reports: list[dict], meta: dict, project_flags: list[dict], project_artifacts: list[dict]) -> dict:
        summary = old_summary(reports, meta, project_flags, project_artifacts)
        preflights = [r.get("sloper102_preflight") for r in reports or [] if isinstance(r.get("sloper102_preflight"), dict)]
        routes = [r.get("sloper102_route") for r in reports or [] if isinstance(r.get("sloper102_route"), dict)]
        if preflights:
            hits = []
            steps = []
            for pf in preflights:
                hits.extend([x for x in pf.get("hits", []) or [] if isinstance(x, dict)])
                steps.extend([x for x in pf.get("steps", []) or [] if isinstance(x, dict)])
            summary["sloper102_preflight"] = {
                "files": len(preflights),
                "hits": sorted(hits, key=lambda x: int(x.get("score", 0) or 0), reverse=True)[:80],
                "steps": sorted(steps, key=lambda x: int(x.get("priority", 0) or 0), reverse=True)[:120],
                "seconds": round(sum(float(x.get("seconds", 0) or 0) for x in preflights), 3),
                "note": "v102 logical preflight ran before heavy sweeps: byte encodings, base/compression chains, ROT/rail/columnar, wrappers and leetspeak evidence.",
            }
            summary.setdefault("sloper93_next_actions", [])
            if hits:
                summary["sloper93_next_actions"].insert(0, {
                    "priority": 130,
                    "step": "Verify v102 logical transformation hits first",
                    "why": f"{len(hits)} fast preflight hits were produced before broad legacy scanning. These are usually cleaner than raw strings.",
                })
        if routes:
            summary["sloper102_routes"] = routes[:40]
        project_evidence = project_multifile_evidence_v100(reports, meta)
        if project_evidence:
            summary.setdefault("workflow_evidence", [])
            summary.setdefault("flags", [])
            existing_flags = {str(x.get("flag") if isinstance(x, dict) else x) for x in summary.get("flags", []) or []}
            for ev in project_evidence:
                if ev not in summary["workflow_evidence"]:
                    summary["workflow_evidence"].append(ev)
                if ev["flag"] not in existing_flags:
                    summary["flags"].append({
                        "flag": ev["flag"],
                        "source": ev["source"],
                        "score": ev["score"],
                        "why": ev["why"],
                        "artifact": ev.get("artifact", ""),
                        "file": ev.get("file", ""),
                    })
                    existing_flags.add(ev["flag"])
        rescued_flags: list[dict[str, Any]] = []
        for r in reports or []:
            for ev in r.get("workflow_evidence", []) or []:
                if not isinstance(ev, dict):
                    continue
                flag = str(ev.get("flag") or "")
                m = core.STRICT_RE.fullmatch(flag)
                if not m:
                    continue
                source_blob = json.dumps(ev, ensure_ascii=False)[:600]
                if not core.body_quality(m.group(1), source_blob):
                    continue
                rescued_flags.append({
                    "flag": flag,
                    "file": r.get("rel", r.get("name", "")),
                    "score": int(ev.get("score", 900) or 900),
                    "why": ev.get("why", "Evidence-backed v100 workflow flag."),
                    "source": ev.get("source", ""),
                    "artifact": ev.get("artifact", ""),
                })
        if rescued_flags:
            seen_rescue = {str(x.get("flag") if isinstance(x, dict) else x) for x in summary.get("flags", []) or []}
            for item in rescued_flags:
                if item["flag"] not in seen_rescue:
                    summary.setdefault("flags", []).append(item)
                    seen_rescue.add(item["flag"])
        explicit_any = _explicit_ctf_cs({"statement": (meta or {}).get("statement", "")}) or any(_explicit_ctf_cs(r) for r in reports or [])
        file_stems = set()
        for r in reports or []:
            for val in (r.get("name", ""), Path(str(r.get("path", ""))).name, Path(str(r.get("path", ""))).stem):
                clean = re.sub(r"[^a-z0-9]+", "_", str(val or "").lower()).strip("_")
                if clean:
                    file_stems.add(clean)
        filtered_flags = []
        for item in summary.get("flags", []) or []:
            flag = item.get("flag") if isinstance(item, dict) else str(item)
            m = core.STRICT_RE.fullmatch(str(flag or ""))
            if not m:
                continue
            body = m.group(1).lower()
            if _generated_body(body):
                continue
            if not core.body_quality(body, json.dumps(item, ensure_ascii=False)[:600] if isinstance(item, dict) else str(item)):
                continue
            why = str(item.get("why", "") if isinstance(item, dict) else "").lower()
            if any(body == stem for stem in file_stems):
                continue
            item_blob = json.dumps(item, ensure_ascii=False)[:800] if isinstance(item, dict) else str(item)
            source_why = (
                (str(item.get("source", "")) + " " + str(item.get("why", "")))
                if isinstance(item, dict) else item_blob
            )
            if _weak_metadata_source(source_why, "") and not re.search(r"zip comment|filename requested|task asks", source_why, re.I):
                continue
            if not explicit_any and ("wrapped" in why or "wrappable" in why or "legacy wrapper candidate" in why):
                continue
            filtered_flags.append(item)
        summary["flags"] = filtered_flags
        alt = []
        for r in reports or []:
            alt.extend([x for x in r.get("alternate_flag_candidates", []) or [] if isinstance(x, dict)])
        seen = set()
        clean_alt = []
        for item in sorted(alt, key=lambda x: int(x.get("score", 0) or 0), reverse=True):
            body = str(item.get("body") or item.get("value") or item.get("candidate") or "").strip().strip("{}")
            if not core.body_quality(body, json.dumps(item, ensure_ascii=False)[:400]):
                continue
            body_low = body.lower()
            if any(body_low == stem for stem in file_stems):
                continue
            key = (str(item.get("value", "")).lower(), item.get("artifact", ""))
            if key in seen:
                continue
            seen.add(key)
            clean_alt.append(item)
        summary["alternate_flag_candidates"] = clean_alt[:160]
        answers = []
        for r in reports or []:
            answers.extend([x for x in r.get("answer_candidates", []) or [] if isinstance(x, dict)])
        seen_ans = set()
        clean_answers = []
        for item in sorted(answers, key=lambda x: int(x.get("score", 0) or 0), reverse=True):
            body = str(item.get("body") or item.get("value") or item.get("candidate") or "").strip().strip("{}")
            if core.STRICT_RE.fullmatch(body):
                body = core.STRICT_RE.fullmatch(body).group(1)
            if not core.body_quality(body, json.dumps(item, ensure_ascii=False)[:400]):
                continue
            body_low = body.lower()
            if any(body_low == stem for stem in file_stems):
                continue
            key = (str(item.get("value") or item.get("candidate") or "").lower(), item.get("artifact", ""), item.get("bucket", ""))
            if key in seen_ans:
                continue
            seen_ans.add(key)
            clean_answers.append(item)
        summary["answer_candidates"] = clean_answers[:240]
        raw_unconfirmed = []
        for r in reports or []:
            for bucket_name in ("unconfirmed_evidence", "answer_candidates", "alternate_flag_candidates", "weak_flag_candidates", "semantic_answer_candidates", "candidate_flags"):
                for item in r.get(bucket_name, []) or []:
                    if isinstance(item, dict):
                        row = dict(item)
                        row.setdefault("bucket", bucket_name)
                        row.setdefault("file", r.get("rel", r.get("name", "")))
                        raw_unconfirmed.append(row)
        clean_unconfirmed = []
        seen_unc = set()
        for item in sorted(raw_unconfirmed, key=lambda x: int(x.get("score", 0) or 0), reverse=True):
            body = str(item.get("body") or item.get("value") or item.get("candidate") or item.get("flag") or "").strip().strip("{}")
            if core.STRICT_RE.fullmatch(body):
                body = core.STRICT_RE.fullmatch(body).group(1)
            if not body or _generated_body(body):
                continue
            body_low = body.lower()
            key = (
                str(item.get("value") or item.get("candidate") or item.get("flag") or body).lower(),
                item.get("artifact", ""),
                item.get("bucket", ""),
                item.get("file", ""),
            )
            if key in seen_unc:
                continue
            seen_unc.add(key)
            item.setdefault("body", body)
            item.setdefault("confirmed", False)
            item.setdefault("why_not_promoted", "Kept as unconfirmed evidence for human review.")
            item.setdefault("wrapped_if_required", f"ctf_cs{{{body_low}}}")
            clean_unconfirmed.append(item)
        summary["unconfirmed_evidence"] = clean_unconfirmed[:500]

        def preview_for_path(path_text: str) -> str:
            try:
                p = Path(str(path_text))
                if not p.exists() or not p.is_file() or p.stat().st_size > 512_000:
                    return ""
                data = p.read_bytes()[:1600]
                if b"\x00" in data[:200]:
                    return ""
                return data.decode("utf-8", "replace")[:1200]
            except Exception:
                return ""

        evidence_paths = {
            str(e.get("artifact") or "")
            for e in summary.get("workflow_evidence", []) or []
            if isinstance(e, dict) and e.get("artifact")
        }
        candidate_paths = {
            str(x.get("artifact") or "")
            for x in (clean_answers + clean_alt + clean_unconfirmed)
            if isinstance(x, dict) and x.get("artifact")
        }
        priority_terms = (
            "open_first", "00_open_first", "start_here", "priority",
            "ascii_art", "figlet", "ocr", "canvas", "reconstruct", "reconstructed", "coordinate",
            "visual", "contact", "bitplane", "lsb", "palette", "alpha", "piet", "green_channel",
            "tile", "threshold", "invert", "contrast", "rotate", "flip", "crop",
            "decoded", "decompressed", "multistep_hit", "priority_chain", "xor_container",
            "zip_password", "zip_local_header", "office", "docx", "xlsx", "pptx", "pdf",
            "pcap_payload", "pcap_covert", "dns", "http", "icmp", "udp", "tcp_stream",
            "time_anomaly", "timeline", "timestamp",
            "double_table", "numeric", "movabs", "byte_array", "constant_array",
            "v102_preflight", "logical_preflight", "columnar", "rail", "rot_", "base64", "base32", "decimal", "octal",
        )
        visual_terms = (
            "ascii_art", "figlet", "ocr", "canvas", "reconstruct", "reconstructed",
            "visual", "contact", "bitplane", "lsb", "palette", "alpha", "piet",
            "green_channel", "tile", "threshold", "invert", "contrast", "rotate", "flip", "crop",
        )

        priority_artifacts: list[dict[str, Any]] = []
        seen_priority = set()
        for artifact in summary.get("artifacts", []) or []:
            if not isinstance(artifact, dict):
                continue
            blob = " ".join(str(artifact.get(k, "")) for k in ("name", "kind", "source", "note", "family", "method", "path", "file")).lower()
            apath = str(artifact.get("path") or "")
            score = int(artifact.get("score", 0) or 0)
            human_score = 0
            reasons: list[str] = []
            if apath in evidence_paths:
                human_score += 95
                reasons.append("direct workflow evidence")
            if apath in candidate_paths:
                human_score += 90
                reasons.append("source for an answer/leetspeak candidate")
            if any(term in blob for term in ("open_first", "00_open_first", "start_here")):
                human_score += 110
                reasons.append("marked as start-here")
            if any(term in blob for term in visual_terms):
                human_score += 100
                reasons.append("human-readable visual/stego reconstruction")
            if any(term in blob for term in priority_terms):
                human_score += 55
                reasons.append("high-signal transformation artifact")
            if "ctf_cs{" in blob or " tsg" in blob or "t5g" in blob or "uid" in blob:
                human_score += 45
                reasons.append("contains flag-like or alternate-format signal")
            if human_score <= 0:
                continue
            key = apath or str(artifact.get("url") or artifact.get("name") or id(artifact))
            if key in seen_priority:
                continue
            seen_priority.add(key)
            item = dict(artifact)
            item["open_first"] = True
            item["human_priority"] = human_score + min(score, 250)
            item["priority_reason"] = "; ".join(dict.fromkeys(reasons))
            if not item.get("preview") and apath:
                item["preview"] = preview_for_path(apath)
            priority_artifacts.append(item)

        for apath in sorted((evidence_paths | candidate_paths) - seen_priority):
            if not apath:
                continue
            p = Path(apath)
            if not p.exists():
                continue
            item = {
                "name": p.name,
                "kind": "priority_evidence",
                "path": apath,
                "url": "/api/raw?path=" + urllib.parse.quote(apath),
                "exists": True,
                "size": p.stat().st_size if p.is_file() else 0,
                "score": 900,
                "source": "workflow_evidence",
                "note": "Evidence artifact referenced by a workflow or candidate but missing from the main artifact list.",
                "open_first": True,
                "human_priority": 1200,
                "priority_reason": "direct workflow evidence",
                "preview": preview_for_path(apath),
            }
            priority_artifacts.append(item)

        priority_artifacts = sorted(
            priority_artifacts,
            key=lambda x: (int(x.get("human_priority", 0) or 0), int(x.get("score", 0) or 0), int(x.get("size", 0) or 0)),
            reverse=True,
        )[:120]
        summary["priority_artifacts"] = priority_artifacts
        summary["human_review_artifacts"] = priority_artifacts

        if priority_artifacts:
            prefixed: list[dict[str, Any]] = []
            seen_paths = set()
            for a in priority_artifacts + [x for x in summary.get("artifacts", []) or [] if isinstance(x, dict)]:
                key = str(a.get("path") or a.get("url") or a.get("name") or id(a))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                prefixed.append(a)
            summary["artifacts"] = prefixed[:8000]

        summary.setdefault("sloper100_review_lanes", {})
        summary["sloper100_review_lanes"].update({
            "alternate_format_candidates": len(clean_alt),
            "answer_candidates": len(clean_answers),
            "unconfirmed_evidence": len(clean_unconfirmed),
            "priority_artifacts": len(priority_artifacts),
            "workflow": "v100 CTF-player: archive-child decode chains, alternate flag formats, legacy v99 agents in stable mode",
        })
        summary.setdefault("sloper93_next_actions", [])
        if priority_artifacts:
            visual_count = len([
                a for a in priority_artifacts
                if any(term in (" ".join(str(a.get(k, "")) for k in ("name", "kind", "source", "note", "path")).lower()) for term in visual_terms)
            ])
            summary["sloper93_next_actions"].insert(0, {
                "priority": 104 if visual_count else 99,
                "step": "Open priority transformation artifacts",
                "why": f"{len(priority_artifacts)} high-signal artifacts were ranked for human review; {visual_count} are visual/reconstruction artifacts that may need eyes on them.",
            })
        if clean_alt:
            summary["sloper93_next_actions"].insert(0, {
                "priority": 98,
                "step": "Review alternate-format flags",
                "why": "UID/TSG/T5G/FLAG-style tokens were found and normalized only when task evidence supports wrapping.",
            })
        hub = summary.get("sloper93_artifact_hub") or {}
        try:
            groups = hub.setdefault("groups", {})
            start = groups.setdefault("start_here", [])
            known = {str(a.get("path") or a.get("name") or "") for a in start if isinstance(a, dict)}
            for a in priority_artifacts[:24]:
                key = str(a.get("path") or a.get("name") or "")
                if key and key not in known:
                    start.insert(0, a)
                    known.add(key)
            groups["start_here"] = start[:40]
            counts = hub.setdefault("counts", {})
            counts["open_first"] = len(groups["start_here"])
            summary["sloper93_artifact_hub"] = hub
        except Exception:
            pass
        summary["sloper100_artifact_hub"] = hub
        return summary

    core.build_summary = build_summary_v100
    mod.project_summary = lambda reports, meta: build_summary_v100(reports or [], meta or {}, [], [])
    mod.APP_TITLE = "CTF SLOPER v102 Logical Workflow"
    return mod
