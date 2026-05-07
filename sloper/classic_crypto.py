"""Deterministic classical crypto transforms for backend file analysis."""
from __future__ import annotations

import base64
import re
import time
from pathlib import Path
from typing import Any


STRICT_RE = re.compile(r"(?is)\b[A-Za-z0-9_]{1,32}\{[^{}\r\n]{1,220}\}")
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{1,15}")


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "classic")).strip("._")[:120] or "classic"


def _text(raw: bytes) -> str:
    for enc in ("utf-8", "latin1"):
        try:
            return raw.decode(enc, errors="ignore")
        except Exception:
            pass
    return ""


def _caesar(s: str, shift: int) -> str:
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + shift) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _rot47(s: str) -> str:
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        out.append(chr(33 + ((o - 33 + 47) % 94)) if 33 <= o <= 126 else ch)
    return "".join(out)


def _atbash(s: str) -> str:
    out: list[str] = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(90 - (o - 65)))
        elif 97 <= o <= 122:
            out.append(chr(122 - (o - 97)))
        else:
            out.append(ch)
    return "".join(out)


def _vigenere_decrypt(s: str, key: str) -> str:
    shifts = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not shifts:
        return s
    out: list[str] = []
    j = 0
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 - shifts[j % len(shifts)]) % 26 + 65))
            j += 1
        elif 97 <= o <= 122:
            out.append(chr((o - 97 - shifts[j % len(shifts)]) % 26 + 97))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def _score(text: str) -> int:
    low = text.lower()
    score = 0
    if STRICT_RE.search(text):
        score += 1000
    score += 180 if "ctf" in low else 0
    score += 120 if "flag" in low else 0
    score += 70 if "{" in text and "}" in text else 0
    score += min(220, len(re.findall(r"[A-Za-z0-9_]{4,}", text)) * 8)
    return score


def _interesting_transform(text: str, score: int) -> bool:
    """Keep deterministic transforms focused on CTF signal, not README prose."""
    low = text.lower()
    return bool(
        STRICT_RE.search(text)
        or ("ctf" in low and "{" in text and "}" in text)
        or ("flag" in low and "{" in text and "}" in text)
        or score >= 360
    )


def _statement_and_readme(mod: Any, report: dict, root: Path) -> str:
    chunks = [str(report.get("statement") or ""), str(report.get("task") or "")]
    try:
        meta = mod.jread(mod.meta_path(str(report.get("pid") or "")), {}) if report.get("pid") and hasattr(mod, "meta_path") else {}
        if isinstance(meta, dict):
            chunks.append(str(meta.get("statement") or ""))
    except Exception:
        pass
    try:
        for p in (root / "files").rglob("*"):
            if p.is_file() and p.name.lower() in {"readme.md", "readme.txt", "statement.txt", "task.txt"} and p.stat().st_size < 200_000:
                chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    return "\n".join(chunks)


def _candidate_keys(statement: str, text: str) -> list[str]:
    keys: list[str] = []
    clues = statement + "\n" + text[:2000]
    for m in re.finditer(r"(?i)\b(?:key|raktas|password|slaptazodis|secret)\s*[:=]\s*([A-Za-z][A-Za-z0-9]{1,15})", clues):
        keys.append(m.group(1))
    for word in WORD_RE.findall(clues):
        if 3 <= len(word) <= 16 and word.lower() not in {"category", "difficulty", "format", "crypto", "stego", "forensics", "misc", "task", "readme"}:
            keys.append(word)
    out: list[str] = []
    seen: set[str] = set()
    for key in ["KEY", "SECRET", "PASSWORD", "CYBER", "SPRINT", "CTF"] + keys:
        k = key.upper()
        if k not in seen and 2 <= len(k) <= 16:
            seen.add(k)
            out.append(k)
    return out[:80]


def _add_flag(report: dict, flag: str, source: str, artifact: str, why: str, score: int) -> None:
    row = {
        "flag": flag,
        "score": score,
        "status": "confirmed",
        "source": source,
        "artifact": artifact,
        "why": why,
        "bucket": "classic_crypto_transform",
        "method": source,
    }
    # Older summary layers expect report["flags"] to be a list of strings.
    # Keep rich evidence in the side channels until the final ranking gate.
    report.setdefault("flags", []).append(flag)
    report.setdefault("verified_flags", []).append(row)
    report.setdefault("findings", []).append(row)
    report.setdefault("workflow_evidence", []).append(row)


def _artifact(root: Path, report: dict, name: str, text: str, method: str, note: str, score: int) -> dict:
    outdir = root / "artifacts" / "classic_crypto"
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / _safe_name(name)
    path.write_text(text[:1_000_000], encoding="utf-8", errors="replace")
    rel = report.get("rel") or report.get("name") or ""
    art = {
        "name": path.name,
        "kind": "classic_crypto_transform",
        "family": "crypto_decode",
        "method": method,
        "source": "classic_crypto",
        "source_file": rel,
        "file": rel,
        "path": str(path),
        "url": "/api/raw?path=" + str(path),
        "score": score,
        "note": note,
        "exists": True,
        "size": path.stat().st_size,
        "preview": text[:700],
    }
    report.setdefault("artifacts", []).append(art)
    return art


def classic_crypto_agent(mod: Any, report: dict, root: Path, data: bytes) -> list[dict]:
    if len(data) > 5_000_000:
        return []
    rel = str(report.get("rel") or report.get("name") or "").lower()
    text_exts = (".txt", ".md", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".py", ".c", ".h", ".cpp", ".java", ".js", ".ts", ".rs", ".go", ".php", ".sh", ".ps1")
    binary_magic = data.startswith((
        b"\x89PNG", b"\xff\xd8", b"GIF87a", b"GIF89a", b"RIFF", b"PK\x03\x04",
        b"%PDF", b"SQLite format 3", b"\x7fELF", b"MZ", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
    ))
    sample = data[:10000]
    printable_ratio = sum(1 for b in sample if b in b"\t\n\r" or 32 <= b <= 126) / max(1, len(sample))
    if binary_magic and not rel.endswith(text_exts):
        return []
    if printable_ratio < 0.68 and not rel.endswith(text_exts):
        return []
    text = _text(data)
    if not text or sum(ch.isprintable() or ch.isspace() for ch in text[:10000]) < max(10, len(text[:10000]) // 2):
        return []
    start = time.time()
    statement = _statement_and_readme(mod, report, root)
    transforms: list[tuple[str, str, str]] = []
    for shift in range(1, 26):
        transforms.append((f"caesar_{shift}", _caesar(text, shift), f"Caesar shift {shift} over source text."))
    transforms.append(("rot47", _rot47(text), "ROT47 over printable source text."))
    transforms.append(("atbash", _atbash(text), "Atbash substitution over source text."))
    for key in _candidate_keys(statement, text):
        transforms.append((f"vigenere_{_safe_name(key)}", _vigenere_decrypt(text, key), f"Vigenere decrypt using clue key {key}."))

    arts: list[dict] = []
    seen: set[str] = set()
    for method, out, note in transforms:
        if time.time() - start > 4.0:
            break
        raw_score = _score(out)
        score = 820 + min(raw_score, 420)
        if not _interesting_transform(out, raw_score):
            continue
        sig = method + "\0" + out[:2000]
        if sig in seen:
            continue
        seen.add(sig)
        art = _artifact(root, report, method + ".txt", out, method, note, score)
        arts.append(art)
        for m in STRICT_RE.finditer(out):
            _add_flag(report, m.group(0), f"classic_crypto:{method}", art["path"], note, score + 160)
        # Common CTF chain: classical output is base64 wrapping the real flag.
        compact = re.sub(r"\s+", "", out)
        if 12 <= len(compact) <= 200000 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            for alt in (None, b"-_"):
                try:
                    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
                    raw = base64.b64decode(padded.encode(), altchars=alt, validate=False)
                    child = raw.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if STRICT_RE.search(child):
                    cart = _artifact(root, report, method + "_base64.txt", child, method + "+base64", note + " Then base64 decoded.", score + 50)
                    arts.append(cart)
                    for m in STRICT_RE.finditer(child):
                        _add_flag(report, m.group(0), f"classic_crypto:{method}+base64", cart["path"], note + " Then base64 decoded.", score + 220)
    if arts:
        report["classic_crypto"] = {"enabled": True, "artifacts": len(arts), "seconds": round(time.time() - start, 3)}
    return arts


def apply(mod: Any) -> None:
    old_analyze = getattr(mod, "analyze_file", None)

    def analyze_file(pid, path, root, i=1, total=1):
        report = old_analyze(pid, path, root, i, total) if old_analyze else {"path": str(path), "name": Path(path).name, "flags": [], "artifacts": []}
        if not isinstance(report, dict):
            report = {"path": str(path), "name": Path(path).name, "flags": [], "artifacts": [], "legacy_result": report}
        try:
            raw = Path(path).read_bytes()[:5_000_000]
            arts = classic_crypto_agent(mod, report, Path(root), raw)
            if arts:
                report.setdefault("artifacts", []).extend([a for a in arts if a not in report.get("artifacts", [])])
        except Exception as exc:
            try:
                from sloper_v72.health import agent_crash
                agent_crash("classic_crypto", exc, report)
            except Exception:
                pass
        return report

    mod.analyze_file = analyze_file
    mod.sloper_classic_crypto_agent = classic_crypto_agent
    mod.SLOPER_CLASSIC_CRYPTO = "deterministic-classic-crypto"
