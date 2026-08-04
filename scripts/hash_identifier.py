#!/usr/bin/env python3
"""Identify likely hash formats without attempting to crack them."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

MAX_VALUES = 10_000
MAX_VALUE_LENGTH = 4_096

HEX_ALGORITHMS: dict[int, tuple[str, ...]] = {
    8: ("CRC-32", "Adler-32"),
    16: ("MySQL 3.2.3", "DES crypt fragment"),
    32: ("MD5", "MD4", "NTLM", "LM"),
    40: ("SHA-1", "RIPEMD-160", "MySQL 4.1+ without leading *"),
    56: ("SHA-224",),
    64: ("SHA-256", "SHA3-256", "BLAKE2s-256"),
    80: ("RIPEMD-320",),
    96: ("SHA-384", "SHA3-384"),
    128: ("SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"),
}

BYTE_LENGTH_ALGORITHMS: dict[int, tuple[str, ...]] = {
    16: HEX_ALGORITHMS[32],
    20: HEX_ALGORITHMS[40],
    28: HEX_ALGORITHMS[56],
    32: HEX_ALGORITHMS[64],
    48: HEX_ALGORITHMS[96],
    64: HEX_ALGORITHMS[128],
}

PREFIX_FORMATS: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "modular-crypt", ("bcrypt",)),
    (re.compile(r"^\$argon2(?:d|i|id)\$"), "PHC", ("Argon2",)),
    (re.compile(r"^\$scrypt\$"), "PHC", ("scrypt",)),
    (re.compile(r"^\$pbkdf2(?:-[a-z0-9]+)?\$", re.IGNORECASE), "encoded", ("PBKDF2",)),
    (re.compile(r"^\$1\$"), "modular-crypt", ("md5crypt",)),
    (re.compile(r"^\$apr1\$"), "modular-crypt", ("Apache md5crypt",)),
    (re.compile(r"^\$5\$"), "modular-crypt", ("sha256crypt",)),
    (re.compile(r"^\$6\$"), "modular-crypt", ("sha512crypt",)),
    (re.compile(r"^\$[PH]\$"), "portable", ("phpass",)),
    (re.compile(r"^\{SSHA\}", re.IGNORECASE), "LDAP", ("salted SHA-1",)),
    (re.compile(r"^\{SHA\}", re.IGNORECASE), "LDAP", ("SHA-1",)),
    (re.compile(r"^\*[0-9A-F]{40}$"), "database", ("MySQL 4.1+",)),
)


@dataclass(frozen=True)
class HashGuess:
    value: str
    normalized: str
    encoding: str
    length: int
    algorithms: tuple[str, ...]
    confidence: str
    note: str


def _guess_prefixed(value: str) -> HashGuess | None:
    for pattern, encoding, algorithms in PREFIX_FORMATS:
        if pattern.search(value):
            return HashGuess(
                value=value,
                normalized=value,
                encoding=encoding,
                length=len(value),
                algorithms=algorithms,
                confidence="high",
                note="format marker identifies the family; parameters may still vary",
            )
    return None


def _decode_base64(value: str) -> bytes | None:
    if len(value) < 16 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    canonical = base64.b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value.rstrip("="):
        return None
    return decoded


def identify_hash(value: str, *, allow_base64: bool = False) -> HashGuess:
    original = value.rstrip("\r\n")
    normalized = original.strip()
    if not normalized:
        return HashGuess(original, normalized, "unknown", 0, (), "none", "empty input")
    if len(normalized) > MAX_VALUE_LENGTH:
        return HashGuess(
            original,
            normalized[:MAX_VALUE_LENGTH],
            "unknown",
            len(normalized),
            (),
            "none",
            f"input exceeds {MAX_VALUE_LENGTH} characters",
        )

    prefixed = _guess_prefixed(normalized)
    if prefixed is not None:
        return prefixed

    if re.fullmatch(r"[0-9a-fA-F]+", normalized):
        algorithms = HEX_ALGORITHMS.get(len(normalized), ())
        if algorithms:
            return HashGuess(
                original,
                normalized.lower(),
                "hex",
                len(normalized),
                algorithms,
                "medium" if len(algorithms) == 1 else "low",
                "digest length is compatible with multiple algorithms; verify context",
            )
        return HashGuess(
            original,
            normalized.lower(),
            "hex",
            len(normalized),
            (),
            "none",
            "valid hexadecimal, but its length is not in the known digest table",
        )

    if allow_base64:
        decoded = _decode_base64(normalized)
        if decoded is not None:
            algorithms = BYTE_LENGTH_ALGORITHMS.get(len(decoded), ())
            note = (
                "decoded byte length matches common digests; arbitrary binary can look identical"
                if algorithms
                else "valid canonical base64, but decoded length is not in the known digest table"
            )
            return HashGuess(
                original,
                normalized,
                "base64",
                len(decoded),
                algorithms,
                "low" if algorithms else "none",
                note,
            )

    return HashGuess(
        original,
        normalized,
        "unknown",
        len(normalized),
        (),
        "none",
        "no recognized hash encoding or format marker",
    )


def collect_values(
    positional: Iterable[str],
    *,
    files: Iterable[Path],
    stdin: Iterable[str] | None = None,
) -> list[str]:
    values = list(positional)
    for path in files:
        if not path.is_file():
            raise FileNotFoundError(path)
        values.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
    if stdin is not None:
        values.extend(line.rstrip("\r\n") for line in stdin)

    filtered = [value for value in values if value.strip() and not value.lstrip().startswith("#")]
    if len(filtered) > MAX_VALUES:
        raise ValueError(f"value limit exceeded ({MAX_VALUES})")
    return filtered


def render_text(guesses: Iterable[HashGuess]) -> str:
    items = list(guesses)
    if not items:
        return "No hash values supplied."
    lines: list[str] = []
    for item in items:
        algorithms = ", ".join(item.algorithms) if item.algorithms else "unknown"
        lines.append(
            f"{item.value}\n"
            f"  encoding: {item.encoding}\n"
            f"  possible: {algorithms}\n"
            f"  confidence: {item.confidence}\n"
            f"  note: {item.note}"
        )
    return "\n\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Identify likely hash families from format markers and digest length."
    )
    parser.add_argument("hashes", nargs="*", help="hash values to inspect")
    parser.add_argument(
        "--file",
        action="append",
        type=Path,
        default=[],
        help="read one hash per line; repeat for multiple files",
    )
    parser.add_argument(
        "--allow-base64",
        action="store_true",
        help="also classify canonical base64 by decoded digest length",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    stdin = (
        sys.stdin
        if not args.hashes and not args.file and not sys.stdin.isatty()
        else None
    )
    try:
        values = collect_values(args.hashes, files=args.file, stdin=stdin)
    except (OSError, ValueError) as exc:
        print(f"hash identification failed: {exc}", file=sys.stderr)
        return 2

    guesses = [identify_hash(value, allow_base64=args.allow_base64) for value in values]
    if args.json:
        print(json.dumps([asdict(item) for item in guesses], indent=2))
    else:
        print(render_text(guesses))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
