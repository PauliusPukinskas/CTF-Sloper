#!/usr/bin/env python3
"""Find likely CTF flags in files without executing or unpacking them."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Pattern

DEFAULT_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_FILES = 5000
DEFAULT_CONTEXT = 32
DEFAULT_PATTERNS: tuple[str, ...] = (
    r"(?i)(?:flag|ctf(?:_[a-z0-9]+)?|picoctf|htb|thm|ks)\{[^\r\n{}]{1,200}\}",
    r"(?i)ictf\[[^\r\n\[\]]{1,200}\]",
)


@dataclass(frozen=True)
class FlagMatch:
    path: str
    offset: int
    candidate: str
    context: str
    pattern: str
    truncated_file: bool


def iter_files(inputs: Iterable[Path], *, max_files: int) -> Iterator[Path]:
    emitted = 0
    for source in inputs:
        if not source.exists():
            raise FileNotFoundError(source)
        if source.is_symlink():
            continue
        if source.is_file():
            emitted += 1
            if emitted > max_files:
                raise RuntimeError(f"file limit exceeded ({max_files})")
            yield source
            continue

        for root, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = sorted(
                name for name in dirs if not (Path(root) / name).is_symlink()
            )
            for name in sorted(files):
                candidate = Path(root) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                emitted += 1
                if emitted > max_files:
                    raise RuntimeError(f"file limit exceeded ({max_files})")
                yield candidate


def compile_patterns(custom: list[str] | None) -> list[Pattern[str]]:
    sources = custom or list(DEFAULT_PATTERNS)
    compiled: list[Pattern[str]] = []
    for source in sources:
        try:
            compiled.append(re.compile(source))
        except re.error as exc:
            raise ValueError(f"invalid regex {source!r}: {exc}") from exc
    return compiled


def sanitize_context(value: str) -> str:
    return "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in value
    )


def scan_file(
    path: Path,
    *,
    patterns: Iterable[Pattern[str]],
    max_bytes: int,
    context_bytes: int,
) -> list[FlagMatch]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        payload = handle.read(max_bytes)
    text = payload.decode("latin-1")
    truncated = size > len(payload)

    matches: list[FlagMatch] = []
    seen: set[tuple[int, str]] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            key = (match.start(), match.group(0))
            if key in seen:
                continue
            seen.add(key)
            context_start = max(0, match.start() - context_bytes)
            context_end = min(len(text), match.end() + context_bytes)
            matches.append(
                FlagMatch(
                    path=str(path),
                    offset=match.start(),
                    candidate=match.group(0),
                    context=sanitize_context(text[context_start:context_end]),
                    pattern=pattern.pattern,
                    truncated_file=truncated,
                )
            )

    return sorted(matches, key=lambda item: (item.offset, item.candidate))


def scan_paths(
    inputs: Iterable[Path],
    *,
    patterns: Iterable[Pattern[str]],
    max_bytes: int,
    max_files: int,
    context_bytes: int,
) -> list[FlagMatch]:
    results: list[FlagMatch] = []
    for path in iter_files(inputs, max_files=max_files):
        results.extend(
            scan_file(
                path,
                patterns=patterns,
                max_bytes=max_bytes,
                context_bytes=context_bytes,
            )
        )
    return results


def render_text(matches: Iterable[FlagMatch]) -> str:
    items = list(matches)
    if not items:
        return "No candidate flags found."
    lines = []
    for item in items:
        suffix = " [file truncated]" if item.truncated_file else ""
        lines.append(
            f"{item.path}:{item.offset}: {item.candidate}{suffix}\n"
            f"  context: {item.context}"
        )
    lines.append(f"\nmatches={len(items)}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search files for likely CTF flag strings using bounded reads."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories")
    parser.add_argument(
        "--regex",
        action="append",
        dest="regexes",
        help="custom Python regex; repeat to provide multiple patterns",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON array",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"maximum bytes read from each file (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help=f"maximum files scanned (default: {DEFAULT_MAX_FILES})",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=DEFAULT_CONTEXT,
        help=f"context bytes shown around matches (default: {DEFAULT_CONTEXT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_bytes < 1:
        raise SystemExit("--max-bytes must be positive")
    if args.max_files < 1:
        raise SystemExit("--max-files must be positive")
    if args.context < 0:
        raise SystemExit("--context cannot be negative")

    try:
        patterns = compile_patterns(args.regexes)
        matches = scan_paths(
            args.paths,
            patterns=patterns,
            max_bytes=args.max_bytes,
            max_files=args.max_files,
            context_bytes=args.context,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flag search failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in matches], indent=2))
    else:
        print(render_text(matches))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
