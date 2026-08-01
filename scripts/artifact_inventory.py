#!/usr/bin/env python3
"""Create a bounded, read-only inventory of CTF challenge artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

DEFAULT_SAMPLE_BYTES = 1024 * 1024
DEFAULT_MAX_FILES = 5000

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip-empty"),
    (b"PK\x07\x08", "zip-spanned"),
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"RIFF", "riff"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3-id3"),
)


@dataclass(frozen=True)
class ArtifactRecord:
    path: str
    size: int
    sha256: str
    kind: str
    extension: str
    entropy: float
    printable_ratio: float
    sampled_bytes: int
    truncated_sample: bool


def iter_files(inputs: Iterable[Path], *, max_files: int) -> Iterator[Path]:
    """Yield regular files in stable order without following directory symlinks."""
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


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def read_sample(path: Path, *, sample_bytes: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(sample_bytes)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(
        1
        for byte in data
        if byte in (9, 10, 13) or 32 <= byte <= 126
    )
    return printable / len(data)


def detect_kind(sample: bytes) -> str:
    for signature, label in MAGIC_SIGNATURES:
        if sample.startswith(signature):
            if label == "riff" and len(sample) >= 12:
                form = sample[8:12]
                if form == b"WAVE":
                    return "wav"
                if form == b"AVI ":
                    return "avi"
                if form == b"WEBP":
                    return "webp"
            return label
    if not sample:
        return "empty"
    return "text" if printable_ratio(sample) >= 0.85 else "binary"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def inspect_file(path: Path, *, sample_bytes: int) -> ArtifactRecord:
    size = path.stat().st_size
    sample = read_sample(path, sample_bytes=sample_bytes)
    return ArtifactRecord(
        path=str(path),
        size=size,
        sha256=sha256_file(path),
        kind=detect_kind(sample),
        extension=path.suffix.lower(),
        entropy=round(shannon_entropy(sample), 4),
        printable_ratio=round(printable_ratio(sample), 4),
        sampled_bytes=len(sample),
        truncated_sample=size > len(sample),
    )


def render_text(records: Iterable[ArtifactRecord]) -> str:
    items = list(records)
    if not items:
        return "No regular files found."
    lines = []
    for record in items:
        lines.append(
            f"{record.path}\n"
            f"  type={record.kind} size={record.size} "
            f"entropy={record.entropy:.4f} printable={record.printable_ratio:.4f}\n"
            f"  sha256={record.sha256}"
        )
    total_bytes = sum(item.size for item in items)
    lines.append(f"\nfiles={len(items)} total_bytes={total_bytes}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely inventory files before running deeper CTF analysis."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON array",
    )
    parser.add_argument(
        "--sample-bytes",
        type=int,
        default=DEFAULT_SAMPLE_BYTES,
        help=f"bytes used for entropy/type metrics (default: {DEFAULT_SAMPLE_BYTES})",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help=f"maximum files to inspect (default: {DEFAULT_MAX_FILES})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.sample_bytes < 1:
        raise SystemExit("--sample-bytes must be positive")
    if args.max_files < 1:
        raise SystemExit("--max-files must be positive")

    try:
        files = list(iter_files(args.paths, max_files=args.max_files))
        records = [
            inspect_file(path, sample_bytes=args.sample_bytes)
            for path in files
        ]
    except (OSError, RuntimeError) as exc:
        print(f"artifact inventory failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(record) for record in records], indent=2))
    else:
        print(render_text(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
