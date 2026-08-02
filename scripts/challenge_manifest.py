#!/usr/bin/env python3
"""Build a deterministic integrity manifest for CTF challenge artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from artifact_inventory import DEFAULT_MAX_FILES, DEFAULT_SAMPLE_BYTES, inspect_file, iter_files


def build_manifest(paths: list[Path], *, max_files: int, sample_bytes: int) -> dict[str, object]:
    files = list(iter_files(paths, max_files=max_files))
    records = [inspect_file(path, sample_bytes=sample_bytes) for path in files]
    return {
        "schema_version": 1,
        "file_count": len(records),
        "total_bytes": sum(record.size for record in records),
        "files": [asdict(record) for record in records],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a deterministic JSON integrity manifest for challenge files."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories")
    parser.add_argument("--output", type=Path, help="write JSON to this path")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--sample-bytes", type=int, default=DEFAULT_SAMPLE_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_files < 1:
        raise SystemExit("--max-files must be positive")
    if args.sample_bytes < 1:
        raise SystemExit("--sample-bytes must be positive")

    try:
        manifest = build_manifest(
            args.paths,
            max_files=args.max_files,
            sample_bytes=args.sample_bytes,
        )
    except (OSError, RuntimeError) as exc:
        print(f"manifest creation failed: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
