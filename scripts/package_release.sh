#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(basename "$PWD")"
cd ..
rm -f "${ROOT}-github-ready.zip" "${ROOT}-github-ready.tar.gz"
python3 - <<'PACKPY'
from pathlib import Path
import zipfile, tarfile
root = Path('ctf-sloper')
ignore = {'.git', '.venv', '__pycache__', '.pytest_cache'}
files = [p for p in root.rglob('*') if p.is_file() and not any(part in ignore for part in p.parts)]
with zipfile.ZipFile(f'{root.name}-github-ready.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for p in files:
        z.write(p, p.as_posix())
with tarfile.open(f'{root.name}-github-ready.tar.gz', 'w:gz') as t:
    for p in files:
        t.add(p, p.as_posix())
print(f'Created {root.name}-github-ready.zip and {root.name}-github-ready.tar.gz')
PACKPY
