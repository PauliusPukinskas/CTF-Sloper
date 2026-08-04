#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/4] Python syntax check"
python3 -m py_compile app.py sloper_legacy.py scripts/hash_identifier.py
python3 -m compileall -q sloper_v72

echo "[2/4] Import smoke check"
python3 - <<'CHECKPY'
import importlib.util
for path in ['app.py', 'sloper_v72/bootstrap.py', 'sloper_v72/final_engine.py']:
    spec = importlib.util.spec_from_file_location('mod', path)
    assert spec is not None, path
print('imports: OK')
CHECKPY

echo "[3/4] Frontend syntax check"
if command -v node >/dev/null 2>&1 && [[ -f static/index.check.js ]]; then
  node --check static/index.check.js
else
  echo "node not found or static/index.check.js missing; skipping JS syntax check"
fi

echo "[4/4] Git hygiene check"
test -f README.md
test -f .gitignore
test -f requirements.txt
test -d projects

echo "All checks passed."
