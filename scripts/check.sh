#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/5] Python syntax check"
python3 -m py_compile app.py sloper_legacy.py
python3 -m compileall -q sloper_v72 sloper_legacy_parts tests

echo "[2/5] Import smoke check"
python3 - <<'CHECKPY'
import sys
from pathlib import Path

root = Path.cwd()
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

import app
import sloper_legacy
from sloper_v72 import bootstrap, final_engine

assert hasattr(app, "app"), "app module did not expose FastAPI app"
assert hasattr(sloper_legacy, "app"), "legacy loader did not expose FastAPI app"
assert hasattr(bootstrap, "boot"), "bootstrap.boot missing"
assert hasattr(final_engine, "install"), "final_engine.install missing"
print('imports: OK')
CHECKPY

echo "[3/5] Frontend syntax check"
if command -v node >/dev/null 2>&1 && [[ -f static/index.check.js ]]; then
  node --check static/index.check.js
else
  echo "node not found or static/index.check.js missing; skipping JS syntax check"
fi

echo "[4/5] Pytest regression suite"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q

echo "[5/5] Git hygiene check"
test -f README.md
test -f .gitignore
test -f requirements.txt
test -d projects

echo "All checks passed."
