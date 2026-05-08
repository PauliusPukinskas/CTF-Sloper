#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

PIP_EXTRA=""
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [ -f "/usr/lib/python${PYVER}/EXTERNALLY-MANAGED" ]; then
  PIP_EXTRA="--break-system-packages"
fi

python3 -m pip install --upgrade-strategy only-if-needed $PIP_EXTRA -r requirements.txt

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-7860}"
echo "Starting CTF Sloper on http://${HOST}:${PORT}"
exec python3 -m uvicorn app:app --host "$HOST" --port "$PORT"
