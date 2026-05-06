#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
  echo "Creating virtualenv in .venv"
  python3 -m venv .venv || {
    echo "Virtualenv creation failed. On Ubuntu/Pop!_OS run: sudo apt install python3-venv"
    exit 1
  }
fi

source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-7860}"
echo "Starting CTF Sloper on http://${HOST}:${PORT}"
exec python -m uvicorn app:app --host "$HOST" --port "$PORT"
