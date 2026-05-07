"""CTF SLOPER FINAL runtime-isolation entrypoint.

The old monolith now lives in sloper_legacy.py.
This file is intentionally small so future versions can move solvers into modules
without growing app.py forever.
"""
from sloper.runtime import boot

_legacy = boot()
app = _legacy.app

# Re-export legacy symbols for compatibility with old scripts/tests that import app.py.
for _k, _v in _legacy.__dict__.items():
    if not _k.startswith("__") and _k not in globals():
        globals()[_k] = _v

APP_TITLE = "CTF SLOPER FINAL"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=7860)
