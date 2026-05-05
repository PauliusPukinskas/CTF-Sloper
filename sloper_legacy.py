
"""Compatibility loader for the split legacy runtime.

The old 21k-line monolith was split into sloper_legacy_parts/part_*.py.
This loader executes those parts in order inside this module namespace so existing
imports like `import sloper_legacy; sloper_legacy.app` keep working.

New code should live in sloper_v72/* or future core/solver modules, not in these
generated legacy parts.
"""
from __future__ import annotations
from pathlib import Path

_PARTS_DIR = Path(__file__).with_name("sloper_legacy_parts")
if not _PARTS_DIR.exists():
    raise RuntimeError(f"missing split legacy parts directory: {_PARTS_DIR}")

_loaded_parts = []
for _part in sorted(_PARTS_DIR.glob("part_*.py")):
    _loaded_parts.append(_part.name)
    _code = compile(_part.read_text(encoding="utf-8"), str(_part), "exec")
    exec(_code, globals(), globals())

LEGACY_PARTS_LOADED = tuple(_loaded_parts)
del _code, _part
