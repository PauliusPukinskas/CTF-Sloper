"""CTF SLOPER runtime bootstrap.

This is the public backend entrypoint.  It keeps the user-facing structure
simple while the compatibility modules continue to preserve older solver code.
"""
from __future__ import annotations

import importlib
from typing import Any

from sloper_v72.bootstrap import install as install_core_compatibility
from sloper_v72.boot_steps import apply_runtime_layers


def boot() -> Any:
    legacy = importlib.import_module("sloper_legacy")
    if getattr(legacy, "SLOPER_RUNTIME", "") == "clean":
        return legacy
    install_core_compatibility(legacy)
    apply_runtime_layers(legacy)
    legacy.SLOPER_RUNTIME = "clean"
    return legacy
