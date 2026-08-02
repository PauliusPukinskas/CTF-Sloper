"""Shared pytest setup for dynamically loaded command-line modules.

Several tests load scripts directly with ``importlib.util`` instead of importing a
package. Python 3.12 dataclasses expect the module to be present in
``sys.modules`` while the class decorator runs. Registering dynamically created
modules here keeps those tests deterministic without changing runtime code.
"""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType
from typing import Any

_ORIGINAL_MODULE_FROM_SPEC = importlib.util.module_from_spec


def _registered_module_from_spec(spec: Any) -> ModuleType:
    module = _ORIGINAL_MODULE_FROM_SPEC(spec)
    name = getattr(spec, "name", None)
    if isinstance(name, str) and name:
        sys.modules[name] = module
    return module


def pytest_configure() -> None:
    importlib.util.module_from_spec = _registered_module_from_spec


def pytest_unconfigure() -> None:
    importlib.util.module_from_spec = _ORIGINAL_MODULE_FROM_SPEC
