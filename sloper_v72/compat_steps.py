"""Compatibility solver-layer manifest.

These modules preserve accumulated solver behavior.  They are grouped here so
the core bootstrap does not keep growing with hand-stitched imports.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from .health import agent_crash


@dataclass(frozen=True)
class CompatStep:
    name: str
    module: str
    function: str = "install"


COMPAT_STEPS: tuple[CompatStep, ...] = (
    CompatStep("workflow engine", "sloper_v72.workflow_v74"),
    CompatStep("job workflow state", "sloper_v72.workflow_v75"),
    CompatStep("semantic triage", "sloper_v72.semantic_v76"),
    CompatStep("strict wrapper handling", "sloper_v72.strict_wraps_v77"),
    CompatStep("universal local extractors", "sloper_v72.universal_v89"),
    CompatStep("reasoned workflow engine", "sloper_v72.v93_reasoned"),
    CompatStep("ctf player workflow", "sloper_v72.v100_ctf_player"),
    CompatStep("final solver engine", "sloper_v72.final_engine"),
)


def apply_compat_layers(mod: Any) -> list[dict[str, str]]:
    status: list[dict[str, str]] = []
    for step in COMPAT_STEPS:
        item = {"name": step.name, "status": "ok", "error": ""}
        try:
            module = importlib.import_module(step.module)
            getattr(module, step.function)(mod)
        except Exception as exc:
            item["status"] = "failed"
            item["error"] = repr(exc)
            agent_crash(f"compat layer: {step.name}", exc, None)
        status.append(item)
    mod.SLOPER_COMPAT_STEPS = status
    return status
