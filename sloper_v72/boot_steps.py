"""Ordered runtime layer manifest for CTF SLOPER.

The legacy solver is intentionally preserved, but new behavior should be
installed through this manifest instead of growing a long hand-written boot
chain.  This keeps the runtime easy to audit: order matters, failures are
reported, and the active layers are visible from the loaded module.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from .health import agent_crash


@dataclass(frozen=True)
class BootStep:
    name: str
    module: str
    function: str = "apply"


BOOT_STEPS: tuple[BootStep, ...] = (
    BootStep("hardening", "sloper_v72.hardening_v108"),
    BootStep("fast lane", "sloper_v72.fast_lane_v110"),
    BootStep("control plane", "sloper_v72.control_plane_v111", "install"),
    BootStep("competition extractors v113", "sloper_v72.competition_v113"),
    BootStep("competition extractors v114", "sloper_v72.competition_v114"),
    BootStep("evidence v113", "sloper_v72.evidence_v113"),
    BootStep("competition extractors v115", "sloper_v72.competition_v115"),
    BootStep("evidence v114", "sloper_v72.evidence_v114"),
    BootStep("evidence v115", "sloper_v72.evidence_v115"),
    BootStep("competition extractors v116", "sloper_v72.competition_v116"),
    BootStep("evidence v116", "sloper_v72.evidence_v116"),
    BootStep("competition extractors v117", "sloper_v72.competition_v117"),
    BootStep("evidence v117", "sloper_v72.evidence_v117"),
    BootStep("ui endpoints", "sloper_v72.ui_v112", "install"),
    BootStep("upload flow v123", "sloper_v72.upload_flow_v123", "install"),
    BootStep("evidence v123", "sloper_v72.evidence_v123"),
    BootStep("classic crypto", "sloper.classic_crypto"),
    BootStep("multistep repair", "sloper.multistep_repair"),
    BootStep("deep workflows", "sloper.deep_workflows"),
    BootStep("pattern intelligence", "sloper.pattern_intelligence"),
    BootStep("final ranking", "sloper.ranking"),
)


def apply_runtime_layers(mod: Any) -> list[dict[str, str]]:
    """Install all runtime layers and record a compact boot report."""
    status: list[dict[str, str]] = []
    for step in BOOT_STEPS:
        item = {"name": step.name, "status": "ok", "error": ""}
        try:
            module = importlib.import_module(step.module)
            fn = getattr(module, step.function)
            fn(mod)
        except Exception as exc:
            item["status"] = "failed"
            item["error"] = repr(exc)
            agent_crash(f"boot step: {step.name}", exc, None)
            print(f"warning: boot step {step.name} failed: {exc}")
        status.append(item)
    mod.SLOPER_BOOT_STEPS = status
    mod.SLOPER_BOOT_VERSION = "clean-runtime"
    return status
