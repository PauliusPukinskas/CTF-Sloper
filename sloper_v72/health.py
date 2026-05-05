
"""CTF SLOPER v72 agent health and traceback reporting."""
from __future__ import annotations
import time
import traceback
from collections import deque
from typing import Any, Dict, List, Optional

AGENT_HEALTH = deque(maxlen=500)

def agent_crash(agent: str, exc: Optional[BaseException] = None, report: Optional[dict] = None) -> Dict[str, Any]:
    item = {
        "agent": str(agent),
        "error": repr(exc) if exc is not None else "",
        "traceback": traceback.format_exc(),
        "file": (report or {}).get("rel") or (report or {}).get("name") or "",
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    AGENT_HEALTH.append(item)
    if isinstance(report, dict):
        report.setdefault("agent_health", []).append(item)
    return item

def install_health_endpoint(app) -> None:
    try:
        @app.get("/api/agent_health")
        def api_agent_health():
            return {"count": len(AGENT_HEALTH), "agent_health": list(AGENT_HEALTH)[-200:]}
    except Exception:
        # Endpoint might already exist during reloads.
        pass
