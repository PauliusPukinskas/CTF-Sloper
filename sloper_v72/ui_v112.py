"""v112 UI convenience routes and frontend health checks."""
from __future__ import annotations
from fastapi.responses import RedirectResponse


def install(mod) -> None:
    def index_redirect():
        return RedirectResponse(url="/static/index.html", status_code=307)

    try:
        if hasattr(mod, "sl103_rebind_route"):
            mod.sl103_rebind_route("/", ["GET"], index_redirect)
        else:
            mod.app.add_api_route("/", index_redirect, methods=["GET"])
    except Exception:
        pass

    def stop_project_v112(pid: str):
        try:
            with mod.LOCK:
                job = mod.JOBS.setdefault(pid, {})
                job["cancel_requested"] = True
                job["status"] = "cancelled"
                job["stage"] = "Stop requested"
                job["updated"] = getattr(mod, "time", __import__("time")).time()
            try:
                mod.log(pid, "Stop requested by user")
            except Exception:
                pass
            return {"ok": True, "status": "cancelled", "pid": pid}
        except Exception as e:
            return {"ok": False, "error": repr(e), "pid": pid}

    try:
        if hasattr(mod, "sl103_rebind_route"):
            mod.sl103_rebind_route("/api/projects/{pid}/stop", ["POST"], stop_project_v112)
    except Exception:
        pass

    @mod.app.get("/api/ui_health")
    def ui_health():
        routes = []
        seen = {}
        for r in getattr(mod.app.router, "routes", []):
            path = getattr(r, "path", "")
            methods = sorted(getattr(r, "methods", []) or [])
            if not path:
                continue
            key = (path, tuple(methods))
            seen[key] = seen.get(key, 0) + 1
            routes.append({"path": path, "methods": methods})
        dupes = [{"path": k[0], "methods": list(k[1]), "count": v} for k, v in seen.items() if v > 1]
        return {"ok": not dupes, "duplicate_routes": dupes, "route_count": len(routes)}
