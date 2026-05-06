from fastapi.testclient import TestClient


def test_v123_upload_create_and_auto_start_route():
    import app

    client = TestClient(app.app, raise_server_exceptions=False)
    routes = [
        (getattr(r, "path", ""), set(getattr(r, "methods", []) or []))
        for r in app.app.routes
    ]
    assert any(path == "/api/projects" and "POST" in methods for path, methods in routes)

    response = client.post(
        "/api/projects",
        data={
            "title": "",
            "statement": "Flag format is ctf_cs{...}",
            "category": "misc",
            "auto_start": "true",
            "attack_preset": "quick",
        },
        files={"files": ("hello world.txt", b"ctf_cs{upload_flow_ok}", "text/plain")},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data.get("ok") is True
    pid = data["id"]
    project = client.get(f"/api/projects/{pid}")
    assert project.status_code == 200
    blob = project.text
    assert "hello world.txt" in blob
    assert "upload_flow_ok" in blob or "done" in blob.lower() or "queued" in blob.lower()
