from pathlib import Path


def test_runtime_files_exist():
    root = Path(__file__).resolve().parents[1]
    for rel in [
        "app.py",
        "sloper_legacy.py",
        "sloper_v72/bootstrap.py",
        "data/basic.yar",
        "static/index.html",
        "requirements.txt",
    ]:
        assert (root / rel).exists(), rel


def test_app_entrypoint_is_small():
    root = Path(__file__).resolve().parents[1]
    text = (root / "app.py").read_text(encoding="utf-8")
    assert "from sloper_v72.bootstrap import boot" in text
    assert "uvicorn.run" in text


if __name__ == "__main__":
    test_runtime_files_exist()
    test_app_entrypoint_is_small()
    print("smoke tests OK")
