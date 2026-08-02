from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "challenge_manifest.py"
SCRIPTS_PATH = str(MODULE_PATH.parent)
if SCRIPTS_PATH not in sys.path:
    sys.path.insert(0, SCRIPTS_PATH)
SPEC = importlib.util.spec_from_file_location("challenge_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
challenge_manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(challenge_manifest)


def test_manifest_is_stable_and_summarizes_files(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_text("beta", encoding="utf-8")
    (tmp_path / "a.txt").write_text("alpha", encoding="utf-8")

    manifest = challenge_manifest.build_manifest(
        [tmp_path], max_files=10, sample_bytes=1024
    )

    assert manifest["schema_version"] == 1
    assert manifest["file_count"] == 2
    assert manifest["total_bytes"] == 9
    assert [Path(item["path"]).name for item in manifest["files"]] == [
        "a.txt",
        "b.txt",
    ]


def test_manifest_respects_file_limit(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")

    try:
        challenge_manifest.build_manifest([tmp_path], max_files=1, sample_bytes=64)
    except RuntimeError as exc:
        assert "file limit exceeded" in str(exc)
    else:
        raise AssertionError("expected bounded manifest failure")


def test_main_writes_json_output(tmp_path: Path) -> None:
    source = tmp_path / "challenge.txt"
    output = tmp_path / "reports" / "manifest.json"
    source.write_text("flag{candidate}", encoding="utf-8")

    result = challenge_manifest.main(
        [str(source), "--output", str(output), "--sample-bytes", "64"]
    )

    assert result == 0
    payload = output.read_text(encoding="utf-8")
    assert '"file_count": 1' in payload
    assert '"sha256"' in payload
