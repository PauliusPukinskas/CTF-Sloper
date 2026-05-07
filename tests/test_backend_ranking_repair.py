import base64
import json
import subprocess
import sys
from pathlib import Path


def test_final_ranking_demotes_readme_metadata_labels():
    from sloper.ranking import rerank_summary

    summary = {
        "flags": [
            {"flag": "ctf_cs{Category}", "score": 9000, "source": "README metadata"},
            {"flag": "ctf_cs{Difficulty}", "score": 8900, "source": "statement"},
            {
                "flag": "ctf_cs{caesar_shift_ok}",
                "score": 100,
                "source": "classic_crypto:caesar_19",
                "artifact": "/tmp/artifacts/classic_crypto/caesar_19.txt",
                "why": "Caesar shift produced strict decoded flag.",
            },
        ]
    }
    out = rerank_summary(summary)
    assert [x["flag"] for x in out["flags"]] == ["ctf_cs{caesar_shift_ok}"]
    manual = {x["flag"] for x in out["related_candidate_flags"]}
    assert {"ctf_cs{Category}", "ctf_cs{Difficulty}"} <= manual


def test_classic_crypto_caesar_and_rot47_promote_real_flags(tmp_path):
    import app  # noqa: F401
    import sloper_legacy as sloper

    files = tmp_path / "files"
    files.mkdir()
    (files / "README.md").write_text(
        "Category: Crypto\nDifficulty: Easy\nFormat: ctf_cs{...}\n",
        encoding="utf-8",
    )
    caesar_plain = "ctf_cs{caesar_shift_ok}"
    caesar_cipher = _caesar(caesar_plain, 7)
    rot_plain = "ctf_cs{rot47_ok}"
    rot_cipher = _rot47(rot_plain)
    caesar_path = files / "04_crypto_caesar_shift.txt"
    rot_path = files / "05_crypto_rot47.txt"
    caesar_path.write_text(caesar_cipher, encoding="utf-8")
    rot_path.write_text(rot_cipher, encoding="utf-8")

    reports = [
        sloper.analyze_file("classic_test", caesar_path, tmp_path, 1, 2),
        sloper.analyze_file("classic_test", rot_path, tmp_path, 2, 2),
        sloper.analyze_file("classic_test", files / "README.md", tmp_path, 1, 1),
    ]
    summary = sloper.project_summary(reports, {"id": "classic_test", "title": "classic crypto regression"})
    flags = [x.get("flag") if isinstance(x, dict) else str(x) for x in summary.get("flags", [])]
    assert "ctf_cs{caesar_shift_ok}" in flags[:5]
    assert "ctf_cs{rot47_ok}" in flags[:5]
    assert "ctf_cs{Category}" not in flags
    assert "ctf_cs{Difficulty}" not in flags


def test_benchmark_worker_uses_json_file_output(tmp_path):
    from sloper.bench_runner import python_cmd, run_json_file_worker

    worker = tmp_path / "worker.py"
    out = tmp_path / "out.json"
    worker.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text(json.dumps({'ok': True, 'text': 'caf\\ufffd'}), encoding='utf-8')\n",
        encoding="utf-8",
    )
    ok, data, err = run_json_file_worker(python_cmd(worker, out), Path.cwd(), 10, out)
    assert ok, err
    assert data["ok"] is True


def test_challenge_pack_ignores_flag_txt_sidecar(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_challenge_pack.py"
    chal = tmp_path / "sidecar_case"
    chal.mkdir()
    (chal / "flag.txt").write_text("ctf_cs{sidecar_must_not_be_input}", encoding="utf-8")
    (chal / "challenge.txt").write_text(
        base64.b64encode(b"ctf_cs{sidecar_must_not_be_input}").decode(),
        encoding="utf-8",
    )
    out = tmp_path / "bench.json"
    html = tmp_path / "bench.html"
    progress = tmp_path / "progress.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            str(chal),
            "--single",
            "--out",
            str(out),
            "--html-out",
            str(html),
            "--progress-out",
            str(progress),
            "--max-depth",
            "3",
        ],
        cwd=str(script.parents[1]),
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["solved"] is True


def _caesar(s: str, shift: int) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + shift) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _rot47(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        out.append(chr(33 + ((o - 33 + 47) % 94)) if 33 <= o <= 126 else ch)
    return "".join(out)
