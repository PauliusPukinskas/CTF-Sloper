import base64
import gzip
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
import app  # noqa: E402
import sloper_legacy as sloper  # noqa: E402
from sloper_v72.fast_lane_v110 import analyze_bytes


def test_v112_preferences_route_rebinds_full_schema():
    client = TestClient(app.app)
    r = client.post('/api/preferences', json={'flag_format': 'ctf_cm', 'flag_prefix': 'ctf_cm', 'attack_preset': 'deep', 'difficulty': 'hard', 'max_depth': 5})
    assert r.status_code == 200
    prefs = r.json()['preferences']
    assert prefs['flag_format'] == 'ctf_cm'
    assert prefs['flag_label'] == 'ctf_cm{...}'
    assert prefs['attack_preset'] == 'deep'
    assert prefs['difficulty'] == 'hard'
    assert prefs['max_depth'] == 5


def test_v112_ui_health_has_no_duplicate_routes():
    client = TestClient(app.app)
    j = client.get('/api/ui_health').json()
    assert j['ok'] is True
    assert j['duplicate_routes'] == []


def test_v112_project_settings_drive_fast_lane(tmp_path):
    pid = 'pytestv112'
    root = sloper.pdir(pid)
    files = root / 'files'
    files.mkdir(parents=True, exist_ok=True)
    path = files / 'flag.txt'
    path.write_text('ctf_cm{project_specific_format}', encoding='utf-8')
    sloper.jwrite(sloper.meta_path(pid), {'id': pid, 'title': 'pytest', 'solver_settings': {'flag_format': 'ctf_cm', 'flag_prefix': 'ctf_cm'}})
    try:
        report = sloper.analyze_file(pid, path, root, 1, 1)
        assert report['v110_fast_lane']['profile']['flag_format'] == 'ctf_cm'
        summary = sloper.project_summary([report], sloper.jread(sloper.meta_path(pid), {}))
        flags = [x.get('flag') if isinstance(x, dict) else str(x) for x in summary.get('flags', [])]
        assert 'ctf_cm{project_specific_format}' in flags
    finally:
        for p in sorted(root.rglob('*'), reverse=True):
            if p.is_file():
                p.unlink(missing_ok=True)
            elif p.is_dir():
                p.rmdir()
        root.rmdir()


def test_v112_recursive_decoder_lanes_find_nested_flags():
    b32 = base64.b32encode(b'ctf_cs{base32_unit}')
    gz_b64 = base64.b64encode(gzip.compress(b'ctf_cs{gzip_unit}'))
    res1 = analyze_bytes(b32, {'flag_format': 'ctf_cs', 'flag_regex': r'(?is)\bctf_cs\{[^{}\r\n]{1,220}\}', 'max_depth': 3, 'max_artifacts': 500})
    res2 = analyze_bytes(gz_b64, {'flag_format': 'ctf_cs', 'flag_regex': r'(?is)\bctf_cs\{[^{}\r\n]{1,220}\}', 'max_depth': 4, 'max_artifacts': 500})
    assert any(x['flag'] == 'ctf_cs{base32_unit}' for x in res1['flags'])
    assert any(x['flag'] == 'ctf_cs{gzip_unit}' for x in res2['flags'])


def test_v112_create_project_deduplicates_colliding_upload_names():
    client = TestClient(app.app)
    files = [
        ('files', ('same.txt', b'first payload', 'text/plain')),
        ('files', ('same.txt', b'second payload', 'text/plain')),
    ]
    r = client.post('/api/projects', data={'title': 'dedupe uploads', 'auto_start': 'false'}, files=files)
    assert r.status_code == 200
    body = r.json()
    assert body['ok'] is True
    pid = body['id']
    root = sloper.pdir(pid)
    try:
        stored = sorted((root / 'files').glob('*.txt'))
        assert [p.name for p in stored] == ['same.txt', 'same__2.txt']
        assert [p.read_text(encoding='utf-8') for p in stored] == ['first payload', 'second payload']
        assert body['project']['files'] == ['same.txt', 'same__2.txt']
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_v112_project_raw_endpoint_is_project_scoped():
    client = TestClient(app.app)
    pid_a = 'pytestrawa'
    pid_b = 'pytestrawb'
    root_a = sloper.pdir(pid_a)
    root_b = sloper.pdir(pid_b)
    try:
        (root_a / 'files').mkdir(parents=True, exist_ok=True)
        (root_b / 'files').mkdir(parents=True, exist_ok=True)
        file_a = root_a / 'files' / 'a.txt'
        file_b = root_b / 'files' / 'b.txt'
        file_a.write_text('project a', encoding='utf-8')
        file_b.write_text('project b', encoding='utf-8')
        ok = client.get(f'/api/projects/{pid_a}/raw', params={'path': str(file_a)})
        blocked = client.get(f'/api/projects/{pid_a}/raw', params={'path': str(file_b)})
        assert ok.status_code == 200
        assert ok.text == 'project a'
        assert blocked.status_code == 403
    finally:
        shutil.rmtree(root_a, ignore_errors=True)
        shutil.rmtree(root_b, ignore_errors=True)
