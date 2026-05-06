# v116 Competition Readiness

Focus: making Sloper stronger against the uploaded Cyber Sprint 2026 stage-1 archive.

## Added

- v116 Cyber Sprint frontier layer (`sloper_v72/competition_v116.py`).
- v116 triage hardening (`sloper_v72/evidence_v116.py`).
- Recursive archive/disk/image payload carving.
- Morse, transposition, pcapng, pyc, ELF/PE static workflows.
- Noise suppression for short XOR/non-ASCII/template flags.

## Important limitation

URL-only OSINT/Web tasks still require live external context or a saved website snapshot. Sloper now emits the decoded URLs and operator playbooks, but cannot guarantee final location answers from offline text alone.

## Validation after Cyber Sprint hardening

Local checks run in the build environment:

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q \
  tests/test_smoke.py \
  tests/test_control_plane_v111.py \
  tests/test_v112_ui_and_decode.py \
  tests/test_v113_competition.py \
  tests/test_v114_competition.py \
  tests/test_v115_competition.py \
  tests/test_v116_cybersprint.py
```

Result: `28 passed, 1 warning`.

Spot checks from the uploaded Cyber Sprint pack:

- `Crypto/CryptoMess` triage best: `ctf_cs{17_15_v3ry_l0ud_1n_7h3_l4b}`.
- `Forensics/Dingusi ataskaita` triage best: `ctf_cs{d3l3t3d_n0t_g0n3}`.
- `Stego/Paslėpta žinutė` triage best: `ctf_cs{st3g0_v1ln1us_2025}`.

The full pack contains offline files plus URL-only OSINT/Web tasks. The recursive benchmark can enumerate them, but URL-only tasks require network snapshots or saved pages to be fully solved locally.
