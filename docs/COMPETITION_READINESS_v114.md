# v114 Competition Readiness Update

v114 is a deeper reliability pass on top of v113. The goal is not to claim magical solving, but to make Sloper better during a live CTF by preserving evidence chains, extracting more local file formats, and producing clearer benchmark reports.

## Major additions

### Payload frontier

`sloper_v72/competition_v114.py` adds a bounded recursive payload frontier. Every candidate payload keeps a label chain such as:

```text
input -> zip:layer1.bin -> base64_token_0 -> gzip -> xor_42
```

This makes multi-step findings easier to trust because the UI can show how the candidate was produced.

### Specialized extractors

- Office ZIP text normalization for DOCX/XLSX/PPTX XML content.
- SQLite read-only table extraction.
- PNG ancillary text and compressed zTXt chunk extraction.
- WAV PCM LSB bit-channel extraction.
- Single-byte XOR rescue when output has flag/file/semantic signal.
- Image bit-plane preview PNG artifacts for visual stego review.

### Evidence triage

`sloper_v72/evidence_v114.py` runs after v113 evidence ranking and adds:

- `v114_triage.best_flag`
- `best_confidence`
- high/medium/related candidate counts
- artifact-kind counts
- operator hint text for live review

### Challenge-pack benchmark reports

`benchmark_challenge_pack.py` now writes JSON and HTML, so you can benchmark real challenge folders and quickly see solved/missed tasks.

## Commands

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_solver.py
python3 scripts/benchmark_challenge_pack.py /path/to/challenges --flag-format ctf_cs --attack-preset deep --difficulty multi_step --max-depth 6
```

## Current validation target

The synthetic benchmark now includes plain, recursive encodings, archives, image LSB, text channels, DOCX XML text, SQLite tables, PNG zTXt, WAV LSB, zlib/base64 frontier peeling, XOR rescue, and decoy demotion.

## Limits

Sloper still does not execute arbitrary binaries, attack remote services, or guarantee solving exploitation-heavy web/pwn tasks. v114 improves local file challenge coverage and makes failures more measurable.
