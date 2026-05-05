# v113 Competition Readiness Update

v113 is focused on live CTF usefulness rather than cosmetic breadth.

## Major additions

- Evidence ranking layer for every candidate flag:
  - `confidence` percentage
  - `risk` percentage
  - `verdict`: high / medium / low
  - transform chain text
  - reasons and warnings
- Decoy suppression:
  - fake/example/test/not-the-flag candidates are demoted
  - decoded candidates with real transform evidence are promoted
- Bounded competition extractors:
  - ZIP members, nested ZIP, TAR members
  - common CTF ZIP passwords for read-only extraction attempts
  - Office-style zipped XML/text documents
  - PNG/image LSB bit planes through Pillow
  - case-bit channels
  - space/tab channels
  - zero-width bit channels
  - printable strings and embedded data URI base64 payloads
- Real challenge pack benchmark script:
  - scans folders or single files
  - reads `flag.txt`, `expected.txt`, `challenge.json`, or sidecar flag files
  - emits JSON pass/fail report

## Commands

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_solver.py
python3 scripts/benchmark_challenge_pack.py /path/to/challenges --flag-format ctf_cs --attack-preset deep --difficulty multi_step --max-depth 5
```

## Current local validation

- `scripts/check.sh`: passed
- `pytest`: 14 passed
- synthetic regression benchmark: 20/20 passed
- synthetic challenge pack smoke benchmark: 2/2 solved

## Limits

v113 still does not execute uploaded binaries, attack remote services, or guarantee a flag when a challenge requires manual exploit development. It is stronger for local file challenges, recursive decoding, stego-ish image/text channels, noisy decoys, and honest benchmark reporting.
