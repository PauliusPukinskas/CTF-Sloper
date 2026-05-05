# v115 validation

Validation was run in the build sandbox after applying the v115 broad extractor + live triage update.

## Passed

```bash
bash scripts/check.sh
# All checks passed.
```

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q tests/test_smoke.py tests/test_control_plane_v111.py tests/test_v112_ui_and_decode.py tests/test_v113_competition.py tests/test_v114_competition.py tests/test_v115_competition.py
# 25 passed when run in grouped/targeted mode.
```

```bash
python3 scripts/benchmark_challenge_pack.py /tmp/sloper_pack_v115 \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 6 \
  --out docs/CHALLENGE_PACK_BENCHMARK_v115.json \
  --html-out docs/CHALLENGE_PACK_BENCHMARK_v115.html
# 4/4 solved: PDF Flate stream, JPEG comment, PCAP payload, PNG LSB.
```

```bash
python3 scripts/benchmark_solver.py --case-indices 0,1,2
# 3/3 solved for smoke chunk: plain, base64, hex.
```

## Note

The full synthetic benchmark is now subprocess-isolated and has worker timeout controls. In the sandbox, full long-run benchmark execution was not used as the release gate because it can exceed the tool runtime; use:

```bash
SLOPER_BENCH_WORKER_TIMEOUT=20 python3 scripts/benchmark_solver.py
```

on your local machine for the full report.
