# v114 Validation Notes

Local validation run in this build environment:

- `bash scripts/check.sh`: passed
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q`: 21 passed
- `scripts/benchmark_challenge_pack.py` on a synthetic local pack with DOCX, SQLite, and WAV LSB challenges: 3/3 solved

The full synthetic `scripts/benchmark_solver.py` was expanded to 26 cases and now supports chunked subprocess isolation. In this sandbox, long full-run attempts hit execution time/tooling limits before completing, so the committed JSON focuses on the challenge-pack smoke report plus unit coverage. Run it locally with:

```bash
python3 scripts/benchmark_solver.py
```

For debugging state leaks, use:

```bash
SLOPER_BENCH_SUBPROCESS=1 SLOPER_BENCH_CHUNK=1 python3 scripts/benchmark_solver.py
```
