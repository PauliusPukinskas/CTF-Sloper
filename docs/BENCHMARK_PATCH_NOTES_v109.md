# Benchmark Patch Notes v109

Validated in this package:

- `python3 -m py_compile app.py sloper_legacy.py sloper_v72/*.py` passes.
- `pytest -q` passes.
- `bash scripts/check.sh` passes.

Runtime fixes included:

- `/api/run_tool`, `/api/run_tool_suite`, `/api/run_verifyloop`, and `/api/run_agents` are sandboxed to uploaded files in `projects/<pid>/files`.
- Generated/cache/internal paths are rejected as default solver input.
- Manual verify/agent endpoints use a bounded safe decode path so clicking UI buttons does not trigger recursive legacy generated-file scans.
- Exact `ctf_cs{...}` evidence is promoted over normalized guesses.
- Base64/hex decoded evidence keeps underscores and punctuation intact.

Known remaining weakness:

- `sloper_legacy.py` is still large. The next major refactor should split it into `core`, `api`, and `solvers` modules.
