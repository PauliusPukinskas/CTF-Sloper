# Repository structure

The app is intentionally kept compatible with the original runtime paths while the repository around it is cleaned for GitHub.

- `app.py` is the public ASGI entrypoint used by uvicorn.
- `sloper_legacy.py` contains the previous monolithic app logic.
- `sloper_v72/` contains modular helper layers used by the wrapper.
- `static/` contains the browser UI.
- `data/` contains tool/workflow catalogs and rules.
- `projects/` is runtime output and is ignored by git except for `.gitkeep`.
- `scripts/` contains repeatable helper scripts for running, checking, packaging, and uploading.
- `docs/` contains human-readable notes.
- `.github/workflows/check.yml` runs syntax/smoke checks on GitHub.
