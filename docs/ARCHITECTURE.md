# Architecture

## Runtime entrypoint

`app.py` stays intentionally small. It imports `sloper_v72.bootstrap.boot()`, receives the legacy FastAPI app, and re-exports legacy symbols for compatibility with old scripts/tests.

## Core modules

- `sloper_legacy.py` contains the original monolithic solver and FastAPI routes.
- `sloper_v72/bootstrap.py` patches and extends the legacy app at startup.
- `sloper_v72/final_engine.py` adds higher-signal tournament workflows and artifact promotion.
- `sloper_v72/artifact_hub.py` groups generated outputs for easier UI review.
- `sloper_v72/hidden_bits.py`, `workflow_v74.py`, `workflow_v75.py`, `semantic_v76.py`, and later modules add specialized agents.

## Important paths

The app computes its base path from `Path(__file__).parent`, so the root runtime files should stay together:

- `app.py`
- `sloper_legacy.py`
- `sloper_v72/`
- `data/`
- `static/`
- `projects/`

A deeper `src/` package layout is possible later, but this cleaned structure keeps the current release runnable without import/path rewrites.
