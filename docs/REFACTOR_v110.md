# Refactor v110

## What changed

- `sloper_legacy.py` is now a 25-line compatibility loader.
- The former 21,748-line monolith is preserved as `sloper_legacy_monolith.py` for audit/history.
- Runtime legacy code is split into `sloper_legacy_parts/part_000.py` ... `part_024.py`.
- New code should not be added to legacy parts; put new work in `sloper_v72/` or future `core/` / `solvers/` modules.
- Added `sloper_v72/fast_lane_v110.py` as a bounded default solver for common CTF encodings.
- Added `scripts/benchmark_solver.py` for repeatable local regression benchmarks.

## Why

The old monolith had hundreds of duplicate functions and was hard to debug. Splitting it makes GitHub review easier while keeping compatibility. The v110 fast lane also prevents easy CTF cases from entering the slow recursive legacy pipeline.

## Deep legacy mode

By default, v110 uses safe bounded analysis. To test the old heavy engine manually:

```bash
SLOPER_ENABLE_LEGACY_DEEP=1 SLOPER_ENABLE_LEGACY_SUMMARY=1 bash START_HERE.sh
```

Use this only for targeted profiling because the old pipeline can still be slow.
