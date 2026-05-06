# Bugfix Report v108/v109

This release adds a public-repo hardening layer without rewriting the legacy solver.

## Fixed

- Manual path endpoints accept only uploaded challenge files under `projects/<pid>/files`.
- Generated/cache/internal paths are blocked as solver input by default.
- Manual verify/agent buttons use a safe bounded decoder pass instead of recursive legacy scans.
- Project summaries promote exact `ctf_cs{...}` evidence above normalized guesses.
- Base64/hex evidence is decoded without removing underscores or punctuation.
- Tool status now checks actual command dependencies more strictly.
- Report reads in the UI apply exact-evidence postprocessing.

## Still TODO

`sloper_legacy.py` is still a large compatibility layer. Next cleanup should split it into core/api/solver modules.
