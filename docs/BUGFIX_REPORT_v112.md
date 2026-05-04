# CTF Sloper v112 Bugfix / UX / Benchmark Report

## Main fixes

- Replaced the duplicated legacy frontend functions with a clean single-page UI.
- Added root redirect from `/` to `/static/index.html`.
- Fixed `/api/preferences` route shadowing so the full v111/v112 schema is actually saved.
- Added `/api/ui_health` to detect duplicate API routes.
- Rebound duplicate `/api/projects/{pid}/stop` routes.
- Fixed project-specific solver settings being ignored by the fast-lane solver.
- Added recursive bounded decoder lanes for medium/multi-step tasks.
- Added cleaner artifact rows for flag candidates and evidence.
- Added tests for UI health, preferences, project-level settings, and nested decoder lanes.

## New recursive decoder lanes

The bounded fast-lane now checks chains including:

- plain text
- URL decode
- HTML entity decode
- ROT 1..25
- reverse text
- base64 / base64url
- hex
- base32
- base85 / ascii85
- gzip / zlib / bz2 / xz when discovered directly or after base decode
- decimal byte lists
- binary bitstreams
- Morse text
- small single-byte XOR

All lanes are bounded by project settings:

- `attack_preset`
- `difficulty`
- `max_depth`
- `max_artifacts`

## UI/UX changes

The UI now has stable pages:

- Create project
- Projects
- Profile / attack controls
- Tool status

Project tabs are stable and no longer mismatched:

- Overview
- Flags
- Artifacts
- Files
- Logs
- Settings
- Manual tools

## Known limits

This still does not mean every possible CTF challenge is solved. Pwn/reversing/web challenges can require target-specific reasoning, emulation, symbolic execution, manual exploit writing, or challenge services. v112 improves the automatic decode/artifact path and makes the UI usable, but it is still a framework that should keep gaining category-specific solvers.
