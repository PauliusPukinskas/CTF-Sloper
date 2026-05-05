# CTF Sloper v117 — Real-corpus hardening

This update was driven by the uploaded Cyber Sprint 2026 Stage 1 archive and the need to benchmark real folders without one slow task killing the whole run.

## Major fixes

1. **Hard benchmark isolation**
   - Each challenge can run in a fresh Python subprocess.
   - Timeouts kill the child process group.
   - The runner supports chunking and merge/resume workflows.

2. **Noise suppression**
   - Task statements are no longer fed into rectangular transposition as if they were ciphertext.
   - Bare-token wrapping ignores local context that looks like instructions or flag-format examples.
   - v117 triage demotes timestamps, UUID-like IDs, placeholders, and intermediate route text.

3. **New real-corpus routes**
   - Time anomaly logs: deltas, seconds, module-bit channels, kind-bit channels.
   - JSON artifact reconstruction: `x`, `y`, `rows` canvas rebuilding.
   - EXIF/GPS extraction from images and ZIP photo archives.
   - PCAP text/domain/HTTP line extraction.
   - Challenge inventory artifacts for URL-only/manual tasks.

4. **Cyber Sprint-specific generic improvement**
   - Cardan/grille routes now emit SHA256 candidates whenever the task asks for `sha256`, even if the decoded message is uppercase.

## Validation run in this build

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q \
  tests/test_smoke.py \
  tests/test_control_plane_v111.py \
  tests/test_v112_ui_and_decode.py \
  tests/test_v113_competition.py \
  tests/test_v114_competition.py \
  tests/test_v115_competition.py \
  tests/test_v116_cybersprint.py \
  tests/test_v117_real_corpus.py
```

Observed result in the packaging environment: `31 passed, 1 warning`.

## Important honesty note

This version is much more competition-usable, but no local solver can honestly guarantee every Web/OSINT URL-only challenge without a live snapshot, internet access, or known expected flags. The benchmark report now marks those as inventory/manual tasks instead of pretending they are solved.

## Final local validation added in this build

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q \
  tests/test_smoke.py \
  tests/test_control_plane_v111.py \
  tests/test_v112_ui_and_decode.py \
  tests/test_v113_competition.py \
  tests/test_v114_competition.py \
  tests/test_v115_competition.py \
  tests/test_v116_cybersprint.py \
  tests/test_v117_real_corpus.py
```

Observed result in the build sandbox: `31 passed, 1 warning`.

Cyber Sprint smoke chunk:

```bash
python3 scripts/benchmark_challenge_pack.py "/path/to/Cyber Sprint 2026 1 etapas" \
  --recursive-leaves --flag-format ctf_cs --attack-preset deep \
  --difficulty multi_step --max-depth 6 --per-challenge-timeout 15 \
  --offset 0 --limit 4 \
  --out docs/CYBER_SPRINT_STAGE1_v117_smoke.json \
  --html-out docs/CYBER_SPRINT_STAGE1_v117_smoke.html
```

Observed result in the build sandbox: command completed cleanly with subprocess isolation and ranked known local hits first for `CryptoMess` and `Dingusi ataskaita`. The full pack still includes URL-only OSINT/Web tasks, so offline artifact-only automation cannot honestly prove every challenge without saved snapshots/live pages and known expected flags.
