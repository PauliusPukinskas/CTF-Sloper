# CTF Sloper

Local browser-based CTF solving workbench for file challenges: stego, misc, reversing, forensics, crypto, PCAP, archives, images, binaries, documents, audio, databases, and generated artifacts.

This repository is structured so it can be uploaded directly to GitHub and still run locally with one command.

## Quick start

```bash
git clone https://github.com/PauliusPukinskas/CTF-Sloper.git
cd CTF-Sloper
bash START_HERE.sh
```

Then open:

```text
http://127.0.0.1:7860
```

## Upload to GitHub

Read [`GITHUB_UPLOAD.md`](GITHUB_UPLOAD.md), or use:

```bash
cd ctf-sloper
bash scripts/git_init_upload.sh YOUR_GITHUB_USERNAME ctf-sloper
```

## Install external CTF tools

For Ubuntu, Pop!_OS, Debian, or similar:

```bash
bash FULL_INSTALL.sh
```

This installs common CTF tooling such as `binwalk`, `exiftool`, `steghide`, `zsteg`, `tshark`, `qpdf`, `gdb`, `jadx`, OCR tools, and Python/Ruby/Node helper packages.

## Clean repository layout

```text
ctf-sloper/
├── README.md                  # Main project overview
├── GITHUB_UPLOAD.md           # Step-by-step GitHub upload guide
├── START_HERE.sh              # One-command local launcher
├── FULL_INSTALL.sh            # Full system tool installer wrapper
├── app.py                     # Small runtime entrypoint
├── sloper_legacy.py           # Legacy solver/app monolith kept for compatibility
├── sloper_v72/                # Modular solver/runtime layers
├── static/                    # Browser UI
├── data/                      # Tool catalogs, workflows, YARA/rules/configs
├── projects/                  # Local generated projects; ignored by git
├── scripts/                   # Start/check/package/upload helpers
├── docs/                      # Architecture, usage, roadmap, changelog
├── tests/                     # Lightweight smoke tests
├── .github/workflows/         # GitHub Actions check workflow
├── requirements.txt           # Python runtime dependencies
├── pyproject.toml             # Project metadata
├── Makefile                   # Short commands: make run/check/package
├── .gitignore                 # Keeps local artifacts/secrets out of commits
└── .gitattributes             # Stable line endings and binary handling
```

## Common commands

```bash
bash START_HERE.sh          # run locally
bash scripts/check.sh       # syntax/import checks
make run                    # same as START_HERE
make check                  # same as scripts/check.sh
make package                # create zip/tar release from repo
```

## CTF usage flow

1. Create a project in the browser UI.
2. Upload all challenge files for that task.
3. Check ranked findings first.
4. Inspect artifacts/transforms/previews when a flag is not obvious.
5. Keep generated challenge outputs inside `projects/`; that folder is ignored by git.

## Important safety note

This is intended for local CTF/lab use. Do not commit private challenge files, credentials, tokens, memory dumps, or generated artifacts from real competitions.

## v110 refactor + benchmark mode

This repo no longer keeps all runtime code inside one massive `sloper_legacy.py`.
The old monolith is split into `sloper_legacy_parts/`, while `sloper_legacy.py` stays as a compatibility loader.
New improvements should go into `sloper_v72/` or future `core/` / `solvers/` modules.

Run the regression benchmark:

```bash
python3 scripts/benchmark_solver.py
```

Safe fast-lane solving is enabled by default. For targeted old-engine profiling only:

```bash
SLOPER_ENABLE_LEGACY_DEEP=1 SLOPER_ENABLE_LEGACY_SUMMARY=1 bash START_HERE.sh
```



## v111: Operator-controlled solving

This version adds a real control plane for CTF runs:

- selectable flag formats: `ctf_cs{...}`, `ctf_cm{...}`, `flag{...}`, `picoCTF{...}`, `HTB{...}`, bare `{...}`, any-prefix, or custom regex;
- attack presets: quick, balanced, deep, hardcore;
- difficulty hints: easy, medium, hard, multi-step;
- per-project solver settings saved in `project.json`;
- cleaner artifact summaries and bounded benchmark scripts.

Run the local regression benchmark:

```bash
python3 scripts/benchmark_solver.py
```

Run a fair benchmark against a local CTF writeup/challenge repo:

```bash
python3 scripts/benchmark_writeup_repo.py /path/to/CTF
```

## v112: clean UI + recursive decoder benchmark

This version adds a cleaner GitHub-ready UI and fixes several control-plane bugs:

- custom flag formats now persist through `/api/preferences`
- per-project solver settings are respected by the fast-lane solver
- UI tabs are stable and no longer mismatched with hidden panels
- `/` redirects to `/static/index.html`
- `/api/ui_health` reports duplicate route problems
- recursive bounded decoders cover base64/base64url, hex, base32, base85, URL, HTML entities, ROT, reverse, gzip/zlib/bz2/xz, decimal bytes, binary bits, Morse, and small XOR

Run local checks:

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_solver.py
```

Latest synthetic benchmark: `15/15` passed; see `docs/BENCHMARK_RESULTS_v112.json`.

## v113: competition evidence + real challenge benchmark

This version adds a competition-readiness layer on top of the v112 UI/decoder engine:

- ranked evidence for every candidate flag: confidence, risk, verdict, chain, reasons and warnings;
- fake/example/decoy flag demotion so obvious red herrings do not outrank decoded evidence;
- bounded extractors for ZIP/TAR/office-style containers, image LSB channels, case bits, space/tab bits, zero-width bits, printable strings and data URI payloads;
- a real challenge-pack benchmark command for folders of CTF tasks;
- UI flag cards now show confidence/risk/chain instead of only raw score.

Run the full local validation:

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_solver.py
```

Benchmark a real local challenge pack:

```bash
python3 scripts/benchmark_challenge_pack.py /path/to/challenges \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 5
```

See [`docs/COMPETITION_READINESS_v113.md`](docs/COMPETITION_READINESS_v113.md).
## v114: frontier extractor + specialized forensics layer

v114 adds another competition-hardening layer over v113. It is designed for harder local file challenges where the flag is hidden behind containers, binary transforms, document formats, or visual/audio side channels.

New in v114:

- recursive payload frontier with explicit transform chains;
- gzip/bz2/xz/zlib/raw-zlib peeling outside the text-only fast lane;
- single-byte XOR rescue for flag-like decoded payloads;
- Office ZIP text normalization for `.docx`, `.xlsx`, and `.pptx` XML text fragments;
- SQLite read-only table/text extraction;
- PNG `tEXt`/`iTXt`/`zTXt`/ancillary chunk extraction;
- WAV PCM LSB channel extraction;
- image bit-plane preview artifacts for fast visual stego review;
- v114 operator triage in the UI: best flag, confidence, risk buckets, artifact-kind counts;
- challenge-pack benchmark now writes both JSON and HTML reports.

Run validation:

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_solver.py
```

Benchmark a real local challenge pack and get an HTML report:

```bash
python3 scripts/benchmark_challenge_pack.py /path/to/challenges \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 6 \
  --out docs/CHALLENGE_PACK_BENCHMARK_v114.json \
  --html-out docs/CHALLENGE_PACK_BENCHMARK_v114.html
```

See [`docs/COMPETITION_READINESS_v114.md`](docs/COMPETITION_READINESS_v114.md).


Validation notes: see [`docs/VALIDATION_v114.md`](docs/VALIDATION_v114.md).


## v115: Broad extractor + live triage upgrade

This version adds a wider competition layer on top of v114:

- deep image LSB extraction across channel orders, bit positions, and pixel order;
- PDF stream/string extraction, including FlateDecode streams;
- JPEG/GIF metadata and comments;
- classic PCAP packet payload extraction;
- dynamic ZIP password retry from local strings and challenge names;
- token rescue for data URIs, base85/ascii85, quoted-printable, and uuencode;
- v115 trusted/promising/manual triage buckets and operator playbook artifacts.

Run local validation:

```bash
bash scripts/check.sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
python3 scripts/benchmark_challenge_pack.py /path/to/challenges --flag-format ctf_cs --attack-preset deep --difficulty multi_step --max-depth 6
```


## v116: Cyber Sprint benchmark hardening

This update adds a new bounded local-only competition layer for Lithuanian Cyber Sprint style packs:

- recursive payload frontier for gzip/tar/zip and carved ZIP/OOXML inside images or disk dumps;
- Morse decoding and Morse-derived archive passwords, including Lithuanian password variants;
- rectangular/route transposition recovery for short crypto text files;
- sibling-aware message+key workflows for paired challenge files;
- pcapng raw IPv4 payload, IP-ID and TTL channel extraction;
- pyc constant/disassembly extraction and ELF/PE static string evidence;
- v116 triage that demotes short XOR/non-ASCII/template false flags.

Cyber Sprint pack benchmark command:

```bash
python3 scripts/benchmark_challenge_pack.py "/path/to/Cyber Sprint 2026 1 etapas" \
  --recursive-leaves \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 6 \
  --out docs/CYBER_SPRINT_2026_STAGE1_v116.json \
  --html-out docs/CYBER_SPRINT_2026_STAGE1_v116.html
```

## v117: real-corpus benchmark and triage hardening

v117 focuses on reliability on real CTF packs rather than synthetic-only wins:

- hard-isolated benchmark runner with per-challenge subprocess/process-group timeouts;
- chunked benchmark flags: `--offset`, `--limit`, `--only-regex`, and `--merge-existing` for large packs;
- task-statement suppression so instructions like `Vėliavėlės formatas ctf_cs{...}` stop becoming fake flags;
- Cardan/grille SHA256 promotion for tasks that ask for the hash of the decoded message;
- v117 triage demotes timestamps, metadata IDs, placeholders, and intermediate route text;
- new real-corpus routes for time-log anomaly extraction, artifact-log reconstruction, EXIF/GPS extraction, ZIP photo packs, and PCAP HTTP/domain text.

Recommended real pack benchmark:

```bash
python3 scripts/benchmark_challenge_pack.py "/path/to/Cyber Sprint 2026 1 etapas" \
  --recursive-leaves \
  --flag-format ctf_cs \
  --attack-preset deep \
  --difficulty multi_step \
  --max-depth 6 \
  --per-challenge-timeout 20 \
  --out docs/REAL_PACK_v117.json \
  --html-out docs/REAL_PACK_v117.html
```

For large packs, run in chunks and merge:

```bash
python3 scripts/benchmark_challenge_pack.py /path/to/pack --recursive-leaves --offset 0  --limit 6 --merge-existing --out docs/REAL_PACK_v117.json
python3 scripts/benchmark_challenge_pack.py /path/to/pack --recursive-leaves --offset 6  --limit 6 --merge-existing --out docs/REAL_PACK_v117.json
python3 scripts/benchmark_challenge_pack.py /path/to/pack --recursive-leaves --offset 12 --limit 6 --merge-existing --out docs/REAL_PACK_v117.json
```
