# CTF Sloper

Local browser-based CTF solving workbench for file challenges: stego, misc, reversing, forensics, crypto, PCAP, archives, images, binaries, documents, audio, databases, and generated artifacts.

This repository is structured so it can be uploaded directly to GitHub and still run locally with one command.

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/ctf-sloper.git
cd ctf-sloper
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
