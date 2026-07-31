# Environment diagnostics

CTF Sloper includes a read-only environment doctor that detects setup problems before a competition or practice session.

## Run it

```bash
make doctor
```

For automation or bug reports:

```bash
make doctor-json > doctor-report.json
```

To require the optional external toolset as well as the core runtime:

```bash
python3 scripts/doctor.py --strict
```

## What is checked

The doctor verifies:

1. Python 3.10 or newer.
2. Every Python package declared by the application runtime.
3. Core repository files and directories.
4. Essential command-line utilities used by common analysis paths.
5. Optional CTF tools such as binwalk, exiftool, steghide, zsteg, tshark, qpdf, gdb, and jadx.

A missing required item produces a non-zero exit code. Missing optional tools are reported as `MISS` but do not fail the command unless `--strict` is supplied.

## Safe to share

The JSON report contains platform metadata, executable paths, and availability results. It does not read challenge files, environment variables, tokens, browser data, or project contents.

Review absolute paths before posting a report publicly because they may reveal a local username or directory layout.

## Suggested troubleshooting order

1. Install runtime dependencies with `pip install -r requirements.txt`.
2. Run `make doctor` again.
3. Install the full external toolset with `bash FULL_INSTALL.sh` when optional capabilities are needed.
4. Run `make check` and `make test` before starting a competition session.
