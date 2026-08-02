# Static triage commands

CTF Sloper includes read-only helpers for inspecting challenge files before deeper analysis.

## Inventory files

```bash
make inventory TARGET=/path/to/challenge
make inventory-json TARGET=/path/to/challenge
```

The inventory reports file type signatures, size, SHA-256, entropy, printable-byte ratio, and whether the analysis sample was truncated.

## Search for candidate flags

```bash
make flags TARGET=/path/to/challenge
make flags-json TARGET=/path/to/challenge
```

The flag hunter performs bounded reads, does not execute or unpack files, skips symlinks, and supports custom Python regular expressions through the underlying script.

```bash
python3 scripts/flag_hunter.py --regex 'TEAM\{[^}]+\}' /path/to/challenge
```

Treat every match as a candidate rather than proof. Confirm it against the challenge context and any decoded evidence.
