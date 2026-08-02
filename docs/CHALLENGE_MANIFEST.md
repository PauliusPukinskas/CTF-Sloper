# Challenge integrity manifests

Use an integrity manifest when a challenge contains several files or when you want to preserve the exact starting state before running transformations.

## Create a manifest

```bash
python3 scripts/challenge_manifest.py /path/to/challenge \
  --output reports/challenge-manifest.json
```

The manifest is deterministic and includes:

* schema version
* file count and total bytes
* stable file ordering
* SHA-256 for every file
* detected type and extension
* entropy and printable-byte ratio
* whether type analysis used a truncated sample

## Bound large challenge packs

```bash
python3 scripts/challenge_manifest.py /path/to/challenge \
  --max-files 1000 \
  --sample-bytes 262144 \
  --output reports/challenge-manifest.json
```

Hashing still covers each complete file. `--sample-bytes` only limits the data used for type, entropy, and printable-ratio analysis.

## Recommended workflow

1. Save the original challenge files in a read-only folder.
2. Create the manifest before extracting or modifying anything.
3. Perform analysis on a working copy.
4. Keep the manifest with notes and solver outputs.
5. Recreate and compare manifests when challenge files are transferred between machines.

Do not publish manifests from active private competitions when filenames, hashes, or metadata could reveal challenge content.
