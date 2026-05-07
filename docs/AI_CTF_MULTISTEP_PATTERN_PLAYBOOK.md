# AI CTF Multistep Pattern Dataset for CTF Sloper
Generated: 2026-05-07T17:05:28.947455+00:00

**Scope:** local/offline CTF challenge artifacts only. This pack intentionally excludes live web exploitation and OSINT target workflows.

This pack gives Sloper thousands of multi-step pattern blueprints, not copied flags or private solutions. Each JSONL row is a retrieval/training/benchmark record describing trigger signals, workflow chain, tools, verifiers, false-positive controls, and benchmark requirements.

## Files
- `ai_ctf_multistep_patterns_3000.jsonl` — 3000 machine-readable workflow patterns.
- `AI_CTF_MULTISTEP_PATTERN_PLAYBOOK.md` — this guide.
- `README_DROP_INSTRUCTIONS.md` — where to place the file in your repo.

## Public source families used
- **ShundaZhang/CTF public corpus** — large public writeup/resource corpus with crypto, pwn, reverse, forensics, misc, cloud, blockchain, ICS categories (https://github.com/ShundaZhang/CTF)
- **picoCTF / picoGym / picoCTF Primer** — education-oriented challenge patterns across crypto, forensics, reverse, binary exploitation, and general CTF workflow (https://primer.picoctf.com/)
- **CryptoHack** — crypto challenge taxonomy: general encodings, symmetric ciphers, RSA, DH, ECC, hashes, lattices, ZKPs, CTF archive (https://cryptohack.org/challenges/)
- **pwn.college** — local binary exploitation training patterns: shellcode, memory errors, ROP, mitigation-aware exploitation (https://pwn.college/)
- **Trail of Bits CTF Field Guide** — forensics methodology: static files, file formats, steganography, memory, disk, PCAP, embedded filesystems (https://trailofbits.github.io/ctf/)
- **CTF101 / CTF Handbook** — category taxonomy: forensics, crypto, reverse engineering, binary exploitation (https://ctf101.org/)
- **HackTricks stego tricks** — stego triage tools and workflows: binwalk, foremost, exiftool, strings, image/audio routes (https://book.hacktricks.wiki/en/crypto-and-stego/stego-tricks.html)
- **CTF Support image steganography** — image stego pattern families: LSB, appended payloads, bit planes, metadata, zsteg/stegsolve/steghide (https://ctf.support/steganography/image-steganography/)
- **CTFlearn public challenge families** — classic beginner-to-medium recurring patterns: git history, image stego, crypto, reverse, binary, programming (https://ctflearn.com/)
- **HackTheBox Cyber Apocalypse / Business CTF public writeup ecosystem** — modern multi-step categories including blockchain, cloud artifacts, ICS captures, pwn/rev/crypto/forensics (https://www.hackthebox.com/)
- **John Hammond ctf-katana / awesome-ctf-style public lists** — tooling-oriented triage patterns and common CTF toolchains (https://github.com/JohnHammond/ctf-katana)

## Category counts
- `archives/containers`: 150 patterns
- `crypto/aes_block_modes`: 150 patterns
- `crypto/ecc_dh_hash_lattice`: 150 patterns
- `crypto/encodings_classical`: 150 patterns
- `crypto/rsa_public_key`: 150 patterns
- `crypto/xor_stream_prng`: 150 patterns
- `documents/pdf_office`: 150 patterns
- `forensics/audio_video`: 150 patterns
- `forensics/disk_memory`: 150 patterns
- `forensics/image/gif_webp_bmp`: 150 patterns
- `forensics/image/jpeg`: 150 patterns
- `forensics/image/png`: 150 patterns
- `forensics/network/pcap`: 150 patterns
- `misc/programming_logic`: 150 patterns
- `pwn/local_binary`: 150 patterns
- `pwn/local_heap_advanced`: 150 patterns
- `reverse/managed_mobile_vm`: 150 patterns
- `reverse/native_binary`: 150 patterns
- `static/blockchain_firmware_ics`: 150 patterns
- `static/git_docker_cloud_config`: 150 patterns

## How the solver should use this


1. Build artifact signals from uploaded files: magic bytes, extension, entropy, strings, metadata, sibling files, statement text, and selected flag format.  
2. Retrieve the nearest pattern rows by category/signals/filenames/metadata.  
3. Execute the workflow as a bounded artifact graph, not as one-shot decoding.  
4. Every transform writes child artifacts with parent pointers.  
5. Every candidate flag must carry chain proof, verifier result, confidence, risk, warnings, and false-positive reasoning.  
6. Statement/example flags must be suppressed before ranking.  
7. If no high-confidence result appears, expand from quick routes to deep routes using the same pattern family.

## JSONL schema
```json
{
  "id": "sloper_pattern_0001",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/image/png",
  "family": "PNG chunk, dimension, IDAT, LSB, palette, and appended payload workflows",
  "variant": "extra-data-after-IEND",
  "difficulty": "medium",
  "multi_step_depth_estimate": 5,
  "input_shape": "dump plus README",
  "flag_profile": "DUCTF{...}",
  "flag_context": "custom Lithuanian CTF prefix",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "Trail of Bits CTF Field Guide",
    "HackTricks stego tricks",
    "CTF Support image steganography",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CTFlearn forensics/binwalk-style",
    "CTFlearn simple_steg-style",
    "picoCTF image/file-format tasks",
    "HackTricks stego triage"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "magic_mismatch_router",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "valid PNG chunk graph",
    "valid child file magic",
    "zlib inflate succeeds",
    "QR decodes cleanly",
    "exact flag regex after transform",
    "metadata key used as archive password succeeds",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_image_png_extra-data-after-IEND.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/image/png::extra-data-after-IEND with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "f35d021775b6"
}
```

## Example full pattern rows by category

### archives/containers
```json
{
  "id": "sloper_pattern_0008",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "archives/containers",
  "family": "Archive repair, password derivation, nested recursion, split/polyglot, and safe extraction workflows",
  "variant": "zip-comment-password",
  "difficulty": "hard",
  "multi_step_depth_estimate": 6,
  "input_shape": "binary plus input sample",
  "flag_profile": "ctf_cm{...}",
  "flag_context": "bare-braces accepted",
  "source_basis": [
    "picoCTF / picoGym / picoCTF Primer",
    "Trail of Bits CTF Field Guide",
    "HackTricks stego tricks",
    "CTFlearn public challenge families",
    "John Hammond ctf-katana / awesome-ctf-style public lists"
  ],
  "public_pattern_anchors": [
    "CTFlearn zippy/brute_force_is_fun-style",
    "picoCTF archive recursion patterns",
    "HackTricks binwalk/foremost patterns"
  ],
  "trigger_signals": [
    "ZIP/RAR/7z/tar/gzip/xz/bz2 magic",
    "trailing central directory",
    "archive comments",
    "encrypted flag",
    "split parts",
    "polyglot magic mismatch",
    "recursion depth",
    "case_sensitive_flag",
    "hidden_binary_then_crypto",
    "bare-braces accepted"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "List archive metadata without extraction",
    "Validate and repair archive indexes where possible",
    "Collect password candidates from sibling files, metadata, filenames, decoded text, and hints",
    "Try bounded password list and known-empty password",
    "Safe-extract into sandbox with path traversal protection",
    "Detect nested archives and polyglots",
    "Classify leaves recursively",
    "Record exact password provenance",
    "Preserve case and braces exactly; never normalize final flag",
    "Recovered bytes are not final; classify and run crypto/decode path"
  ],
  "recommended_tools": [
    "7z",
    "unzip",
    "zipinfo",
    "zipdetails",
    "bkcrack",
    "john/zip2john",
    "binwalk",
    "foremost",
    "unar",
    "python-libarchive"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "exact_flag_preserver",
    "recursive_classify",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "archive listing succeeds",
    "extraction creates valid child files",
    "password source recorded",
    "known-plaintext attack validates CRC",
    "flag found in extracted leaf",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "No unbounded rockyou by default",
    "Never unsafe-extract absolute paths/symlinks",
    "Demote archive comments unless used as key or exact flag",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/archives_containers_zip-comment-password.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching archives/containers::zip-comment-password with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "147964ead918"
}
```

### crypto/aes_block_modes
```json
{
  "id": "sloper_pattern_0012",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "crypto/aes_block_modes",
  "family": "AES/block cipher misuse, mode recovery, nonce/IV mistakes, padding, and local transcript workflows",
  "variant": "ECB-repeated-blocks",
  "difficulty": "easy",
  "multi_step_depth_estimate": 10,
  "input_shape": "archive chain",
  "flag_profile": "HTB{...}",
  "flag_context": "bare-braces accepted",
  "source_basis": [
    "CryptoHack",
    "CTF101 / CTF Handbook",
    "picoCTF / picoGym / picoCTF Primer",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "CryptoHack symmetric ciphers category",
    "picoCTF AES/CBC/ECB patterns",
    "public CTF block-mode writeups"
  ],
  "trigger_signals": [
    "16-byte block alignment",
    "repeated ciphertext blocks",
    "IV/nonce/key fields",
    "Salted__ header",
    "padding errors in logs",
    "multiple ciphertexts same nonce",
    "AES import/code",
    "case_sensitive_flag",
    "lithuanian_flag_terms",
    "bare-braces accepted"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Parse key/iv/nonce/ciphertext from files/scripts/logs",
    "Detect mode from structure and repeated blocks",
    "Derive password/key candidates from artifacts",
    "Test candidate decryptions with padding and language score",
    "Exploit nonce/keystream reuse when multiple ciphertexts exist",
    "If key in binary/script, extract constants first",
    "Classify plaintext recursively",
    "Verify by re-encryption or auth-tag relation when available",
    "Preserve case and braces exactly; never normalize final flag",
    "Boost Lithuanian/English leetspeak flag-like terms but require exact verifier",
    "Run recursive decoder on short high-confidence text outputs",
    "Classify recovered bytes before treating them as text",
    "Write ranked_findings.json with chain, score, risk, warnings, and offsets"
  ],
  "recommended_tools": [
    "openssl",
    "python cryptography/pycryptodome",
    "CyberChef-equivalent local recipes",
    "hashcat/john for bounded KDF tests",
    "binwalk/strings for key extraction"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "exact_flag_preserver",
    "lt_en_language_scorer",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "PKCS#7 padding valid",
    "re-encryption matches ciphertext",
    "nonce reuse equations match",
    "plaintext high score/exact flag",
    "derived key source recorded",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not accept wrong-key printable garbage",
    "Require padding/auth/reencryption proof",
    "Do not do unbounded password cracking",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/crypto_aes_block_modes_ECB-repeated-blocks.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching crypto/aes_block_modes::ECB-repeated-blocks with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "afb1b21b98a3"
}
```

### crypto/ecc_dh_hash_lattice
```json
{
  "id": "sloper_pattern_0013",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "crypto/ecc_dh_hash_lattice",
  "family": "ECC/DH/hash/lattice/secret-sharing math challenge workflows",
  "variant": "ECDSA-reused-nonce",
  "difficulty": "easy",
  "multi_step_depth_estimate": 5,
  "input_shape": "image plus hint text",
  "flag_profile": "just_braces:{...}",
  "flag_context": "flag split across artifacts",
  "source_basis": [
    "CryptoHack",
    "CTF101 / CTF Handbook",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "CryptoHack ECC/DH/hash/lattice categories",
    "public CTF Archive math-crypto patterns"
  ],
  "trigger_signals": [
    "ECDSA signatures",
    "r repeated",
    "curve parameters",
    "DH p/g/A/B",
    "smooth p-1",
    "hash(mac||msg)",
    "shares list",
    "lattice/knapsack numbers",
    "LLL hint",
    "nested_archive_child",
    "polyglot_magic_mismatch",
    "flag split across artifacts"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Parse mathematical parameters and group related records",
    "Identify weak family from repeated values or smoothness",
    "Recover nonce/private key/secret using correct attack",
    "Verify by signature/DH/share/hash equation",
    "Derive symmetric key or plaintext from recovered secret",
    "Decode/decrypt child payload recursively",
    "Record equations and validation results",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Extension and magic bytes disagree; prioritize magic and carve tails",
    "Classify recovered bytes before treating them as text"
  ],
  "recommended_tools": [
    "sage",
    "python ecdsa",
    "hashpumpy-compatible local logic",
    "fpylll",
    "sympy",
    "Crypto.Util.number"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "magic_mismatch_router",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "signature verifies with recovered key",
    "shared secret recomputed",
    "LLL solution satisfies bounds",
    "hash extension digest matches",
    "secret reconstructs all shares",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not call lattice success without equation check",
    "Demote approximate numeric outputs unless verified",
    "Record curve/domain parameters",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/crypto_ecc_dh_hash_lattice_ECDSA-reused-nonce.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching crypto/ecc_dh_hash_lattice::ECDSA-reused-nonce with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Do not stop at the first plausible text if a child file magic is found. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "23dd50735710"
}
```

### crypto/encodings_classical
```json
{
  "id": "sloper_pattern_0009",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "crypto/encodings_classical",
  "family": "Recursive encodings, whitespace/Unicode channels, and classical ciphers with scoring workflows",
  "variant": "base64-matryoshka-with-reverse",
  "difficulty": "multi_step",
  "multi_step_depth_estimate": 7,
  "input_shape": "image plus hint text",
  "flag_profile": "just_braces:{...}",
  "flag_context": "flag is generated by solver",
  "source_basis": [
    "CryptoHack",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "CTFlearn so_many_64s-style",
    "CryptoHack general encodings",
    "CTF101 cryptography overview"
  ],
  "trigger_signals": [
    "base64 alphabet/padding",
    "hex-looking text",
    "binary/octal/decimal groups",
    "ROT-like letter frequencies",
    "whitespace anomalies",
    "zero-width unicode",
    "classical cipher keywords",
    "nested_archive_child",
    "decoy_statement_flag",
    "flag is generated by solver"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Tokenize visible and extracted text",
    "Detect encoding alphabets and separators",
    "Run bounded recursive decode tree with loop detection",
    "Try classical cipher families with language/flag scoring",
    "Use keys from metadata/sibling artifacts/task title",
    "Normalize Unicode and whitespace channels",
    "Classify decoded outputs recursively",
    "Promote only verified readable or flag-format results",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Task statement contains example flag; apply statement suppression before ranking"
  ],
  "recommended_tools": [
    "internal recursive decoder",
    "CyberChef-equivalent local recipes",
    "quipqiup-like scoring",
    "python codecs",
    "wordfreq/language scoring",
    "task_statement_suppressor"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "statement_suppression",
    "decoy_flag_demoter",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "decode is reversible or deterministic",
    "printable ratio high",
    "language score improves",
    "exact flag regex or valid child magic",
    "key provenance recorded",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Avoid endless decode loops",
    "Demote every accidental base64-looking token in binary dumps",
    "Do not rank format hints from statements",
    "Record transform chain",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/crypto_encodings_classical_base64-matryoshka-with-reverse.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching crypto/encodings_classical::base64-matryoshka-with-reverse with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Do not stop at the first plausible text if a child file magic is found. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "93542070f786"
}
```

### crypto/rsa_public_key
```json
{
  "id": "sloper_pattern_0011",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "crypto/rsa_public_key",
  "family": "RSA parameter, padding, factorization, CRT, and PEM workflows",
  "variant": "small-e-no-padding",
  "difficulty": "multi_step",
  "multi_step_depth_estimate": 9,
  "input_shape": "folder with statement and artifact",
  "flag_profile": "ctf_cs{...}",
  "flag_context": "bare-braces accepted",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "CryptoHack",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CryptoHack RSA category",
    "0xL4ugh RSA-GCD-style",
    "picoCTF RSA pattern families"
  ],
  "trigger_signals": [
    "n/e/c integers",
    "PEM public key",
    "multiple moduli",
    "same n",
    "small exponent",
    "prime hints",
    "dp/dq/phi leaks",
    "ciphertext integer",
    "local_sandbox_execution",
    "password_from_metadata",
    "bare-braces accepted"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Parse RSA parameters from text/PEM/scripts",
    "Normalize integers and group by modulus/exponent",
    "Run weakness detectors in priority order",
    "Recover p/q/phi/d or direct plaintext",
    "Handle padding/unpadding/long_to_bytes",
    "Verify by modular re-encryption",
    "Decode/plaintext-classify recursively",
    "Report exact math path used",
    "Executable must run only in sandbox with timeout and no network",
    "Use metadata/title/filename/chunk/comment as bounded password candidates",
    "Run exact flag regex on every generated child artifact",
    "Run recursive decoder on short high-confidence text outputs",
    "Classify recovered bytes before treating them as text"
  ],
  "recommended_tools": [
    "RsaCtfTool",
    "openssl",
    "sage",
    "python Crypto.Util.number",
    "sympy",
    "gmpy2",
    "password_candidate_collector",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "sandbox_runner",
    "password_candidate_collector",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "p*q == n",
    "pow(m,e,n) == c",
    "private exponent valid",
    "padding validates",
    "plaintext exact flag or child magic",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not trust factorization without p*q check",
    "Avoid interpreting random big-int bytes as flag",
    "Record all parsed integers and source files",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/crypto_rsa_public_key_small-e-no-padding.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching crypto/rsa_public_key::small-e-no-padding with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Prefer format-specific parsers before generic strings. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "d4860c6c4e31"
}
```

### crypto/xor_stream_prng
```json
{
  "id": "sloper_pattern_0010",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "crypto/xor_stream_prng",
  "family": "XOR, stream-cipher misuse, repeated keystream, LCG/MT/LFSR, and timestamp seed workflows",
  "variant": "single-byte-xor",
  "difficulty": "hard_multi_step",
  "multi_step_depth_estimate": 8,
  "input_shape": "archive chain",
  "flag_profile": "flag{...}",
  "flag_context": "flag split across artifacts",
  "source_basis": [
    "CryptoHack",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "CTFlearn a_secure_lcg-style",
    "CryptoHack stream/symmetric patterns",
    "public many-time-pad writeups"
  ],
  "trigger_signals": [
    "high entropy ciphertext",
    "same-length ciphertexts",
    "known flag prefix possible",
    "random.py or srand references",
    "LCG constants",
    "MT output list",
    "bitstream sequence",
    "xor keyword",
    "polyglot_magic_mismatch",
    "local_sandbox_execution",
    "flag split across artifacts"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Parse byte arrays/ciphertexts/sequences",
    "Try single-byte and repeating-key XOR scoring",
    "Use selected flag prefix as crib carefully",
    "Detect keystream reuse across multiple ciphertexts",
    "Recover PRNG seed/state/parameters if outputs are given",
    "Decrypt and classify plaintext recursively",
    "Verify by replaying PRNG or re-encrypting",
    "Rank only reproducible decryptions",
    "Extension and magic bytes disagree; prioritize magic and carve tails",
    "Executable must run only in sandbox with timeout and no network",
    "Save operator-visible proof artifacts for every promoted finding",
    "Run exact flag regex on every generated child artifact",
    "Run recursive decoder on short high-confidence text outputs"
  ],
  "recommended_tools": [
    "internal XOR solver",
    "xortool",
    "cribdrag",
    "sage/python",
    "z3",
    "randcrack",
    "Berlekamp-Massey implementation",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "magic_mismatch_router",
    "sandbox_runner",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "re-encryption equals ciphertext",
    "PRNG replay matches all known outputs",
    "plaintext printable/language/flag",
    "key length/source recorded",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not overfit random bytes to flag prefix",
    "Demote single-byte XOR outputs without strong score",
    "Require verification across whole ciphertext",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/crypto_xor_stream_prng_single-byte-xor.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching crypto/xor_stream_prng::single-byte-xor with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Record tool stderr/stdout summaries to explain failures. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "b293e95bb6c5"
}
```

### documents/pdf_office
```json
{
  "id": "sloper_pattern_0007",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "documents/pdf_office",
  "family": "PDF, Office, OLE, RTF, spreadsheet, and presentation hidden-object workflows",
  "variant": "PDF-FlateDecode-stream-base64",
  "difficulty": "easy",
  "multi_step_depth_estimate": 5,
  "input_shape": "single unknown file",
  "flag_profile": "custom_regex",
  "flag_context": "flag hidden in child artifact",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "Trail of Bits CTF Field Guide",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "Trail of Bits static-data forensics",
    "CTFlearn pdf/document patterns",
    "public Office macro CTF writeups"
  ],
  "trigger_signals": [
    "PDF header",
    "xref/object streams",
    "OOXML zip",
    "OLE CFB",
    "macros",
    "hidden sheets",
    "comments",
    "embedded relationships",
    "RTF objdata",
    "local_sandbox_execution",
    "case_sensitive_flag",
    "flag hidden in child artifact"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Classify PDF/OOXML/OLE/RTF container",
    "Extract visible text and metadata",
    "Enumerate internal object graph/relationships/streams",
    "Inflate/decode streams and embedded files",
    "Extract comments, notes, hidden sheets, macros, formulas",
    "Normalize text and code strings",
    "Classify embedded payloads recursively",
    "Score only with document-object evidence",
    "Executable must run only in sandbox with timeout and no network",
    "Preserve case and braces exactly; never normalize final flag"
  ],
  "recommended_tools": [
    "pdfinfo",
    "pdftotext",
    "qpdf",
    "mutool",
    "pdf-parser.py",
    "oletools",
    "unzip",
    "python-docx",
    "openpyxl",
    "strings",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "sandbox_runner",
    "exact_flag_preserver",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "stream decompresses cleanly",
    "embedded file has valid magic",
    "formula/comment path recorded",
    "macro deobfuscation reproducible",
    "candidate exact flag regex",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Demote ordinary author/editor metadata",
    "Do not execute macros",
    "Do not accept PDF producer strings as flags",
    "Preserve object IDs",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/documents_pdf_office_PDF-FlateDecode-stream-base64.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching documents/pdf_office::PDF-FlateDecode-stream-base64 with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "20245e54e66c"
}
```

### forensics/audio_video
```json
{
  "id": "sloper_pattern_0004",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/audio_video",
  "family": "Audio/video spectrogram, channel, timing, subtitle, and frame-reconstruction workflows",
  "variant": "spectrogram-text",
  "difficulty": "hard_multi_step",
  "multi_step_depth_estimate": 8,
  "input_shape": "image plus hint text",
  "flag_profile": "ctf_cm{...}",
  "flag_context": "flag split across artifacts",
  "source_basis": [
    "picoCTF / picoGym / picoCTF Primer",
    "CryptoHack",
    "Trail of Bits CTF Field Guide",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CTFlearn music_to_my_ears-style",
    "CTFlearn tone_dailing-style",
    "picoCTF media forensics patterns"
  ],
  "trigger_signals": [
    "WAV/MP3/OGG/MP4/MKV magic",
    "audio channels",
    "unusual sample rate",
    "tone frequencies",
    "subtitles",
    "video frames",
    "duration anomalies",
    "metadata comments",
    "case_sensitive_flag",
    "nested_archive_child",
    "flag split across artifacts"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract container metadata and streams",
    "Render waveform/spectrogram/contact sheets",
    "Detect tones, Morse, DTMF, and timing gaps",
    "Try sample LSB on each channel and stereo difference",
    "Extract subtitles/chapters/attachments",
    "Sample frames at fixed intervals and scene changes",
    "Run OCR/QR on frames/spectrograms",
    "Decode recovered text recursively",
    "Preserve case and braces exactly; never normalize final flag",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Write ranked_findings.json with chain, score, risk, warnings, and offsets",
    "Save operator-visible proof artifacts for every promoted finding",
    "Run exact flag regex on every generated child artifact"
  ],
  "recommended_tools": [
    "ffprobe",
    "ffmpeg",
    "sox",
    "Audacity-compatible exports",
    "python-scipy",
    "Pillow",
    "zbarimg",
    "tesseract"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "exact_flag_preserver",
    "archive_recursion",
    "budget_guard",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "spectrogram text visible in saved preview",
    "DTMF sequence maps to plausible code",
    "Morse timing has stable dot/dash ratios",
    "subtitle extraction produces valid text",
    "candidate is exact flag format",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Demote random ASCII from audio LSB unless stable across channel/order",
    "Save visual proof for spectrogram/fame findings",
    "Do not upload media to online decoders",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_audio_video_spectrogram-text.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/audio_video::spectrogram-text with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Do not stop at the first plausible text if a child file magic is found. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "7f7d7fe9e802"
}
```

### forensics/disk_memory
```json
{
  "id": "sloper_pattern_0006",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/disk_memory",
  "family": "Disk images, filesystem artifacts, deleted data, browser data, registry, and memory dump workflows",
  "variant": "deleted-file-carve",
  "difficulty": "multi_step",
  "multi_step_depth_estimate": 10,
  "input_shape": "image plus hint text",
  "flag_profile": "ctf_cm{...}",
  "flag_context": "hash-of-message final",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "Trail of Bits CTF Field Guide",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "Trail of Bits disk/memory forensics",
    "CTFlearn dump/dumpster-style",
    "public Volatility CTF patterns"
  ],
  "trigger_signals": [
    "raw disk image",
    "E01/VHD/VMDK",
    "filesystem signatures",
    "memory dump",
    "SQLite files",
    "registry hives",
    "pagefile/swap",
    "MFT records",
    "polyglot_magic_mismatch",
    "sibling_file_key",
    "hash-of-message final"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Identify container and partition/filesystem map",
    "Mount/read-only or parse with forensic library",
    "Enumerate files, deleted entries, timelines, and metadata",
    "Carve unallocated/slack/pagefile regions",
    "Extract browser/terminal/app histories",
    "For memory: list processes, env, cmdline, netscan, filescan",
    "Classify recovered files recursively",
    "Score with path/process context",
    "Extension and magic bytes disagree; prioritize magic and carve tails",
    "Treat sibling file names and contents as keys/masks/wordlists",
    "Run exact flag regex on every generated child artifact",
    "Run recursive decoder on short high-confidence text outputs",
    "Classify recovered bytes before treating them as text"
  ],
  "recommended_tools": [
    "file",
    "mmls",
    "fls",
    "icat",
    "tsk_recover",
    "foremost",
    "bulk_extractor",
    "volatility3",
    "strings",
    "sqlite3"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "magic_mismatch_router",
    "sibling_context_joiner",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "filesystem parser validates structure",
    "deleted file recovered with original path",
    "SQLite query returns coherent rows",
    "memory process context recorded",
    "candidate not from random dump offset only",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Demote orphan memory strings without process/path",
    "Never mount RW",
    "Avoid full-dump grep rank1 without context",
    "Use task-statement suppression",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_disk_memory_deleted-file-carve.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/disk_memory::deleted-file-carve with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Use cheap reversible transforms first, then deeper brute-force only with evidence. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "f6e543c786e5"
}
```

### forensics/image/gif_webp_bmp
```json
{
  "id": "sloper_pattern_0003",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/image/gif_webp_bmp",
  "family": "Animated, palette, alpha, frame-delta, and raw bitmap stego workflows",
  "variant": "GIF-frame-delay-morse",
  "difficulty": "multi_step",
  "multi_step_depth_estimate": 7,
  "input_shape": "script plus ciphertext",
  "flag_profile": "picoCTF{...}",
  "flag_context": "flag split across artifacts",
  "source_basis": [
    "picoCTF / picoGym / picoCTF Primer",
    "Trail of Bits CTF Field Guide",
    "CTF Support image steganography",
    "CTFlearn public challenge families",
    "John Hammond ctf-katana / awesome-ctf-style public lists"
  ],
  "public_pattern_anchors": [
    "picoCTF animated image patterns",
    "CTFlearn QR inception/visual reconstruction patterns",
    "public stego writeups"
  ],
  "trigger_signals": [
    "animated frames",
    "palette entries",
    "frame delays",
    "alpha channel",
    "BMP padding",
    "multi-page image",
    "dimension stack",
    "lossless WebP",
    "local_sandbox_execution",
    "visual_proof_required",
    "flag split across artifacts"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Split all frames/pages/resolutions",
    "Render frame contact sheet and delta images",
    "Extract frame delay/timing channels",
    "Analyze palette order/index bits",
    "Extract alpha and bitplanes",
    "Inspect row padding or unused planes",
    "Run QR/OCR on reconstructed images",
    "Recurse into recovered text/binary",
    "Executable must run only in sandbox with timeout and no network",
    "If route is visual, save previews and require OCR/QR/manual-readable evidence"
  ],
  "recommended_tools": [
    "file",
    "exiftool",
    "ffmpeg",
    "ImageMagick",
    "Pillow",
    "zsteg",
    "gifsicle",
    "webpmux",
    "zbarimg",
    "preview_artifact_writer",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "sandbox_runner",
    "preview_artifact_writer",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "frame reconstruction readable",
    "delay sequence decodes to valid Morse/binary",
    "QR decodes",
    "palette bitstream printable",
    "BMP padding contains valid magic",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Avoid ranking arbitrary frame delay numbers",
    "Require at least two independent clues for frame-order claims",
    "Keep previews for operator verification",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_image_gif_webp_bmp_GIF-frame-delay-morse.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/image/gif_webp_bmp::GIF-frame-delay-morse with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Treat every recovered payload as a new artifact and rerun triage. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "41bf0744213b"
}
```

### forensics/image/jpeg
```json
{
  "id": "sloper_pattern_0002",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/image/jpeg",
  "family": "JPEG EXIF, comments, thumbnails, steghide, appended archive, and visual residue workflows",
  "variant": "EXIF-user-comment-password",
  "difficulty": "hard",
  "multi_step_depth_estimate": 6,
  "input_shape": "pcap plus notes",
  "flag_profile": "DUCTF{...}",
  "flag_context": "custom Lithuanian CTF prefix",
  "source_basis": [
    "Trail of Bits CTF Field Guide",
    "HackTricks stego tricks",
    "CTF Support image steganography",
    "CTFlearn public challenge families",
    "John Hammond ctf-katana / awesome-ctf-style public lists"
  ],
  "public_pattern_anchors": [
    "CTFlearn exif-style",
    "CTFlearn abandoned_place-style",
    "HackTricks/CTF Support steghide patterns"
  ],
  "trigger_signals": [
    "JPEG SOI/EOI",
    "EXIF tags",
    "thumbnail blob",
    "APP markers",
    "comment marker",
    "bytes after EOI",
    "DCT entropy",
    "steghide candidate",
    "polyglot_magic_mismatch",
    "multi_child_vote",
    "custom Lithuanian CTF prefix"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Run metadata/comment extraction",
    "Extract embedded thumbnail and classify it",
    "Check EOI offset for appended data",
    "Try steghide info/extract with empty password and derived candidate passwords",
    "Run stegseek only with bounded local wordlist",
    "Compare image pairs if sibling images exist",
    "Extract DCT/LSB candidates where supported",
    "Recurse into carved payloads",
    "Score only verified candidates",
    "Extension and magic bytes disagree; prioritize magic and carve tails"
  ],
  "recommended_tools": [
    "file",
    "exiftool",
    "jhead",
    "binwalk",
    "foremost",
    "steghide",
    "stegseek",
    "jpeginfo",
    "Pillow",
    "zbarimg"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "magic_mismatch_router",
    "evidence_merger",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "thumbnail valid image",
    "steghide extraction exit success",
    "archive opens after derived password",
    "decoded text has language/flag score",
    "candidate offset is after EOI or inside known marker",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not brute force huge wordlists by default",
    "Demote camera-model metadata",
    "Demote unrelated EXIF GPS unless challenge hints location",
    "Do not accept `flag` words from tool banners",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_image_jpeg_EXIF-user-comment-password.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/image/jpeg::EXIF-user-comment-password with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "cc1a237e4a80"
}
```

### forensics/image/png
```json
{
  "id": "sloper_pattern_0001",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/image/png",
  "family": "PNG chunk, dimension, IDAT, LSB, palette, and appended payload workflows",
  "variant": "extra-data-after-IEND",
  "difficulty": "medium",
  "multi_step_depth_estimate": 5,
  "input_shape": "dump plus README",
  "flag_profile": "DUCTF{...}",
  "flag_context": "custom Lithuanian CTF prefix",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "Trail of Bits CTF Field Guide",
    "HackTricks stego tricks",
    "CTF Support image steganography",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CTFlearn forensics/binwalk-style",
    "CTFlearn simple_steg-style",
    "picoCTF image/file-format tasks",
    "HackTricks stego triage"
  ],
  "trigger_signals": [
    "PNG magic",
    "IHDR/IDAT/IEND chunks",
    "high entropy tail",
    "ancillary chunk names",
    "alpha channel",
    "palette image",
    "dimension mismatch",
    "zlib streams",
    "nested_archive_child",
    "polyglot_magic_mismatch",
    "custom Lithuanian CTF prefix"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Run file/magic/entropy triage",
    "Parse PNG chunks and validate CRC/length/order",
    "Extract tEXt/iTXt/zTXt and normalize strings",
    "Check for bytes after IEND and carve known file signatures",
    "Render RGB/R/G/B/A bitplanes and palette-index planes",
    "Try bounded LSB extraction across channel order, bit order, and traversal",
    "Classify recovered payloads recursively",
    "Run QR/OCR on previews and recovered images",
    "Rank candidates only when chain evidence and exact format agree",
    "Recovered payload is an archive; recurse but cap depth/time"
  ],
  "recommended_tools": [
    "file",
    "xxd",
    "pngcheck",
    "exiftool",
    "binwalk",
    "foremost",
    "zsteg",
    "Pillow",
    "zbarimg",
    "tesseract"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "magic_mismatch_router",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "valid PNG chunk graph",
    "valid child file magic",
    "zlib inflate succeeds",
    "QR decodes cleanly",
    "exact flag regex after transform",
    "metadata key used as archive password succeeds",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Demote raw task-statement flag examples",
    "Demote random LSB printable fragments without magic or regex",
    "Avoid infinite recursion on repeated zlib streams",
    "Do not trust chunk names alone",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_image_png_extra-data-after-IEND.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/image/png::extra-data-after-IEND with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "f35d021775b6"
}
```

### forensics/network/pcap
```json
{
  "id": "sloper_pattern_0005",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "forensics/network/pcap",
  "family": "PCAP/PCAPNG stream, object, covert-field, USB, and protocol-specific extraction workflows",
  "variant": "HTTP-object-export-then-zip",
  "difficulty": "medium",
  "multi_step_depth_estimate": 9,
  "input_shape": "folder with sibling files",
  "flag_profile": "custom_regex",
  "flag_context": "bare-braces accepted",
  "source_basis": [
    "picoCTF / picoGym / picoCTF Primer",
    "Trail of Bits CTF Field Guide",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "Trail of Bits PCAP forensics",
    "CTFlearn a_capture_of_a_flag-style",
    "picoCTF packet capture patterns"
  ],
  "trigger_signals": [
    "pcap magic",
    "pcapng blocks",
    "HTTP streams",
    "DNS labels",
    "ICMP payloads",
    "USB captures",
    "TCP conversations",
    "protocol object export possible",
    "nested_archive_child",
    "hash_final_answer",
    "bare-braces accepted"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Run capinfos/tshark summary",
    "List endpoints, conversations, and protocols",
    "Export HTTP/SMB/FTP/SMTP objects where possible",
    "Follow suspicious TCP/UDP streams",
    "Extract DNS/ICMP/TCP/IP header covert channels",
    "Decode USB HID keyboard/mouse if present",
    "Classify carved files recursively",
    "Rank with stream/protocol context",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Challenge may ask for hash of recovered message; detect statement keywords and compute exact digest",
    "Save operator-visible proof artifacts for every promoted finding",
    "Run exact flag regex on every generated child artifact",
    "Run recursive decoder on short high-confidence text outputs"
  ],
  "recommended_tools": [
    "capinfos",
    "tshark",
    "Wireshark export objects",
    "tcpflow",
    "NetworkMiner-like parsers",
    "scapy",
    "dpkt",
    "usbpcap parsers"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "digest_finalizer",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "reassembled file has valid magic",
    "stream ordering respects sequence numbers",
    "DNS labels decode to printable/flag",
    "USB HID maps to coherent text",
    "candidate linked to packet indexes",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not rank challenge URLs or hostnames as flags",
    "Preserve packet numbers for evidence",
    "Avoid mixing streams from unrelated conversations",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/forensics_network_pcap_HTTP-object-export-then-zip.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching forensics/network/pcap::HTTP-object-export-then-zip with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Do not stop at the first plausible text if a child file magic is found. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "10c4a386717e"
}
```

### misc/programming_logic
```json
{
  "id": "sloper_pattern_0018",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "misc/programming_logic",
  "family": "Offline programming puzzles, parsers, graphs, games, simulations, checksums, and reconstruction workflows",
  "variant": "maze-BFS-with-teleports",
  "difficulty": "easy",
  "multi_step_depth_estimate": 10,
  "input_shape": "archive chain",
  "flag_profile": "flag{...}",
  "flag_context": "flag requires preserving case",
  "source_basis": [
    "picoCTF / picoGym / picoCTF Primer",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "CTFlearn programming category",
    "picoCTF general skills patterns",
    "public misc CTF puzzle writeups"
  ],
  "trigger_signals": [
    "input/output samples",
    "grid/maze files",
    "CSV/logs",
    "MIDI/SVG/font files",
    "chess notation",
    "checksum rules",
    "large generated data",
    "custom language",
    "polyglot_magic_mismatch",
    "sibling_file_key",
    "flag requires preserving case"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Parse all structured files and samples",
    "Infer puzzle model from filenames/statement/data shape",
    "Validate against sample outputs or internal invariants",
    "Render visual previews for grids/tiles/fonts/SVG/audio",
    "Extract resulting text/coordinates/hash",
    "Decode/recurse if output is encoded",
    "Save solver script and reproducible proof",
    "Build deterministic solver rather than manual guessing",
    "Extension and magic bytes disagree; prioritize magic and carve tails",
    "Treat sibling file names and contents as keys/masks/wordlists",
    "Classify recovered bytes before treating them as text",
    "Write ranked_findings.json with chain, score, risk, warnings, and offsets",
    "Save operator-visible proof artifacts for every promoted finding"
  ],
  "recommended_tools": [
    "python",
    "networkx optional",
    "Pillow",
    "fonttools",
    "mido",
    "svgpathtools",
    "openpyxl",
    "z3"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "magic_mismatch_router",
    "sibling_context_joiner",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "sample tests pass",
    "invariants hold",
    "rendered preview readable",
    "solver deterministic",
    "exact flag generated",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not manually guess puzzle answer",
    "Rank only solver-derived candidates",
    "Store generated script and input hashes",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/misc_programming_logic_maze-BFS-with-teleports.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching misc/programming_logic::maze-BFS-with-teleports with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Prefer format-specific parsers before generic strings. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "9718a9bfe510"
}
```

### pwn/local_binary
```json
{
  "id": "sloper_pattern_0016",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "pwn/local_binary",
  "family": "Local-only binary exploitation harness, mitigation-aware primitive selection, and proof capture workflows",
  "variant": "ret2win-no-PIE",
  "difficulty": "hard_multi_step",
  "multi_step_depth_estimate": 8,
  "input_shape": "folder with statement and artifact",
  "flag_profile": "picoCTF{...}",
  "flag_context": "standard exact flag",
  "source_basis": [
    "pwn.college",
    "picoCTF / picoGym / picoCTF Primer",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families",
    "ShundaZhang/CTF public corpus"
  ],
  "public_pattern_anchors": [
    "pwn.college shellcode/memory-error levels",
    "CTFlearn simple_bof/rip_my_bof-style",
    "public ret2win/ROP CTF patterns"
  ],
  "trigger_signals": [
    "ELF executable",
    "checksec mitigations",
    "gets/scanf/printf imports",
    "crashable input",
    "win function",
    "no RELRO/NX/PIE/canary state",
    "seccomp filter",
    "case_sensitive_flag",
    "nested_archive_child",
    "standard exact flag"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Run checksec and dynamic smoke test in sandbox",
    "Find crash offset with cyclic pattern",
    "Identify primitive from imports/disassembly/crash behavior",
    "Choose strategy based on mitigations",
    "Build pwntools local exploit template",
    "Leak addresses if needed and calculate bases",
    "Execute local exploit repeatedly and capture output",
    "Save exploit.py, run log, and exact flag evidence",
    "Preserve case and braces exactly; never normalize final flag",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Run exact flag regex on every generated child artifact",
    "Run recursive decoder on short high-confidence text outputs",
    "Classify recovered bytes before treating them as text"
  ],
  "recommended_tools": [
    "checksec",
    "pwntools",
    "gdb/pwndbg local",
    "ROPgadget",
    "one_gadget optional",
    "seccomp-tools",
    "readelf",
    "objdump"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "exact_flag_preserver",
    "archive_recursion",
    "budget_guard",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "local exploit prints flag or proof output",
    "offset reproducible",
    "leak calculation documented",
    "payload avoids forbidden bytes as needed",
    "run log saved",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "No remote target connection in this scope",
    "Do not claim solved from crash alone",
    "Do not reuse libc assumptions without evidence",
    "Sandbox local binary execution",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/pwn_local_binary_ret2win-no-PIE.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching pwn/local_binary::ret2win-no-PIE with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Keep decoy and statement text in low-confidence bucket. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "3ecc3e1a0519"
}
```

### pwn/local_heap_advanced
```json
{
  "id": "sloper_pattern_0017",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "pwn/local_heap_advanced",
  "family": "Local heap, UAF, tcache, integer, FILE-structure, and allocator-state exploitation workflows",
  "variant": "tcache-poisoning",
  "difficulty": "hard",
  "multi_step_depth_estimate": 9,
  "input_shape": "zip challenge pack",
  "flag_profile": "ctf_cs{...}",
  "flag_context": "standard exact flag",
  "source_basis": [
    "pwn.college",
    "ShundaZhang/CTF public corpus",
    "CTF101 / CTF Handbook"
  ],
  "public_pattern_anchors": [
    "pwn.college memory errors",
    "public heap CTF writeups",
    "BusinessCTF pwn families"
  ],
  "trigger_signals": [
    "malloc/free menu binary",
    "heap chunks",
    "delete/edit/show options",
    "glibc version",
    "UAF pattern",
    "double free crash",
    "size fields",
    "allocator checks",
    "nested_archive_child",
    "hash_final_answer",
    "standard exact flag"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Infer menu protocol and heap object lifecycle",
    "Automate interactions with pwntools",
    "Identify leak primitive and target write primitive",
    "Map allocator/glibc constraints",
    "Choose tcache/unsorted/UAF/off-by-one strategy",
    "Build reliable local exploit with state assertions",
    "Capture proof and heap notes",
    "Demote if only causes crash",
    "Recovered payload is an archive; recurse but cap depth/time",
    "Challenge may ask for hash of recovered message; detect statement keywords and compute exact digest",
    "Run recursive decoder on short high-confidence text outputs",
    "Classify recovered bytes before treating them as text",
    "Write ranked_findings.json with chain, score, risk, warnings, and offsets"
  ],
  "recommended_tools": [
    "pwntools",
    "gdb/pwndbg heap commands",
    "libc database local",
    "checksec",
    "one_gadget optional",
    "gef/pwndbg"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "archive_recursion",
    "budget_guard",
    "digest_finalizer",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "leak matches mapped libc/heap base",
    "write primitive verified locally",
    "exploit stable across runs",
    "flag/proof captured",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "No remote exploitation",
    "Do not assume glibc version without file/container evidence",
    "Store interaction transcript",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/pwn_local_heap_advanced_tcache-poisoning.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching pwn/local_heap_advanced::tcache-poisoning with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "9352a0ab1ff4"
}
```

### reverse/managed_mobile_vm
```json
{
  "id": "sloper_pattern_0015",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "reverse/managed_mobile_vm",
  "family": "Java/.NET/Python/Android/WASM/custom VM/esolang reversing workflows",
  "variant": "Java-vault-door-char-checks",
  "difficulty": "medium",
  "multi_step_depth_estimate": 7,
  "input_shape": "pcap plus notes",
  "flag_profile": "DUCTF{...}",
  "flag_context": "decoy flag present",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "picoCTF / picoGym / picoCTF Primer",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CTFlearn apk_login_cracking/basic_android patterns",
    "picoCTF Java vault-door patterns",
    "public WASM/custom VM writeups"
  ],
  "trigger_signals": [
    ".class/.jar/.pyc/.apk/.wasm/.dll",
    "DEX/smali",
    "managed metadata",
    "bytecode loop",
    "opcode table",
    "esolang symbols",
    "packed Python archive",
    "local_sandbox_execution",
    "visual_proof_required",
    "decoy flag present"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Collect filenames, extensions, timestamps, comments, and statement text as context but not final evidence",
    "Identify runtime/container",
    "Extract/decompile bytecode/resources/native libs",
    "Locate validation/decryption routines",
    "Normalize obfuscated constants/strings",
    "If VM: recover opcode semantics and build emulator/disassembler",
    "Solve constraints or execute safely in sandbox",
    "Verify with original program/app where possible",
    "Recurse into recovered payloads",
    "Executable must run only in sandbox with timeout and no network",
    "If route is visual, save previews and require OCR/QR/manual-readable evidence"
  ],
  "recommended_tools": [
    "jadx",
    "apktool",
    "dex2jar",
    "fernflower/cfr",
    "dnSpy/ilspy equivalents",
    "uncompyle6/pycdc",
    "pyinstxtractor",
    "wasm2wat",
    "z3",
    "preview_artifact_writer",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "sandbox_runner",
    "preview_artifact_writer",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "patched/solved input passes validator",
    "bytecode emulator matches sample execution",
    "resource/native key decrypts payload",
    "candidate exact format",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not assume resources.arsc strings are final flags",
    "Demote debug/test keys",
    "Record which method/class produced candidate",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/reverse_managed_mobile_vm_Java-vault-door-char-checks.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching reverse/managed_mobile_vm::Java-vault-door-char-checks with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Use sibling artifacts as keys only after recording provenance. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "4ff7541e0eda"
}
```

### reverse/native_binary
```json
{
  "id": "sloper_pattern_0014",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "reverse/native_binary",
  "family": "Native ELF/PE/Mach-O static/dynamic reversing, constraints, packers, anti-debug, and hidden-data workflows",
  "variant": "xor-obfuscated-strings",
  "difficulty": "easy",
  "multi_step_depth_estimate": 6,
  "input_shape": "image plus hint text",
  "flag_profile": "DUCTF{...}",
  "flag_context": "flag split across artifacts",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "picoCTF / picoGym / picoCTF Primer",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "CTFlearn reverse city-series-style",
    "picoCTF vault-door/native reverse patterns",
    "BusinessCTF rev families"
  ],
  "trigger_signals": [
    "ELF/PE/Mach-O magic",
    "stripped binary",
    "imports",
    "anti-debug strings",
    "high entropy section",
    "weird constants",
    "input validation loop",
    "UPX markers",
    "Go/Rust metadata",
    "polyglot_magic_mismatch",
    "multi_child_vote",
    "flag split across artifacts"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Run file/checksec/strings/imports/sections",
    "Detect packers/runtime/language and unpack if safe",
    "Locate validation or decrypt path by xrefs/imports/constants",
    "Extract constants and transform logic",
    "Build emulator/z3/model for constraints when feasible",
    "Patch anti-debug only in local copy or use static path",
    "Run original binary locally to verify candidate",
    "Save decompilation notes and proof",
    "Extension and magic bytes disagree; prioritize magic and carve tails",
    "Multiple child artifacts agree; increase confidence only if chains are independent"
  ],
  "recommended_tools": [
    "file",
    "checksec",
    "readelf",
    "objdump",
    "strings",
    "rabin2/radare2",
    "Ghidra headless",
    "angr",
    "z3",
    "gdb local sandbox"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "magic_mismatch_router",
    "evidence_merger",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "candidate accepted by binary",
    "decrypted buffer exact flag",
    "constraint model satisfies all checks",
    "runtime trace reaches success path",
    "static constants reproduce output",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not rank random binary strings as flags without path evidence",
    "Do not run unknown binary outside sandbox",
    "Preserve patched/original hash separation",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/reverse_native_binary_xor-obfuscated-strings.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching reverse/native_binary::xor-obfuscated-strings with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Require a verifier before rank-1 promotion. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "4408784f76c8"
}
```

### static/blockchain_firmware_ics
```json
{
  "id": "sloper_pattern_0020",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "static/blockchain_firmware_ics",
  "family": "Static blockchain source/local chain traces, firmware images, and ICS/protocol capture workflows",
  "variant": "Solidity-storage-slot-secret",
  "difficulty": "hard",
  "multi_step_depth_estimate": 6,
  "input_shape": "pcap plus notes",
  "flag_profile": "DUCTF{...}",
  "flag_context": "hash-of-message final",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "CryptoHack",
    "Trail of Bits CTF Field Guide",
    "CTF101 / CTF Handbook"
  ],
  "public_pattern_anchors": [
    "CyberApocalypse/BusinessCTF blockchain and ICS category families",
    "Trail of Bits embedded filesystem guidance",
    "public firmware CTF writeups"
  ],
  "trigger_signals": [
    ".sol/.vy files",
    "ABI/logs/calldata",
    "local chain artifacts",
    "firmware bin",
    "SquashFS/JFFS2/cpio",
    "U-Boot env",
    "Modbus/CAN/ICS pcap",
    "register values",
    "case_sensitive_flag",
    "hidden_binary_then_crypto",
    "hash-of-message final"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Extract printable strings in ASCII/UTF-16LE/UTF-16BE with offsets",
    "Classify static artifact family",
    "For blockchain: parse ABI/source/logs/calldata/storage locally and build local Foundry/Hardhat test if needed",
    "Search init scripts/configs/webroots locally",
    "For ICS/CAN: decode protocol fields/registers and reconstruct byte/text channels",
    "Classify extracted payloads recursively",
    "Record no-live-contact proof",
    "For firmware: binwalk/carve/extract filesystems read-only",
    "Preserve case and braces exactly; never normalize final flag",
    "Recovered bytes are not final; classify and run crypto/decode path",
    "Save operator-visible proof artifacts for every promoted finding"
  ],
  "recommended_tools": [
    "solc",
    "foundry/anvil local optional",
    "cast/ethers local",
    "binwalk",
    "sasquatch/unsquashfs",
    "jefferson",
    "strings",
    "tshark",
    "scapy",
    "cantools"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "exact_flag_preserver",
    "recursive_classify",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "ABI decode succeeds",
    "local test reproduces exploit condition",
    "filesystem mounts/extracts read-only",
    "register sequence maps to printable/flag",
    "candidate exact regex",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not transact on real chains",
    "Do not contact real ICS/cloud endpoints",
    "Demote ordinary firmware version strings",
    "Record static-only evidence",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/static_blockchain_firmware_ics_Solidity-storage-slot-secret.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching static/blockchain_firmware_ics::Solidity-storage-slot-secret with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Prefer format-specific parsers before generic strings. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "48af406d8bcc"
}
```

### static/git_docker_cloud_config
```json
{
  "id": "sloper_pattern_0019",
  "origin_type": "pattern_family_derived_from_public_ctf_taxonomies_and_writeups_not_copied_challenge_solution",
  "scope": "local/offline CTF artifacts only; no live web or OSINT targets",
  "category": "static/git_docker_cloud_config",
  "family": "Local git history, Docker layers, CI logs, Terraform/Kubernetes/static cloud-config artifact workflows",
  "variant": "git-deleted-commit",
  "difficulty": "medium",
  "multi_step_depth_estimate": 5,
  "input_shape": "single unknown file",
  "flag_profile": "ctf_cs{...}",
  "flag_context": "flag requires preserving case",
  "source_basis": [
    "ShundaZhang/CTF public corpus",
    "picoCTF / picoGym / picoCTF Primer",
    "CTF101 / CTF Handbook",
    "CTFlearn public challenge families"
  ],
  "public_pattern_anchors": [
    "0xL4ugh git/terraform-style",
    "CTFlearn gitisgood-style",
    "BusinessCTF cloud artifact families"
  ],
  "trigger_signals": [
    ".git directory",
    "Docker image tar",
    "layer.tar",
    "terraform.tfstate",
    "kubeconfig",
    ".github/workflows",
    "CI logs",
    "YAML/JSON config",
    "base64 secret fields",
    "local_sandbox_execution",
    "case_sensitive_flag",
    "flag requires preserving case"
  ],
  "workflow": [
    "Create project and snapshot file hashes before transforms",
    "Run entropy scan and magic-byte scan over all files",
    "Inventory local repository/image/config artifacts",
    "For git: enumerate refs, logs, stashes, commits, blobs, submodules, LFS pointers",
    "For IaC: parse state outputs/secrets and base64 fields",
    "For CI: extract logs/artifacts locally",
    "Decode and classify recovered values recursively",
    "Demote cloud provider URLs unless local evidence contains flag",
    "Never contact live services",
    "For Docker: inspect config/history/layers and deleted files",
    "Executable must run only in sandbox with timeout and no network",
    "Preserve case and braces exactly; never normalize final flag"
  ],
  "recommended_tools": [
    "git",
    "git fsck",
    "git log",
    "git show",
    "tar",
    "dive-like layer parser",
    "jq",
    "yq",
    "base64",
    "python",
    "sandbox_runner"
  ],
  "sloper_actions": [
    "classify_artifact",
    "extract_signals",
    "retrieve_patterns",
    "sandbox_runner",
    "exact_flag_preserver",
    "execute_bounded_workflow",
    "classify_children",
    "score_candidates",
    "write_chain_proof"
  ],
  "verifiers": [
    "blob/layer path recorded",
    "deleted file recovered",
    "state output decoded",
    "no live network access needed",
    "candidate exact regex",
    "exact selected flag-format check",
    "parent-child artifact chain recorded",
    "rank-1 result has low/medium risk justification"
  ],
  "false_positive_controls": [
    "Do not use real credentials or contact cloud",
    "Demote normal access keys unless challenge flag format",
    "Preserve provenance path",
    "suppress sample flags from statements/README/tool banners",
    "demote candidates without reproducible transform chain",
    "preserve exact case/braces for final flag"
  ],
  "artifact_outputs": [
    "triage.json",
    "artifact_graph.json",
    "pattern_hypotheses.json",
    "ranked_findings.json",
    "proof/static_git_docker_cloud_config_git-deleted-commit.md",
    "recovered_payloads/",
    "tool_logs/",
    "previews/"
  ],
  "benchmark_blueprint": {
    "generator_goal": "Create a synthetic local challenge matching static/git_docker_cloud_config::git-deleted-commit with at least one intermediate artifact and one decoy.",
    "must_include": [
      "one exact true flag using selected profile",
      "one decoy or sample flag that should be demoted",
      "at least one child artifact produced by the workflow",
      "deterministic seed and expected chain proof"
    ],
    "pass_condition": "true flag ranked #1 in trusted or low-risk bucket with reproducible chain proof",
    "failure_labels": [
      "missed_pattern",
      "missing_tool",
      "bad_rank",
      "false_positive",
      "timeout",
      "artifact_not_saved"
    ]
  },
  "ai_instruction": "Use sibling artifacts as keys only after recording provenance. Never guess; run the verifier and show the artifact chain.",
  "confidence_features": {
    "promote_when": [
      "exact flag regex",
      "valid child magic or verified decrypt/exploit/parser result",
      "source offset/path recorded",
      "chain depth >= 2",
      "decoy suppression passed"
    ],
    "demote_when": [
      "statement-only occurrence",
      "tool banner/example output",
      "random printable fragment",
      "no parent transform",
      "non-reproducible brute-force result"
    ]
  },
  "fingerprint": "6996b624b039"
}
```

## Implementation rules for Sloper


### Artifact graph rule
Do not overwrite outputs. Every tool/transform creates a child artifact with `{parent_id, transform, tool, confidence, risk, notes}`.

### Verifier rule
A result is not trusted unless a verifier passes: exact flag regex, valid file magic, successful archive extraction, valid padding, re-encryption check, binary accepts input, QR decodes, PCAP stream reconstructs, or a deterministic puzzle solver passes samples.

### False-positive rule
Demote: sample flags, task statement format examples, tool banners, placeholder/test/dummy strings, random printable fragments, and candidates without parent-chain evidence.

### Benchmark rule
Every pattern can become a synthetic local challenge. A pass requires exact flag at rank 1 or trusted bucket plus chain proof and saved artifacts.

### UI rule
Show: selected pattern hypothesis, chain timeline, previews, recovered payloads, exact verifier, decoys demoted, warnings, and next suggested deeper workflows.
