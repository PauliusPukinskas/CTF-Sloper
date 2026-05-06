# v111 Operator Control Plane

v111 makes the solver configurable from the UI and backend instead of hard-coding `ctf_cs{...}` and one solving style.

## Flag formats

Supported presets:

- `ctf_cs{...}`
- `ctf_cm{...}`
- `flag{...}`
- `picoCTF{...}`
- `HTB{...}`
- `anyPrefix{...}`
- bare `{...}`
- custom regex

The selected format is used by the fast lane, ranking, preferred-copy buttons, and project summaries.

## Attack presets

- `quick`: fast plain/decode scan.
- `balanced`: default for easy/medium tasks.
- `deep`: more multi-step budget.
- `hardcore`: enables slower legacy/deep-style budgets; use only for hard tasks.

Each project stores its solver settings in `project.json` under `solver_settings`.

## Artifact hygiene

Generated artifacts are summarized with clean metadata: name, kind, source, file, path/url, score, size, note, and existence. Large blobs are not shoved into the project summary.

## Benchmarks

Run:

```bash
python3 scripts/benchmark_solver.py
```

The v111 benchmark includes ctf_cs, ctf_cm, flag{}, bare braces, custom regex, and a multi-step base64→rot13 case.

For a local writeup/challenge repository:

```bash
python3 scripts/benchmark_writeup_repo.py /path/to/ShundaZhang/CTF
```

This mines expected flags from writeups but excludes obvious writeup/solution files from solver input so results are not inflated by simply reading the answer page.
