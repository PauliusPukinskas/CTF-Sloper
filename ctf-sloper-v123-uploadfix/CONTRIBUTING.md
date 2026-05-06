# Contributing

## Local checks

Run:

```bash
bash scripts/check.sh
```

## Style

- Keep runtime code local-first and offline-friendly.
- Do not hardcode private CTF answers.
- Store generated files only under ignored folders such as `projects/` or `generated/`.
- Prefer small modules for new solver logic instead of growing `sloper_legacy.py`.
