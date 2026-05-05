# Usage

## Start the app

```bash
bash START_HERE.sh
```

Then open `http://127.0.0.1:7860`.

## Recommended workflow

1. Create one project per CTF challenge.
2. Upload every provided file at once when possible.
3. Put the challenge statement into the project notes/brief.
4. Wait for first-pass automation to finish.
5. Review results in this order:
   - Brief
   - Open First
   - Flags
   - Artifacts
   - Transforms
   - Files
   - Health
   - Logs

## Git hygiene

Generated challenge data is ignored by `.gitignore`. Do not commit private challenge files, extracted flags, `.venv`, `local_tools`, or project outputs.
