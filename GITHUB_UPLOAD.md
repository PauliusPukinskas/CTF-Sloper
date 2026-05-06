# Upload this project to GitHub

## Easiest web upload

1. Unzip this package.
2. Open GitHub and create a new repository named `ctf-sloper`.
3. Click **uploading an existing file**.
4. Open the unzipped `ctf-sloper/` folder on your computer.
5. Select everything inside it, not the outer folder itself.
6. Drag the selected files into GitHub.
7. Commit with message: `Initial CTF Sloper upload`.

This works for small/medium repos. If GitHub refuses many files or large files, use the terminal method below.

## Terminal upload

```bash
cd ctf-sloper
bash scripts/git_init_upload.sh PauliusPukinskas CTF-Sloper
```

That script initializes git, commits everything, sets `origin`, and gives you the final push command.

## Manual terminal upload

```bash
cd ctf-sloper

git init
git add .
git commit -m "Initial CTF Sloper upload"
git branch -M main
git remote add origin https://github.com/PauliusPukinskas/CTF-Sloper.git
git push -u origin main
```

## Before pushing

```bash
bash scripts/check.sh
```

## Important

The `projects/` folder is intentionally ignored except for `.gitkeep`, because it will contain challenge files, generated artifacts, and possible secrets.
