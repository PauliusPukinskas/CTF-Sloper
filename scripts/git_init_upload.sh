#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${1:-}"
REPO_NAME="${2:-ctf-sloper}"

if [[ -z "$USER_NAME" ]]; then
  echo "Usage: bash scripts/git_init_upload.sh YOUR_GITHUB_USERNAME [repo-name]"
  echo "Example: bash scripts/git_init_upload.sh gryynz ctf-sloper"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed. Install git first."
  exit 1
fi

cd "$(dirname "$0")/.."

if [[ ! -d .git ]]; then
  git init
fi

git branch -M main

git add .
if git diff --cached --quiet; then
  echo "Nothing new to commit."
else
  git commit -m "Initial CTF Sloper upload"
fi

REMOTE="https://github.com/${USER_NAME}/${REPO_NAME}.git"
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE"
else
  git remote add origin "$REMOTE"
fi

cat <<DONE

Ready to push to:
  $REMOTE

If the GitHub repo does not exist yet, create it in the browser first:
  https://github.com/new

Then run:
  git push -u origin main
DONE
