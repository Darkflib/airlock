#!/bin/sh
# Deploy the current working tree to the host as a systemd service behind Caddy.
# Secrets come from 1Password and travel over SSH stdin only.
#   scripts/deploy.sh
set -eu
cd "$(dirname "$0")/.."
HOST="${AIRLOCK_HOST:-airlock@airlock.darkflib.dev}"
KEY_REF=$(sed -n 's/^VULTR_INFERENCE_API_KEY="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' .env)
ref() { sed -n "s/^$1=\"\\{0,1\\}\\([^\"]*\\)\"\\{0,1\\}\$/\\1/p" .env; }
ID_REF=$(ref GITHUB_CLIENT_ID)
SECRET_REF=$(ref GITHUB_CLIENT_SECRET)

rsync -az --delete \
  --exclude .git/ --exclude .env --exclude .venv/ --exclude assets/ \
  --exclude evals/results/ --exclude __pycache__/ --exclude .pytest_cache/ \
  ./ "$HOST:airlock/"
{ op read "$KEY_REF"; op read "$ID_REF"; op read "$SECRET_REF"; } | ssh "$HOST" "cd ~/airlock && scripts/install-web.sh"
