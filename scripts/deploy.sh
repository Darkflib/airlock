#!/bin/sh
# Deploy the current working tree to the host as a systemd service behind Caddy.
# Secrets are 1Password references in .env (see .env.example); their values travel
# over SSH stdin only. Settings (not secrets) come from the environment or .env:
#   AIRLOCK_HOST (ssh target), AIRLOCK_PUBLIC_URL, AIRLOCK_OWNERS, AIRLOCK_GUEST_REPOS, AIRLOCK_SLOTS
#   scripts/deploy.sh
set -eu
cd "$(dirname "$0")/.."
ref() { sed -n "s/^$1=\"\\{0,1\\}\\([^\"]*\\)\"\\{0,1\\}\$/\\1/p" .env; }
HOST="${AIRLOCK_HOST:-$(ref AIRLOCK_HOST)}"; HOST="${HOST:-airlock@airlock.darkflib.dev}"
KEY_REF=$(ref VULTR_INFERENCE_API_KEY)
ID_REF=$(ref GITHUB_CLIENT_ID)
SECRET_REF=$(ref GITHUB_CLIENT_SECRET)
APP_REF="op://Private/Airlock Github App"  # used where .env names no App references
APP_ID_REF=$(ref GITHUB_APP_ID); APP_ID_REF="${APP_ID_REF:-$APP_REF/app-id}"
APP_KEY_REF=$(ref GITHUB_APP_PRIVATE_KEY); APP_KEY_REF="${APP_KEY_REF:-$APP_REF/private-key}"
HOOK_REF=$(ref GITHUB_WEBHOOK_SECRET); HOOK_REF="${HOOK_REF:-$APP_REF/webhook-secret}"
setting() { v=$(printenv "$1" || true); [ -n "$v" ] || v=$(ref "$1"); [ -z "$v" ] || printf "%s='%s' " "$1" "$v"; }
SETTINGS="$(setting AIRLOCK_PUBLIC_URL)$(setting AIRLOCK_OWNERS)$(setting AIRLOCK_GUEST_REPOS)$(setting AIRLOCK_SLOTS)"

rsync -az --delete \
  --exclude .git/ --exclude .env --exclude .venv/ --exclude assets/ \
  --exclude evals/results/ --exclude __pycache__/ --exclude .pytest_cache/ \
  ./ "$HOST:airlock/"
{ op read "$KEY_REF"; op read "$ID_REF"; op read "$SECRET_REF"; op read "$APP_ID_REF"; op read "$APP_KEY_REF" | base64 | tr -d '\n'; echo; \
  op read "$HOOK_REF" 2>/dev/null || echo; } | ssh "$HOST" "cd ~/airlock && ${SETTINGS}scripts/install-web.sh"
