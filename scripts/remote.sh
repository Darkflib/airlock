#!/bin/sh
# Sync the working tree to the dev host and run a command there from ~/airlock,
# with VULTR_INFERENCE_API_KEY read from 1Password and piped over stdin (never on disk).
#   scripts/remote.sh uv run airlock analyse evals/fixtures/left-padder-hostile.tgz
set -eu
cd "$(dirname "$0")/.."
ENV="$(dirname "$0")/../.env"
HOST="${AIRLOCK_HOST:-$(sed -n 's/^AIRLOCK_HOST="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$ENV" 2>/dev/null)}"
HOST="${HOST:-airlock@airlock.darkflib.dev}"
REF=$(sed -n 's/^VULTR_INFERENCE_API_KEY="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' .env)

rsync -az --delete \
  --exclude .git/ --exclude .env --exclude .venv/ --exclude assets/ \
  --exclude evals/results/ --exclude __pycache__/ --exclude .pytest_cache/ \
  ./ "$HOST:airlock/"
op read "$REF" | ssh "$HOST" "IFS= read -r K; export VULTR_INFERENCE_API_KEY=\"\$K\"; cd ~/airlock && $*"
