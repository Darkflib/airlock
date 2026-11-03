#!/bin/sh
# Sync evals/ to the dev host, run the harness there with the inference key from
# 1Password (piped over stdin, never written to disk), then pull results back.
#   evals/run.sh [harness args...]   e.g. evals/run.sh --models glm-5.3 --tasks node-missing-dep
set -eu
cd "$(dirname "$0")/.."
HOST="${AIRLOCK_HOST:-airlock@airlock.darkflib.dev}"
REF=$(sed -n 's/^VULTR_INFERENCE_API_KEY="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' .env)

ssh "$HOST" mkdir -p airlock/evals
rsync -az --delete --exclude results/ evals/ "$HOST:airlock/evals/"
op read "$REF" | ssh "$HOST" "IFS= read -r K; export VULTR_INFERENCE_API_KEY=\"\$K\"; cd ~/airlock/evals && uv run -q harness.py $*"
rsync -az "$HOST:airlock/evals/results/" evals/results/
