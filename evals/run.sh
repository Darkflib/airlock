#!/bin/sh
# Run the eval harness on the dev host, then pull results back.
#   evals/run.sh [harness args...]   e.g. evals/run.sh --models glm-5.3 --tasks node-missing-dep
set -eu
cd "$(dirname "$0")/.."
HOST="${AIRLOCK_HOST:-airlock@airlock.darkflib.dev}"

scripts/remote.sh "cd evals && uv run -q harness.py $*"
rsync -az "$HOST:airlock/evals/results/" evals/results/
