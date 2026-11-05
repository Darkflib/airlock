#!/bin/sh
# Compare the host's tools with the pins: uv, mitmproxy and Caddy from infra/cloud-init.yaml,
# microsandbox from uv.lock (the SDK's bundled msb is both the runtime and the CLI).
# The VM images are pinned by digest in airlock/sandbox.py (IMAGES); this checks they resolve.
#   scripts/check-pins.sh
set -eu
cd "$(dirname "$0")/.."
HOST="${AIRLOCK_HOST:-$(sed -n 's/^AIRLOCK_HOST="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' .env 2>/dev/null)}"
HOST="${HOST:-airlock@airlock.darkflib.dev}"
UV=$(sed -n 's#.*astral.sh/uv/\([0-9.]*\)/install.sh.*#\1#p' infra/cloud-init.yaml)
MITM=$(sed -n 's#.*mitmproxy==\([0-9.]*\).*#\1#p' infra/cloud-init.yaml)
CADDY=$(sed -n 's#.*install -y -qq caddy=\([0-9.]*\).*#\1#p' infra/cloud-init.yaml)
MSB=$(awk '/^name = "microsandbox"$/ {getline; gsub(/version = |"/, ""); print; exit}' uv.lock)
IMAGES=$(sed -n 's#^ *"[a-z]*": "\([^"]*@sha256:[0-9a-f]*\)",#\1#p' airlock/sandbox.py | tr '\n' ' ')

# The host reads the whole script before running it, so no command in it can eat the rest from stdin.
ssh "$HOST" 'script=$(cat); exec sh -c "$script" check </dev/null' "'$UV'" "'$MITM'" "'$CADDY'" "'$MSB'" "'$IMAGES'" <<'EOF'
fail=0
check() {  # name, pinned, found
  if [ "$2" = "$3" ]; then echo "ok    $1 $2"; else echo "DRIFT $1: pinned $2, host has ${3:-nothing}"; fail=1; fi
}
check uv "$1" "$(uv --version | cut -d' ' -f2)"
check mitmproxy "$2" "$(~/.local/bin/mitmdump --version | sed -n 's/^Mitmproxy: //p')"
check caddy "$3" "$(caddy version | cut -d' ' -f1 | sed 's/^v//')"
check msb "$4" "$(~/.local/bin/msb --version | cut -d' ' -f2)"
check "msb CLI is the SDK's" "$HOME/airlock/.venv/bin/msb" "$(readlink ~/.local/bin/msb)"
for ref in $5; do
  if ~/.local/bin/msb image pull "$ref" >/dev/null 2>&1; then echo "ok    image $ref"; else echo "DRIFT image $ref doesn't resolve"; fail=1; fi
done
exit $fail
EOF
