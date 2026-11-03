#!/bin/sh
# Runs ON THE HOST (via scripts/deploy.sh). Reads five lines on stdin: the
# inference API key, the GitHub OAuth client id and secret, the GitHub App id,
# and the App private key (base64, one line). Writes them
# only to a mode-600 env file, installs the systemd unit and Caddy config, and
# restarts both. The session secret is generated once and kept across deploys.
set -eu
cd "$(dirname "$0")/.."
IFS= read -r KEY
IFS= read -r CLIENT_ID
IFS= read -r CLIENT_SECRET
IFS= read -r APP_ID
IFS= read -r APP_KEY_B64
[ -n "$KEY" ] && [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] && [ -n "$APP_ID" ] && [ -n "$APP_KEY_B64" ] \
  || { echo "missing secrets on stdin" >&2; exit 1; }

uv sync -q
[ -x ~/.local/bin/mitmdump ] || uv tool install -q mitmproxy

umask 077
CONF=~/.config/airlock
mkdir -p "$CONF"
[ -s "$CONF/session_secret" ] || head -c 48 /dev/urandom | base64 | tr -d '\n' > "$CONF/session_secret"
[ -f "$CONF/allowed_users" ] || printf '# GitHub logins allowed to sign in, one per line (re-read on every request)\n' > "$CONF/allowed_users"
{
  printf 'VULTR_INFERENCE_API_KEY=%s\n' "$KEY"
  printf 'GITHUB_CLIENT_ID=%s\n' "$CLIENT_ID"
  printf 'GITHUB_CLIENT_SECRET=%s\n' "$CLIENT_SECRET"
  printf 'AIRLOCK_SESSION_SECRET=%s\n' "$(cat "$CONF/session_secret")"
  printf 'AIRLOCK_ALLOWED_USERS=%s\n' "${AIRLOCK_OWNERS:-Darkflib}"
  printf 'AIRLOCK_PUBLIC_URL=https://airlock.darkflib.dev\n'
  printf 'GITHUB_APP_ID=%s\n' "$APP_ID"
  printf 'GITHUB_APP_PRIVATE_KEY_B64=%s\n' "$APP_KEY_B64"
} > "$CONF/web.env"

# Basic auth has been replaced by OAuth: remove its leftovers.
sudo rm -f /etc/caddy/airlock.env /etc/systemd/system/caddy.service.d/airlock.conf

sudo install -m 644 infra/Caddyfile /etc/caddy/Caddyfile
sudo install -m 644 infra/airlock-web.service /etc/systemd/system/airlock-web.service
sudo install -m 644 infra/airlock-sinkhole.service /etc/systemd/system/airlock-sinkhole.service
sudo systemctl daemon-reload
sudo systemctl enable -q airlock-sinkhole airlock-web caddy
sudo systemctl restart airlock-sinkhole
# mitmproxy writes its CA on first start; runs need it to route through the sinkhole
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s ~/.mitmproxy/mitmproxy-ca-cert.pem ] && break; sleep 1; done
sudo systemctl restart airlock-web
sudo systemctl restart caddy
sleep 3
systemctl is-active airlock-sinkhole airlock-web caddy
curl -fsS -o /dev/null -w "app health: http %{http_code}\n" http://127.0.0.1:8000/healthz
