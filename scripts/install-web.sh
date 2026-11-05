#!/bin/sh
# Runs ON THE HOST (via scripts/deploy.sh). Reads six lines on stdin: the
# inference API key, the GitHub OAuth client id and secret, the GitHub App id,
# the App private key (base64, one line) and the App's webhook secret (may be
# empty: automatic PR runs are then off). Writes them
# only to a mode-600 env file, installs the systemd unit and Caddy config, and
# restarts both. The session secret is generated once and kept across deploys.
# Settings from the environment: AIRLOCK_PUBLIC_URL (https://<domain>; Caddy gets a
# certificate for that domain), AIRLOCK_OWNERS (comma-separated GitHub logins) and
# AIRLOCK_GUEST_REPOS (owner/repo list: automatic PR runs, and guests' PRs).
set -eu
cd "$(dirname "$0")/.."
IFS= read -r KEY
IFS= read -r CLIENT_ID
IFS= read -r CLIENT_SECRET
IFS= read -r APP_ID
IFS= read -r APP_KEY_B64
IFS= read -r WEBHOOK_SECRET || true
[ -n "$KEY" ] && [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] && [ -n "$APP_ID" ] && [ -n "$APP_KEY_B64" ] \
  || { echo "missing secrets on stdin" >&2; exit 1; }

# No defaults: a forgotten owner list must not hand someone else's login the keys.
[ -n "${AIRLOCK_PUBLIC_URL:-}" ] && [ -n "${AIRLOCK_OWNERS:-}" ] \
  || { echo "set AIRLOCK_PUBLIC_URL and AIRLOCK_OWNERS (in .env or the environment)" >&2; exit 1; }
PUBLIC_URL="${AIRLOCK_PUBLIC_URL%/}"
DOMAIN="${PUBLIC_URL#https://}"
printf '%s' "$DOMAIN" | grep -Eqx '[A-Za-z0-9.-]+' && [ "$PUBLIC_URL" = "https://$DOMAIN" ] \
  || { echo "AIRLOCK_PUBLIC_URL must be https://<domain> (Caddy serves it on 443)" >&2; exit 1; }

uv sync -q --locked
# The msb CLI is the SDK's own bundled binary, so it is the uv.lock version the runtime uses
ln -sf ~/airlock/.venv/bin/msb ~/.local/bin/msb
ln -sf msb ~/.local/bin/microsandbox
~/.local/bin/msb doctor >/dev/null 2>&1 || { ~/.local/bin/msb doctor >&2; echo "msb doctor failed: this host can't run VMs" >&2; exit 1; }
[ -x ~/.local/bin/mitmdump ] || uv tool install -q mitmproxy==12.3.1

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
  printf 'AIRLOCK_ALLOWED_USERS=%s\n' "$AIRLOCK_OWNERS"
  printf 'AIRLOCK_PUBLIC_URL=%s\n' "$PUBLIC_URL"
  [ -z "${AIRLOCK_GUEST_REPOS:-}" ] || printf 'AIRLOCK_GUEST_REPOS=%s\n' "$AIRLOCK_GUEST_REPOS"
  printf 'GITHUB_APP_ID=%s\n' "$APP_ID"
  printf 'GITHUB_APP_PRIVATE_KEY_B64=%s\n' "$APP_KEY_B64"
  [ -z "$WEBHOOK_SECRET" ] || printf 'GITHUB_WEBHOOK_SECRET=%s\n' "$WEBHOOK_SECRET"
} > "$CONF/web.env"

# Basic auth has been replaced by OAuth: remove its leftovers.
sudo rm -f /etc/caddy/airlock.env /etc/systemd/system/caddy.service.d/airlock.conf

sudo install -m 644 infra/Caddyfile /etc/caddy/Caddyfile
sudo mkdir -p /etc/systemd/system/caddy.service.d  # the Caddyfile's site address is {$AIRLOCK_DOMAIN}
printf '[Service]\nEnvironment=AIRLOCK_DOMAIN=%s\n' "$DOMAIN" | sudo tee /etc/systemd/system/caddy.service.d/airlock-domain.conf >/dev/null
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
