#!/bin/sh
# Runs ON THE HOST (via scripts/deploy.sh). Reads two lines on stdin: the
# inference API key, then the web basic-auth password. Writes them only to
# mode-600 files, installs the systemd unit and Caddy config, and restarts both.
set -eu
cd "$(dirname "$0")/.."
IFS= read -r KEY
IFS= read -r PASSWORD
[ -n "$KEY" ] && [ -n "$PASSWORD" ] || { echo "missing key or password on stdin" >&2; exit 1; }

uv sync -q

# Stop the ad-hoc dev server if scripts/serve.sh started one.
if [ -f ~/.airlock-web.pid ]; then kill "$(cat ~/.airlock-web.pid)" 2>/dev/null || true; rm -f ~/.airlock-web.pid; fi

umask 077
mkdir -p ~/.config/airlock
printf 'VULTR_INFERENCE_API_KEY=%s\n' "$KEY" > ~/.config/airlock/web.env

HASH=$(printf '%s\n' "$PASSWORD" | caddy hash-password)
printf 'AIRLOCK_WEB_USER=airlock\nAIRLOCK_WEB_HASH=%s\n' "$HASH" | sudo tee /etc/caddy/airlock.env >/dev/null
sudo chmod 600 /etc/caddy/airlock.env

sudo install -d /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironmentFile=/etc/caddy/airlock.env\n' | sudo tee /etc/systemd/system/caddy.service.d/airlock.conf >/dev/null
sudo install -m 644 infra/Caddyfile /etc/caddy/Caddyfile
sudo install -m 644 infra/airlock-web.service /etc/systemd/system/airlock-web.service

sudo systemctl daemon-reload
sudo systemctl enable -q airlock-web caddy
sudo systemctl restart airlock-web
sudo systemctl restart caddy
sleep 3
systemctl is-active airlock-web caddy
curl -fsS -o /dev/null -w "app on localhost: http %{http_code}\n" http://127.0.0.1:8000/
