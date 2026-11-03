#!/bin/sh
# Run on the host (normally via scripts/remote.sh): (re)start the web app on
# 127.0.0.1:8000 in the background, inheriting VULTR_INFERENCE_API_KEY.
set -eu
cd "$(dirname "$0")/.."
PID=~/.airlock-web.pid
LOG=~/airlock-web.log

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  kill "$(cat "$PID")"
  sleep 1
fi
uv sync -q
setsid nohup .venv/bin/uvicorn airlock.web.app:app_factory --factory --host 127.0.0.1 --port 8000 \
  >"$LOG" 2>&1 </dev/null &
echo $! >"$PID"
sleep 3
curl -fsS -o /dev/null -w "airlock web: http %{http_code} (pid $(cat "$PID"))\n" http://127.0.0.1:8000/ || tail -20 "$LOG"
