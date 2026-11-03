#!/bin/sh
# Manage who can sign in. Takes effect immediately (the app re-reads the file).
#   scripts/allow.sh                 list
#   scripts/allow.sh add <login>     allow a GitHub login
#   scripts/allow.sh rm <login>      revoke (also ends their current session)
set -eu
HOST="${AIRLOCK_HOST:-airlock@airlock.darkflib.dev}"
FILE='~/.config/airlock/allowed_users'
case "${1:-list}" in
  list) ssh "$HOST" "grep -v '^#' $FILE || true" ;;
  add)  [ -n "${2:-}" ] && ssh "$HOST" "grep -qix '$2' $FILE || echo '$2' >> $FILE" && echo "allowed: $2" ;;
  rm)   [ -n "${2:-}" ] && ssh "$HOST" "sed -i '/^$2\$/Id' $FILE" && echo "revoked: $2" ;;
  *)    echo "usage: $0 [list | add <login> | rm <login>]" >&2; exit 2 ;;
esac
