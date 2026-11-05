#!/bin/sh
# Manage who can sign in. Takes effect immediately (the app re-reads the file).
#   scripts/allow.sh                 list
#   scripts/allow.sh add <login>     allow a GitHub login
#   scripts/allow.sh rm <login>      revoke (also ends their current session)
# Accounts admitted by an invite link carry a "# invite <id>" tag; see scripts/invite.sh.
set -eu
ENV="$(dirname "$0")/../.env"
HOST="${AIRLOCK_HOST:-$(sed -n 's/^AIRLOCK_HOST="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$ENV" 2>/dev/null)}"
HOST="${HOST:-airlock@airlock.darkflib.dev}"
FILE='~/.config/airlock/allowed_users'
case "${1:-list}" in
  list) ssh "$HOST" "grep -v '^#' $FILE || true" ;;
  add)  [ -n "${2:-}" ] && ssh "$HOST" "grep -qiE '^$2([[:space:]]*#.*)?\$' $FILE || echo '$2' >> $FILE" && echo "allowed: $2" ;;
  rm)   [ -n "${2:-}" ] && ssh "$HOST" "sed -i -E '/^$2([[:space:]]*#.*)?\$/Id' $FILE" && echo "revoked: $2" ;;
  *)    echo "usage: $0 [list | add <login> | rm <login>]" >&2; exit 2 ;;
esac
