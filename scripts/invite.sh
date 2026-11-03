#!/bin/sh
# Invite links for judges and others whose GitHub logins we don't know in advance.
#   scripts/invite.sh new [--days 30] [--max 50] [--id lablab]   print a sign-up link
#   scripts/invite.sh list                                       accounts admitted per invite
#   scripts/invite.sh revoke <id>                                stop the link and remove its accounts
# Everyone admitted is in allowed_users tagged "# invite <id>", so scripts/allow.sh works on them too.
set -eu
HOST="${AIRLOCK_HOST:-airlock@airlock.darkflib.dev}"
ssh "$HOST" "set -a; . ~/.config/airlock/web.env; set +a; cd ~/airlock && .venv/bin/python -m airlock.web.invite $*"
