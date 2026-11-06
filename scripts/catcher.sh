#!/usr/bin/env bash
# The outside catcher for the escape lab (infra/catcher): a separate Vultr box, plus a DNS zone
# delegated to it so a token in a lookup that reaches any real resolver lands in its log.
#
#   scripts/catcher.sh up      create the box (London, vc2-1c-1gb) and the DNS records
#   scripts/catcher.sh status  the box, its records, and whether the catcher answers
#   scripts/catcher.sh log     print the catcher's hits.jsonl
#   scripts/catcher.sh down    destroy the box and remove the records
#
# The box is on VULTR_API_KEY's account; darkflib.dev's DNS is on VULTR_DNS_API_KEY's (both in .env).
set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN=darkflib.dev
ZONE="catch.$DOMAIN"          # delegated to the box
NS="ns-catch"                 # $NS.$DOMAIN: the box's name, glue for the delegation
LABEL=airlock-catcher
ref() { grep "^$1=" .env | cut -d'"' -f2; }
box() { VULTR_API_KEY="$(op read "$(ref VULTR_API_KEY)")" vultr-cli "$@"; }
dns() { VULTR_API_KEY="$(op read "$(ref VULTR_DNS_API_KEY)")" vultr-cli "$@"; }
instance() { box instance list -o json | jq -r --arg l "$LABEL" '.instances[]? | select(.label==$l)'; }
records() { dns dns record list "$DOMAIN" -o json | jq -r --arg ns "$NS" --arg z catch \
  '.records[] | select(.name==$ns or .name==$z) | "\(.id) \(.type) \(.name) \(.data)"'; }

case "${1:-}" in
  up)
    [ -z "$(instance)" ] || { echo "$LABEL already exists"; exit 1; }
    ud="$(mktemp)"; trap 'rm -f "$ud"' EXIT
    sed -e "s|CATCHER_PY_B64|$(base64 < infra/catcher/catcher.py | tr -d '\n')|" \
        -e "s|CATCHER_ZONE_VALUE|$ZONE|" infra/catcher/cloud-init.yaml > "$ud"
    os="$(box os list -o json | jq -r '.os[] | select(.name=="Ubuntu 24.04 LTS x64") | .id')"
    box instance create --region lhr --plan vc2-1c-1gb --os "$os" --label "$LABEL" --host catcher \
      --ipv6 --userdata-file "$ud" -o json | jq -r '.instance.id'
    echo "waiting for addresses..."
    for _ in $(seq 60); do
      v4="$(instance | jq -r .main_ip)"; v6="$(instance | jq -r .v6_main_ip)"
      [ -n "$v4" ] && [ "$v4" != 0.0.0.0 ] && [ -n "$v6" ] && break; sleep 5
    done
    echo "box: $v4 $v6"
    dns dns record create "$DOMAIN" --type A --name "$NS" --data "$v4" --ttl 300 >/dev/null
    dns dns record create "$DOMAIN" --type AAAA --name "$NS" --data "$v6" --ttl 300 >/dev/null
    dns dns record create "$DOMAIN" --type NS --name catch --data "$NS.$DOMAIN" --ttl 300 >/dev/null
    records ;;
  status)
    instance | jq -r '"\(.label) \(.main_ip) \(.v6_main_ip) \(.status)/\(.server_status)"'
    records
    dig +short +time=3 "status-check.$ZONE" A @8.8.8.8 || true ;;
  log)
    ssh "catcher@$NS.$DOMAIN" cat /var/lib/catcher/hits.jsonl ;;
  down)
    id="$(instance | jq -r .id)"; [ -n "$id" ] && box instance delete "$id" && echo "deleted $id"
    records | while read -r rid _; do dns dns record delete "$DOMAIN" "$rid"; done ;;
  *) sed -n 2,10p "$0"; exit 1 ;;
esac
