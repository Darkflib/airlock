"""mitmproxy addon: Airlock's sinkhole.

Sandboxes route all TCP through this proxy (microsandbox outbound proxy, SOCKS5).
Connections to 198.18.0.0/15 were handed out by the in-guest fake DNS for names
that aren't allowlisted: we answer them ourselves, log the full request, and
never open an upstream connection. Allowlisted registries pass through untouched
(--ignore-hosts). Runs as the airlock-sinkhole systemd unit.
"""

import base64
import ipaddress
import json
import os
import time

from mitmproxy import http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

SINK = ipaddress.ip_network("198.18.0.0/15")
LOG = os.environ.get("AIRLOCK_SINKHOLE_LOG", os.path.expanduser("~/.local/share/airlock/sinkhole.jsonl"))
MAX_BODY = 8000


def _in_sink(address) -> bool:
    try:
        return ipaddress.ip_address(address[0]) in SINK
    except (TypeError, ValueError, IndexError):
        return False


def _write(rec: dict) -> None:
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def server_connect(data: ServerConnectionHookData) -> None:
    """Belt and braces: nothing addressed to the sinkhole ever connects upstream."""
    if _in_sink(data.server.address):
        data.server.error = "airlock sinkhole: upstream connections are never made"


def request(flow: http.HTTPFlow) -> None:
    if not _in_sink(flow.server_conn.address):
        return
    raw = flow.request.raw_content or b""
    body = flow.request.get_text(strict=False) or ""
    _write({
        "ts": time.time(), "dest": flow.server_conn.address[0], "host": flow.request.pretty_host,
        "method": flow.request.method, "url": flow.request.pretty_url, "bytes": len(raw),
        "body": body[:MAX_BODY], "truncated": len(body) > MAX_BODY,
        # the raw bytes too: get_text() mangles binary bodies (raw gzip, XOR), which proof matching needs
        "raw_b64": base64.b64encode(raw[:MAX_BODY]).decode(),
        "user_agent": flow.request.headers.get("user-agent", ""),
    })
    flow.response = http.Response.make(200, b'{"ok":true}', {"content-type": "application/json"})
