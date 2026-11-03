"""mitmproxy addon (spike): answer every request to the sinkhole range ourselves.

Anything addressed to 198.18.0.0/15 (handed out by Airlock's fake DNS for names
that aren't allowlisted) gets a 200 from here and is logged with its body. With
connection_strategy=lazy, mitmproxy never opens an upstream connection for it.

  mitmdump --mode socks5 --listen-host 127.0.0.1 --listen-port 1080 \
    --set connection_strategy=lazy --ignore-hosts '<allowlist regex>' -s sinkhole_addon.py
"""

import ipaddress
import json
import os
import time

from mitmproxy import http

SINK = ipaddress.ip_network("198.18.0.0/15")
LOG = os.environ.get("AIRLOCK_SINKHOLE_LOG", "/tmp/sinkhole.jsonl")


def _sinkholed(flow: http.HTTPFlow) -> bool:
    try:
        return ipaddress.ip_address(flow.server_conn.address[0]) in SINK
    except (TypeError, ValueError):
        return False


def request(flow: http.HTTPFlow) -> None:
    if not _sinkholed(flow):
        return
    body = flow.request.get_text(strict=False) or ""
    rec = {
        "ts": time.time(), "host": flow.request.pretty_host, "dest": flow.server_conn.address[0],
        "method": flow.request.method, "path": flow.request.path, "scheme": flow.request.scheme,
        "bytes": len(flow.request.raw_content or b""), "body": body[:4000],
        "canary": "AIRLOCKCANARY" in body,
    }
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")
    flow.response = http.Response.make(200, b'{"ok":true}', {"content-type": "application/json"})
