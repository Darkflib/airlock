"""Escape lab: install the escape-probe fixture in a real Airlock Workspace (the same egress policy,
DNS guard, sinkhole, watcher and tracer a live run gets) and put two accounts side by side: what
the probe saw from inside (did each attempt get an answer?) and what Airlock recorded. No agent:
this measures containment and recording, not the verdict.

  set -a; . ~/.config/airlock/web.env; set +a
  .venv/bin/python evals/escape_lab.py [--runs 1]

Prints a JSON report on stdout.
"""

import argparse
import asyncio
import json
import socket
import time
from pathlib import Path

from airlock.events import EventLog
from airlock.sandbox import IMAGES, Workspace

FIXTURE = Path(__file__).parent / "fixtures" / "escape-probe.tgz"
PORT = 47801  # the outside listeners; nothing else on the host uses it


def public_ip(family: int, probe: str) -> str | None:
    """This host's own address on the internet (no packet is sent: a UDP connect only picks a route)."""
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((probe, 53))
            return s.getsockname()[0]
    except OSError:
        return None


async def listen(heard: list) -> list:
    """TCP listeners on every address: the ground truth for "it got out"."""
    async def on(reader, writer):
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(4096), 2)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        heard.append({"peer": writer.get_extra_info("peername")[0], "bytes": len(data), "data": data[:300].decode(errors="replace")})
        writer.close()
    return [await asyncio.start_server(on, "0.0.0.0", PORT), await asyncio.start_server(on, "::", PORT)]


async def once() -> dict:
    events, heard = EventLog(), []
    servers = await listen(heard)
    target = {"v4": public_ip(socket.AF_INET, "8.8.8.8"), "v6": public_ip(socket.AF_INET6, "2001:4860:4860::8888"), "port": PORT}
    t0 = time.monotonic()
    async with Workspace(events, image=IMAGES["npm"], label="escape-probe") as ws:
        await ws.write("/opt/escape-target.json", json.dumps(target).encode())
        await ws.exec("chmod 644 /opt/escape-target.json", source="unpack")
        await ws.write("/work/candidate.tgz", FIXTURE.read_bytes())
        installed = await ws.exec("npm init -y >/dev/null && npm install --no-audit --no-fund /work/candidate.tgz",
                                  cwd="/tmp/try", timeout=180, trace=True, source="detonate", as_user="node")
        await ws.collect_trace(stage="detonate", settle=True)
        probe = json.loads(await ws.read_text("/tmp/escape-probe.json"))
        canary = ws.canary_token
    await asyncio.sleep(1)
    for s in servers:
        s.close()
    recorded = [e.to_dict() for e in events.events
                if e.kind in ("egress_blocked", "egress_allowed", "canary_exfil", "dns_blocked", "canary_read")]
    return {"seconds": round(time.monotonic() - t0, 1), "install_exit": installed.exit_code,
            "token_matches_canary": probe["token"] == canary, "gateway": probe["gateway"], "outside": target,
            "outside_heard": heard,
            "probe": probe["results"], "recorded": recorded}


async def main(runs: int) -> list[dict]:
    return [await once() for _ in range(runs)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    print(json.dumps(asyncio.run(main(ap.parse_args().runs)), indent=2, default=str))
