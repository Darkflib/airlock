"""Escape lab: install the escape-probe fixture in a real Airlock Workspace (the same egress policy,
DNS guard, sinkhole, watcher and tracer a live run gets) and put two accounts side by side: what
the probe saw from inside (did each attempt get an answer?) and what Airlock recorded. No agent:
this measures containment and recording, not the verdict.

  set -a; . ~/.config/airlock/web.env; set +a
  .venv/bin/python evals/escape_lab.py [--runs 1] [--catcher catch.darkflib.dev]

With --catcher, the probe also aims at the outside catcher (a separate box with a DNS zone delegated to
it: infra/catcher, scripts/catcher.sh), and the lab first reaches it from the host itself, a control
that shows the catcher hears what gets there. evals/outside_count.py then joins the report with the
catcher's log.

Prints a JSON report on stdout.
"""

import argparse
import asyncio
import json
import secrets
import socket
import subprocess
import time
import urllib.request
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


def catcher_addrs(zone: str) -> dict:
    """The catcher's addresses, through the public delegation (as an attacker's name would resolve)."""
    found = {fam: sa[0] for fam, _, _, _, sa in socket.getaddrinfo(f"addr.{zone}", 80, proto=socket.IPPROTO_TCP)}
    return {"zone": zone, "v4": found.get(socket.AF_INET), "v6": found.get(socket.AF_INET6)}


def control(c: dict) -> dict:
    """From the host, not a VM: the same kinds of contact the probe tries, carrying a marker. Each should
    show in the catcher's log; if they don't, the catcher's silence about the VM means nothing."""
    mark = "CONTROL" + secrets.token_hex(6).upper()
    done = {"marker": mark}
    try:
        urllib.request.urlopen(urllib.request.Request(f"http://h80.{c['zone']}/control?t={mark}", data=mark.encode()), timeout=5)
        done["http_name"] = "ok"
    except OSError as e:
        done["http_name"] = str(e)
    try:
        socket.getaddrinfo(f"{mark}.res.{c['zone']}", 80)
        done["dns_resolver"] = "ok"
    except OSError as e:
        done["dns_resolver"] = str(e)
    with socket.create_connection((c["v4"], 4444), timeout=5) as s:
        s.sendall(mark.encode())
    done["tcp_v4"] = "ok"
    if c["v6"]:
        try:
            with socket.create_connection((c["v6"], 47801), timeout=5) as s:
                s.sendall(mark.encode())
            done["tcp_v6"] = "ok"
        except OSError as e:
            done["tcp_v6"] = str(e)
    ping = subprocess.run(["ping", "-c", "1", "-W", "2", "-p", mark.encode()[:16].hex(), c["v4"]], capture_output=True)
    done["icmp"] = "ok" if ping.returncode == 0 else ping.stderr.decode()[-80:]
    return done


async def once(catcher: dict | None) -> dict:
    events, heard = EventLog(), []
    servers = await listen(heard)
    target = {"v4": public_ip(socket.AF_INET, "8.8.8.8"), "v6": public_ip(socket.AF_INET6, "2001:4860:4860::8888"), "port": PORT}
    if catcher:
        target["catcher"] = catcher
    t0, started = time.monotonic(), time.time()
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
    return {"seconds": round(time.monotonic() - t0, 1), "window": [started, time.time()], "install_exit": installed.exit_code,
            "token_matches_canary": probe["token"] == canary, "probe_token": probe["token"],  # fake, made for this run
            "gateway": probe["gateway"], "outside": target,
            "outside_heard": heard,
            "probe": probe["results"], "recorded": recorded}


async def main(runs: int, zone: str | None) -> dict:
    catcher = catcher_addrs(zone) if zone else None
    report = {"catcher": catcher, "control": control(catcher) if catcher else None}
    report["runs"] = [await once(catcher) for _ in range(runs)]
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--catcher", help="the catcher's DNS zone, e.g. catch.darkflib.dev")
    a = ap.parse_args()
    print(json.dumps(asyncio.run(main(a.runs, a.catcher)), indent=2, default=str))
