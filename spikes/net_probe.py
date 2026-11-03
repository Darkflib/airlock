"""Spike: does microsandbox's default-deny egress do what Airlock needs?

Run on the host:  uv run --with microsandbox spikes/net_probe.py
"""

import asyncio
import time

from microsandbox import Action, Destination, Network, NetworkPolicy, Protocol, Rule, Sandbox
from microsandbox.types import TlsConfig

PROBES = [
    ("allowed: registry.npmjs.org", "curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://registry.npmjs.org/left-pad"),
    ("allowed: pypi.org", "curl -s -o /dev/null -w '%{http_code}' --max-time 8 https://pypi.org/simple/requests/"),
    ("denied: example.com https", "curl -s -w ' %{http_code}' --max-time 8 https://example.com/ ; echo \" exit=$?\""),
    ("denied: raw IP http", "curl -s -w ' %{http_code}' --max-time 8 http://1.1.1.1/ ; echo \" exit=$?\""),
    ("denied: dns", "getent hosts evil.example.net ; echo \"exit=$?\""),
]


def show(label, out):
    fields = {k: getattr(out, k) for k in dir(out) if not k.startswith("_") and not callable(getattr(out, k))}
    print(f"--- {label}")
    for k, v in fields.items():
        if v not in (None, "", b""):
            print(f"    {k}: {str(v).strip()[:300]}")


async def main():
    policy = NetworkPolicy(
        default_egress=Action.DENY,
        default_ingress=Action.ALLOW,
        rules=(
            *Rule.allow_dns(),
            Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain("registry.npmjs.org")),
            Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain("pypi.org")),
        ),
    )
    t0 = time.monotonic()
    async with await Sandbox.create(
        "net-probe",
        image="python",
        cpus=2,
        memory=1024,
        replace=True,
        network=Network(policy=policy, tls=TlsConfig(), strict=True),
    ) as sb:
        print(f"boot: {time.monotonic() - t0:.2f}s")
        setup = await sb.shell("command -v curl || echo no-curl")
        show("curl present?", setup)
        for label, cmd in PROBES:
            show(label, await sb.shell(cmd))


asyncio.run(main())
