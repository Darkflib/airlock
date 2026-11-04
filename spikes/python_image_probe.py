"""Spike: which OCI image can Airlock boot for Python packages?

Needs python3 (the watcher), pip that builds sdists, runuser/useradd for the
unprivileged package user, and pypi.org reachable through default-deny egress.

Run on the host:  .venv/bin/python spikes/python_image_probe.py [image ...]
"""

import asyncio
import sys
import time

from microsandbox import Action, Destination, Network, NetworkPolicy, Protocol, Rule, Sandbox

PROBES = [
    ("os", "head -2 /etc/os-release"),
    ("python3", "python3 --version; python3 -m pip --version; python3 -c 'import setuptools' && echo setuptools-ok"),
    ("venv", "python3 -m venv /tmp/v && /tmp/v/bin/pip --version"),
    ("users", "id node; command -v runuser useradd adduser curl"),
    ("pypi", "python3 -c \"import urllib.request as u; print(u.urlopen('https://pypi.org/simple/six/', timeout=8).status)\""),
    ("files", "python3 -c \"import urllib.request as u; print(u.urlopen('https://files.pythonhosted.org/', timeout=8).status)\" 2>&1 | tail -1"),
]


async def probe(image: str) -> None:
    hosts = ("pypi.org", "files.pythonhosted.org")
    policy = NetworkPolicy(default_egress=Action.DENY, default_ingress=Action.ALLOW, rules=(
        *Rule.allow_dns(),
        *(Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain(h)) for h in hosts)))
    t0 = time.monotonic()
    async with await Sandbox.create(f"probe-{image.replace(':', '-').replace('.', '-')}", image=image, replace=True,
                                    memory=1024, network=Network(policy=policy)) as sb:
        print(f"=== {image}: up in {time.monotonic() - t0:.1f}s")
        for label, cmd in PROBES:
            out = await sb.shell(cmd, timeout=60)
            print(f"--- {label} (exit {out.exit_code})\n{(out.stdout_text + out.stderr_text).strip()[:400]}")


async def main() -> None:
    for image in sys.argv[1:] or ["node", "python:3.12-slim"]:
        try:
            await probe(image)
        except Exception as e:  # noqa: BLE001
            print(f"=== {image}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
