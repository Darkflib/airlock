# Escape lab — 20261105T220624Z

`evals/escape_lab.py`, 3 runs on the VX1 host, identical outcomes. The `escape-probe` fixture's postinstall (`evals/fixtures/src/escape-probe/probe.js`) tries 38 ways out, each carrying the run's canary credentials, inside a real Airlock `Workspace`: the same egress policy, DNS guard, sinkhole, watcher and tracer as a live run (no agent: this measures containment and recording, not the verdict). The probe writes down from the inside what answered each attempt. Outside the sandbox, the lab listens on the host's public IPv4 and IPv6 (port 47801): **those listeners heard nothing in any run.**

"Proven" means captured on the host with this run's token; "observed" means the Node tracer or the root watcher in the guest saw it (never counted as proof).

| Way out | What answered, from inside | Airlock recorded |
| --- | --- | --- |
| HTTPS / HTTP POST to a name | Airlock's sinkhole (`{"ok":true}`) | **proven** exfil, body captured |
| HTTP POST to a name on port 4444 | refused | exfil attempt, observed (tracer); refused-connect count |
| Token in a DNS name, system resolver | the watcher, with a sinkhole address | exfil attempt, observed (watcher) **[new 5 Nov]** |
| Token in a DNS name, sent straight to the gateway | DnsGuard: NXDOMAIN | **proven** exfil |
| Token in a DNS name, sent straight to 8.8.8.8 (UDP) or 1.1.1.1 (TCP) | NXDOMAIN from microsandbox; `example.com` the same way also NXDOMAIN, so it never reached a real resolver | **not recorded** (contained) |
| HTTPS / HTTP POST to a raw public IP (1.1.1.1, 203.0.113.7) | microsandbox: `403 network_policy_denied` | exfil attempt, observed (tracer) |
| TCP to a raw IP on port 4444 | refused | refused-connect count |
| IPv6 (Cloudflare 2606:4700:4700::1111) | `403 network_policy_denied` on HTTP | blocked egress |
| The host's own public IPv4 / IPv6, port 80 | `403 network_policy_denied` | exfil attempt, observed (tracer) |
| The lab's listener on the host's public IPv4 / IPv6, port 47801 | refused; **listener heard nothing** | refused-connect count |
| Cloud metadata: 169.254.169.254 (AWS and Vultr paths), 169.254.170.2 (ECS), 100.100.100.200 (Alibaba) | `403 network_policy_denied` | blocked egress |
| Cloud metadata by name (metadata.google.internal) | Airlock's sinkhole | blocked egress (sinkholed) |
| The gateway's ports 22, 1080 (sinkhole proxy), 2019 (Caddy admin), 8000 (Airlock web) | refused | refused-connect count |
| The gateway's ports 53, 80, 443 | microsandbox's own DNS and HTTP(S) interception | — |
| Docker API 172.17.0.1:2375 | refused | refused-connect count |
| Private ranges 10.0.0.1:80, 192.168.1.1:80 | accepted by microsandbox's port-80 interception (which answers HTTP with the policy 403, as above) | — |
| ICMP (ping with token bytes) | no `ping` binary; an unprivileged ping socket is refused (`EACCES`) | — |
| Token in a URL on registry.npmjs.org (allowed) | **the registry** (HTTP 200) | exfil, observed: "it reached that host" **[new 5 Nov]** |

Two recording gaps found and fixed on 5 Nov: a token in a request URL was invisible to the tracer (it checked bodies only), and the watcher didn't flag a token in a DNS name (the system resolver had lowercased it). One stays open: DNS queries addressed straight to an outside resolver are refused by microsandbox before Airlock sees them, so they're contained but not on the timeline.

The registry row is the one way out that works by design: an allowed host is reachable, so anything put in a request to it gets there. Only the registry operator can read it, not the package's author, but it's flagged so a reviewer sees it.
