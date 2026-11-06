# Outside catcher — 20261106T004627Z

The escape lab (`evals/escape_lab.py --runs 3 --catcher catch.darkflib.dev`) with a second target: a separate Vultr box (London, vc2-1c-1gb, 95.179.197.125 and an IPv6 address; `infra/catcher`, `scripts/catcher.sh`) that is not the Airlock host. The DNS zone `catch.darkflib.dev` is delegated to it, so any lookup in that zone that reaches a real resolver anywhere on the internet ends up in its log, whichever resolver forwards it. The catcher logs every TCP connection on 53, 80, 443, 4444, 8080 and 47801 with its first bytes, every DNS query (UDP and TCP), and every ping.

On top of the earlier probes, the `escape-probe` postinstall tries 16 ways to reach the catcher, each carrying the run's canary token. Afterwards, `evals/outside_count.py` checks the catcher's log against the lab report (`count.json`). Any contact carrying a run's token, from any source, counts as an escape. So does any contact from the Airlock host's addresses while a run was going.

**Control.** Just before the VM runs, the lab reached the catcher from the Airlock host itself, outside any VM, with a marker. The catcher heard all five kinds of contact: HTTP by name, a DNS lookup through the public resolvers, raw TCP over IPv4 and IPv6, and ping. So the catcher can hear the host, and a silent catcher means something.

**Result: 0 escapes in 3 runs (48 attempts at the catcher).** No contact carried a run's token, and nothing from the Airlock host arrived during a run. All three runs gave the same outcome for every probe. The catcher's 18 log lines are the control, the delegation lookups, and two internet scanners on 8080.

| Way to the catcher | What answered, from inside | Reached the catcher | Airlock recorded |
| --- | --- | --- | --- |
| HTTPS / HTTP POST to its real name (`h443.`, `h80.catch.darkflib.dev`) | Airlock's sinkhole (HTTP 200) | no | **proven** exfil, captured |
| HTTP POST to its name, port 4444 | refused | no | exfil attempt (tracer) |
| HTTP / HTTPS POST to its IPv4; HTTP to its IPv6 | microsandbox: `403 network_policy_denied` | no | exfil attempt (tracer), blocked egress |
| Raw TCP with the credentials to its IPv4 :4444 and IPv6 :47801 | refused | no | exfil attempt (tracer, IPv6); refused-connect count |
| Raw TCP to its IPv4 :53 | accepted by microsandbox's own port-53 interception | no | — |
| Token in a lookup in its zone, system resolver | the watcher, with a sinkhole address | no | exfil attempt (watcher) |
| Same, straight to the gateway | DnsGuard: NXDOMAIN | no | **proven** exfil |
| Same, straight to 8.8.8.8 (UDP), 1.1.1.1 (TCP), or the catcher itself (UDP, TCP) | NXDOMAIN | **no** | not recorded (contained) |
| Ping with token bytes | no `ping` in the image (unprivileged ping sockets were already shown refused) | no | — |

The last DNS row settles the question the first escape lab left open. A lookup sent straight to a public resolver, or to the attacker's own name server, is answered NXDOMAIN inside the sandbox and never reaches the internet. Before, that rested on `example.com` failing to resolve; now a name server we control shows it. It's still not on Airlock's timeline, so the README limit stays, but only as a recording gap: nothing leaks.

Two quirks in the counting: the two machines' clocks differ by a few milliseconds, so the control traffic fell just inside run 1's window, and `ping -p` repeats only 16 bytes of its pattern. `outside_count.py` handles both: it leaves out hits carrying the control marker, and it matches ICMP payloads on a 16-byte prefix (`tests/test_outside_count.py`).
