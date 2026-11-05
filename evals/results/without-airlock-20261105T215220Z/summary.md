# Without Airlock: demo PR #3 as a plain CI job — 20261105T215220Z

`evals/without_airlock.py`, three runs on the VX1 host, PR head `06e0a24`. A fresh microVM stands in for the CI runner: the same fake credential files Airlock plants (`~/.npmrc`, `~/.aws/credentials`), `npm ci` and `npm test` as an unprivileged user, and none of Airlock (no watcher, tracer, sinkhole or AI). The stealer's address doesn't exist (`.invalid`), so a stand-in for the attacker's server listens inside the VM under that name, with a certificate the VM trusts.

| Run | CI result | `npm ci` | `npm test` | Requests to the attacker | npm token arrived | AWS secret arrived | Total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | pass | exit 0, 1.0 s | exit 0, 0.2 s | 1 POST `/v1` | yes | yes | 3.3 s |
| 2 | pass | exit 0 | exit 0 | 1 POST `/v1` | yes | yes | 3.2 s |
| 3 | pass | exit 0 | exit 0 | 1 POST `/v1` | yes | yes | 3.2 s |

What the attacker received in each run (fake values, made for that run):

```
//registry.npmjs.org/:_authToken=npm_CIBASELINE<run token>
[default]
aws_access_key_id = AKIA<…>
aws_secret_access_key = CIBASELINE<run token>/ci
```

The same PR through Airlock (`product-20261105T142257Z`, 3/3): MALICIOUS, exfiltration proven by the captured request on every run, 6 containment events during detonation, all 6 new versus the merge base, median 23.2 s.
