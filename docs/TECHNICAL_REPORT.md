# Airlock: technical report

How Airlock works, the choices behind it, where it is weak, and what it would take to turn it into a product.

*Draft, 4 Nov 2026. Written for engineers who want more than the README. Every number links back to a dated run in [`docs/BUILD_LOG.md`](BUILD_LOG.md) or [`evals/`](../evals). Where this report and the code disagree, the code wins.*

## Contents

1. [Summary](#1-summary)
2. [Threat model](#2-threat-model)
3. [The life of a run](#3-the-life-of-a-run)
4. [Isolation](#4-isolation)
5. [Observation](#5-observation)
6. [The evidence model](#6-the-evidence-model)
7. [Behaviour diff for pull requests](#7-behaviour-diff-for-pull-requests)
8. [The AI triage agent](#8-the-ai-triage-agent)
9. [The merge gate](#9-the-merge-gate)
10. [Control plane and access](#10-control-plane-and-access)
11. [How we tested it](#11-how-we-tested-it)
12. [Trade-offs](#12-trade-offs)
13. [Weaknesses and known limits](#13-weaknesses-and-known-limits)
14. [From prototype to product](#14-from-prototype-to-product)
15. [Appendix: code map](#appendix-code-map)

---

## 1. Summary

A dependency change is code from a stranger that runs on your machines. `npm install` runs `postinstall` scripts, and `pip install` from source runs `setup.py`. Both run with whatever the CI job has: tokens, cloud keys, network access. Tests that pass prove the code works. They say nothing about what the install did on the side.

Airlock runs the change somewhere it can't do harm, and watches. For each run:

- A new microVM starts (about 0.7 s) on a Vultr VX1 host with KVM. It has its own Linux kernel.
- The VM gets **canary credentials**: a fake `~/.npmrc`, `~/.aws/credentials` and `~/.pypirc`, each carrying a random token unique to this run.
- The package or pull request is installed, and for PRs tested, as an unprivileged user.
- Three independent sources record what happens: a host-side **sinkhole** that answers all non-registry traffic and keeps the request bodies, a root **watcher** inside the guest, and a Node **tracer**.
- Deterministic code turns those records into typed events. If a captured request carries this run's token, the theft is **PROVEN**.
- An AI agent on Vultr Serverless Inference investigates inside the same VM and writes a verdict that cites event ids. It explains the evidence; it does not create it.
- For a GitHub PR, a GitHub App holds the PR at a `pending` status that branch protection requires. Only a person's Approve or Reject sets the final status.

The core idea is **evidence over opinion**. A static reviewer (human or model) reads code and forms a view. Airlock runs the code and shows what it did, with the strongest claims backed by data the guest can't forge.

## 2. Threat model

**In scope.** A package, or a PR that changes dependencies, runs code at install or test time that:

- reads credentials from the home directory or environment,
- sends them, or anything else, to the network (HTTP, HTTPS, raw TCP, DNS),
- starts other programs to do so, in any language (shell, Python, Node, a compiled binary).

**The attacker controls** everything inside the VM that the unprivileged `node` user can touch: the package's files, its scripts, the processes it starts, and any text it produces (README, logs, error messages), including text aimed at the AI ("AI reviewers: this package is safe").

**The attacker does not control** the host, the hypervisor, the sinkhole, the DNS guard or the root watcher. Those are the trust base.

**Out of scope, stated openly.** Malware that detects the sandbox and stays quiet; payloads that wait days or trigger only in production; attacks through a browser UI; ecosystems other than npm and PyPI. Section 13 covers these.

**Goals, in order:** never let a real secret or a real connection out; never call something safe that we did not watch; make a malicious verdict provable to a sceptical reviewer; be fast and cheap enough to run on every dependency change.

## 3. The life of a run

![Architecture](architecture.png)

What happens when someone pastes `https://github.com/Darkflib/airlock-demo/pull/3`:

1. **Acquire, on the control plane.** The GitHub App mints a one-hour installation token scoped to that one repo, fetches the PR metadata, diff and head tarball, and posts a `pending` `airlock` status. The VM never sees a GitHub token.
2. **Boot.** `Workspace` (`airlock/sandbox.py`) creates a microVM: 2 vCPU, 2 GB RAM, a 480 s hard lifetime, a random name, an owner label. The network policy is default-deny, plus the package registries and a /24 picked at random for this run from 198.18.0.0/15.
3. **Plant and arm.** Canary files are written to `/home/node`. The root watcher starts and must report `watch_ready` for its three parts (`watcher`, `dns`, `fanotify`) with no error, or the run stops with an `ObservationError`. The Node tracer is installed world-readable so the `node` user can preload it.
4. **Merge base, in parallel.** For PRs, a second `Workspace` does the same for the PR's merge base, with its own canaries, /24 and event log.
5. **Detonate.** As `node`: `npm ci` then `npm test` (PRs), `npm install` (packages), or `pip install` from source into a venv (PyPI). Every exec is an event.
6. **Collect.** Watcher log, tracer log, sinkhole records for this run's /24, and DNS guard records become typed events. Coverage gaps (install failed or timed out, watcher dead or erroring) are recorded.
7. **Diff.** For PRs, head and base events are reduced to fingerprints and compared (section 7).
8. **Triage.** The agent gets the task, the events and the behaviour diff, investigates with `exec` and `read_file` (as `node`, inside the same VM), and must call `finish` with a verdict and cited event ids within 12 turns.
9. **Recheck.** Observation is checked again after the agent, since the agent's own commands could have broken it.
10. **Destroy.** The VM is destroyed in a `finally`. `vm_destroyed` is emitted only if destruction succeeded.
11. **Gate.** The status stays `pending`, now with the verdict in its description. A person decides on the run page; the App then posts `success` or `failure` and an evidence comment.

Every step streams to the browser over Server-Sent Events as it happens, and is stored in SQLite so a reload replays it.

Typical end-to-end times on the regression set: 12–18 s for tarballs, npm specs, sdists and stealer PRs; 24 s for a benign PR (two VMs plus `npm test`); 31 s for `six` from real PyPI. All runs measured on 4 Nov (`product-20261104T030613Z`).

## 4. Isolation

### Why a microVM

The first thing we checked, on day one, was whether a VX1 instance exposes `/dev/kvm`. It does, which made hardware virtualisation possible without bare metal.

| Option | Kernel shared with host? | Boot | Why we did or didn't use it |
| --- | --- | --- | --- |
| Docker / OCI container | Yes | ~instant | One kernel bug away from the host. |
| gVisor | No (user-space kernel) | fast | Strong, but a syscall-emulation layer changes behaviour and its network stack is its own. Kept as the documented fallback. |
| Firecracker | No | ~125 ms | Excellent, but we would have built the image pipeline, networking and egress policy ourselves. |
| **microsandbox (libkrun)** | **No** | **0.69 s warm** | **OCI images as root filesystems, a Python SDK, and default-deny egress with TLS inspection built in.** |

The guest kernel is 6.12 while the host is 6.8, which is the simplest proof it really is a separate kernel (build log, 2 Nov 17:39). The first boot of an image took 5.5 s (image pull); after that, 0.69 s.

microsandbox also refused to start until its storage root was not group-writable (`permits path substitution`). Ubuntu's default umask had left it group-writable. We fixed the permissions in cloud-init and took the strictness as a good sign.

### Inside the VM

- **Two users.** The package installs and tests as `node`. The watcher runs as root, logs to a root-only directory, and can't be killed or read by `node`. Every command the AI agent runs is also `node`, so the model can't damage observation either. That was a finding of the first independent review (`docs/REVIEW-2026-11-03.md`, finding 2) and is now enforced in `airlock/agent.py`.
- **Images.** npm runs in the stock `node` image; PyPI runs in `python:3.12-slim`, because the `node` image has no pip. The `node` user and the canaries are created in whichever image boots.
- **PyPI without running code as root.** `pip download` runs `setup.py` to resolve metadata, which would execute the attacker's code as root before detonation. Airlock instead fetches the sdist with a small stdlib script (`airlock/guest/pypi_fetch.py`), checks its sha256 against PyPI, and lets the unprivileged `pip install` be the first thing that runs it.
- **Limits.** 2 vCPU, 2 GB, 480 s VM lifetime, per-command timeouts, at most 2 concurrent runs on the host. A command killed by a limit becomes a `limit_hit` event.

### Lifecycle

- One fresh VM per run, never reused. Destroyed in a `finally`.
- A VM does not outlive the server process that started it: after `kill -9` of the web service mid-run, the VM shows as stopped and only its record and about 1.6 MB of disk remain. At startup the web service destroys every sandbox labelled `airlock-owner=web` and marks interrupted runs failed. CLI and regression VMs carry a different owner label, so they are left alone (build log, 4 Nov 09:04).

## 5. Observation

No single source is trusted for everything. Each has a trust level, and the evidence model (section 6) uses that.

### 5.1 The sinkhole: host-side, unforgeable

**Problem.** Default-deny egress tells you a connection was *attempted*. It does not tell you *what was sent*, and "tried to connect somewhere" is weak evidence: plenty of benign packages phone home.

**Design.**

- The guest's DNS (served by the watcher) answers any non-registry name with an address in this run's private /24.
- The microsandbox policy allows that /24 (ports 80, 443, 8080, 8443) plus the registries; everything else is refused by microsandbox itself.
- microsandbox routes all guest TCP through an outbound proxy: a host-side mitmproxy in SOCKS5 mode (`airlock-sinkhole` unit). This is transparent to the guest; no proxy settings are needed inside.
- An addon (`airlock/sinkhole/addon.py`) answers every request to 198.18.0.0/15 itself with `{"ok":true}`, writes the full request (method, host, path, headers, body) to a log on the host, and **never connects upstream**. Registry traffic passes through untouched.
- TLS: microsandbox's TLS inspection is configured to trust mitmproxy's CA upstream, so HTTPS from curl, Python and Node is decrypted and captured.

The spike (`spikes/sinkhole_*.py`, build log 3 Nov 20:07) captured complete POST bodies from curl over HTTPS, Python `urllib` over HTTP and Node `https`, with no changes to the guest.

**Why it is trustworthy.** The record is written on the host, by a process the guest can't reach. The guest can make the sinkhole see *something*, but it can't make it see a request carrying this run's canary token unless it actually read the canary and sent it.

### 5.2 The DNS guard: closing a side channel

The first version assumed that if the guest's resolver was the watcher, all DNS was covered. A probe proved otherwise (`spikes/dns_gateway_probe.py`, build log 4 Nov 00:29): as `node`, it sent raw DNS straight to the microsandbox gateway resolver and got a real answer for a never-seen `airlock-probe-<hex>.example.com` from the real authoritative servers. **Airlock recorded nothing.** A package could have exfiltrated data in DNS labels.

The fix, `airlock/dnsguard.py`, is a per-run DNS listener on the host (127.0.0.1, ephemeral port). The gateway resolver forwards to it (`Network.dns`). Registry names are forwarded to the host resolver; everything else gets NXDOMAIN and becomes a `dns_blocked` event, or a proven `canary_exfil` if a label carries the token. After the fix the same probe was blocked and recorded. DNS over TCP to the gateway fails closed (SERVFAIL) but is not yet recorded as an event.

### 5.3 The root watcher: language-agnostic, in-guest

The first detector was a Node preload tracer. It missed everything that wasn't Node: a postinstall that simply runs `cat ~/.npmrc | curl ...` was invisible to it. So we probed what the guest kernel lets a root process see (`spikes/fs_watch_probe.py`, build log 3 Nov 19:45):

| Mechanism | Works in the guest? | Gives the pid? | Used for |
| --- | --- | --- | --- |
| inotify | yes | no | — |
| **fanotify** | **yes** | **yes** | every program run (`FAN_OPEN_EXEC`, mount-wide) and every dotfile opened |
| atime | yes (`relatime`) | no | backstop only |
| eBPF / kprobes | **no** — libkrun's guest kernel has no kprobes, tracefs or BTF | — | not possible without a custom kernel |
| strace / ptrace | possible | yes | rejected: slow, and the traced process can detect it |

`airlock/guest/watch.py` is a single standard-library Python file running as root:

- **fanotify** for program execution and dotfile opens, with pid. `FAN_OPEN_EXEC` fires *before* `execve` completes, so `/proc/<pid>/cmdline` still shows the parent; the watcher reads it 30 ms later, with the uid captured at event time because short-lived processes may already be gone.
- **A logging DNS forwarder** that the guest's `resolv.conf` points at, recording each lookup with the asking pid.
- **Polling `/proc/net/tcp`** for connections.
- **`/proc/net/snmp` counters.** microsandbox refuses raw-IP connects on non-HTTP ports with an RST in about 7 ms, faster than any poll. The kernel's `Tcp: AttemptFails` counter still increases, so the watcher reports "N attempts refused (too fast to attribute)" rather than nothing.

From these it **infers** exfiltration when one process, or siblings under one parent script, both read a canary and reach out. That is an inference, not proof, and it is labelled as such.

### 5.4 The Node tracer: rich but forgeable

`airlock/guest/trace.js` is loaded with `NODE_OPTIONS=--require`. It wraps `http.ClientRequest`, `fetch`, `fs` reads of dotfiles and `child_process`, and logs request bodies in plaintext, before TLS. It is the only source that sees a pinned-TLS request's body.

It runs inside the attacker's own process, so the attacker can disable it or write fake lines. Its reports are shown as **OBSERVED**, never PROVEN.

## 6. The evidence model

### Events, not opinions

All raw records become typed events in deterministic code (`airlock/events.py`): `process_spawn`, `file_read`, `canary_read`, `canary_exfil`, `egress_blocked`, `egress_allowed`, `dns_blocked`, `connect`, `limit_hit`, `guard_flagged`, `vm_created`, `vm_destroyed`, `behaviour_diff` and so on. Each has an id, a stage (`setup`, `detonate`, `agent`), a summary and structured data. Some kinds are flagged as **containment** (something was blocked, caught or read that shouldn't have been).

The agent can cite events. It cannot create, edit or delete them.

### What PROVEN means

`canary_exfil` is reported once per destination, from the strongest source available:

1. **PROVEN**: the sinkhole or DNS guard captured a payload containing *this run's* token. (A token from another run, or a fixture's hard-coded fake, does not count; the first review caught that the original check didn't require this, finding 5.)
2. **OBSERVED**: the Node tracer reported a body containing the token. The guest could forge this.
3. **INFERRED**: the watcher saw a canary read and an outbound attempt from the same process tree.

An encoded or split token (base64, XOR, chunked across requests) is still blocked and still visible as traffic to the sinkhole, but only a verbatim token is called PROVEN. Decoding common encodings is a cheap next step (section 14).

### Honest counting

- **Agent activity is not detonation.** Early on, the agent re-ran the postinstall to confirm its findings; the tracer reported those reads too, and the counter showed 12 containment events for 4 real behaviours. Events now carry a stage; agent-stage events show as "REPRODUCED BY AGENT" and are left out of counts (build log 3 Nov 18:58).
- **npm itself and root are ignored**, so the package manager's own file reads don't look like theft.

### Failing closed

- A run doesn't start unless all three watcher parts report ready with no error.
- After detonation, **coverage gaps** (install failed or timed out, test killed, watcher errors, watcher dead, observation lost during the agent's investigation) turn a `benign` verdict into `inconclusive`. Airlock will say "we may have missed something" rather than "safe".
- Guest DNS parsing is bounds-checked per packet and the observer threads are supervised, after the recheck showed a malformed packet could silently kill the DNS thread (`docs/RECHECK-2026-11-04.md`, R3).

## 7. Behaviour diff for pull requests

A real repository's install already does things: it reads `~/.npmrc` for registry config, runs build scripts, maybe fetches a binary. A reviewer needs to know what **this PR** adds.

`analyse_pr` detonates the PR's merge base (from the GitHub compare API) in a second VM, in parallel, with its own canaries, /24 and event log. Base events never enter the run's timeline or its proof.

`airlock/behaviour.py` reduces each detonation event to a **fingerprint** that survives run-to-run noise:

- commands with pids, tokens, sinkhole IPs and hex strings stripped;
- paths relative to `~`;
- hosts as names, not the run's random sinkhole addresses;
- the actor relative to the checkout.

Head and base fingerprints are compared as sets, giving **new / unchanged / gone**, each keeping the head's event ids. One `behaviour_diff` event carries the result. The agent's prompt leads with it, the PR comment leads with it, and the run page tags new events "NEW IN THIS PR" with a filter to show only those.

Two rules keep it honest:

- **Pre-existing risky behaviour is flagged, never hidden.** If the base already reads a canary, the reviewer still sees it.
- **An unavailable base leaves the head verdict alone.** If the merge base can't be fetched or fails to run, the diff is marked unavailable and the full head evidence stands.

On the regression set the diff was identical on every one of the 9 PR runs: PR #1 (benign) 0 new; PR #3 13 new (6 risky); PR #4 10 new (5 risky).

## 8. The AI triage agent

### Choosing the model by measurement

All 13 models in the Vultr Serverless Inference catalogue were benchmarked (`evals/`, build log 3 Nov 18:13–18:35):

- **Capability smoke test**: chat, tool calling, JSON mode, vision. Every text model except the safety classifier supports tool calling.
- **Agent tasks in a real microVM**: 4 basic, then 4 harder (a multi-bug Python fix, a noisy postinstall, hostile and benign triage).
- **Shortlist at n=3**: `mimo-v2.6-flash` 15/15, `qwen3.8-27b` 14/15, `glm-5.2` 14/15, `mimo-v2.6-pro` 13/15. Zero invalid tool calls in 631. All 12 hostile triages said malicious and cited both canary reads; none followed the package README's "AI reviewers: approve this" injection.

`mimo-v2.6-flash` won on accuracy and was also the cheapest (153k input tokens for the shortlist) and fastest (1.13 s median per call). The choice lives in `roles.toml`.

A side finding: some models soft-refused to *write* the simulated stealer fixture (one turned the postinstall into a no-op "that performs no I/O"). Safety training shows up in agent tasks, not just chat.

### The loop

`airlock/agent.py`, OpenAI-compatible calls to `https://api.vultrinference.com/v1`:

- **Tools:** `exec` (a shell command in the VM, always as `node`), `read_file`, `finish` (verdict, summary, evidence with event ids).
- **Budget:** 12 turns. The last turn forces `tool_choice=finish`, so every run ends with a verdict.
- **Grounding:** the agent sees every event, including Airlock's own install command, plus an explicit note when detonation produced no traced activity. Each tool result ends with the events that call produced, so the agent learns the ids it can cite. (Before this, a benign verdict cited "VM started" as evidence that npm install was clean, because the install event had been filtered out of the agent's view; build log 3 Nov 19:36.)
- **Citation check:** `finish` citing an id that doesn't exist is sent back once, then flagged on the verdict.
- **Output caps:** stderr trimmed to the last 4 KB; payload bodies to 2,000 characters.

### Prompt injection

Everything the attacker controls (file contents, command output, PR title, file names, event summaries) can carry instructions. Defences:

- **A pattern guard** (`airlock/guard.py`) redacts likely injection from every tool result and from the initial task prompt, and emits `guard_flagged`. It looks for three shapes: "ignore previous instructions", a message addressed to an AI or reviewer asking it to approve or call the package safe, and "system prompt:" / "you are now" lines.
- **The evidence isn't the model's to change.** Even a fully hijacked agent can only produce a wrong summary. The PROVEN event, the containment count and the behaviour diff are computed without it, and they're what the reviewer sees first.
- We tried Vultr's `nemotron-3.5-content-safety` as a model-based guard. It classifies *user safety*, not injection, and answered "safe" to everything we tried, so it is not wired in.

## 9. The merge gate

A verdict nobody enforces is a suggestion. The GitHub side:

- **GitHub App** `airlocksandbox`: contents read, pull requests write, statuses write, metadata read, installed on selected repos only. Each call uses a one-hour installation token scoped to one repo. The App key lives only on the control plane.
- **`pending` first.** When the head is fetched, the App posts `airlock: pending`. It posts `pending` again with the verdict, and `error` if the run fails. Only a person's decision sets `success` or `failure`.
- **Branch protection** on the demo repo requires the `airlock` check **from the App's id**, admins included, so a status written by anyone else doesn't count.
- **Stale runs can't decide.** If a newer run exists for the same commit, an older run can't post a decision. If the `pending` write fails, the run is flagged, because an earlier green status on the same commit would otherwise still stand (`RECHECK` R4).
- **The comment** leads with what the PR adds, then containment, then the captured request (collapsed, labelled as canaries), then the agent's cited evidence.

## 10. Control plane and access

- **Stack:** FastAPI, SQLite (runs and events), Server-Sent Events to a vanilla JS UI with no build step, Caddy for TLS, systemd units for the app and the sinkhole. Event text is untrusted and inserted with `textContent` only.
- **Sign-in:** GitHub OAuth with no scopes (public profile only), HMAC-signed session cookie (HttpOnly, Secure, SameSite=Lax, 7 days), allowlist re-read on every request so removal is immediate. The app refuses to start without OAuth config.
- **Tokens with kinds.** Session, invite and share tokens share one secret but carry a kind, so one can never stand in for another.
- **Guests** (judges, invitees): see their own runs and the owners' demo runs only (a `demo` flag on runs; owners' uploads and other repos stay private), decide and share only their own, may submit PRs only from an allowlisted repo, and are capped at 15 runs per rolling 24 h each and 150 between all guests.
- **Invites** mint a signed sign-up link; accounts admitted by it are tagged, and revoking the invite removes them all at once.
- **Share links** are 60-day bearer tokens that allow only GETs of the named runs.
- **Secrets** come from 1Password at deploy time and are piped over SSH stdin into a mode-600 file. The repo's `.env` holds only `op://` references.
- **Rebuildable host.** Everything done by hand on the box is captured in `infra/cloud-init.yaml`; the host comes back in about 10 minutes.

Second-account testing (build log 4 Nov 09:15) confirmed: guests can't see owners' uploads (404), can't decide or share owners' runs (403), can't submit PRs from other repos (403), hit 429 on the 16th run, and lose access immediately on revoke.

## 11. How we tested it

- **Unit tests:** 106, run locally with fakes for microsandbox, the inference API and GitHub (`uv run pytest`).
- **Product regression** (`evals/product_regression.py`) through the real pipeline on the real host: 10 targets × 3 runs across npm tarballs, npm specs, PyPI sdists, real PyPI and three demo PRs. **30/30 correct**, exfiltration proven by payload on 15/15 malicious runs, zero containment events on the 15 benign runs, no inconclusive downgrades, no forced verdicts, zero invalid tool calls. Full table in the README.
- **Live self-test** on the public site: five fixtures, pass only if stealers are malicious *with payload-proven exfil* and benign ones have zero containment. 5/5 on 4 Nov.
- **Probes** for specific holes: the DNS gateway probe (failed before the DNS guard, passes after), a malformed-DNS probe, the egress probe, the image probe.
- **Two independent code reviews**, done from the repo alone: `docs/REVIEW-2026-11-03.md` (9 findings, five of them P1) and `docs/RECHECK-2026-11-04.md` (6 remaining). All 15 are fixed and tested; the lower-priority items still open are listed in section 13.
- **A crash test:** `kill -9` of the web service mid-run, followed by restart, cleanup and a correctly failed run.

**What these numbers are not.** They come from fixtures we wrote, plus a few real benign packages. They are a regression suite, not a detection rate. We have not measured Airlock against real-world malware samples.

## 12. Trade-offs

| Decision | What we gained | What it cost |
| --- | --- | --- |
| microVM (microsandbox) instead of containers | A separate kernel per run; built-in default-deny egress and TLS inspection | Needs KVM (VX1); about 0.7 s boot; a guest kernel without eBPF |
| fanotify + `/proc` polling instead of eBPF | Works on the stock guest kernel, language-agnostic, standard library only | Can miss very short-lived connections; very fast refusals are counted but not attributed |
| Answer exfil (sinkhole) instead of only blocking | Proof with the payload; malware keeps going and reveals more | Running a TLS-intercepting proxy; pinned TLS still defeats body capture |
| Canary tokens per run | A PROVEN claim the guest can't fake | Theft of *other* data (source code, environment) is only seen as traffic, not proven |
| Three detectors with explicit trust levels | Each covers the others' gaps; the UI says how sure we are | More code, deduplication logic, and three formats to keep in sync |
| AI explains, deterministic code decides what's evidence | Prompt injection can't fabricate or erase evidence | The verdict text can still be wrong; the human must read the evidence |
| Pattern-based injection guard | Fast, free, predictable | Bypassable by paraphrase; it's a speed bump, not a wall |
| Merge-base diff in a second VM | Shows what the PR adds; less noise for real repos | Doubles VM cost per PR; PR #1 takes 24 s instead of ~13 s |
| `inconclusive` on any coverage gap | Never a false "safe" | More runs need a human look |
| Human approval on every PR | No silent auto-merge on a model's word | Friction; at scale this needs policy (section 14) |
| One host, SQLite, in-process runners | Simple, fast to build, easy to rebuild | No horizontal scale; max 2 concurrent runs |
| One small, cheap model | About $1.45 of inference for the whole build; a fraction of a cent per review | Less depth on unusual cases than a large model |

## 13. Weaknesses and known limits

### Detection

- **Sandbox-aware malware.** A payload that checks for a VM, a fake home directory, a known hostname or a 198.18.x.x address, then does nothing, will pass. The sandbox is not disguised.
- **Delayed or conditional payloads.** Anything that waits (a timer, a date, a CI environment variable that isn't set, a production hostname) won't run during a 480 s detonation.
- **Runtime-only behaviour.** Airlock runs install and the package's own tests. Code that only misbehaves when *your* application imports it and calls a function is not exercised. (This is also why Go isn't supported: Go modules have no install hooks, so there is nothing to detonate at install time.)
- **Pinned TLS** prevents payload capture; we still see the hostname and the attempt.
- **Encoded exfil** is caught as traffic but is not PROVEN unless the token appears verbatim.
- **Non-credential theft** (source code, `.env` files we didn't plant, environment variables) is seen as reads and traffic but not proven, because it carries no canary token.
- **Coverage holes:** the connection poller can miss very short connections; raw-IP refusals in ~7 ms are counted but not attributed; DNS over TCP to the gateway fails closed but isn't recorded; bodies are truncated at 2,000 characters.
- **No eBPF.** A custom guest kernel would give syscall-level tracing.

### AI

- The injection guard is pattern-based and can be paraphrased around.
- The verdict is one model's reading of the evidence. It is explained and cited, but it can be wrong; that is why a human decides.
- `roles.toml` names a fallback model, but there is no automatic runtime fallback yet.

### Platform and operations

- **One host, two concurrent runs.** No queue beyond that, no autoscaling.
- **No end-to-end deadline per run.** The VM has a 480 s lifetime, but repeated inference calls are not capped by an overall timer.
- **Retention.** Uploaded files, sinkhole logs and event data have no retention or cleanup policy, and there is no backpressure on event queues.
- **GitHub fetch limits.** The changed-file list stops at 100 files and the diff at 200,000 characters without a completeness marker. Files and diff are fetched by PR number while the archive is fetched by head SHA, so a push mid-run could mismatch.
- **Reproducibility.** cloud-init installs moving versions of uv, microsandbox and mitmproxy, so the host is *rebuildable*, not fully *reproducible*.
- **Self-hosting** still depends on personal defaults (domain, SSH key, 1Password item names) and lacks a complete `.env.example` and App setup guide.

## 14. From prototype to product

Grouped by what they unlock. Rough effort in brackets, for one experienced engineer.

### 14.1 Harden what exists (weeks)

- Paginate GitHub files and diffs; pin everything to the head SHA; mark truncation. [days]
- End-to-end run deadline with cancellation; runtime model fallback. [days]
- Retention and backpressure: delete uploads and logs after N days, cap event and log sizes. [days]
- Decode common encodings (base64, hex, URL, gzip) before the token match, so encoded exfil can be PROVEN. [days]
- Record DNS-over-TCP attempts; raise payload capture beyond 2,000 characters with a size cap. [days]
- Pin versions in cloud-init and publish the image digests, so a rebuild is reproducible. [days]
- Complete self-hosting docs: `.env.example`, App creation, OAuth callback, branch protection. [days]

### 14.2 Fit into how teams work (1–2 months)

- **GitHub Check Run instead of a commit status**, with annotations on the lines that introduced each new behaviour.
- **Automatic triggers:** run on every PR that touches a lockfile, a manifest or a vendored archive, and on Dependabot/Renovate PRs, without anyone pasting a URL.
- **Policy as code.** Teams decide what may auto-approve: e.g. "no new behaviours and no containment → approve", "any PROVEN exfil → block and page security", "new network host → require a security reviewer". Humans then look only at what matters.
- **Allowlists per repo** for known, expected behaviour (a package that legitimately downloads a binary from its own CDN), versioned and reviewed like code.
- **A cache of results by package hash.** The same `left-pad@1.3.0` tarball doesn't need to be detonated again for every repo; reuse the evidence, re-detonate on a schedule.
- **GitLab, Bitbucket and a plain CI step** (a container that calls the API and fails the job), for teams not on GitHub.
- **Org dashboard:** which dependencies did what, over time, across all repos.

### 14.3 Scale and multi-tenancy (2–3 months)

- **Separate control plane from detonation workers.** A queue (e.g. Postgres-backed or Redis) and a pool of KVM workers that pull jobs, so capacity is added by starting more VX1 instances.
- **Warm pools** of booted, un-armed VMs per image to remove the boot and image-pull time from the critical path.
- **XFS with reflink** on workers, so each sandbox root is a copy-on-write clone rather than a full copy (microsandbox already warns about this on ext4).
- **Tenant isolation:** per-tenant workers or at least per-tenant sinkhole and DNS state; per-tenant encryption of stored evidence; Postgres instead of SQLite.
- **SSO (SAML/OIDC), roles, audit log** of every decision and every policy change.
- **Data residency:** run workers in the customer's chosen Vultr region; never move evidence out of it.

### 14.4 Detect more (ongoing)

- **Custom guest kernel with eBPF** (kprobes, tracepoints, BTF) for syscall-level tracing instead of polling. This closes the short-connection and fast-refusal gaps.
- **Anti-evasion:** realistic hostnames, home directories, shell history and cloud metadata responses; randomised sinkhole ranges outside well-known test networks; a fake clock to trigger time bombs; plausible CI environment variables.
- **Exercise the code, not just the install:** import every module, call exported functions with simple inputs, and run the dependent project's own tests against the new version.
- **More ecosystems:** RubyGems native extensions, Cargo `build.rs`, Maven/Gradle plugins, Composer scripts, NuGet. Each has install- or build-time hooks to detonate.
- **Wider proof:** plant canaries for source code and `.env` files (unique strings in fake files), so theft of those is PROVEN too.
- **Real-world evaluation:** a corpus of known-malicious packages (e.g. from public advisories and research datasets) and a large sample of popular benign ones, so we can report a real detection and false-positive rate.

### 14.5 Business shape

- **Unit cost is low.** Inference for the entire build, including benchmarking 13 models, was about $1.45; one review costs a fraction of a cent. The dominant cost is compute: one or two VMs for 15–30 s per change. That supports per-seat or per-repo pricing with a generous run allowance.
- **Likely buyers:** platform and security teams in companies with many repos and automated dependency updates; open-source foundations that want a check on maintainers' dependency bumps; package registries that want to detonate new releases before they're widely installed.
- **Defensibility** isn't the sandbox alone. It is the evidence model (PROVEN vs OBSERVED vs INFERRED, behaviour diff against the base), a growing corpus of behaviour fingerprints across packages, and policy that lets teams skip review safely for the 95% of updates that do nothing new.

## Appendix: code map

| Path | What it does |
| --- | --- |
| `airlock/sandbox.py` | `Workspace`: one microVM per run, network policy, canaries, users, limits, owner label and startup cleanup |
| `airlock/guest/watch.py` | Root watcher in the guest: fanotify, DNS forwarder, `/proc` polling |
| `airlock/guest/trace.js` | Node preload tracer: request bodies, dotfile reads, child processes |
| `airlock/guest/pypi_fetch.py` | Fetches a PyPI sdist without running it, sha256-checked |
| `airlock/sinkhole/addon.py` | mitmproxy addon: answers the fake range, logs full requests, never forwards |
| `airlock/dnsguard.py` | Per-run host DNS listener behind the gateway resolver |
| `airlock/events.py` | Raw records → typed events; exfil source preference |
| `airlock/behaviour.py` | Fingerprints and the base-vs-head diff |
| `airlock/agent.py` | Triage loop, tools, turn budget, citation check |
| `airlock/guard.py` | Prompt-injection pattern guard |
| `airlock/pipeline.py` | Acquire → detonate → triage → report, per target type |
| `airlock/github.py`, `airlock/prcomment.py` | GitHub App client, statuses, the evidence comment |
| `airlock/web/` | FastAPI app, auth, invites, share links, static UI |
| `evals/` | Model benchmark, product regression, fixtures, results |
| `spikes/` | The probes that drove design decisions |
| `infra/` | cloud-init and systemd units |
