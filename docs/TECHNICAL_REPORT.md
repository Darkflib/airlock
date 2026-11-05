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
9. [The merge gate and the GitHub App](#9-the-merge-gate-and-the-github-app)
10. [Control plane, sign-in and access](#10-control-plane-sign-in-and-access)
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
- For a GitHub PR, a GitHub App holds the PR at a `pending` status that branch protection requires. Proven theft is rejected automatically; otherwise only a person's Approve or Reject sets the final status, and nothing is ever approved automatically.

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
11. **Gate.** If exfiltration was proven by a captured payload, the App rejects at once: `failure` and the evidence comment. Otherwise the status stays `pending`, now with the verdict in its description, until a person decides on the run page; the App then posts `success` or `failure` and the comment.

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

## 9. The merge gate and the GitHub App

A verdict nobody enforces is a suggestion. Airlock enforces it through GitHub's own branch protection, using a GitHub App (`airlock/github.py`, `gate_pr` and `decide` in `airlock/web/app.py`).

### Why a GitHub App

We considered three ways to act on a repository:

| Option | Problem |
| --- | --- |
| A personal access token | Acts as a person, across every repo that person can reach. A leak is a leak of that person. Statuses look like they came from a human. |
| The signed-in user's OAuth token | Same breadth, plus Airlock would need write scopes at sign-in, and would act as whoever happened to click. |
| **A GitHub App** (chosen) | Installed per repo by the repo's owner, with only the permissions it declares. Acts as its own identity, `airlocksandbox[bot]`. Tokens are short-lived and can be narrowed to one repo. Branch protection can name the App as the only accepted source of a check. |

The last point decides it: with a PAT, anyone who can write a commit status could also write a green `airlock` status. With an App, branch protection can require `airlock` **from that App's id**, so nobody else's status counts.

### Permissions

Installed on selected repositories only, with:

| Permission | Level | Used for |
| --- | --- | --- |
| Metadata | read | Required by GitHub for every App; also lets Airlock look up a person's access to the repo (section "Who may decide") |
| Contents | read | Downloading the head and merge-base archives; computing the merge base |
| Pull requests | write | Reading the PR, its files and diff; posting the evidence comment |
| Commit statuses | write | Posting the `airlock` status that branch protection requires |

It cannot push code, merge, change settings or read secrets.

### Automatic runs (webhook)

The App subscribes to **Pull request** events and delivers them to `/api/github/webhook`. A run starts by itself when a PR is `opened`, `reopened` or pushed to (`synchronize`); every other action is ignored. The push case matters most: a new head commit has no `airlock` status, so branch protection blocks it, and without the webhook every push would need someone to start a run by hand.

- **Authenticated by signature, not by login.** GitHub can't sign in, so this one path skips the login check. Instead every delivery must carry `X-Hub-Signature-256`, an HMAC-SHA256 of the raw body made with the App's webhook secret, compared in constant time. A bad or missing signature gets 401 and starts nothing. With no secret configured, the endpoint answers 404: it is off, not open.
- **Only enabled repos.** Deliveries from other repos the App might be installed on are acknowledged and ignored, so a stranger's install can't spend VM time or inference. Today that is the demo repo (`AIRLOCK_GUEST_REPOS`).
- **One run per commit.** GitHub redelivers when it times out, so each delivery id is used once (recorded in SQLite for 7 days, so this holds across restarts), and a head commit that already has a run that didn't fail isn't analysed again.
- **Its own cap:** 50 automatic runs per rolling 24 hours (`AIRLOCK_WEBHOOK_DAILY_RUNS`), so a burst of pushes can't run up the bill.
- **Answers at once.** The handler replies 202 with the run's URL and the analysis runs afterwards; GitHub stops waiting after 10 seconds and a run takes 12–31 s.
- **Same run, same gate.** It starts exactly the run the UI would, attributed to the GitHub user who caused the event and marked `(webhook)`. The App posts `pending`, and the decision is still a person's, with the write-access check below.

### How a token is minted

1. The control plane signs a JWT with the App's private key (RS256). It is valid for nine minutes, back-dated by 60 seconds to tolerate clock skew.
2. With that JWT it looks up the App's installation on the target repo. A 404 becomes a plain error: "the Airlock GitHub App is not installed on owner/repo".
3. It asks for an installation token **restricted to that one repository**, even if the installation covers more. GitHub issues it for one hour.
4. The token is cached per repo and replaced five minutes before it expires.

The private key comes from 1Password at deploy time and exists only in the web service's mode-600 env file on the host. The VM never sees it, or any GitHub token: the control plane downloads the PR's archive and copies it into the VM, which has no route to GitHub.

### The gate, step by step

1. **Head fetched:** the App posts `airlock: pending` ("Detonating in a microVM; merge waits for a human decision") on the head commit. From this moment, branch protection blocks the merge. It also posts a short PR comment, "Airlock: testing this PR…", with a link to the live run. That comment is the run's **one comment on the PR**: every later step rewrites it in place rather than adding another, so the PR conversation shows where the run is without stacking bot messages.
2. **Verdict ready, theft proven:** if the run has exfiltration proven by a payload the host captured with this run's token, the run is rejected automatically: `failure` ("rejected automatically: exfiltration proven by a captured payload") and the evidence comment, with no click.
3. **Verdict ready, anything else:** `pending` again, now carrying the verdict ("Verdict: malicious; comment /airlock approve or /airlock reject to decide"), and the comment becomes the full evidence report headed "waiting for a decision", with how to decide. The AI's verdict never turns the check green or red.
4. **Run failed:** `error`, and the comment says the run failed and why. Still not mergeable.
5. **Person decides**, on the run page or by commenting `/airlock approve [note]` or `/airlock reject [note]` on the PR: `success` (approved) or `failure` (rejected), with "approved by @login" in the description, plus the evidence comment. This is the only path to green. The pending status itself says how: "comment /airlock approve or /airlock reject to decide".

Details that matter:

- **Branch protection** on `Darkflib/airlock-demo` `main` requires `airlock` from the App's id, and applies to admins too.
- **Stale runs can't decide.** If a newer run exists for the same commit, the older one neither updates the status nor accepts a decision (HTTP 409, "decide that one instead"). Otherwise an old approval could overwrite a newer, more worrying result.
- **Decisions are claimed atomically, and writes per commit are serialized.** Checking "undecided and still the latest run" before asking GitHub about permissions isn't enough: another decision or a new run can land during that await. So the decision is recorded by one conditional SQL update that re-checks both, and loses with a 409 if either changed (first decision stands). Every status and comment write for a commit runs under that commit's lock and re-checks that its run is still the latest inside the lock, so an older run's write can't land after a newer run's. The lock is in-process, so the service runs as a single uvicorn worker (stated in `airlock-web.service`); several workers would need a database-backed lock. (Found by the 4 Nov authority review, A1.)
- **A failed `pending` write is loud.** If it fails, the run records "the PR is NOT held" in its timeline and marks its gate as unsynced, because an earlier green status on the same commit would otherwise still stand (`RECHECK` R4).
- **GitHub writes are retried.** Status and comment posts back off and try again (four attempts, about 7 s, via `tenacity`) on network errors, 5xx and rate limits, never on a 4xx Airlock caused. A status is idempotent, so any failure is retried; a comment is not retried once the request may have reached GitHub (a read timeout), so a blip can't post the evidence twice.
- **A failed decision post doesn't undo the decision.** The decision is stored first; if GitHub is still failing after the retries, the error is logged on the run and the PR stays at `pending`, so it fails safe. The run page then offers **Post again**, which re-checks the same rules as a decision (write access, no newer run of the commit) and posts once.
- **The comment** leads with what the PR adds, then containment, then the captured request (collapsed, labelled as canaries), then the agent's cited evidence.

### Why reject automatically, but never approve

A person reviewing proven theft has nothing to weigh: the host captured a request carrying this run's canary token, which the guest can't forge (section 6). Waiting for a click only leaves the PR sitting at `pending` with a known stealer in it. So that one case is decided by code, at once.

The rule reads the evidence, not the AI. It fires only when `proven_exfil` is true for the package's own activity, the same test the self-test uses; the model's verdict plays no part, so prompt injection can't trigger or prevent it. An automatic rejection appears on the run page and on GitHub as "rejected automatically", never under a person's name. It is final for that commit; a new push starts a new run.

Approval stays human on purpose. "No new behaviour and nothing blocked" is strong evidence, but not proof: sandbox-aware or delayed malware looks exactly like that (section 13). Automatic approval is a policy choice for each team to make (section 14.2), not a default. `AIRLOCK_AUTO_REJECT=0` turns automatic rejection off.

### Who may decide

Apart from the automatic rejection above, two checks, both required on the run page. First, Airlock's own rule: an owner, or the person who submitted the run. Second, for a PR run, **GitHub's rule**: at decision time, Airlock asks GitHub (with the App's installation token) what access the signed-in login has to the repository, and accepts the decision only for `admin` or `write` (GitHub reports `maintain` as `write`). Anyone else gets HTTP 403 with the reason, and the PR stays at `pending`. If GitHub can't answer, the decision is refused with 503: it fails closed.

The reasoning: the decision sets the check that branch protection requires, so it is effectively a merge approval. The people who may give it should be the people GitHub already trusts to change that repo, not whoever has an Airlock account. The login being checked is the one GitHub itself confirmed at sign-in, so it can't be typed in. A side effect for the hackathon: judges can run the demo PRs and see the verdict, but only the repo's owner can approve or reject them on GitHub. Their own npm and PyPI runs they can still decide.

**Deciding from GitHub.** Developers live in the PR, so they can decide there: a comment with `/airlock approve [note]` or `/airlock reject [note]` on its own line. The App receives `issue_comment` webhooks (signed like the PR events; GitHub offers this event only to Apps with the Issues permission, read is enough, so that is the one permission this adds), and the same command in the body of a submitted PR review (`pull_request_review`) works too, and applies **the same rules as the run page**: the latest run of *this PR's* current head commit (fetched from GitHub when the comment arrives; a run of another PR that shares the commit doesn't count), bound to what the commenter saw (a review must be of that head commit, and any command must be written after that run's result was published, so a delayed delivery after a new push can't approve a commit nobody looked at), never after a decision (an automatic rejection stands), and GitHub write access for the commenter. The Airlock allowlist plays no part here: GitHub has already authenticated the commenter, and its write access is the authority. Refusals get a short reply on the PR saying why ("@reader not recorded: … needs write access"); a successful decision is announced by the usual evidence comment, "approved by @login", with the note. Comments from bots, edits and redeliveries are ignored.

**Self-approval.** By default the PR's author may approve their own PR (the demo has one maintainer). `AIRLOCK_SELF_APPROVAL=0` bars it on both paths, so a compromised contributor account can't wave its own dependency through; rejecting is always allowed.

Buttons on a Check Run (section 14.2) are the more native form of the same thing; the comment command needs no new App permission and leaves the status that branch protection relies on unchanged, so it shipped first.

## 10. Control plane, sign-in and access

- **Stack:** FastAPI, SQLite (runs and events), Server-Sent Events to a vanilla JS UI with no build step, Caddy for TLS, systemd units for the app and the sinkhole. Event text is untrusted and inserted with `textContent` only.
- **Secrets** come from 1Password at deploy time and are piped over SSH stdin into a mode-600 file. The repo's `.env` holds only `op://` references.
- **Rebuildable host.** Everything done by hand on the box is captured in `infra/cloud-init.yaml`; the host comes back in about 10 minutes.

### Sign-in

The site is private: every page and API call needs a signed-in, allowlisted user, a valid share link, or is one of a few public paths (login, static files, health check). Sign-in is "Log in with GitHub" (`airlock/web/auth.py`).

**Two GitHub identities, on purpose.** Sign-in uses a GitHub **OAuth App**; repo actions use the **GitHub App** from section 9. They have different jobs and different secrets. The OAuth App only proves who you are. It requests **no scopes**, so it can read your public profile and nothing else, and the access token it returns is used once, to read your login, then thrown away. Nothing Airlock does to a repository is done with your token. A GitHub App can also sign users in, and merging the two is on the list (section 14.2); keeping them apart was simpler to reason about for the hackathon.

**The flow:**

1. `/auth/login` creates a random `state`, stores it with the page you were going to in a signed cookie that lasts 10 minutes, and redirects to GitHub (`allow_signup=false`).
2. GitHub sends you back to `/auth/callback` with a code. The `state` must match the cookie (constant-time compare), or sign-in fails. This stops login CSRF.
3. The code is exchanged for a token, the token reads `/user`, and Airlock gets your login.
4. If the login is on the allowlist, or you arrived through a valid invite, you get a session cookie and are sent back to where you were going. The "next" path must be a local path, so the login flow can't be used as an open redirect.

**Sessions are signed cookies with an id.** The session is a cookie holding your login, a random session id, the issue time and an expiry, signed with HMAC-SHA256 (HttpOnly, Secure, SameSite=Lax, 7 days). There is no session table, only a small revocation file: **Sign out** records that session's id, so a copied cookie stops working too, and **Sign out everywhere** records a cut-off time for the login, ending every session issued before it on every device. Entries are pruned once no live session could match them. On top of that, the allowlist is **re-read on every request**, so removing a login (`scripts/allow.sh rm`) locks that person out on their next click, whatever cookie they hold. Cookies from before session ids existed are refused, so everyone signs in once more. The app refuses to start without OAuth configuration, so a missing secret can't silently open the site.

**One secret, four kinds of token.** Session, OAuth-state, invite and share tokens are all signed with the same secret, but each carries a kind (`k`), and every check asks for a specific kind. A share link can't be presented as a session, and an invite can't be presented as either. Rotating the secret logs everyone out and kills every share link and invite at once: a blunt but useful emergency switch.

### Owners and guests

- **Owners** are listed in the service's environment (`AIRLOCK_ALLOWED_USERS`). They see everything and aren't rate-limited.
- **Guests** are everyone else on the allowlist file: judges and invitees. Guests see their own runs plus the owners' **demo** runs (self-tests, public npm and PyPI packages, PRs from the demo repo); owners' uploads and other repos stay private. Guests decide and share only their own runs, may submit PRs only from `AIRLOCK_GUEST_REPOS`, and are capped at 15 runs per rolling 24 h each and 150 between all guests (HTTP 429 after that). The caps exist because every run boots real VMs and calls a paid model.

### Invites and share links

**Invites** solve "we don't know the judges' GitHub logins in advance". `scripts/invite.sh new` mints a signed link with an expiry (default 30 days) and a maximum number of accounts (default 50). Whoever signs in through it is appended to the allowlist file, tagged `# invite <id>`. Revoking the invite does two things: it adds the id to a revocation file, so the link stops admitting people, and it removes every account it admitted, at once. Invited accounts are still ordinary allowlist lines, so `scripts/allow.sh` lists and removes them like any other.

**Share links** (`/s/<token>`) let someone without an account read specific runs or a self-test. The token names the runs, lasts 60 days, and allows only `GET` and `HEAD` of those exact pages and their event streams: no decisions, no new runs, nothing else. It is a bearer token, so anyone holding the link can read those runs. Each link has an id and is recorded in a ledger on the host (who made it, for which runs, when it expires; never the token itself). The run or self-test page lists its live links, and the person who made one, or an owner, can **Revoke** it: the link and any cookie it already set stop working on the next request, while other links to the same run keep working. Links minted before ids existed can only be ended by rotating the secret. Links still live in 1Password and never in the repo, slides or video.

Second-account testing (build log 4 Nov 09:15) confirmed: guests can't see owners' uploads (404), can't decide or share owners' runs (403), can't submit PRs from other repos (403), hit 429 on the 16th run, and lose access immediately on revoke.

## 11. How we tested it

- **Unit tests:** 148, run locally with fakes for microsandbox, the inference API and GitHub (`uv run pytest`).
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
| Automatic rejection on proof only; approval always human | Proven theft is blocked with no wait, and no model's word ever merges code | Everything short of proof (suspicious but unproven, and every clean change) still needs a person; at scale this needs policy (section 14) |
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
- **Retention.** Uploaded files, sinkhole logs and event data have no retention or cleanup policy. Per run, sizes are bounded (5 November): a 600 s deadline, 5,000 events, 32 MB per guest log, 64 KB of each command's output, and a 1,000-event backlog per live viewer.
- **GitHub fetch limits.** The changed-file list stops at GitHub's 3,000 files and the agent's diff at 200,000 characters; either cut is disclosed to the agent, on the run page and in the PR comment (5 November). The diff and archive are pinned to the base and head SHAs, and the file list is read between two reads of the head.
- **Reproducibility.** cloud-init installs moving versions of uv, microsandbox and mitmproxy, so the host is *rebuildable*, not fully *reproducible*.
- **Automatic runs cover one repo.** The webhook acts only on repos in `AIRLOCK_GUEST_REPOS`; turning it on per installation needs the multi-tenant work in 14.3.
- **Self-hosting** still depends on personal defaults (domain, SSH key, 1Password item names) and lacks a complete `.env.example` and App setup guide.

## 14. From prototype to product

Grouped by what they unlock. Effort in brackets assumes one experienced engineer working with coding agents, which is how this prototype went from nothing to a gated, live service in under a week. The estimates are deliberately optimistic: about **ten weeks** from here to a multi-tenant beta that paying teams could use.

### 14.1 Harden what exists (about a week)

- Runtime model fallback. [half a day] (The end-to-end run deadline, event and log caps and viewer backpressure are done.)
- Retention: delete uploads and logs after N days. [half a day]
- Decode common encodings (base64, hex, URL, gzip) before the token match, so encoded exfil can be PROVEN. [a day]
- Record DNS-over-TCP attempts; raise payload capture beyond 2,000 characters with a size cap. [half a day]
- Pin versions in cloud-init and publish the image digests, so a rebuild is reproducible. [half a day]
- Complete self-hosting docs: `.env.example`, App creation, OAuth callback, branch protection. [half a day]

### 14.2 Fit into how teams work (2–4 weeks)

- **GitHub Check Run instead of a commit status**, with annotations on the lines that introduced each new behaviour, and **Approve / Reject buttons on the check itself** (Check Run requested actions), replacing today's `/airlock approve` comment command with the native control.
- **One GitHub App for everything:** sign users in through the GitHub App (user-to-server tokens) instead of a separate OAuth App, and let an org admin install it once and pick repos, with no allowlist file.
- **Smarter automatic triggers:** the webhook already runs every PR and push in an enabled repo. Next: enable it per installation, and skip PRs that touch no lockfile, manifest or vendored archive, so Dependabot/Renovate bumps are covered without detonating documentation changes.
- **Policy as code.** Today one rule is built in: proven theft is rejected automatically (`AIRLOCK_AUTO_REJECT`), and nothing is approved automatically. A product makes this configurable per repo. Teams decide what may auto-approve: e.g. "no new behaviours and no containment → approve", "any PROVEN exfil → block and page security", "new network host → require a security reviewer". Humans then look only at what matters.
- **Allowlists per repo** for known, expected behaviour (a package that legitimately downloads a binary from its own CDN), versioned and reviewed like code.
- **A cache of results by package hash.** The same `left-pad@1.3.0` tarball doesn't need to be detonated again for every repo; reuse the evidence, re-detonate on a schedule.
- **GitLab, Bitbucket and a plain CI step** (a container that calls the API and fails the job), for teams not on GitHub.
- **Org dashboard:** which dependencies did what, over time, across all repos.

### 14.3 Scale and multi-tenancy (4–6 weeks)

- **Separate control plane from detonation workers.** A queue (e.g. Postgres-backed or Redis) and a pool of KVM workers that pull jobs, so capacity is added by starting more VX1 instances.
- **Warm pools** of booted, un-armed VMs per image to remove the boot and image-pull time from the critical path.
- **XFS with reflink** on workers, so each sandbox root is a copy-on-write clone rather than a full copy (microsandbox already warns about this on ext4).
- **Tenant isolation:** per-tenant workers or at least per-tenant sinkhole and DNS state; per-tenant encryption of stored evidence; Postgres instead of SQLite.
- **SSO (SAML/OIDC), roles, audit log** of every decision and every policy change.
- **Data residency:** run workers in the customer's chosen Vultr region; never move evidence out of it.

### 14.4 Detect more (ongoing; first slices in 2–3 weeks)

Runs alongside the stages above. The first slices worth doing are the canaries for source code and `.env` files and the anti-evasion basics (a few days each); the eBPF guest kernel and the real-world evaluation are the larger pieces.

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
