# Airlock — Dependency Detonation Chamber (PRD)

Nov 3, 2026 · @Mike Preston, which is the source of truth

## Summary

Airlock runs an untrusted dependency change (a GitHub pull request, a new npm package, or an uploaded tarball) inside a disposable microVM with fake credentials and no real internet access. It reports what the change actually *did*: credentials read, programs run, hosts contacted, and the exact data it tried to send out. An AI reviewer gives a verdict, and nothing reaches GitHub until a human approves or rejects.

**Status (end of Tue 3 Nov):** every P0 requirement works end to end on the live site, two days ahead of the Thursday cut line.

- **Live site:** https://airlock.darkflib.dev, with GitHub sign-in and an allowlist.
- **Regression:** 18/18 correct on the real pipeline. Every malicious target had its exfil proven by payload, and every benign target had zero containment events.
- **Remaining work:** presentation (video, slides, PRD), plus optional depth: a harder obfuscated fixture, the Pattern B browser check, and a base-vs-head behaviour diff.

**Hackathon fit:** Vultr Agent Rush, Challenge 1 "Blast Radius Zero".

- **Pattern A** (sandboxed execution, errors fed back for retries) is the core of every run.
- **The human approval gate** is in place.
- **Pattern B** (Playwright screenshot verification) is optional and not built yet.
- **Containment is the product,** so the required "containment moment" happens on its own.

**Hard constraints, all met**

- **Deployed on Vultr Cloud Compute VX1**, which exposes `/dev/kvm`, so each run gets a real microVM with its own kernel. The box rebuilds from cloud-init plus one deploy script.
- **All runtime LLM calls go through Vultr Serverless Inference** (`mimo-v2.6-flash`, chosen by benchmarking all 13 catalogue models).
- **Submission still needs:** a public MIT repo (private until submission), a live URL (done), a video showing a containment moment, slides, and a README covering Vultr services, architecture and use case (done).

## Problem, users, goals

**Problem.** A dependency change is reviewed by reading a diff, but the risk is in what runs: `postinstall` scripts, build plugins, code paths that only trigger at test time. The usual check is "CI passed", and CI runs that code with real tokens and open egress. Lockfile bumps touching hundreds of transitive packages never get read.

**Users**

| User | Job to be done |
| --- | --- |
| Maintainer of an open-source repo | Triage a stranger's PR, or a Dependabot/Renovate bump, before running it anywhere that matters |
| Platform / security engineer | A gate in CI: untrusted changes run in Airlock first; a merge needs a clean verdict or a signed-off human override |
| Developer adding a new package | "What does `npm install foo` actually do?" answered in two minutes |

**Goals (hackathon)**

1. Analyse a GitHub PR URL or a `package@version` end to end in under 5 minutes, with no host exposure.
2. Show a behavioural verdict: benign / suspicious / malicious, with the evidence that drove it.
3. Make every containment event visible in a live timeline. At least two layers: network/VM and LLM context.
4. Require human approval before any outward action (posting a PR comment, approving a merge).

**Non-goals**

- Static CVE scanning (Snyk, OSV and Socket already do this; we may link OSV results, but we don't rebuild them).
- Ecosystems beyond npm and PyPI in the hackathon build.
- Defeating sandbox-aware malware that deliberately stays dormant. We note it as a limit and don't claim it.
- Multi-tenant SaaS, auth, or billing.

## User flow and requirements

One run per submitted change. The PR flow is the headline:

1. **Submit** a GitHub PR URL, an npm spec (`left-pad@1.3.0`) or a `.tgz`, in the web UI (GitHub sign-in, allowlist) or with `airlock analyse`.
2. **Setup** (Airlock code, no AI). A fresh microVM boots in about 0.7 s. Canary `~/.npmrc` and `~/.aws/credentials` carrying a per-run token are planted, and a root watcher starts.
3. **Acquire.** The control plane fetches the PR head and diff through the GitHub App (the VM has no GitHub access), or the npm package or tarball.
4. **Detonate.** `npm ci` and `npm test` run as the unprivileged `node` user, with all observation layers on and all traffic routed through the sinkhole.
5. **Investigate.** The triage agent (`mimo-v2.6-flash`) reads the code and re-runs what it needs within a 12-turn budget; the last turn forces `finish`. Every tool result passes the injection guard and ends with the Airlock events it produced, so citations are real.
6. **Decide.** A human approves or rejects. Only then does `airlocksandbox[bot]` set an `airlock` commit status and post the evidence as a PR comment. The VM is destroyed when the run ends.

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| F1 | Accept a PR URL, npm spec or `.tgz`; queue a run; return a run ID | P0 | Done |
| F2 | One microVM per run: CPU, memory and wall-clock limits; destroyed on completion or timeout | P0 | Done |
| F3 | Default-deny egress to real destinations; registries allowlisted; every attempt recorded | P0 | Done |
| F4 | Per-run canary credentials; detect reads and exfiltration attempts | P0 | Done |
| F5 | Tool-calling agent (`exec`, `read_file`, `finish`), errors fed back for retries, hard turn budget | P0 | Done |
| F6 | Injection guard on untrusted text before it reaches the model (pattern guard live; model-based guard not wired) | P0 | Partial |
| F7 | Live run page: staged timeline, verdict with linked evidence, containment stats | P0 | Done |
| F8 | Human approval gate before any outward action; commit status and PR comment via GitHub App | P0 | Done |
| F9 | Behaviour diff: base branch vs PR | P1 | Not started |
| F10 | Playwright screenshot verification (Pattern B) | P1 | Not started |
| F11 | Automatic trigger on PR open (App webhook) | P2 | Not started |
| F12 | PyPI support | P2 | Not started |
| F13 | Language-agnostic observation: in-guest watcher (fanotify, DNS, TCP), package runs unprivileged | Added | Done |
| F14 | Sinkhole: fake DNS into a per-run /24, mitmproxy answers and logs, exfil **proven** with the payload | Added | Done |
| F15 | GitHub OAuth sign-in with an allowlist; who submitted and who decided recorded per run | Added | Done |

## Architecture

Everything runs on one VX1 instance. Untrusted code only ever runs inside a per-run microVM with its own kernel. Every TCP connection it makes goes through the host-side sinkhole, and only the npm and PyPI registries are ever reached for real.

![Airlock architecture: one VX1 host, one microVM per run](docs/architecture.png)

The control plane holds every real secret: the GitHub App key, the inference key and the OAuth client. Nothing secret is ever copied into a VM.

**Three independent containment layers**

| Layer | What it does | Where it runs |
| --- | --- | --- |
| microsandbox default-deny | Real internet destinations are refused. The policy allows only the registries and this run's fake /24 (TLS inspection on, trusting the sinkhole's CA upstream) | Host, in the VMM network stack |
| Fake DNS + sinkhole | Non-allowlisted names resolve into the run's private /24. mitmproxy answers those requests itself, logs the full body and never connects upstream, so exfil is **proven** with the payload | Guest DNS (the watcher); mitmproxy on the host |
| Watchers | Root fanotify watcher: every program run and every dotfile opened, with pid; DNS lookups; TCP connections. Node tracer: plaintext bodies and hostnames. The package runs as `node` and can't reach either log | Inside the VM |

**Events, not opinions.** Deterministic code turns raw observations into typed events: `canary_read`, `canary_exfil` (proven or inferred), `egress_blocked`, `process_spawn`, `guard_flagged`, `limit_hit`. The agent explains and cites them but never creates them. Activity from the agent's own re-runs is tagged and not counted.

**Limits we don't claim to solve**

- **Sandbox-aware or delayed payloads.** Malware that notices it's being watched and stays quiet is a known limit.
- **No eBPF.** The guest kernel has no kprobes, tracefs or BTF, so the watcher polls `/proc` rather than hooking syscalls.
- **Very fast refusals.** A raw-IP connection refused in about 7 ms is counted but not attributed to a process.
- **Pinned TLS** prevents payload capture; we still see the hostname.

**Stack:** Python (FastAPI) control plane, SQLite, Server-Sent Events to a vanilla JS UI, Caddy for TLS, systemd units (`airlock-web`, `airlock-sinkhole`), microsandbox 0.7 (Python SDK), mitmproxy 12.

## Model routing and evals

The agent is **`mimo-v2.6-flash`** on Vultr Serverless Inference. It was chosen by measurement after benchmarking all 13 catalogue models, and the role assignment lives in `roles.toml`.

| Role | Model | Why |
| --- | --- | --- |
| Triage agent and verdict | `mimo-v2.6-flash` | 15/15 on the harder tasks at n=3, fewest tokens (153k in), 1.13 s median per call |
| Fallback agent | `qwen3.8-27b` | 14/15, fastest per call (0.97 s) |
| Injection guard | Pattern guard in `airlock/guard.py` | `nemotron-3.5-content-safety` classifies user safety, not injection: it answered "safe" to everything |
| Screenshot check (P1) | Any chat model except `muse-glimmer-30b` | Every other model named a solid red square correctly; muse answered "white" |

**What the evals showed** (`evals/RESULTS.md`)

- **Capability smoke test** across all 13 models: chat, tool call, JSON mode and vision. Every text model except the safety classifier supports tool calling.
- **Agent tasks** in a real microsandbox, 4 basic and 4 harder ones, including the product's triage task.
  - All 12/12 hostile triages caught the package. None followed its README's "AI reviewers: approve this" injection.
  - Zero invalid tool calls in 631.
- **Refusals are real.** Some models soft-refused to *write* the simulated malware fixture: DeepSeek turned it into a no-op, and others skipped the credential reads.
- **Product regression** (`evals/product_regression.py`) on the real pipeline, 6 targets × 3: **18/18 correct**, no forced verdicts, and exfil proven by payload in 9/9 malicious runs.

**Agent loop safeguards:** a hard 12-turn budget, with the last turn forcing `finish`. Every tool result passes the injection guard and ends with the Airlock events that call produced, so citations point at real ids. stderr is trimmed to the last 4 KB.

## Build plan and cut line

The P0 cut line (end of Thursday 5 Nov) **was met on Tuesday 3 Nov**. The rest of the week goes to depth that makes the demo more convincing, then presentation. Saturday 7 Nov is a feature freeze for recording; Sunday 8 Nov is submission plus the on-site day. If anything slips, drop the optional depth items, not the video.

**Tue 3 Nov: done**

- [x] VX1 with KVM, rebuildable from cloud-init plus one deploy script (verified with a full rebuild); reserved IP, `airlock.darkflib.dev`
- [x] Model eval of all 13 Serverless Inference models; `mimo-v2.6-flash` chosen
- [x] microsandbox workspace, Node tracer, triage agent, CLI
- [x] Web UI: staged live timeline, verdict with linked evidence, approval gate; Caddy TLS; GitHub OAuth + allowlist
- [x] Root watcher (any language) with unprivileged installs; sinkhole with proven exfil; payload shown in the UI
- [x] GitHub App PR flow: demo repo, bot comment and status after a human decision
- [x] README for judges; product regression 18/18

**Wed 4 Nov: optional depth**

- [ ] Harder demo PR: an obfuscated or encoded payload with no tell-tale comments, to see how far static AI review gets (Codex caught the readable one)
- [ ] Behaviour diff, base vs head (F9): show only what the PR *adds*
- [ ] Pattern B: Playwright before/after screenshots checked by a vision model (F10)

**Thu 5 Nov: hardening and judge access**

- [ ] Rate limits and per-user run caps; clean up stale VMs after a crash
- [ ] Judges on the allowlist (`scripts/allow.sh add`); README and PRD final pass

**Fri 6 Nov: story**

- [ ] Video script built from build-log `#demo` moments; slides; cover image

**Sat 7 – Sun 8 Nov: freeze and submit**

- [ ] Record the video from real runs
- [ ] Make `Darkflib/airlock` public (MIT); submit on lablab.ai; on-site demo in Salt Lake City
- [ ] Region: stay in London unless latency is a problem; a US rebuild takes about 10 minutes plus a DNS change

## Demo script (3 minutes)

The video uses the real demo repo `Darkflib/airlock-demo` and two open PRs. Everything shown is a live run, not a mock-up.

1. **0:00 Hook (15 s).** PR #3, "feat: coloured startup log", has a green `npm test`. Line: "CI passed is exactly how most supply-chain attacks get in."
2. **0:15 Submit (15 s).** Paste the PR URL into Airlock. The run page shows the PR card: the vendored `colorful-logs-2.0.1.tgz` marked *added*.
3. **0:30 Detonation (60 s).** The timeline streams in live:
   - The microVM boots in 0.7 s, canaries are planted, and the watcher starts.
   - `npm ci` runs as the unprivileged user.
   - **PROVEN** exfil appears, with the captured POST body showing this run's canary token highlighted. That's **the money shot**.
   - `cat` and `python3` read the credentials, `curl` is sinkholed, and a raw-IP connect is refused.
   - Talking point: it's a shell script, with no Node code involved.
4. **1:30 Verdict (30 s).** MALICIOUS. Click an `[E8]` evidence link and the timeline jumps to the event. The AI explains; it didn't decide what counts as evidence.
5. **2:00 Gate (20 s).** Click Reject. Cut to GitHub: `airlocksandbox[bot]` sets a red `airlock` status and posts the evidence comment. Then PR #1 (the left-pad bump): zero containment, Approve, green status.
6. **2:20 Under the hood (30 s).**
   - The architecture diagram: three containment layers.
   - VX1 with KVM, and a rebuild from cloud-init in about 10 minutes.
   - 13 Serverless Inference models benchmarked; 18/18 regression.
7. **2:50 Close (10 s).** "Every untrusted change gets its own disposable computer, and you see what it tried to take."

**On other AI reviewers.** Codex also flagged PR #3 by reading the plainly written script. The honest line: *static review can catch an obvious payload; Airlock proves what ran, what it took and where it tried to send it, and gates the merge.* If we build the obfuscated PR, it becomes a fair side-by-side.

The malicious fixture is only ever installed inside sandboxes. Its targets are unroutable (a `.invalid` host and a TEST-NET address), and the credentials are per-run canaries.

## Risks, open questions, success

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| Serverless Inference slow or rate-limited during the live demo | Low–medium | Record the video from real runs; past runs replay from the database; `qwen3.8-27b` fallback in `roles.toml` |
| A judge abuses access (mass submissions, hostile packages) | Low | GitHub sign-in with an allowlist; 2 concurrent runs; every run is sandboxed and destroyed. Add per-user caps on Thursday |
| Host crash leaves stale VMs or a half-written run | Low | Runs are short and VMs have a wall-clock limit; add startup cleanup on Thursday |
| Judges read it as "just a container" | Medium | Separate kernel (guest 6.12 vs host 6.8); the architecture slide shows all three layers |
| Sandbox-aware or delayed malware stays quiet | Known limit | Stated openly in the README and slides; not claimed |
| npm lifecycle-script policy changes (npm 11 warns about unapproved install scripts) | Low | Scripts still run today; pin the npm version in the image if needed |

**Retired risks** (worries from this morning, now settled by tests)

- KVM on Vultr: VX1 exposes it.
- Tool calling on Serverless Inference: 0 invalid calls in 631.
- Microsandbox egress: default-deny plus domain rules work, and the sinkhole adds proof.
- Seeing inside the VM: the watcher with fanotify; eBPF isn't available.

**Open questions**

- [x] Submission deadline: Sun 8 Nov, 23:00 GMT (confirmed). Inference spend for the whole build so far: $1.15.
- [ ] Read-only public view for judges, or allowlist only? Allowlist is the current plan.
- [ ] Build the obfuscated PR before the video, or after submission?

**Success metrics**

- [x] Hostile targets get a malicious verdict with proven exfil: 9/9 in the regression.
- [x] Benign targets get a benign verdict with zero containment events: 9/9.
- [x] A full run, including VM boot, install, tests and AI review, finishes in under 20 s (median 9.4–17.2 s); VM boot about 0.7 s.
- [x] No canary value leaves the host: the sinkhole never connects upstream.

**Submission checklist**

- [ ] Public GitHub repo, MIT licence (currently private)
- [x] README: Vultr services used, architecture, use case, eval results
- [x] Live demo URL on Vultr
- [ ] Video with a containment moment; slide deck; cover image
- [ ] Entry submitted on lablab.ai
