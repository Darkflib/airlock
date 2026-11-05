# Airlock — Dependency Detonation Chamber (PRD)

Nov 3, 2026 · @Mike Preston · this file is the source of truth

## Summary

Airlock runs an untrusted dependency change (a GitHub pull request, a new npm or PyPI package, or an uploaded package file) inside a disposable microVM with fake credentials and no internet access beyond the package registries. It reports what the change actually *did*: credentials read, programs run, hosts contacted, and the exact data it tried to send out. An AI reviewer gives a verdict, and the PR cannot merge until a human approves or rejects: it is held at a pending status that branch protection requires.

**Status (Wed 4 Nov):** every P0 requirement works end to end on the live site, and the Thursday hardening items are done and verified live, a day early.

- **Live site:** https://airlock.darkflib.dev, with GitHub sign-in and an allowlist.
- **Regression:** 33/33 correct on the real pipeline (11 scenarios × 3: npm, PyPI, a runtime-only stealer caught through the agent's exercise, and three demo PRs). Every malicious target had its exfil proven by payload, and every benign target had zero containment events.
- **Remaining work:** the video, slides and cover image, then the pre-publish audit and submission. The hidden-stealer PR #4, PyPI support and the base-vs-head behaviour diff are done.

**Hackathon fit:** Vultr Agent Rush, Challenge 1 "Blast Radius Zero".

- **Pattern A** (sandboxed execution, errors fed back for retries) is the core of every run.
- **The human approval gate** is in place.
- **Pattern B** (Playwright screenshot verification) is descoped: the demo repo has no UI to check. Vision was still measured in the model eval.
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
4. Require a person's approval before anything merges. Airlock posts its own status and evidence comment, and rejects on its own only when theft is proven by a captured payload; it never approves.

**Non-goals**

- Static analysis: CVE lookups (Snyk, OSV) and reading package code for risky patterns (Socket's approach). We may link OSV results, but we don't rebuild them. Airlock's difference is what it can show: evidence captured on the host and tied to one run's token, a comparison with the commit before the change, and a merge check that enforces the decision.
- Ecosystems beyond npm and PyPI in the hackathon build.
- Defeating sandbox-aware malware that deliberately stays dormant. We note it as a limit and don't claim it.
- Multi-tenant SaaS, auth, or billing.

## User flow and requirements

One run per submitted change. The PR flow is the headline:

1. **Submit** a GitHub PR URL, an npm spec (`left-pad@1.3.0`), a PyPI spec (`pypi:requests==2.32.3`), or a package file (npm `.tgz` or a Python sdist `.tar.gz`/`.zip`), in the web UI (GitHub sign-in, allowlist) or with `airlock analyse`.
2. **Setup** (Airlock code, no AI). A fresh microVM boots in about 0.7 s. Canary `~/.npmrc`, `~/.aws/credentials` and `~/.pypirc` carrying a per-run token are planted, and a root watcher starts.
3. **Acquire.** The control plane fetches the PR head and diff through the GitHub App (the VM has no GitHub access), or the npm package or tarball.
4. **Detonate.** For npm, `npm ci` and `npm test`; for Python, `pip install` from source into a venv (so `setup.py` and build hooks run). Both run as the unprivileged `node` user, with all observation layers on and all traffic routed through the sinkhole.
5. **Investigate.** The triage agent (`mimo-v2.6-flash`) reads the code and re-runs what it needs within a 12-turn budget; the last turn forces `finish`. Every tool result passes the injection guard and ends with the Airlock events it produced, and cited IDs are checked against the run (a nonexistent ID is sent back once, then flagged).
6. **Decide.** While the run is in progress and until the decision, `airlocksandbox[bot]` holds the `airlock` status at `pending`, and branch protection blocks the merge button. Exfiltration proven by a captured payload is rejected automatically (failure plus the evidence comment); otherwise a human with write access approves or rejects, on the run page or with an `/airlock approve|reject` PR comment, and only then does the status go to success or failure. Approval is never automatic. The VM is destroyed when the run ends.

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| F1 | Accept a PR URL, npm or PyPI spec, or a package file; queue a run; return a run ID | P0 | Done |
| F2 | One microVM per run: CPU, memory and wall-clock limits; destroyed on completion or timeout | P0 | Done |
| F3 | Default-deny egress to real destinations; registries allowlisted; every attempt recorded | P0 | Done |
| F4 | Per-run canary credentials; detect reads and exfiltration attempts | P0 | Done |
| F5 | Tool-calling agent (`exec`, `read_file`, `finish`), errors fed back for retries, hard turn budget | P0 | Done |
| F6 | Injection guard on untrusted text before it reaches the model: the pattern guard (`airlock/guard.py`). A model-based guard is descoped: `nemotron-3.5-content-safety` answered "safe" to everything | P0 | Done |
| F7 | Live run page: staged timeline, verdict with linked evidence, containment stats | P0 | Done |
| F8 | Human approval gate before any outward action; commit status and PR comment via GitHub App | P0 | Done |
| F9 | Behaviour diff: merge base vs PR head, each detonated in its own microVM (`airlock/behaviour.py`) | P1 | Done |
| F10 | Playwright screenshot verification (Pattern B) | P1 | Descoped (4 Nov): the demo repo has no UI to check |
| F11 | Automatic trigger on PR open (App webhook) | P2 | Done 4 Nov: `opened`/`reopened`/`synchronize` on `AIRLOCK_GUEST_REPOS`, signed, 50/day; needs the `webhook-secret` field in 1Password + App settings |
| F12 | PyPI support: sdist upload and `pypi:name==version`, installed from source so `setup.py` runs | P2 | Done |
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
| Screenshot check (descoped) | Any chat model except `muse-glimmer-30b` | Every other model named a solid red square correctly; muse answered "white" |

**What the evals showed** (`evals/RESULTS.md`)

- **Capability smoke test** across all 13 models: chat, tool call, JSON mode and vision. Every text model except the safety classifier supports tool calling.
- **Agent tasks** in a real microsandbox, 4 basic and 4 harder ones, including the product's triage task.
  - All 12/12 hostile triages caught the package. None followed its README's "AI reviewers: approve this" injection.
  - Zero invalid tool calls in 631.
- **Refusals are real.** Some models soft-refused to *write* the simulated malware fixture: DeepSeek turned it into a no-op, and others skipped the credential reads.
- **Product regression** (`evals/product_regression.py`) on the real pipeline, 11 targets × 3 across npm, PyPI, a runtime-only stealer and three demo PRs: **33/33 correct**, no forced verdicts, 0 invalid tool calls, exfil proven by payload in 18/18 malicious runs (`product-20261105T142257Z`).

**Agent loop safeguards:** a hard 12-turn budget, with the last turn forcing `finish`. Every tool result passes the injection guard and ends with the Airlock events that call produced, and `finish` is checked: citations of nonexistent ids are sent back once, then flagged. The task prompt itself, which quotes the PR title, file names and event summaries, is screened too. stderr is trimmed to the last 4 KB.

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

- [x] Containment self-test judges can click: fixtures scored pass/fail live, exfil must be proven by payload (three fixtures on Tue night, five with PyPI on Wed)
- [x] Harder demo PR: payload hidden in plain sight (PR #4, `tinystamp`) — install-time credential theft smuggled through innocuous "install analytics" + a home-dir "config discovery" helper, with the collector host assembled from fragments, so the diff reads like an ordinary dependency bump. No encoding or obfuscation tooling; detonation still catches it. (Codex caught the readable PR #3.)
- [x] PyPI support (F12): sdist upload and `pypi:name==version`, installed from source in `python:3.12-slim` so `setup.py` runs under the watcher; two Python fixtures (stealer + benign) added to the regression and self-test
- [x] Behaviour diff, base vs head (F9): the merge base is detonated in a second VM in parallel; fingerprints drop run noise (pids, tokens, sinkhole IPs, checkout paths); the agent, the PR comment and the run page see what the PR adds; pre-existing risky behaviour is flagged, never hidden; the diff never lowers a verdict
- [x] Live five-fixture self-test on the host: 5/5 (`20261104-084347-33a1a2`); README "what we measured" updated; share link minted (60 days, stored outside the repo)
- [x] Fresh run of PR #4 with the behaviour diff: malicious, proven, 10 new behaviours (5 containment) vs the base, 4 unchanged, 20.2 s (`20261104-084529-f40401`); left pending; share link minted
- [x] Pattern B (F10) descoped (4 Nov): `status-api` has no UI, so a screenshot check would need a page invented for it, and it adds nothing to what a package *did*. Vision ability stays measured in `evals/RESULTS.md`

**Thu 5 Nov: hardening and judge access**

- [x] Per-user and global daily run caps for guests (owners exempt)
- [x] Judge access: signed invite link (`scripts/invite.sh`) that adds whoever signs in through it to the allowlist, tagged and revocable; signed read-only share links for runs and self-tests
- [x] Clean up after a crash (4 Nov): a VM doesn't outlive its process (after `kill -9` it shows as stopped), but its record and root directory stayed. VMs now carry an owner label, and `airlock-web` destroys its own leftovers at startup (`reap_leftovers`); CLI and regression VMs are untouched. Verified by killing the service mid-run: the restart removed the VM and the run shows as an error
- [x] Close F6: the pattern guard is the guard; the model-based guard is descoped (`nemotron-3.5-content-safety` answers "safe" to everything)
- [x] Judge access end to end with a second GitHub account (4 Nov, one-use `guesttest` invite, since revoked): guest sees 18 demo runs and none of the owner's uploads (direct fetch 404); deciding or sharing an owner's run 403; PR from another repo 403; own run decided and shared; the 16th run in a day 429. Share links signed out: only their own runs (others, the run list, decide and submit 401); a tampered link goes to `/login?error=share`. Revoking ended the guest's session at once
- [x] Run, queue and output budgets (5 Nov): 600 s deadline per run, 5,000 events, 32 MB per guest log, 64 KB per command stream, bounded viewer queues; caps make a quiet run inconclusive. Checked in real VMs on the four package fixtures and a PR #3 webhook run on the deployed build (all correct, timings unchanged)
- [x] PR snapshots pinned to one head (5 Nov): diff from `compare/base...head`, every page of the file list between two head reads, a refused diff no longer fails the run, partial views disclosed to the agent, run page and PR comment. Deployed and checked on PR #3 (5 Nov 05:42)
- [x] Queue survives restarts and deploys, with back-pressure (5 Nov): runs store their target; queued runs resume with the same id, interrupted runs fail with their evidence and are retried once, and a stop gives runs in progress 75 s. Guests get 429 past 5 unfinished runs or 10 queued per slot; the run page shows queue position and a webhook PR shows `pending: Queued (N ahead)`
- [x] Nothing half-done on GitHub after a restart (5 Nov): a PR held `pending` by a run the restart killed is set to `error` at startup, a decision recorded but never posted is posted (last 24 h), both only while the run is the latest of its commit; handled webhook deliveries kept in SQLite for 7 days. Checked by restarting `airlock-web` during a PR #3 run: `pending` → `error` one second later
- [x] Retention (5 Nov): uploads deleted when their run ends (orphans after a day); non-demo runs and their events after 30 days (`AIRLOCK_RETAIN_DAYS`), demo runs kept for share links; `sinkhole.jsonl` rotated when a day old or past 16 MB, only while no VM on the host runs, and a live run follows the rotation by inode. Swept at startup and every 6 h. Deployed 5 Nov 06:05; PR #3 run after the rotation still PROVEN
- [x] Self-hosting guide (5 Nov): [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) and `.env.example` (host, OAuth App, GitHub App permissions and events, `.env`, deploy, access, self-test check, branch protection from the App only, configuration, operations, troubleshooting). Deploy scripts take the host, public URL, owners and guest repos from `.env` instead of hard-coding ours; `install-web.sh` refuses to run without owners and a plain `https://<domain>` URL
- [x] Pinned runtime inputs (5 Nov): VM images by digest (`node` was `node:latest`), uv 0.13.7 / mitmproxy 12.3.1 / Caddy 2.11.7 (held) in cloud-init, microsandbox from `uv.lock` (the SDK's bundled `msb` is the runtime; the CLI now links to it instead of the always-latest installer), `uv sync --locked`, `msb doctor` fails a deploy. `scripts/check-pins.sh` clean on the host; PR #3 (node) and the Python stealer (python:3.12-slim) MALICIOUS with PROVEN exfil on the pinned digests. Rebuilt on a fresh VX1 from the pinned cloud-init (5 Nov 06:45): pins clean, all five self-test fixtures and PR #3 correct, instance destroyed
- [x] Access matrix (5 Nov): `tests/test_access_matrix.py`, 7 viewers × 4 runs × every run, self-test and share route (175 cells). Found and fixed: the run page confirmed runs the API hides (200 vs 404), and "post again" answered before checking who asked
- [x] One access module and explicit production settings (5 Nov): `airlock/web/access.py` (`Viewer`) holds the read/change/submit rules every route asks; the production config requires `AIRLOCK_PUBLIC_URL` and owners (no fallback to ours), `AIRLOCK_GUEST_REPOS` defaults to none, and startup logs the effective access settings. Deployed 06:52; PR #3 webhook run MALICIOUS, rejected
- [x] PRD final pass (4 Nov): status line, "18/18" in model routing and the demo script, success metrics (now 30/30, proven 15/15, medians 12–31 s), risk-table "on Thursday" items, the answered obfuscated-PR question, demo script without PR #4 / behaviour diff / PyPI

**Fri 6 Nov: story**

- [x] Demo script reworked (4 Nov): PR #3 (readable stealer) → PR #4 (hidden stealer caught at runtime, with "new in this PR" vs the merge base) → the gate, with PR #1's greyed-out merge button (left pending for this shot); PyPI as one line under "under the hood"
- [x] Video script drafted from build-log `#demo` moments: [docs/VIDEO_SCRIPT.md](docs/VIDEO_SCRIPT.md) (shots, 425-word narration, pre-recording checklist, sources)
- [x] Slide outline drafted (10 slides, including the $1.45 inference spend): [docs/SLIDES.md](docs/SLIDES.md)
- [x] Deck built from the outline (10 slides, Airlock palette; claude.ai Slides artifact, exports to PDF/PPTX)
- [ ] Swap the two screenshot placeholders (slides 4 and 5) for frames from the Sat recording; recheck 33/33 and the spend on slide 9
- [x] Cover image: `assets/airlock-cover.png` (1920×1080), rendered from `assets/airlock-cover.html`

**Sat 7 Nov: freeze and record**

- [ ] Feature freeze; one regression on the frozen commit
- [ ] Record the video from real runs on the host
- [ ] Region: stay in London unless latency is a problem; a US rebuild takes about 10 minutes plus a DNS change

**Sun 8 Nov: publish and submit (deadline 23:00 GMT)**

- [ ] Pre-publish audit: scan git history for secrets and share-link tokens; `.env` holds only `op://` references. First pass 5 Nov: both repos clean (`scripts/audit-history.py`); rerun on the final commits before flipping visibility
- [ ] Make `Darkflib/airlock` public (MIT)
- [ ] `Darkflib/airlock-demo` goes public (decided 5 Nov), so PR links in bot comments and slides work for judges. Before: tidy runs and bot comments; close test PRs #5-#7. README warning that PRs #3/#4 carry deliberate (unroutable) stealers: done 5 Nov via PR #8
- [ ] `scripts/check-submission.py` passes (long description at 1903/2000: additions must replace text); submit on lablab.ai; on-site demo in Salt Lake City

**If anything slips,** cut slide polish and the cover image first. Never the video or the pre-publish audit.

## Demo script (3 minutes)

The video uses the real demo repo `Darkflib/airlock-demo` and three PRs. Everything shown is a live run, not a mock-up. The arc: a readable stealer, then one that reads like a routine bump, then the merge gate.

1. **0:00 Hook (15 s).** PR #3, "feat: coloured startup log", has a green `npm test`. Line: "A green test run doesn't tell you what the install script did."
2. **0:15 Detonation, PR #3 (60 s).** Paste the PR URL. The PR card shows the vendored `colorful-logs-2.0.1.tgz` marked *added*. The timeline streams in live:
   - The microVM boots in 0.7 s, canaries are planted, and the watcher starts.
   - `npm ci` runs as the unprivileged user.
   - **PROVEN** exfil appears, with the captured POST body showing this run's canary token highlighted. That's **the money shot**.
   - `cat` and `python3` read the credentials, `curl` is sinkholed, and a raw-IP connect is refused.
   - Talking point: it's a shell script, with no Node code involved.
3. **1:15 Verdict (20 s).** MALICIOUS. Click an evidence link (`[E#]`) and the timeline jumps to the event. The AI explains; it didn't decide what counts as evidence.
4. **1:35 The hard one, PR #4 (40 s).** Line: "That script was easy to read. This one isn't." PR #4, "feat: timestamped startup log", reads like a routine dependency bump: the theft is split across "install analytics" and a "config discovery" helper, and the collector host is built from fragments. Commit a one-line README change to the PR #4 branch in GitHub's web editor: the webhook starts a `(webhook)` run by itself and the `airlock` check turns pending. Cut the wait to the finished run: "only what this PR adds" filter on, **10 behaviours new versus the merge base, 5 of them containment**, each tagged NEW IN THIS PR. The merge base was detonated in a second microVM alongside it. Exfil to `telemetry.tinystamp.invalid` is PROVEN by payload again.
5. **2:15 Gate (18 s).** On GitHub, PR #4's merge button is greyed out: the `airlock` check is pending. The run is already rejected automatically (proven theft): `airlocksandbox[bot]` has set a red status and posted the evidence comment, with no click. Then PR #1 (the left-pad bump): 0 new behaviours, zero containment; a `/airlock approve` comment on GitHub turns the check green, and the merge button unlocks.
6. **2:33 Under the hood (17 s).**
   - The architecture diagram: three containment layers, host-captured evidence the guest can't forge.
   - VX1 with KVM: a separate guest kernel, and a rebuild from cloud-init in about 10 minutes.
   - npm and PyPI; 13 Serverless Inference models benchmarked; regression 33/33 (11 scenarios × 3); about $0.003 of inference per review, about 620 PR runs an hour on one host.
7. **2:50 Close (10 s).** "Every untrusted change gets its own disposable computer, and you see what it tried to steal."

**Before recording:** a fresh run of PR #3; PR #4's run is started on camera by the push, so prepare the README edit and do one practice push the day before. PR #1 is already held at pending for the gate shot: don't push to it. PR #3 and PR #4 already carry bot comments from earlier decisions, so film the newest comment or tidy the older ones first.

**On other AI reviewers.** Codex also flagged PR #3 by reading the plainly written script. The honest line: *static review can catch an obvious payload; Airlock proves what ran, what it took and where it tried to send it, and gates the merge.* PR #4 (`tinystamp`) is the fair side-by-side: no tell-tale script, the credential read and exfil are split across innocuous-looking "install analytics" and a "config discovery" helper, and the collector host is built from fragments — the diff reads like a routine dependency bump, but detonation still proves the exfil. (For a blind static-review test, strip the fixture's honest NOTICE comments first.)

The malicious fixture is only ever installed inside sandboxes. Its targets are unroutable (a `.invalid` host and a TEST-NET address), and the credentials are per-run canaries.

## Risks, open questions, success

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| Serverless Inference slow or rate-limited during the live demo | Low–medium | Record the video from real runs; past runs replay from the database; `qwen3.8-27b` fallback in `roles.toml` |
| A judge abuses access (mass submissions, hostile packages) | Low | GitHub sign-in with an allowlist; one run per core at once (4); every run is sandboxed and destroyed; guests capped at 15 runs a day each and 150 between them (verified with a second account, 4 Nov) |
| Host crash leaves stale VMs or a half-written run | Low | VMs die with their process; at startup, interrupted runs are marked failed and the web service removes its leftover sandboxes (verified 4 Nov) |
| Judges read it as "just a container" | Medium | Separate kernel (guest 6.12 vs host 6.8); the architecture slide shows all three layers |
| Sandbox-aware or delayed malware stays quiet | Known limit | Stated openly in the README and slides; not claimed |
| npm lifecycle-script policy changes (npm 11 warns about unapproved install scripts) | Low | Scripts still run today; pin the npm version in the image if needed |

**Retired risks** (worries from this morning, now settled by tests)

- KVM on Vultr: VX1 exposes it.
- Tool calling on Serverless Inference: 0 invalid calls in 631.
- Microsandbox egress: default-deny plus domain rules work, and the sinkhole adds proof.
- Seeing inside the VM: the watcher with fanotify; eBPF isn't available.

**Open questions**

- [x] Submission deadline: Sun 8 Nov, 23:00 GMT (confirmed). Spend for the whole build so far: $8.26 ($1.52 inference, $6.74 compute; 5 Nov).
- [x] Read-only public view for judges, or allowlist only? Both: signed read-only share links to recorded runs, plus an invite link with run caps for judges who want to submit their own (decided Tue 3 Nov). The lablab page is public, so the invite link should be treated as public.
- [x] Build the obfuscated PR before the video, or after submission? Before, without obfuscation tooling: PR #4 (`tinystamp`, 4 Nov) splits the theft across innocuous-looking files, which is enough to make the diff read as a routine bump. Runtime detection doesn't depend on how readable the code is.
- [x] Should deleting an account also remove its access? No, for the hackathon: `DELETE /api/me` removes the guest's runs, self-tests and share links and ends their sessions, but the allowlist entry stays, so they can sign in again (decided Thu 5 Nov). A product would handle accounts and access differently anyway, so this isn't the model to build on.

**Success metrics**

- [x] Hostile targets get a malicious verdict with proven exfil: 18/18 in the regression (npm, shell, Python, runtime-only via exercise, PR #3, PR #4).
- [x] Benign targets get a benign verdict with zero containment events: 15/15.
- [x] A full run finishes well inside goal 1's 5 minutes: medians 12–31 s end to end, VM boot about 0.7 s. The tighter 20 s target holds for tarballs, npm specs, sdists and the stealer PRs (12–18 s), but not for PR #1 (24 s: two VMs plus `npm test`) or real PyPI `six` (31 s).
- [x] No canary value reaches an unapproved destination: the sinkhole never connects upstream, and DNS bypasses are answered on the host (verified 4 Nov). Canary text does go to Vultr inference in tool output, and into the PR comment after a human decision, by design.

**Submission checklist**

- [ ] Public GitHub repo, MIT licence (currently private)
- [x] README: Vultr services used, architecture, use case, eval results
- [x] Live demo URL on Vultr
- [ ] Video with a containment moment; slide deck; cover image
- [ ] Entry submitted on lablab.ai

## Review follow-up — 3 Nov, 23:46 UTC

The independent [working-tree review](docs/REVIEW-2026-11-03.md) found unresolved issues behind the earlier P0-complete claim. Before publishing judge invites: separate guest access from maintainer/GitHub authority, run model-selected commands unprivileged, fail closed on incomplete observation, preserve unique VM names, and require current-run host-captured canaries for PROVEN evidence. Cleanup guarantees, merge-gate setup, and submission copy also need correction. These findings are not fixed by the review; 54 local unit tests passing and the recorded 18/18 fixture regression do not establish those security properties. Follow-up on 4 Nov at 00:00 UTC verified the live homepage and existing self-test result (3/3) through the browser; invite, quota and signed-out share enforcement were not independently verified by the reviewer.

**Status, 4 Nov:** fixed and tested (59 unit tests): guest privileges separated from owners (guests decide and share only their own runs; PRs only from `AIRLOCK_GUEST_REPOS`), agent commands always run as `node`, PROVEN requires this run's token in a host-captured payload with sinkhole /24s reserved per live run, unique VM names, and a shell-quoted, tightened npm spec. The rest (watcher fail-closed, cleanup after failed setup, the DNS-to-gateway check, claim wording, and the merge gate as a pending status plus branch protection) was fixed on 4 Nov.


**Independent recheck, 4 Nov 01:52 UTC:** most original fixes confirmed through `8c902b1`; 68 tests pass. The [recheck report](docs/RECHECK-2026-11-04.md) records remaining scope: all owner runs remain readable by invited guests (including non-demo material), test timeouts and observation loss during investigation can still return BENIGN, guest DNS worker failure is not supervised, pending-status failures can preserve a previous success, and initial prompt screening/citation validation remain incomplete. The live homepage also retains the old absolute wording. These are follow-ups to the implemented fixes, not a reversal of them. **Status, 4 Nov:** all six fixed and tested (78 tests): a `demo` flag limits guest reads, test timeouts/kills are coverage gaps and observation is rechecked after the agent, the guest DNS parser is bounds-checked with a per-packet boundary and supervised observer threads, a failed status write is flagged on the run and stale same-commit runs can't decide or post, the task prompt is screened and citations validated, and the homepage/short description reworded.
