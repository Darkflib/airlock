# Slide outline

Draft, 4 Nov. Eleven slides (slide 3 added 5 Nov) for the lablab submission and the "under the hood" beat of the video. One idea per slide; every number points to a dated run (see the sources table in `docs/VIDEO_SCRIPT.md`). Colours from the logo: navy, cyan, hazard orange.

## 1. Title

**Airlock Sandbox: Catch Stolen Keys Before You Merge**
Every untrusted change gets its own disposable computer.
Vultr Agent Rush, Challenge 1 "Blast Radius Zero" · airlock.darkflib.dev
*Visual:* logo on navy; the cover image if it's ready.

## 2. The problem

A green test run doesn't tell you what the install script did.
- Postinstall scripts and test hooks run in CI with real tokens and open network access.
- Nobody reads the diff of a lockfile bump or a vendored tarball.
- Static review catches the obvious payload, not the one that reads like a routine bump.
*Visual:* PR #3 on GitHub with the green `npm test` check.

## 3. The same PR without Airlock

PR #3 run as a plain CI job: a fresh machine with the same fake credential files, `npm ci`, `npm test`, nothing watching.
- `npm ci` ✓ `npm test` ✓: the check is green.
- One POST delivered the npm token and the AWS secret to the attacker. 3 runs out of 3, about 3.2 s each.
- Through Airlock, the same PR: MALICIOUS, the request captured with nothing sent, merge held, rejected automatically.
*Visual:* left, the two green steps; right, "Attacker's server received:" with the POST body, token and secret highlighted. Caption: "Recorded 5 Nov (`evals/without_airlock.py`). The stealer's real address doesn't exist, so our stand-in played the attacker's server."

## 4. What Airlock does

A push to a PR starts it by itself (or paste an npm or PyPI package, or upload a tarball) → it runs in a fresh microVM with fake credentials → you see what it tried to steal → the PR stays blocked until a human approves.
Scanners such as Socket read a package's code for risky patterns. Airlock runs the change and keeps what it actually sent, tied to this run's token, compared with the code before the change, and enforced as a merge check.
*Visual:* four-step strip: Start → Run → Explain → Decide.

## 5. The money shot: proven exfiltration

The captured POST from PR #3, with the run's canary token highlighted.
- Every destination outside the registries is answered by Airlock on the host, never forwarded.
- So exfiltration is **proven by the payload**, not inferred from a connection attempt.
- It was a shell script: detection doesn't depend on the language.
*Visual:* screenshot of the expanded PROVEN row.

## 6. Where the agent earns its place: PR #9

A config library with no install script; its tests pass. Install and tests alone **didn't expose it**.
- The agent reads the code: it only sends data when `NODE_ENV=production`.
- It asks Airlock to **exercise** it that way. Airlock runs it from a clean copy with its own harness, so what's caught counts as proof.
- POST to `cfg-metrics.tinyconf.invalid` with this run's token: **PROVEN**, rejected automatically.
"The agent found it. Airlock proved it."
*Visual:* Detonation "✓ nothing suspicious" above Agent investigation "4 contained", with the exercise row and the PROVEN POST.

## 7. The gate

- A push starts a run (App webhook); the GitHub App holds the PR at a pending `airlock` status; branch protection requires it.
- Proven theft (a captured payload with this run's token) is rejected automatically: red check and evidence comment, no click. Everything else waits for a human Approve or Reject, from someone with write access to the repo on GitHub: on the run page, or with an `/airlock approve` comment on the PR.
- The AI explains; it never merges.
*Visual:* greyed-out merge button beside the bot's evidence comment.

## 8. Architecture

Three containment layers, evidence the guest can't forge:
1. **Default-deny egress** (microsandbox policy): registries only.
2. **Fake DNS + sinkhole** on a per-run /24, plus a host-side DNS guard: answers every non-registry request itself, records it, forwards none.
3. **In-guest watcher** as root (fanotify, DNS, connections); the package runs as an unprivileged user and can't touch it.
Fail closed: no watcher, no run; a blind spot turns "benign" into "inconclusive".
*Visual:* `docs/architecture.png`.

## 9. Built on Vultr

- **VX1 with KVM:** a separate guest kernel per run (guest 6.12, host 6.8), boot in 0.69 s. "Isn't this just Docker?" No.
- **Serverless Inference:** triage agent `mimo-v2.6-flash`, chosen by benchmarking all 13 catalogue models.
- **Rebuildable:** the host comes back from `infra/cloud-init.yaml` in about 10 minutes.

## 10. Numbers

| | |
|---|---|
| Regression (11 npm/PyPI scenarios × 3) | **33/33** correct |
| Malicious runs with exfil proven by payload | **18/18** |
| Runtime-only stealer, silent in install and tests | **proven 3/3** via the agent's exercise |
| Reviewer forced to answer "benign" (hijack lab) | **still rejected 3/3**: the captured proof decides, not the AI |
| Containment events on benign runs | **0** |
| 24 real npm/PyPI packages × 2 | **0 false alarms**, 42 clean, 6 inconclusive (binary downloads blocked, or no compiler) |
| Median run, end to end | **17–35 s** fixtures, **46 s** real packages |
| Inference per review (median) | **≈ $0.003** fixtures, **≈ $0.025** real packages |
| One VX1 host ($113/month), 8 at once | **≈ 700 PR runs/hour**, ≈ 455 real-package reviews/hour |
| Whole build to 5 Nov, inference + compute | **$8.26** |
"11 scenarios × 3 runs" is a regression on fixtures we wrote plus real packages, not a detection rate. Recheck the 33/33 on the frozen commit and the spend on Sat before exporting.

## 11. Limits and try it

- Not caught: malware that detects the sandbox and stays quiet, or waits. So a quiet run reads "No malicious behaviour observed", with what ran, and never "safe".
- npm and PyPI only; installs that download binaries come back inconclusive, never approved; browser-level behaviour (Pattern B) descoped.
- **Try it:** airlock.darkflib.dev → Run self-test (five known packages, scored live). Repo: github.com/Darkflib/airlock (MIT).

## Notes for building the deck

- Screenshots come from the Sat recording session, so they match the video.
- Don't put share-link or invite URLs on a slide; they're bearer tokens and the deck is public.
- `Darkflib/airlock-demo` is public (6 Nov), so slides can link its PRs.
