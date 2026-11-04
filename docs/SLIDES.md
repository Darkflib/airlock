# Slide outline

Draft, 4 Nov. Ten slides for the lablab submission and the "under the hood" beat of the video. One idea per slide; every number points to a dated run (see the sources table in `docs/VIDEO_SCRIPT.md`). Colours from the logo: navy, cyan, hazard orange.

## 1. Title

**Airlock: Dependency Detonation Chamber**
Every untrusted change gets its own disposable computer.
Vultr Agent Rush, Challenge 1 "Blast Radius Zero" · airlock.darkflib.dev
*Visual:* logo on navy; the cover image if it's ready.

## 2. The problem

A green test run doesn't tell you what the install script did.
- Postinstall scripts and test hooks run in CI with real tokens and open network access.
- Nobody reads the diff of a lockfile bump or a vendored tarball.
- Static review catches the obvious payload, not the one that reads like a routine bump.
*Visual:* PR #3 on GitHub with the green `npm test` check.

## 3. What Airlock does

A push to a PR starts it by itself (or paste an npm or PyPI package, or upload a tarball) → it runs in a fresh microVM with fake credentials → you see what it tried to steal → the PR stays blocked until a human approves.
*Visual:* four-step strip: Start → Run → Explain → Decide.

## 4. The money shot: proven exfiltration

The captured POST from PR #3, with the run's canary token highlighted.
- Every destination outside the registries is answered by Airlock on the host, never forwarded.
- So exfiltration is **proven by the payload**, not inferred from a connection attempt.
- It was a shell script: detection doesn't depend on the language.
*Visual:* screenshot of the expanded PROVEN row.

## 5. The hard one: PR #4

Reads like a routine dependency bump; the theft is split across "install analytics" and a "config discovery" helper, and the host is built from fragments.
- Merge base detonated in a second VM: **10 new behaviours, 5 of them containment**.
- Exfil to `telemetry.tinystamp.invalid` proven by payload.
*Visual:* run page with "only what this PR adds" on.

## 6. The gate

- A push starts a run (App webhook); the GitHub App holds the PR at a pending `airlock` status; branch protection requires it.
- Proven theft (a captured payload with this run's token) is rejected automatically: red check and evidence comment, no click. Everything else waits for a human Approve or Reject, from someone with write access to the repo on GitHub.
- The AI explains; it never merges.
*Visual:* greyed-out merge button beside the bot's evidence comment.

## 7. Architecture

Three containment layers, evidence the guest can't forge:
1. **Default-deny egress** (microsandbox policy): registries only.
2. **Fake DNS + sinkhole** on a per-run /24, plus a host-side DNS guard: captures every request, forwards none.
3. **In-guest watcher** as root (fanotify, DNS, connections); the package runs as an unprivileged user and can't touch it.
Fail closed: no watcher, no run; a blind spot turns "benign" into "inconclusive".
*Visual:* `docs/architecture.png`.

## 8. Built on Vultr

- **VX1 with KVM:** a separate guest kernel per run (guest 6.12, host 6.8), boot in 0.69 s. "Isn't this just Docker?" No.
- **Serverless Inference:** triage agent `mimo-v2.6-flash`, chosen by benchmarking all 13 catalogue models.
- **Rebuildable:** the host comes back from `infra/cloud-init.yaml` in about 10 minutes.

## 9. Numbers

| | |
|---|---|
| Regression (10 npm/PyPI targets × 3) | **30/30** correct |
| Malicious runs with exfil proven by payload | **15/15** |
| Containment events on benign runs | **0** |
| Median run, end to end | **12–31 s** |
| Inference for the whole build | **≈ $1.45** |
Recheck the 30/30 on the frozen commit and the spend on Sat before exporting.

## 10. Limits and try it

- Not caught: malware that detects the sandbox and stays quiet, or waits.
- npm and PyPI only; browser-level behaviour (Pattern B) descoped.
- **Try it:** airlock.darkflib.dev → Run self-test (five known packages, scored live). Repo: github.com/Darkflib/airlock (MIT).

## Notes for building the deck

- Screenshots come from the Sat recording session, so they match the video.
- Don't put share-link or invite URLs on a slide; they're bearer tokens and the deck is public.
- `Darkflib/airlock-demo` is private; if it stays private, don't link PRs from the slides (judges get a 404). Screenshots are fine.
