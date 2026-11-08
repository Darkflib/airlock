# Slide outline

The deck as submitted on 8 Nov: fourteen slides, exported to PDF for the lablab form. One idea per slide; every number points to a dated run (see the sources table in `docs/VIDEO_SCRIPT.md`). Colours from the logo: navy, cyan, hazard orange; IBM Plex Sans and JetBrains Mono. Speaker notes are summarised under each slide.

## 1. Cover

**Airlock: Catch stolen keys before you merge**
Every untrusted code change runs in its own disposable computer. See what it tried to steal.
We test new pull requests and new npm and PyPI packages in a throwaway virtual machine, before they reach your project.
Vultr Agent Rush · Blast Radius Zero · airlock.darkflib.dev · github.com/Darkflib/airlock
*Visual:* logo and the cover terminal card (PR #3: VM started, fake keys, canary read, request captured, MALICIOUS).

## 2. The problem

Passing tests do not show what the install script did.
- **Real secrets at risk:** install scripts in CI run with real passwords, real tokens and full internet access.
- **Nobody reads it:** reviewers rarely read a lockfile change or the files inside a packaged dependency.
- **Easy to hide:** reading the code finds obvious attacks, and can miss one that looks like a normal update.
*Notes:* PR #3 adds a coloured logger and its tests pass. Would you merge it?

## 3. The same PR without Airlock

The check is green. Both keys went to the attacker.
- PR #3 as a plain CI job: `npm ci` ✓, `npm test` ✓, the same fake credential files, nothing watching. 3 runs out of 3, about 3.2 s each.
- "Attacker's server received:" the POST with the npm token and AWS secret highlighted.
- Through Airlock, the same PR: MALICIOUS, the request captured with nothing sent, merge held, rejected automatically.
*Footer:* recorded 5 Nov (`evals/without_airlock.py`). The stealer's real address doesn't exist, so our stand-in played the attacker's server.

## 4. What Airlock does

Run it safely. Watch what it does. A person decides.
1. **Start:** a push to a pull request starts a run by itself, or paste an npm or PyPI package name, or upload a package file.
2. **Run:** a new VM with fake passwords and no internet except the registries; install and tests run as a normal user; for a PR, the code from before the change runs alongside, so only what's new stands out.
3. **Explain:** an AI agent on Vultr Serverless Inference reads the evidence and writes a verdict; each claim links to an event.
4. **Decide:** proven theft is rejected automatically; anything else can't merge until a person approves or rejects it.

## 5. Proven theft: PR #3 (colorful-logs)

We capture the stolen data, so the theft is proven.
- Fake passwords and keys, with a token unique to this run.
- Anything outside the registries reaches a fake server Airlock controls. Nothing gets out.
- The request carries this run's token, so it's proven, not guessed.
- It was a shell script: proof doesn't depend on the language.
*Visual:* screenshot of the run page, proven event E10, run `20261106-164620-b13d8d`.

## 6. Where the agent earns its place: PR #9 (tinyconf)

Install and tests were silent. The agent found it. Airlock proved it.
The agent reads the code: it only sends data when `NODE_ENV=production`. It asks Airlock to call it that way, from a clean copy, so what's caught counts as proof.
*Visual:* screenshot of run `20261108-162701-117993` (started by a push, rejected automatically): the exercise event E55 and the proven POST E57.

## 7. The merge gate

Proof blocks it. A person approves it.
- **Waiting:** a push starts a run and Airlock sets its GitHub check to "pending"; the repository requires it, so Merge is disabled.
- **#9, rejected by itself:** the theft is proven, so the check turns red and the evidence is posted on the PR.
- **#1, approved:** nothing new, nothing blocked; a person comments `/airlock approve`, the check turns green, and it can merge.
*Footer:* only people with write access on GitHub can decide, on the PR or in Airlock. Automatic rejection uses the captured proof, never the AI's verdict; nothing is approved automatically; only the App can set the check, admins included.

## 8. Three layers of protection

1. **Blocked network:** the machine reaches the npm and PyPI registries only.
2. **Fake internet:** other addresses and DNS names are answered by Airlock on the host, recorded, never forwarded.
3. **A watcher inside the machine:** every program, file read and connection; the package runs as a normal user and can't stop it.
Safe by default: no working watcher, no run; if Airlock might have missed something, the result is "inconclusive", never "safe".
*Visual:* `docs/architecture.png`.

## 9. Built on Vultr

- **0.69 s:** VM start on a VX1 with KVM; each run has its own Linux kernel.
- **13:** every Serverless Inference model tested; `mimo-v2.6-flash` scored best and was the cheapest and fastest (15/15 on the final round).
- **~10 min:** the whole server rebuilds from one cloud-init file. London region.

## 10. Results from real runs on Vultr

- **78%** of 680 known-malicious packages (Datadog's dataset) called malicious; 85% with suspicious.
- **27** of them with theft proven by the captured payload, up from 6 with fake env tokens (p < 0.0001).
- **33/33** regression correct: 11 npm and PyPI scenarios × 3; 18/18 stealers proven.
- **0** false alarms on 24 real npm and PyPI packages, run twice each.
- **3/3** still rejected with the AI forced to say "benign": the proof decides, not the model.
- **≈3¢** of AI per real review; one $113/month host runs about 700 PR reviews an hour.
*Footer:* `evals/results`: datadog-sample-20261108T142051Z, product-20261105T142257Z, real-packages-20261105T164727Z, hijack-lab-20261105T234710Z. The 33 runs are a regression on fixtures plus real packages, not a detection rate.

## 11. Who pays, and why now

Platform and security teams that approve dependency changes every day.
- **454,600** new malicious packages in 2025, over 99% on npm (Sonatype).
- **14M** Dependabot PRs merged on GitHub in a year, each one a change somebody approved (GitHub Octoverse).
- **$5.5B** supply-chain security platforms in 2025, $10.1B by 2030 (Mordor Intelligence; other estimates $2–6B).
- **≈3¢** of AI per review, so pricing per repository leaves a wide margin.
**Revenue:** a subscription per repository, plus a self-hosted licence for teams that keep evidence in their own region. **Why AI:** the agent finds code that only misbehaves when called, and turns it into proof.
*Footer:* sources read 7 Nov 2026.

## 12. Honest limits

- **Malware that waits:** code that notices the sandbox and stays quiet; a quiet run reads "No malicious behaviour observed", never "safe".
- **What it can't run:** installs that download binaries, wheel-only PyPI releases and broken packages come back inconclusive or unsupported, never approved.
- **npm and PyPI only:** other ecosystems and browser-level behaviour are out of scope for now.
- **The AI wobbles on quiet packages:** re-run, a do-nothing package can move between suspicious and benign; what the sandbox saw stays the same.
*Notes:* in the Datadog sample 13 of 680 installs failed (inconclusive) and 20 of 200 sampled PyPI packages were wheel-only or broken; over five runs the sandbox's evidence changed for at most 2 of 63 borderline packages.

## 13. What's next

Run more, see deeper, scale out (`docs/TECHNICAL_REPORT.md` section 14).
- **Cover what we can't run yet:** wheel-only PyPI releases through the agent's exercise; a false-alarm rate on a large set of popular benign packages.
- **See deeper:** a custom guest kernel with eBPF to trace every system call instead of polling; known exfiltration services as a fixed rule (264 of the 680 contacted one).
- **Scale out:** a control plane separate from a pool of Vultr KVM workers; warm VM pools, Postgres, per-tenant isolation.

## 14. End card

Airlock logo on navy. "Every untrusted change runs in its own disposable computer. See what it tried to steal."
github.com/Darkflib/airlock · Open source, MIT licence
Mike Preston · Team OwlSuperb · github.com/Darkflib · darkflib.com · mikepreston.org
No live-site URL: the demo host won't stay up long after judging, and the video will.

## Notes

- Screenshots were taken from the live site with headless Chrome, so they match the runs named in each footer.
- Don't put share-link or invite URLs on a slide; they're bearer tokens and the deck is public.
- `Darkflib/airlock-demo` is public (6 Nov), so slides can link its PRs.
