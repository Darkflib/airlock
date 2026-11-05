# Video script (3:00)

Draft, 4 Nov. Built from the PRD demo script and the `#demo` entries in `docs/BUILD_LOG.md`. Every shot is a real run on the live site; nothing is mocked. Narration is about 405 words in short, plain sentences for judges who speak English as a second language: about 3:00 at a slow 135 words a minute, with no slack. If a read-through runs long, trim the 0:15 and 2:33 blocks first. 5 Nov: the 1:35 block is now PR #9 (`tinyconf`) instead of PR #4. Each scene proves a different fact: PR #3, that theft is captured; PR #9, that the agent finds what a sandbox alone misses and Airlock turns it into proof; PR #1, that approval stays human. PR #9 is started on camera by a push (the GitHub webhook) and rejected automatically because the theft is proven, so the gate shot has no Reject click; PR #1's approval is still a person's, made with an `/airlock approve` comment on GitHub.

## Before recording (Sat 7 Nov, after the freeze)

- [ ] Run the regression once on the frozen commit; the 33/33 figure on the "under the hood" slide must match it.
- [ ] Fresh run of PR #3 to film live.
- [ ] PR #9 is started on camera by a push. Prepare a one-line README change on the PR #9 branch in GitHub's web editor (don't commit it yet). Check the App's webhook is active: **Advanced → Recent Deliveries** shows a 200. Do one practice push the day before, and check the `(webhook)` run appears within a few seconds.
- [ ] Don't push to PR #1: a push starts a run and moves its status.
- [ ] PR #1 is held at a pending `airlock` status; check it still is, and that its merge button is greyed out.
- [ ] The App has **Issues: read** and subscribes to **Issue comment** events (accept the new permission on the installation). On PR #1, type `/airlock approve` in the comment box but don't send it. Practise the command the day before on a throwaway PR in `airlock-demo`, not on PR #1.
- [ ] Do 2–3 practice runs of PR #9 the day before and check the agent uses `exercise` each time (it did on 3/3 regression runs and both live runs on 5 Nov); if a take doesn't, push again.
- [ ] PR #3 and PR #9 carry bot comments from earlier decisions: tidy them, or frame only the newest.
- [ ] Browser: signed in as `Darkflib`, zoom 125%, bookmarks bar hidden, notifications off, one tab for the site and one for GitHub.
- [ ] Burn in English captions that match the narration word for word; many judges read English more easily than they hear it.
- [ ] Speak slowly and leave a short pause after each number.
- [ ] Recheck the spend on the Vultr dashboard ($8.26 total on 5 Nov: $1.52 inference, $6.74 compute) and the per-review figures if they moved.
- [ ] Nothing on screen shows a share-link URL, an invite link, `.env` or a terminal with secrets. Canary values are fine (they're fake and per-run), but don't zoom in on them for long.

## Shots and narration

Timings are targets. **[SCREEN]** is what's on camera; the quoted text is the voice-over.

### 0:00–0:15 Hook

**[SCREEN]** GitHub, `Darkflib/airlock-demo` PR #3 "feat: coloured startup log". Scroll to the green `npm test` check, then the Files tab with one line in `package.json` and a vendored `colorful-logs-2.0.1.tgz`.

> "This pull request adds a coloured logger. The tests pass. Would you merge it? Passing tests show that the code works. They do not show what the install script did with your passwords."

### 0:15–1:15 Detonation, PR #3 (live)

**[SCREEN]** airlock.darkflib.dev. Paste the PR URL, submit. The PR card shows `colorful-logs-2.0.1.tgz` marked *added*. The timeline streams in.

> "Airlock runs every untrusted change in its own disposable computer. This is a small virtual machine on Vultr. It started in under one second."

**[SCREEN]** Setup stage: VM started, canaries (fake passwords) planted, watcher ready.

> "First, we put fake passwords in the machine, each with a token unique to this run. The machine can only reach the package registry."

**[SCREEN]** Detonation stage: `npm ci` as the unprivileged user. Events land: `cat` reads `.npmrc` and `.aws/credentials`, `curl` is sinkholed, raw-IP connect refused.

> "Now the install runs, as a normal user. A watcher that the package cannot touch records the programs it runs, the password files it opens, and where it tries to connect."

**[SCREEN]** The PROVEN exfil row. Expand it: the captured POST body with this run's token highlighted. Hold for three seconds. **This is the money shot.**

> "And there it is. The script read both password files and sent them out. But every address outside the registry goes to Airlock's fake server. So we caught the request, with the stolen token inside. It is proof. And it works for any language."

### 1:15–1:35 Verdict

**[SCREEN]** Verdict card: MALICIOUS. Click an `[E#]` link; the timeline jumps to the exfil event.

> "Next, an AI agent on Vultr Serverless Inference looks inside the same machine and writes a verdict. Every claim links to an event."

### 1:35–2:15 The quiet one, PR #9: where the agent earns its place (started live by a push)

**[SCREEN]** GitHub PR #9 "feat: layered config via tinyconf", Files tab: `index.js` now reads its port through `tinyconf.load()`. Nothing else stands out.

> "This one is harder. Pull request nine adds a small config library. There is no install script, and the tests pass."

**[SCREEN]** In GitHub's web editor, commit the prepared one-line README change to the PR #9 branch. Switch to the Airlock tab: a new run `Darkflib/airlock-demo#9 (webhook)` appears by itself and starts streaming. On GitHub, the PR's `airlock` check turns pending.

> "Nobody pastes anything. A push starts Airlock by itself."

**[SCREEN]** Cut to the same run, finished (about 30 s later; cut the wait). The Detonation stage reads "✓ nothing suspicious".

> "Install and tests show nothing. A sandbox alone would let this through."

**[SCREEN]** Open Agent investigation. Show the agent reading `lib/beacon.js`, then the `exercise` row: "Airlock calls … with NODE_ENV=production from a fresh copy (chosen by the agent)", then the PROVEN POST to `cfg-metrics.tinyconf.invalid` right under it. Expand it: the run's token in the body.

> "The agent reads the code and finds a check: it only sends data in production. So it asks Airlock to run the code the way a live server would. Airlock runs it from a clean copy, and catches the stolen passwords. The agent found it. Airlock proved it."

### 2:15–2:33 The gate

**[SCREEN]** The run page already shows REJECTED, "automatically: exfiltration proven by a captured payload". Nobody clicked. On GitHub, PR #9: red `airlock` status with the same reason, merge blocked, and the `airlocksandbox[bot]` evidence comment.

> "During the test, the pull request cannot be merged. The repository requires the Airlock check. Here the theft is proven, so Airlock rejects it by itself and posts the evidence on the pull request."

**[SCREEN]** PR #1, the left-pad bump: run page shows 0 new behaviours, zero containment. Switch to GitHub, PR #1: comment `/airlock approve` (typed ahead, just press Comment). The `airlock` check turns green, the bot's evidence comment appears, and the merge button unlocks.

> "This one is quiet: nothing new, nothing blocked. Airlock says what it saw, not that it's safe. So approval is a person's job, here in GitHub. Now it can merge."

### 2:33–2:50 Under the hood

**[SCREEN]** Slide: architecture diagram (`docs/architecture.png`), then the numbers slide.

> "Three layers of protection: a blocked network, a fake internet that records what is sent to it, and a watcher the package cannot touch. Thirty-three out of thirty-three correct in our tests. On twenty-four real packages: no false alarms. A review costs about two cents in AI."

### 2:50–3:00 Close

**[SCREEN]** Airlock logo, URL `airlock.darkflib.dev`, repo link.

> "Every untrusted change runs in its own disposable computer, and you see exactly what it tried to steal."

## Cutaways if a shot fails on the day

- **PR #3 live run stalls or inference is slow:** film the fresh run recorded during prep instead; the page replays stored events in the same order.
- **Exfil row doesn't appear:** stop. That's a regression; check the sinkhole unit (`systemctl status airlock-sinkhole`) before recording anything else.
- **GitHub status lags:** refresh once on camera, or cut the wait.
- **`/airlock approve` doesn't turn the check green within ~5 s:** look for the bot's reply on the PR saying why; otherwise click **Approve** on the PR #1 run page and say "I approve it" instead.
- **The agent doesn't call `exercise` on PR #9 (no PROVEN row in Agent investigation):** push again for a fresh run, or film the practice run from the day before.
- **The webhook run doesn't appear within ~5 s:** check Recent Deliveries for the error, then paste the PR #9 URL into Airlock instead and drop the line "nobody has to paste anything"; the rest of the block still works.

## Sources

| Claim on camera | Where it's measured |
|---|---|
| Boot under a second (0.69 s) | BUILD_LOG 3 Nov 17:39 |
| Shell stealer, proven exfil, `cat`/`curl`/raw-IP | BUILD_LOG 3 Nov 22:37; self-test `20261104-084347-33a1a2` |
| PR #9: silent in install and tests; proven when Airlock exercised it; rejected automatically | BUILD_LOG 5 Nov 14:30 and 14:35; PR #9's first webhook run, 5 Nov 14:30 (recheck on the live run) |
| A push starts a run by itself | BUILD_LOG 4 Nov 14:55 (webhook) |
| Proven theft is rejected automatically | BUILD_LOG 4 Nov (auto-reject) |
| Merge held at pending, branch protection | BUILD_LOG 4 Nov 02:10 |
| 13 models benchmarked | BUILD_LOG 3 Nov 18:16, `evals/RESULTS.md` |
| 24 real packages × 2: no false alarms, 6 inconclusive; about 2.5 cents of inference per review | `real-packages-20261105T164727Z`, BUILD_LOG 5 Nov 17:05 |
| 33/33, proven 18/18 | `product-20261105T142257Z` (rerun on the frozen commit) |
| About $0.003 of inference per review; about 600 PR runs an hour on one host | median tokens in `product-20261104T030613Z` × mimo-v2.6-flash price; load test BUILD_LOG 5 Nov 13:15 |
