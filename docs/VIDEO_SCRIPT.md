# Video script (3:00)

Draft, 4 Nov. Built from the PRD demo script and the `#demo` entries in `docs/BUILD_LOG.md`. Every shot is a real run on the live site; nothing is mocked. Narration is 407 words in short, plain sentences for judges who speak English as a second language: about 3:00 at a slow 135 words a minute, with no slack. If a read-through runs long, trim the 0:15 and 2:33 blocks first. PR #4 is now started on camera by a push (the GitHub webhook); to make room, the 2:33 block no longer says "npm and PyPI" (the numbers slide still does) and PR #4 no longer mentions the host built from pieces. PR #4 is now rejected automatically because the theft is proven, so the gate shot has no Reject click; PR #1's Approve is still a person's.

## Before recording (Sat 7 Nov, after the freeze)

- [ ] Run the regression once on the frozen commit; the 30/30 figure on the "under the hood" slide must match it.
- [ ] Fresh run of PR #3 to film live.
- [ ] PR #4 is started on camera by a push. Prepare a one-line README change on the PR #4 branch in GitHub's web editor (don't commit it yet). Check the App's webhook is active: **Advanced → Recent Deliveries** shows a 200. Do one practice push the day before, and check the `(webhook)` run appears within a few seconds.
- [ ] Don't push to PR #1: a push starts a run and moves its status.
- [ ] PR #1 is held at a pending `airlock` status; check it still is, and that its merge button is greyed out.
- [ ] PR #3 and PR #4 carry bot comments from earlier decisions: tidy them, or frame only the newest.
- [ ] Browser: signed in as `Darkflib`, zoom 125%, bookmarks bar hidden, notifications off, one tab for the site and one for GitHub.
- [ ] Burn in English captions that match the narration word for word; many judges read English more easily than they hear it.
- [ ] Speak slowly and leave a short pause after each number.
- [ ] Recheck the inference spend on the Vultr dashboard and update the $1.45 figure if it moved.
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

> "Now the install runs, as a normal user. A watcher that the package cannot touch records every program, every file it reads, and every connection."

**[SCREEN]** The PROVEN exfil row. Expand it: the captured POST body with this run's token highlighted. Hold for three seconds. **This is the money shot.**

> "And there it is. The script read both password files and sent them out. But every address outside the registry goes to Airlock's fake server. So we caught the request, with the stolen token inside. This is not a guess. It is proof. And it works for any language."

### 1:15–1:35 Verdict

**[SCREEN]** Verdict card: MALICIOUS. Click an `[E#]` link; the timeline jumps to the exfil event.

> "Next, an AI agent on Vultr Serverless Inference looks inside the same machine and writes a verdict. Every claim links to an event. The AI explains the evidence. It does not decide what the evidence is."

### 1:35–2:15 The hard one, PR #4 (started live by a push)

**[SCREEN]** GitHub PR #4 "feat: timestamped startup log", Files tab. Scroll past "install analytics" and a "config discovery" helper.

> "That script was easy to read. This one is not. Pull request four looks like a normal update. The stealing code is split across two files that look harmless."

**[SCREEN]** In GitHub's web editor, commit the prepared one-line README change to the PR #4 branch. Switch to the Airlock tab: a new run `Darkflib/airlock-demo#4 (webhook)` appears by itself and starts streaming. On GitHub, the PR's `airlock` check turns pending.

> "And nobody has to paste anything. When a developer pushes to the pull request, Airlock starts testing by itself."

**[SCREEN]** Cut to the same run, finished (about 30 s later; cut the wait). Turn on "only what this PR adds". Rows tagged NEW IN THIS PR; the counter shows 10 new, 5 containment. Expand the PROVEN POST to `telemetry.tinystamp.invalid`.

> "It also ran the code from before this change, in a second machine. So we see only what is new: ten new behaviours, five of them blocked or caught. The stolen data is captured again. What matters is what the code does, not how it looks."

### 2:15–2:33 The gate

**[SCREEN]** The run page already shows REJECTED, "automatically: exfiltration proven by a captured payload". Nobody clicked. On GitHub, PR #4: red `airlock` status with the same reason, merge blocked, and the `airlocksandbox[bot]` evidence comment.

> "During the test, the pull request cannot be merged. The repository requires the Airlock check. Here the theft is proven, so Airlock rejects it by itself and posts the evidence on the pull request."

**[SCREEN]** PR #1, the left-pad bump: run page shows 0 new behaviours, zero containment. Click **Approve**. GitHub: green status, merge button unlocks.

> "This one is a safe update: nothing new, nothing blocked. Approval is a person's job. I click Approve, and now it can be merged."

### 2:33–2:50 Under the hood

**[SCREEN]** Slide: architecture diagram (`docs/architecture.png`), then the numbers slide.

> "Three layers of protection: a blocked network, a fake internet that records everything, and a watcher the package cannot touch. We tested all thirteen Serverless Inference models. Thirty out of thirty correct in our tests. The AI cost for the whole project: about one dollar fifty."

### 2:50–3:00 Close

**[SCREEN]** Airlock logo, URL `airlock.darkflib.dev`, repo link.

> "Every untrusted change runs in its own disposable computer, and you see exactly what it tried to steal."

## Cutaways if a shot fails on the day

- **PR #3 live run stalls or inference is slow:** film the fresh run recorded during prep instead; the page replays stored events in the same order.
- **Exfil row doesn't appear:** stop. That's a regression; check the sinkhole unit (`systemctl status airlock-sinkhole`) before recording anything else.
- **GitHub status lags:** refresh once on camera, or cut the wait.
- **The webhook run doesn't appear within ~5 s:** check Recent Deliveries for the error, then paste the PR #4 URL into Airlock instead and drop the line "nobody has to paste anything"; the rest of the block still works.

## Sources

| Claim on camera | Where it's measured |
|---|---|
| Boot under a second (0.69 s) | BUILD_LOG 3 Nov 17:39 |
| Shell stealer, proven exfil, `cat`/`curl`/raw-IP | BUILD_LOG 3 Nov 22:37; self-test `20261104-084347-33a1a2` |
| PR #4: 10 new, 5 containment, proven | BUILD_LOG 4 Nov 08:50, run `20261104-084529-f40401` (recheck on the live run) |
| A push starts a run by itself | BUILD_LOG 4 Nov 14:55 (webhook) |
| Proven theft is rejected automatically | BUILD_LOG 4 Nov (auto-reject) |
| Merge held at pending, branch protection | BUILD_LOG 4 Nov 02:10 |
| 13 models benchmarked | BUILD_LOG 3 Nov 18:16, `evals/RESULTS.md` |
| 30/30, proven 15/15 | `product-20261104T030613Z` (rerun on the frozen commit) |
| $1.45 inference | PRD, 4 Nov 08:25 (recheck before recording) |
