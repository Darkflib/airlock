# Video script (3:00)

Draft, 4 Nov. Built from the PRD demo script and the `#demo` entries in `docs/BUILD_LOG.md`. Every shot is a real run on the live site; nothing is mocked. Narration is 425 words: about 2:50 at 150 words a minute, which is tight. If a read-through runs long, trim the 0:15 and 2:30 blocks first.

## Before recording (Sat 7 Nov, after the freeze)

- [ ] Run the regression once on the frozen commit; the 30/30 figure on the "under the hood" slide must match it.
- [ ] Fresh run of PR #3 to film live. Fresh run of PR #4 to cut to (record it first, film the finished page).
- [ ] PR #1 is held at a pending `airlock` status; check it still is, and that its merge button is greyed out.
- [ ] PR #3 and PR #4 carry bot comments from earlier decisions: tidy them, or frame only the newest.
- [ ] Browser: signed in as `Darkflib`, zoom 125%, bookmarks bar hidden, notifications off, one tab for the site and one for GitHub.
- [ ] Recheck the inference spend on the Vultr dashboard and update the $1.45 figure if it moved.
- [ ] Nothing on screen shows a share-link URL, an invite link, `.env` or a terminal with secrets. Canary values are fine (they're fake and per-run), but don't zoom in on them for long.

## Shots and narration

Timings are targets. **[SCREEN]** is what's on camera; the quoted text is the voice-over.

### 0:00–0:15 Hook

**[SCREEN]** GitHub, `Darkflib/airlock-demo` PR #3 "feat: coloured startup log". Scroll to the green `npm test` check, then the Files tab with one line in `package.json` and a vendored `colorful-logs-2.0.1.tgz`.

> "This pull request adds a coloured logger. The tests pass. Would you merge it? A green test run tells you the code works. It doesn't tell you what the install script did with your credentials."

### 0:15–1:15 Detonation, PR #3 (live)

**[SCREEN]** airlock.darkflib.dev. Paste the PR URL, submit. The PR card shows `colorful-logs-2.0.1.tgz` marked *added*. The timeline streams in.

> "Airlock gives every untrusted change its own disposable computer. This is a microVM with its own kernel on a Vultr VX1, booted in under a second."

**[SCREEN]** Setup stage: VM started, canaries planted, watcher ready.

> "Before anything runs, we plant fake credentials carrying a token unique to this run: an npm token, AWS keys. The VM can reach the package registry and nothing else."

**[SCREEN]** Detonation stage: `npm ci` as the unprivileged user. Events land: `cat` reads `.npmrc` and `.aws/credentials`, `curl` is sinkholed, raw-IP connect refused.

> "Now `npm ci` runs, as an unprivileged user, while a watcher outside its reach records every program, every credential file opened, every lookup and connection."

**[SCREEN]** The PROVEN exfil row. Expand it: the captured POST body with this run's token highlighted. Hold for three seconds. **This is the money shot.**

> "And there it is. The install script read both credential files and posted them out. Every destination outside the registry is answered by Airlock itself, so we caught the request with the stolen token inside. That's not a guess: it's proven by the payload. And notice this is a shell script. No Node, nothing language-specific to hook."

### 1:15–1:35 Verdict

**[SCREEN]** Verdict card: MALICIOUS. Click an `[E#]` link; the timeline jumps to the exfil event.

> "A triage agent on Vultr Serverless Inference investigates inside the same VM and writes the verdict. Every claim cites an event. The AI explains the evidence; it doesn't get to decide what the evidence is."

### 1:35–2:10 The hard one, PR #4 (recorded run)

**[SCREEN]** GitHub PR #4 "feat: timestamped startup log", Files tab. Scroll past "install analytics" and a "config discovery" helper.

> "That script was easy to read. This one isn't. PR #4 reads like a routine dependency bump. The theft is split across install analytics and a config helper, and the collector's hostname is assembled from fragments."

**[SCREEN]** Cut to the finished PR #4 run. Turn on "only what this PR adds". Rows tagged NEW IN THIS PR; the counter shows 10 new, 5 containment. Expand the PROVEN POST to `telemetry.tinystamp.invalid`.

> "Airlock also detonated the merge base in a second VM, so this view shows only what the PR adds: ten new behaviours, five of them containment events. And the exfiltration is proven again, by the payload. It doesn't matter how readable the code is, only what it does when it runs."

### 2:10–2:30 The gate

**[SCREEN]** GitHub PR #4: merge button greyed out, `airlock` check pending. Back on the run page, click **Reject**. On GitHub: red `airlock` status and the `airlocksandbox[bot]` evidence comment.

> "While all this happens, the PR can't merge: branch protection requires the Airlock check, and it stays pending until a human decides. Reject, and the bot posts the evidence on the PR."

**[SCREEN]** PR #1, the left-pad bump: run page shows 0 new behaviours, zero containment. Click **Approve**. GitHub: green status, merge button unlocks.

> "A clean bump: nothing new, nothing contained. Approve, and it's free to merge."

### 2:30–2:50 Under the hood

**[SCREEN]** Slide: architecture diagram (`docs/architecture.png`), then the numbers slide.

> "Three containment layers: default-deny egress, a sinkhole that captures what leaves, and a watcher the package can't touch. npm and PyPI. We benchmarked all 13 Serverless Inference models to pick the agent. Thirty out of thirty on our regression, exfiltration proven on every malicious run. And the inference for the whole build cost about a dollar fifty."

### 2:50–3:00 Close

**[SCREEN]** Airlock logo, URL `airlock.darkflib.dev`, repo link.

> "Every untrusted change gets its own disposable computer, and you see exactly what it tried to steal."

## Cutaways if a shot fails on the day

- **PR #3 live run stalls or inference is slow:** film the fresh run recorded during prep instead; the page replays stored events in the same order.
- **Exfil row doesn't appear:** stop. That's a regression; check the sinkhole unit (`systemctl status airlock-sinkhole`) before recording anything else.
- **GitHub status lags:** refresh once on camera, or cut the wait.

## Sources

| Claim on camera | Where it's measured |
|---|---|
| Boot under a second (0.69 s) | BUILD_LOG 3 Nov 17:39 |
| Shell stealer, proven exfil, `cat`/`curl`/raw-IP | BUILD_LOG 3 Nov 22:37; self-test `20261104-084347-33a1a2` |
| PR #4: 10 new, 5 containment, proven | BUILD_LOG 4 Nov 08:50, run `20261104-084529-f40401` |
| Merge held at pending, branch protection | BUILD_LOG 4 Nov 02:10 |
| 13 models benchmarked | BUILD_LOG 3 Nov 18:16, `evals/RESULTS.md` |
| 30/30, proven 15/15 | `product-20261104T030613Z` (rerun on the frozen commit) |
| $1.45 inference | PRD, 4 Nov 08:25 (recheck before recording) |
