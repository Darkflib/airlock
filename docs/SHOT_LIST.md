# Shot list (recording day, Sat 7 Nov)

Built from [VIDEO_SCRIPT.md](VIDEO_SCRIPT.md) (narration, cutaways, sources) and [SLIDES.md](SLIDES.md). This file covers **what to capture, in what order, and where each shot sits in the 3:00 edit**.

## Timing note

The script's block timings don't match its narration. At 135–140 words a minute:

| Block | Words | Script slot | Narration needs |
|---|---|---|---|
| Hook | 37 | 15 s | ~16 s |
| Detonation | 116 | 60 s | ~50 s + 3 s hold |
| Verdict | 23 | 20 s | ~10 s |
| PR #9 | 85 | 40 s | ~37 s |
| Gate | 54 | 18 s | ~24 s |
| Under the hood | 48 | 17 s | ~21 s |
| Close | 38 | 10 s | ~16 s |

The total of 401 words still fits in 3:00. The front half has slack and the back half overruns, so the timecodes below move the block boundaries. If the read still runs long, use the script's own trims (0:15 and 2:33 blocks).

## Edit timeline

**LIVE** means screen-captured on the site or GitHub. **SLIDE** means a full-screen deck frame. **Still** means grab this frame for the deck.

| # | In–Out | Dur | Src | On screen | VO starts | Still for deck |
|---|---|---|---|---|---|---|
| 1 | 0:00–0:06 | 6 s | LIVE | GitHub PR #3 "coloured startup log": scroll to green `npm test` check, then Files tab (`package.json` line + vendored `.tgz`) | "This pull request adds a coloured logger…" | **Slide 2**: PR #3 with green check |
| 2 | 0:06–0:17 | 11 s | SLIDE | Slide 3 "same PR without Airlock". Hold 2 s on the right side (attacker's POST, token and secret highlighted) | "We ran it like a normal CI job…" | (slide 3 itself) |
| 3 | 0:17–0:29 | 12 s | LIVE | airlock.darkflib.dev: paste PR #3 URL, submit; PR card shows `colorful-logs-2.0.1.tgz` *added*; timeline starts streaming | "Airlock runs every untrusted change…" | spare: PR card |
| 4 | 0:29–0:40 | 11 s | LIVE | Setup stage: VM started (boot time visible), canaries planted, watcher ready | "First, we put fake passwords…" | **Slide 9** (optional): boot time |
| 5 | 0:40–0:53 | 13 s | LIVE | Detonation: `npm ci` as unprivileged user; `cat .npmrc` / `.aws/credentials`, `curl` sinkholed, raw-IP refused | "The install runs as a normal user…" | spare |
| 6 | 0:53–1:09 | 16 s | LIVE | **Money shot.** PROVEN exfil row expanded, run token highlighted in the POST body. Hold 3 s still | "And there it is…" | **Slide 5**: expanded PROVEN row, full res |
| 7 | 1:09–1:20 | 11 s | LIVE | Verdict card MALICIOUS; click an `[E#]` link and the timeline jumps to the exfil event | "Next, an AI agent on Vultr Serverless Inference…" | spare: verdict card |
| 8 | 1:20–1:28 | 8 s | LIVE | GitHub PR #9 "layered config via tinyconf", Files tab: `index.js` uses `tinyconf.load()` | "This one is harder…" | — |
| 9 | 1:28–1:34 | 6 s | LIVE | Commit the prepared README line in the web editor, switch to the Airlock tab: `#9 (webhook)` run appears; GitHub `airlock` check pending | "Nobody pastes anything…" | — |
| 10 | 1:34–1:37 | 3 s | LIVE | Same run finished (cut the ~30 s wait): Detonation "✓ nothing suspicious" | "Install and tests alone…" | — |
| 11 | 1:37–1:59 | 22 s | LIVE | Agent investigation: reads `lib/beacon.js` → `exercise` row (NODE_ENV=production, chosen by the agent) → PROVEN POST to `cfg-metrics.tinyconf.invalid`, expanded with token. Hold 2 s | "The agent reads the code…" | **Slide 6**: Detonation ✓ above exercise + PROVEN in one frame (zoom out to fit) |
| 12 | 1:59–2:09 | 10 s | LIVE | Run page REJECTED "automatically…"; GitHub PR #9: red `airlock` status, merge blocked, `airlocksandbox[bot]` evidence comment | "While Airlock tests it…" | **Slide 7** (alt): red status + bot comment |
| 13 | 2:09–2:23 | 14 s | LIVE | PR #1 run page: 0 new behaviours, zero containment → GitHub PR #1: press Comment on `/airlock approve` → check green, bot comment, merge unlocks | "This one is quiet…" | **Slide 7**: greyed merge button, grabbed *before* pressing Comment |
| 14a | 2:23–2:32 | 9 s | SLIDE | Slide 8 architecture (`docs/architecture.png`) | "Three layers of protection…" | — |
| 14b | 2:32–2:44 | 12 s | SLIDE | Slide 10 numbers | "Thirty-three out of thirty-three…" | — |
| 15a | 2:44–2:54 | 10 s | SLIDE | Slide 11, first two bullets (limits) | "What it can't do…" | — |
| 15b | 2:54–3:00 | 6 s | SLIDE | End card: logo (`assets/airlock-logo.png`), airlock.darkflib.dev, repo link | "…what it tried to steal." | — |

## Capture order (morning)

Record each take as its own clip with ~2 s of handles. The VO is done in three passes: a draft VO for timing, then the picture cut to it, then a final VO read against the cut.

0. **Draft VO**: read the script straight through in one take at the target pace, with a short breath between lines. Then run `python3 scripts/vo_timings.py take.m4a`: it transcribes with whisper.cpp, matches the words to each narration line in `VIDEO_SCRIPT.md`, and prints when each line starts and ends next to its slot here, with the difference. Where a line is more than ~2 s off, update the In–Out column: that's the cut you film to. A quick read is enough, since it gets replaced. If you re-read a whole line, check that line by hand, because the matching may pick either take. Running the script on the final VO gives caption timings for free.
1. **Pre-flight** (the script's checklist): regression 33/33 on the frozen commit; webhook Recent Deliveries shows 200; PR #1 still pending with merge greyed out; `/airlock approve` typed but **not sent**; browser at 125% zoom, signed in, notifications off; old bot comments tidied.
2. **Export slide 3** as a full-screen frame (it doesn't exist as an image yet).
3. **Take A, shot 1**: PR #3 on GitHub. Repeatable.
4. **Take B, shots 3–7**: one continuous PR #3 run on the site. Repeatable; record 2 takes.
5. **Take C, shots 8–12**: PR #9 push → webhook run → result → GitHub red status. Repeatable by pushing again. Check the `exercise` row appears before moving on; if it doesn't, push again.
6. **Stills for slides 5, 6, 7 (red)** from takes B and C while the pages are still open: full-res screenshots beat frame grabs.
7. **Still for slide 7 (greyed merge on PR #1)**, then **Take D, shot 13**: the PR #1 approve. **Do this last, and only once**: approving can't be redone on camera. Run the screen recorder before you open the page.
8. **Optional:** the self-test page (Run self-test) for slide 11; the Vultr dashboard spend for a recheck.
9. **Rough cut** to the draft VO. Live shots will run longer or shorter than planned (the webhook run appearing, the `exercise` row landing): let the picture decide, and note where words now need to move or go.
10. **Final VO**, read while watching the rough cut so each line lands on its shot (above all the PROVEN rows in shots 6 and 11, and the merge button unlocking in shot 13). Slow, with a pause after each number. If you change any wording, change `VIDEO_SCRIPT.md` too, so the captions and the sources table still match.
11. **Captions** burned in from the final VO's wording, word for word.

## Slide assets checklist

| Slide | Source |
|---|---|
| 1 Title | `assets/airlock-logo.png` |
| 2 Problem | Still from shot 1 |
| 3 Without Airlock | Build from `evals/results/without-airlock-20261105T215220Z`; caption "recorded 5 Nov", "attacker's server: our stand-in" |
| 4 What it does | Drawn strip (Start → Run → Explain → Decide) |
| 5 Money shot | Still from shot 6 |
| 6 PR #9 | Still from shot 11 |
| 7 The gate | Still before shot 13 (greyed merge) + shot 12 (bot comment) |
| 8 Architecture | `docs/architecture.png` |
| 9 Vultr | Text; optional boot-time still from shot 4 |
| 10 Numbers | Text; recheck 33/33 and $ spend first |
| 11 Limits / try it | Text; optional self-test still |

No share links, invite URLs, `.env` or terminals in any frame.
