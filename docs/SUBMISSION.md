# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock: Catch Stolen Keys Before You Merge

## Short Description

Airlock tests a new pull request, npm package or PyPI package in a throwaway Vultr virtual machine with fake passwords. It captures what the code tries to steal as proof, an AI explains it, and nothing merges until a person approves.

## Long Description

Passing tests do not show what an install script did. In CI, install scripts and test hooks run with real passwords, real tokens and full internet access, and reviewers rarely read a lockfile change.

Airlock runs every untrusted code change in its own disposable computer. Paste a GitHub pull request, an npm or PyPI package, or a package file. A new virtual machine starts in about 0.7 seconds on a Vultr server. It has its own Linux kernel and can reach only the package registries. Inside are fake passwords, each with a token unique to the run. Install and tests run as a normal user while a watcher records programs run, password files opened, DNS lookups and connections.

Every other address is answered by a fake server that Airlock controls on the host, and nothing is forwarded. So when malicious code sends the fake passwords out, Airlock captures the request, stolen data included: the theft is proven, not guessed. For a pull request, Airlock also runs the code from before the change in a second machine and shows only what is new. A registry can still receive data; Airlock flags it.

An AI agent on Vultr Serverless Inference (mimo-v2.6-flash, best of 13 models tested) then investigates. If code only misbehaves when called, the agent has Airlock call it from a clean copy, so that theft counts as proof too. Every claim cites an event. Meanwhile a required GitHub check holds the pull request at "pending", so it cannot merge. If the theft is proven, Airlock rejects the pull request by itself and posts the evidence. Otherwise a person decides, and only a person can approve.

On 680 known-malicious packages from Datadog's public dataset, Airlock called 78% malicious and 85% malicious or suspicious. On 24 real packages, run twice: no false alarms, and 6 runs inconclusive where an install failed. A real review takes about 46 seconds and 2.5 cents of AI.

Signed-in judges can click Run self-test to score five known packages live.

## Other form fields

- **Categories and technologies:** pick the closest to: Security, Developer tools, AI agents / Vultr Cloud Compute, Vultr Serverless Inference, Microsandbox, GitHub, Python, FastAPI.
- **Participation mode** (hybrid event): online or onsite, whichever is true on the day.
- **Cover image:** `assets/airlock-cover.png` (1920×1080, 16:9 as required).
- **Video:** MP4 or MOV, up to 300 MB, under 5 minutes (ours is about 4:15). The lablab cut has captions burned in.
- **Slides:** a PDF, exported from the published deck.
- **GitHub repository:** https://github.com/Darkflib/airlock (public, MIT).
- **Demo application platform:** Vultr Cloud Compute (VX1, London).
- **Demo application URL:** https://airlock.darkflib.dev

## Rules that apply

Read 7 Nov from five lablab pages: the event page, hackathon rules, "Delivering your hackathon solution", and the two guides. The event page and the form take priority over the general guides.

- **Deadline:** the event page doesn't give a time. The PRD has Sun 8 Nov, 23:00 GMT (confirmed), and there's a 5-minute grace period after it. If a technical problem blocks submission, tell the organisers before the deadline; only they can extend it.
- **Video:** at most 5 minutes, MP4 or MOV, up to 300 MB. The Presentation rubric gives only 2 out of 5 to a video under 3 minutes, and 3–4 to one under 5. Challenge 1's video must show at least one containment moment (ours: the captured request in PR #3).
- **Repo:** public, with setup docs, and the README must explain the Vultr services and architecture, the agent's use case, and how it does real tasks. The code must be original and MIT-compatible. Judges look for commits spread across the event.
- **Challenge 1 tech:** a Vultr VM backend, a web app on Vultr, Vultr Serverless Inference for the agent's model calls, and isolated sandbox execution (Microsandbox is on the event's list).
- **Judging:** Application of Technology, Presentation, Business Value and Originality, each scored 1–5; the event page gives no weights. Application of Technology scores 1 without a demo video, demo link or code, and at most 3 if the code is only partly available.
- **Disqualification:** plagiarism, gaming the votes, tampering or fraud. Missing guidelines can mean a lower score or exclusion.
- **Teams:** 1–6 people; enroll on lablab and join its Discord. Submitting on lablab is what gets judged; posting on the Vultr Community is optional.
