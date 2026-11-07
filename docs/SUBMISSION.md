# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock Sandbox: Catch Stolen Keys Before Merge

## Short Description

Airlock tests a new pull request, npm package or PyPI package in a throwaway Vultr virtual machine with fake passwords. It captures what the code tries to steal as proof, an AI explains it, and nothing merges until a person approves.

## Long Description

Passing tests do not show what an install script did. In CI, install scripts and test hooks run with real passwords, real tokens and full internet access, and reviewers rarely read a lockfile change.

Airlock runs every untrusted code change in its own disposable computer. Paste a GitHub pull request, an npm or PyPI package, or a package file. A new virtual machine starts in about 0.7 seconds on a Vultr server. It has its own Linux kernel and can reach only the package registries. Inside are fake passwords, each with a token unique to the run. Install and tests run as a normal user while a watcher records programs run, password files opened, DNS lookups and connections.

Every other address is answered by a fake server that Airlock controls on the host, and nothing is forwarded. So when malicious code sends the fake passwords out, Airlock captures the request, stolen data included: the theft is proven, not guessed. For a pull request, Airlock also runs the code from before the change in a second machine and shows only what is new. A registry can still receive data; Airlock flags it.

An AI agent on Vultr Serverless Inference (mimo-v2.6-flash, best of 13 models tested) then investigates. If code only misbehaves when called, the agent has Airlock call it from a clean copy, so that theft counts as proof too. Every claim cites an event. Meanwhile a required GitHub check holds the pull request at "pending", so it cannot merge. If the theft is proven, Airlock rejects the pull request by itself and posts the evidence. Otherwise a person decides, and only a person can approve.

Our regression (our stealers, two real packages, three PRs; 11 × 3) scored 33 of 33, stolen data captured on all 18 malicious runs. It is not a detection rate. On 24 real packages, run twice: no false alarms, and 6 runs inconclusive where an install failed. A real review takes about 46 seconds and 2.5 cents of AI.

Signed-in judges can click Run self-test to score five known packages live.
