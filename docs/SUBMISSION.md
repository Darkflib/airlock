# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock: Dependency Detonation Chamber

## Short Description

Airlock runs an untrusted pull request or npm package inside a disposable Vultr microVM with fake credentials and no real internet. It proves what the code tried to steal, an AI explains it, and a human approves before anything reaches GitHub.

## Long Description

"CI passed" is how most supply-chain attacks get in: a postinstall script or test hook runs with real tokens and open network access, and nobody reads the diff of a lockfile bump.

Airlock gives every untrusted dependency change its own disposable computer. Paste a GitHub pull request URL, an npm package or a tarball. A fresh microVM with its own kernel boots in about 0.7 seconds on a Vultr VX1 instance, which exposes KVM. The VM holds canary credentials carrying a token unique to the run, and it has no real internet. npm ci and npm test run as an unprivileged user while a root watcher records every program started, every credential file read and every connection attempt.

Outbound traffic goes to a sinkhole that answers requests itself and never forwards them. When a stealer posts the canary credentials, Airlock captures the exact payload, so exfiltration is proven rather than guessed.

A tool-calling agent on Vultr Serverless Inference (mimo-v2.6-flash, chosen by benchmarking all 13 catalogue models) investigates inside the same VM and gives a verdict in which every claim links to the event that proves it. Nothing is posted until a human clicks Approve or Reject. Then the Airlock GitHub App sets a commit status and posts the evidence on the PR.

Results: 18 of 18 correct on the real pipeline, with exfiltration proven by payload on every malicious target and zero containment events on benign ones. The median run takes 10 to 17 seconds end to end. Inference for the whole build cost $1.15.

Judges can click Run self-test to detonate three known packages and watch them scored live.
