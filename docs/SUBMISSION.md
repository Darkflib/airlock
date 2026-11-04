# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock: Dependency Detonation Chamber

## Short Description

Airlock runs an untrusted pull request or npm package in a disposable Vultr microVM with fake credentials and no internet beyond the registries. It proves what the code tried to steal, AI explains it, and a human approves before anything reaches GitHub.

## Long Description

A passing test suite doesn't rule out a malicious install script. Postinstall scripts and test hooks run with real tokens and open network access in CI, and nobody reads the diff of a lockfile bump.

Airlock gives every untrusted dependency change its own disposable computer. Paste a GitHub pull request URL, an npm package or a tarball. A fresh microVM with its own kernel boots in about 0.7 seconds on a Vultr VX1 instance, which exposes KVM. The VM holds canary credentials carrying a token unique to the run, and can reach nothing but the package registries. npm ci and npm test run as an unprivileged user while a root watcher records the programs started, credential files opened, DNS lookups and connections.

Every other destination, DNS included, is answered by Airlock on the host and never forwarded. When a stealer posts the canary credentials, Airlock captures the exact payload, so exfiltration is proven rather than guessed.

A tool-calling agent on Vultr Serverless Inference (mimo-v2.6-flash, chosen by benchmarking all 13 catalogue models) investigates inside the same VM, as the same unprivileged user, and gives a verdict that cites the events behind it. While it runs, the Airlock GitHub App holds the PR at a pending status that branch protection requires, so it cannot merge. Only a human click on Approve or Reject sets the final status and posts the evidence on the PR.

On a small fixture regression through the real pipeline: 18 of 18 correct, with exfiltration proven by payload on every malicious run and zero containment events on benign ones. The median run takes 10 to 17 seconds end to end. Inference for the whole build cost about $1.15 as of 3 November.

Judges can click Run self-test to detonate three known packages and watch them scored live.
