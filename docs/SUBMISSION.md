# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock: Dependency Detonation Chamber

## Short Description

Airlock runs an untrusted PR, npm or PyPI package in a disposable Vultr microVM with fake credentials and no internet beyond the registries. It proves what the code tried to steal, AI explains it, and the PR stays blocked until a human approves.

## Long Description

A passing test suite doesn't rule out a malicious install script. Postinstall scripts and test hooks run with real tokens and open network access in CI, and nobody reads the diff of a lockfile bump.

Airlock gives every untrusted dependency change its own disposable computer. Paste a GitHub pull request URL, an npm or PyPI package, or a tarball. A fresh microVM with its own kernel boots in about 0.7 seconds on a Vultr VX1 instance, which exposes KVM. The VM holds canary credentials carrying a token unique to the run, and can reach nothing but the package registries. npm ci and npm test (or pip install for PyPI) run as an unprivileged user while a root watcher records the programs started, credential files opened, DNS lookups and connections.

Every other destination, DNS included, is answered by Airlock on the host and never forwarded. When a stealer posts the canary credentials, Airlock captures the exact payload, so exfiltration is proven rather than guessed. For a PR, its merge base is detonated in a second VM, so the review shows what the PR adds.

A tool-calling agent on Vultr Serverless Inference (mimo-v2.6-flash, chosen by benchmarking all 13 catalogue models) investigates inside the same VM, as the same unprivileged user, and gives a verdict that cites the events behind it. While it runs, the Airlock GitHub App holds the PR at a pending status that branch protection requires, so it cannot merge. Only a human click on Approve or Reject sets the final status and posts the evidence on the PR.

On a small regression through the real pipeline (10 npm and PyPI targets, including three demo PRs, three runs each): 30 of 30 correct, exfiltration proven by payload on all 15 malicious runs and zero containment events on benign ones. Median run time is 12 to 31 seconds end to end. Inference for the whole build cost about $1.45 as of 4 November.

Judges can click Run self-test to detonate five known npm and PyPI packages and watch them scored live.
