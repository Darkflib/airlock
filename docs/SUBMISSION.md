# lablab submission fields

Limits from the form: title 5–50 characters; short description 50–255; long description 600–2000 characters and at least 100 words. Counts are checked by `scripts/check-submission.py`.

## Submission Title

Airlock: Dependency Detonation Chamber

## Short Description

Airlock tests a new pull request, npm package or PyPI package in a throwaway Vultr virtual machine with fake passwords. It captures what the code tries to steal as proof, an AI explains it, and nothing merges until a person approves.

## Long Description

Passing tests do not show what an install script did. In CI, install scripts and test hooks run with real passwords, real tokens and full internet access, and reviewers rarely read a lockfile change.

Airlock runs every untrusted code change in its own disposable computer. Paste a GitHub pull request, an npm or PyPI package, or a package file. A new virtual machine starts in about 0.7 seconds on a Vultr VX1 server. It has its own Linux kernel and can reach only the package registries. Inside are fake passwords, each with a token unique to the run. The install and the tests run as a normal user, while a watcher records every program, file read, DNS lookup and connection.

Every other address is answered by a fake server that Airlock controls on the host, and nothing is forwarded. So when malicious code sends the fake passwords out, Airlock captures the full request: the theft is proven, not guessed. For a pull request, Airlock also runs the code from before the change in a second machine and shows only what is new.

An AI agent on Vultr Serverless Inference (mimo-v2.6-flash, chosen by testing all 13 models) then looks inside the same machine and writes a verdict. Every claim links to the event that proves it. During the run, the Airlock GitHub App keeps the pull request at "pending", and the repository requires this check, so it cannot be merged. Only a person clicking Approve or Reject sets the final result and posts the evidence on the pull request.

In our test set, 10 npm and PyPI packages ran through the real system 3 times each: 30 of 30 correct. The stolen data was captured on all 15 malicious runs, and the 15 safe runs had no false alarms. A typical run takes 12 to 31 seconds. The AI cost for the whole project was about $1.45 (4 November).

Judges can click Run self-test to test five known packages live and see the score.
