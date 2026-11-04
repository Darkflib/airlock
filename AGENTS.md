# AGENTS.md

Instructions for coding agents (Claude Code, Codex, etc.) working in this repo.

## What this is

Airlock: run an untrusted dependency change (PR, new package, version bump) inside a disposable microVM, watch what it actually does, and gate merge on a human approval. Built for the Vultr "Agent Rush" hackathon, Challenge 1 "Blast Radius Zero". Read `PRD.md` before starting non-trivial work; it holds scope, the P0/P1 cut line and the demo script.

Key dates: P0 cut line end of Thu 5 Nov 2026; video and freeze Sat 7 Nov; submission Sun 8 Nov.

## Hard rules

- **Runtime LLM calls go through Vultr Serverless Inference only** (`https://api.vultrinference.com/v1`, OpenAI-compatible). Never wire another provider into the app.
- **Untrusted code only runs inside a microsandbox VM.** Never run a PR's install/build/test on the host or on a dev laptop.
- **Secrets stay on the control plane.** Nothing real (GitHub token, inference key) is copied into a sandbox; sandboxes get canary values only.
- **Secrets come from 1Password.** `.env` holds `op://` references only; run things as `op run --env-file .env -- <cmd>`. Never write a literal secret to any file, log or commit.
- **The host is rebuildable.** Anything done by hand on the box must land in `infra/cloud-init.yaml`, then be proven by a reinstall.
- The repo is private until submission; it must be public (MIT) for judging.

## Environment

- Dev host: `ssh airlock@airlock.darkflib.dev` (Vultr VX1, London, Ubuntu 24.04, KVM). `msb` and `uv` are on PATH.
- Vultr CLI: `op run --env-file .env -- vultr-cli ...`
- microsandbox 0.7.x: Python SDK (`uv add microsandbox`), no daemon. Its storage root (`~/.microsandbox`) must not be group-writable.
- Python with `uv`. Keep dependencies minimal.
- Run anything that needs KVM or the inference key on the host via `scripts/remote.sh "<cmd>"`. It rsyncs the tree to `~/airlock` and pipes the key from 1Password. Example: `scripts/remote.sh "uv run airlock analyse evals/fixtures/left-padder-hostile.tgz"`.
- Web UI: live at https://airlock.darkflib.dev. Sign-in is GitHub OAuth (1Password "Airlock OAuth") with an allowlist: `Darkflib` is always allowed, and judges and others go in `~/.config/airlock/allowed_users` on the host. Manage it with `scripts/allow.sh [list | add <login> | rm <login>]`; changes take effect immediately, including revoking. For people whose logins we don't know (judges), `scripts/invite.sh new|list|revoke` mints a signed sign-up link; accounts it admits are appended to `allowed_users` tagged `# invite <id>`. Guests (everyone not in `AIRLOCK_ALLOWED_USERS`) see their own runs and the owners' demo runs (runs carry a `demo` flag: self-tests, npm specs and PRs from `AIRLOCK_GUEST_REPOS`; owners' uploads and other repos stay private), decide and share only their own, may submit PRs only from `AIRLOCK_GUEST_REPOS` (default `Darkflib/airlock-demo`), and are capped per rolling 24 h: `AIRLOCK_USER_DAILY_RUNS` (15) each and `AIRLOCK_GLOBAL_DAILY_RUNS` (150) between them. Deploy the working tree with `scripts/deploy.sh`. It pipes secrets from 1Password over SSH stdin into a mode-600 env file and restarts the `airlock-web` unit and Caddy. Logs: `journalctl -u airlock-web -f`.
- Unit tests run locally: `uv run pytest`. Evals: `evals/run.sh`; results go in `evals/RESULTS.md`.
- Model per role lives in `roles.toml`. Change it only with eval evidence.

## Code map

- `airlock/sandbox.py`: `Workspace`, one microVM per run (default-deny egress, canaries, limits, tracer). Every exec is an event. `IMAGES` maps ecosystem→OCI image: npm uses `node`, PyPI uses `python:3.12-slim` (the stock `node` image has no pip; `spikes/python_image_probe.py`). The `node` package user and `~/.pypirc` canary are created in whatever image boots.
- `airlock/guest/trace.js`: Node preload tracer that logs dotfile reads, outbound requests, canary payloads (in plaintext) and spawned processes. It lives in world-readable `/opt/airlock-trace` so the package user can load it.
- `airlock/guest/pypi_fetch.py`: stdlib-only, runs in the VM to download a package's sdist from PyPI (sha256-checked) without building it — `pip download` would run `setup.py` as root before detonation, so Airlock downloads the file itself and lets the unprivileged detonation build it.
- `airlock/guest/watch.py`: root watcher in the guest, standard library only and language-agnostic. fanotify sees every program run and dotfile opened (with pid); a DNS forwarder logs every lookup (with pid); polling `/proc/net/tcp` sees connections; `/proc/net/snmp` counts connects refused too fast to see. Its log lives in root-only `/opt/airlock`. The package installs as the unprivileged `node` user, so it can't tamper with the watcher.
- `airlock/sinkhole/addon.py`: mitmproxy addon run by the `airlock-sinkhole` unit (SOCKS5 on 127.0.0.1:1080). Every sandbox's TCP is routed through it. Requests to 198.18.0.0/15 are answered by the addon itself and logged with their full body to `~/.local/share/airlock/sinkhole.jsonl`; nothing is ever connected upstream. Registries pass through untouched.
- Egress per run: each `Workspace` gets its own fake /24 in 198.18.0.0/15. The guest DNS (watcher) answers non-allowlisted names with addresses in it, and the microsandbox policy allows only that /24 plus the registries, with TLS inspection trusting mitmproxy's CA upstream. Real internet destinations are still denied by microsandbox. Set `AIRLOCK_SINKHOLE=off` to disable.
- `airlock/events.py`: typed events. `events_from_sinkhole`, `events_from_trace` (Node tracer) and `WatchTranslator` (watcher) turn raw records into events. Exfiltration has one report per destination, in order of preference: captured payload (PROVEN only when it carries this run's token), then Node tracer (OBSERVED: the guest could forge it), then the watcher's inference. The watcher infers exfiltration when one process, or siblings under one parent, both reads a canary and reaches out. Root and npm's own activity are ignored.
- `airlock/dnsguard.py`: per-run DNS listener on the host (127.0.0.1, ephemeral port). The microsandbox gateway resolver forwards to it (`Network.dns`), so lookups that bypass the guest resolver can't reach the internet: registry names are forwarded to the host resolver, everything else gets NXDOMAIN and becomes a `dns_blocked` event (or proven `canary_exfil` if the label carries the token). Without it, the gateway resolved any name: verified with `spikes/dns_gateway_probe.py`.
- Fail closed: a run starts only when the watcher reports `watch_ready` for `watcher`, `dns` and `fanotify` with no `watch_error` (else `ObservationError`). After detonation, `coverage_gaps` (install failed or timed out, watcher errors or dead) turns a benign verdict into `inconclusive`. A failure after the VM boots destroys it; `vm_destroyed` is emitted only when destruction succeeded. Runs left queued or running are failed at startup. Every VM is labelled with its owner (`AIRLOCK_VM_OWNER`: `web` in `airlock-web.service`, `cli` otherwise), and the web service destroys its own leftover sandboxes at startup (`reap_leftovers`), leaving CLI and regression VMs alone.
- `airlock/guard.py`: redacts likely prompt injection from untrusted text before it reaches the model.
- `airlock/agent.py`: triage loop with a hard turn budget; the last turn forces `finish`. The agent's `exec` always runs as `node`, never root.
- `airlock/pipeline.py`: acquire → unpack → detonate under the tracer → agent triage → report. `analyse` routes by target: PR URL, Python target (`is_python_target`: a `pypi:name==version` spec, or a local sdist `.tar.gz`/`.zip`) via `analyse_python`, else npm. Python detonation is `pip install` from source into a venv as `node`, so `setup.py`/build hooks run. `parse_pypi_spec` only accepts `==` pins (no ranges, no shell syntax); the web layer reuses it to validate specs.
- `airlock/behaviour.py`: base-vs-head behaviour diff. `analyse_pr` detonates the PR's merge base (`GitHubApp.merge_base`) in a second `Workspace` in parallel (`detonate_base`), with its own `EventLog` so base events never reach the run's timeline or its proof. Detonation events become fingerprints without run noise and are compared as sets; one `behaviour_diff` event carries new / unchanged / gone with the head's event ids. The agent's task, the PR comment and the run page (NEW IN THIS PR tags, "only what this PR adds" filter) use it. Pre-existing risky behaviour is flagged, never hidden; an unavailable base leaves the head verdict alone. A PR run uses two VMs.
- `airlock/cli.py`: `airlock analyse <file.tgz | npm-spec | sdist.tar.gz | pypi:name==version | PR URL>`.
- `airlock/github.py`: GitHub App client (`airlocksandbox`). It signs a JWT with the App key, mints a one-hour installation token scoped to one repo, fetches the PR, tarball and diff, and posts comments and commit statuses. The key comes from 1Password "Airlock Github App" via `scripts/deploy.sh`.
- PR runs: `airlock analyse https://github.com/o/r/pull/N`, or paste the URL in the UI. The control plane fetches the head (the VM has no GitHub access), and the VM runs `npm ci` and `npm test` as `node` under detonation before the agent triages. **Before a human decides, only a `pending` `airlock` status is posted** (when the head is fetched, and again with the verdict; `error` if the run fails), via the `gate` hook on `Runner`. Branch protection on `Darkflib/airlock-demo` requires `airlock` to be `success`, so the PR cannot merge until someone approves. Deciding a PR run also requires the signed-in login to have `write` or `admin` on the repo, asked of GitHub with the App's token at decision time (`GitHubApp.permission`; 403 otherwise, 503 if GitHub can't say), so guests can't approve the demo PRs. **Automatic rejection:** when the verdict is in and `store.proven_exfil` is true (a host-captured payload with this run's token, never the model's verdict), `gate_pr` records `rejected` with `meta.auto_decision` and posts `failure` plus the comment itself; nothing is ever approved automatically. `AIRLOCK_AUTO_REJECT=0` turns it off. The decision then sets `success` or `failure` as `<app>[bot]`, and `airlock/prcomment.py` builds the comment.
- Webhook: `POST /api/github/webhook` (public path; every delivery must carry a valid `X-Hub-Signature-256` made with `GITHUB_WEBHOOK_SECRET`, else 401; 404 when no secret is set). `pull_request` `opened`/`reopened`/`synchronize` on a repo in `AIRLOCK_GUEST_REPOS` starts the same PR run as the UI, labelled `(webhook)`, attributed to the event's sender, answered 202 at once. One run per delivery id and per head commit; capped at `AIRLOCK_WEBHOOK_DAILY_RUNS` (50) per rolling 24 h. The secret is the `webhook-secret` field of 1Password "Airlock Github App"; `scripts/deploy.sh` passes it if present. **Don't push to PR #1 before the gate shot**: a push starts a run.
- Demo repo: `Darkflib/airlock-demo` (private). PR #1 is a benign left-pad bump (left at a pending `airlock` status for the gate shot); PR #3 vendors the `colorful-logs` shell stealer; PR #4 vendors `tinystamp`, whose theft is split across innocuous-looking files; `npm test` passes on all three.
- `airlock/store.py`: SQLite for runs and events (`$AIRLOCK_DATA`, default `~/.local/share/airlock`).
- `airlock/web/auth.py`: GitHub OAuth, HMAC-signed session cookie, allowlist re-checked on every request. The app refuses to start without OAuth config (it fails closed). Session, share and invite tokens share the session secret and carry a kind (`k`) so one can't stand in for another. A share token (`/s/<token>`, cookie `airlock_share`) allows only GETs of the runs and self-test it names.
- `airlock/web/invite.py`: CLI behind `scripts/invite.sh`.
- Self-test: `POST /api/selftests` runs the five `evals/fixtures` fixtures (Node stealer, shell stealer, benign npm, Python `setup.py` stealer, benign Python sdist) as ordinary runs; `judge_probe` in `airlock/web/app.py` requires payload-proven exfil for stealers and zero containment for the benign one.
- `airlock/web/`: FastAPI app (submit, SSE event stream, approval decision) and the static UI. Event text is untrusted: insert it with `textContent` only.

## Build log (required)

We keep `docs/BUILD_LOG.md` as raw material for the demo video, slides and write-up. **After any meaningful step, append an entry before you finish your turn**, whether it worked or not. Failures and dead ends are the most valuable entries.

Log an entry when you:

- get something working for the first time (first sandbox boot, first tool call, first containment event)
- hit a bug, surprise or wrong assumption, and what fixed it
- make or change a design decision, and why
- measure something (boot time, latency, eval scores, cost)
- drop or descope something

Format: newest entries at the bottom, under a heading per day.

```markdown
### HH:MM — Short title
**Tried:** what we did.
**Result:** what happened, with numbers or the exact error where there is one.
**So:** the decision or the fix, and what it changes.
Tags: #win #fail #decision #metric #descope #demo
```

Rules for entries:

- Facts, not marketing. Quote the real error message; give the real number.
- Two to six lines. Link to a commit, file or spike instead of pasting large output.
- Tag `#demo` anything worth showing on camera or in a slide.
- Never paste secrets, tokens, or canary values into the log.
- Times are UTC.

## Working conventions

- Small commits with clear messages; push to `origin/main` unless told to branch.
- Spikes live in `spikes/` and may be rough; product code must not import from them.
- When a finding changes the plan, update `PRD.md` as well as the log.
