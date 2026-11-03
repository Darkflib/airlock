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
- Web UI: live at https://airlock.darkflib.dev. Sign-in is GitHub OAuth (1Password "Airlock OAuth") with an allowlist: `Darkflib` is always allowed, and judges and others go in `~/.config/airlock/allowed_users` on the host. Manage it with `scripts/allow.sh [list | add <login> | rm <login>]`; changes take effect immediately, including revoking. For people whose logins we don't know (judges), `scripts/invite.sh new|list|revoke` mints a signed sign-up link; accounts it admits are appended to `allowed_users` tagged `# invite <id>`. Guests (everyone not in `AIRLOCK_ALLOWED_USERS`) are capped per rolling 24 h: `AIRLOCK_USER_DAILY_RUNS` (15) each and `AIRLOCK_GLOBAL_DAILY_RUNS` (150) between them. Deploy the working tree with `scripts/deploy.sh`. It pipes secrets from 1Password over SSH stdin into a mode-600 env file and restarts the `airlock-web` unit and Caddy. Logs: `journalctl -u airlock-web -f`.
- Unit tests run locally: `uv run pytest`. Evals: `evals/run.sh`; results go in `evals/RESULTS.md`.
- Model per role lives in `roles.toml`. Change it only with eval evidence.

## Code map

- `airlock/sandbox.py`: `Workspace`, one microVM per run (default-deny egress, canaries, limits, tracer). Every exec is an event.
- `airlock/guest/trace.js`: Node preload tracer that logs dotfile reads, outbound requests, canary payloads (in plaintext) and spawned processes. It lives in world-readable `/opt/airlock-trace` so the package user can load it.
- `airlock/guest/watch.py`: root watcher in the guest, standard library only and language-agnostic. fanotify sees every program run and dotfile opened (with pid); a DNS forwarder logs every lookup (with pid); polling `/proc/net/tcp` sees connections; `/proc/net/snmp` counts connects refused too fast to see. Its log lives in root-only `/opt/airlock`. The package installs as the unprivileged `node` user, so it can't tamper with the watcher.
- `airlock/sinkhole/addon.py`: mitmproxy addon run by the `airlock-sinkhole` unit (SOCKS5 on 127.0.0.1:1080). Every sandbox's TCP is routed through it. Requests to 198.18.0.0/15 are answered by the addon itself and logged with their full body to `~/.local/share/airlock/sinkhole.jsonl`; nothing is ever connected upstream. Registries pass through untouched.
- Egress per run: each `Workspace` gets its own fake /24 in 198.18.0.0/15. The guest DNS (watcher) answers non-allowlisted names with addresses in it, and the microsandbox policy allows only that /24 plus the registries, with TLS inspection trusting mitmproxy's CA upstream. Real internet destinations are still denied by microsandbox. Set `AIRLOCK_SINKHOLE=off` to disable.
- `airlock/events.py`: typed events. `events_from_sinkhole`, `events_from_trace` (Node tracer) and `WatchTranslator` (watcher) turn raw records into events. Exfiltration has one report per destination, in order of preference: captured payload (PROVEN), then Node tracer, then the watcher's inference. The watcher infers exfiltration when one process, or siblings under one parent, both reads a canary and reaches out. Root and npm's own activity are ignored.
- `airlock/guard.py`: redacts likely prompt injection from untrusted text before it reaches the model.
- `airlock/agent.py`: triage loop with a hard turn budget; the last turn forces `finish`.
- `airlock/pipeline.py`: acquire → unpack → detonate under the tracer → agent triage → report.
- `airlock/cli.py`: `airlock analyse <file.tgz | npm-spec>`.
- `airlock/github.py`: GitHub App client (`airlocksandbox`). It signs a JWT with the App key, mints a one-hour installation token scoped to one repo, fetches the PR, tarball and diff, and posts comments and commit statuses. The key comes from 1Password "Airlock Github App" via `scripts/deploy.sh`.
- PR runs: `airlock analyse https://github.com/o/r/pull/N`, or paste the URL in the UI. The control plane fetches the head (the VM has no GitHub access), and the VM runs `npm ci` and `npm test` as `node` under detonation before the agent triages. **Nothing is posted until a human decides.** Then `airlock/prcomment.py` builds the comment, and a status of `success` or `failure` is set as `<app>[bot]`.
- Demo repo: `Darkflib/airlock-demo` (private). PR #1 is a benign left-pad bump; PR #3 vendors the `colorful-logs` shell stealer; `npm test` passes on both.
- `airlock/store.py`: SQLite for runs and events (`$AIRLOCK_DATA`, default `~/.local/share/airlock`).
- `airlock/web/auth.py`: GitHub OAuth, HMAC-signed session cookie, allowlist re-checked on every request. The app refuses to start without OAuth config (it fails closed). Session, share and invite tokens share the session secret and carry a kind (`k`) so one can't stand in for another. A share token (`/s/<token>`, cookie `airlock_share`) allows only GETs of the runs and self-test it names.
- `airlock/web/invite.py`: CLI behind `scripts/invite.sh`.
- Self-test: `POST /api/selftests` runs the three `evals/fixtures` tarballs as ordinary runs; `judge_probe` in `airlock/web/app.py` requires payload-proven exfil for stealers and zero containment for the benign one.
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
