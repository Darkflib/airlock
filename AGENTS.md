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
- Web UI: live at https://airlock.darkflib.dev (basic auth; user `airlock`, password in 1Password as "Airlock web - hackathon"). Deploy the working tree with `scripts/deploy.sh`. It rsyncs, writes secrets to mode-600 files on the host from 1Password via SSH stdin, installs `infra/Caddyfile` and the `airlock-web` systemd unit, and restarts both. Logs: `journalctl -u airlock-web -f`.
- Unit tests run locally: `uv run pytest`. Evals: `evals/run.sh`; results go in `evals/RESULTS.md`.
- Model per role lives in `roles.toml`. Change it only with eval evidence.

## Code map

- `airlock/sandbox.py`: `Workspace`, one microVM per run (default-deny egress, canaries, limits, tracer). Every exec is an event.
- `airlock/guest/trace.js`: Node preload tracer that logs dotfile reads, outbound requests, canary payloads and spawned processes.
- `airlock/events.py`: typed events, plus translating trace lines into containment events.
- `airlock/guard.py`: redacts likely prompt injection from untrusted text before it reaches the model.
- `airlock/agent.py`: triage loop with a hard turn budget; the last turn forces `finish`.
- `airlock/pipeline.py`: acquire → unpack → detonate under the tracer → agent triage → report.
- `airlock/cli.py`: `airlock analyse <file.tgz | npm-spec>`.
- `airlock/store.py`: SQLite for runs and events (`$AIRLOCK_DATA`, default `~/.local/share/airlock`).
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
