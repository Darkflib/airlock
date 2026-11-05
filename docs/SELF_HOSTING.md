# Running your own Airlock

This walks through standing up Airlock from nothing: a KVM host, sign-in, the GitHub App and a protected branch. It takes about an hour, most of it in GitHub's settings pages. The reference instance, `airlock.darkflib.dev`, was built this way. On 5 November we followed steps 1, 4, 5 and 7 on a fresh Vultr instance: cloud-init took a few minutes, the deploy 14 seconds, and the five self-test packages and a PR all came out right on the first run.

You will end up with:

- a host that boots one microVM per run (microsandbox on KVM), with the egress sinkhole and the web control plane as systemd services behind Caddy;
- sign-in with GitHub, limited to an allowlist;
- a GitHub App that holds each PR at a `pending` `airlock` status until someone decides, and branch protection that makes that status a merge requirement.

## What you need

| | Notes |
| --- | --- |
| **A Linux host with `/dev/kvm`** | Ubuntu 24.04. Every run is a real microVM, so the host must expose hardware virtualisation; most cloud VMs don't. We use a Vultr VX1 (`vx1-g-4c-16g-240s`: 4 vCPU, 16 GB). Each run takes 2 vCPU and 2 GB, and two run at once. |
| **A domain name** | An A record for the host, e.g. `airlock.example.com`. Caddy gets the certificate. |
| **Vultr Serverless Inference** | An API key. The agent's model calls go only to `https://api.vultrinference.com/v1`; [`roles.toml`](../roles.toml) picks the model. |
| **A GitHub account** | To create an OAuth App (sign-in) and a GitHub App (the merge gate). |
| **1Password and its CLI (`op`)** | The deploy scripts read every secret with `op read` and pass the values to the host over SSH stdin, so no secret is written on your laptop. If you use another secret manager, see [Without 1Password](#without-1password). |
| **On your laptop** | `ssh`, `rsync`, `uv`, `gh` (optional, for checks). |

## 1. Create the host

[`infra/cloud-init.yaml`](../infra/cloud-init.yaml) builds the host from a blank Ubuntu 24.04 image. **Before you use it, replace the `ssh_authorized_keys` entry with your own public key**; the one in the file is ours.

Every tool it installs is pinned to an exact version. microsandbox itself comes later, with the Python environment, at the version in `uv.lock`. It creates an `airlock` user (in the `kvm` group, with passwordless sudo, which the deploy script needs to install the services) and locks down SSH to keys only. It also enables `ufw` for ports 22, 80 and 443, and installs `uv`, mitmproxy (the sinkhole), microsandbox and Caddy.

On Vultr, pass it as user data when you create the instance. Elsewhere, any cloud-init capable image works. Then check the host:

```bash
ssh airlock@airlock.example.com 'cat /var/log/airlock-kvm'
```

You want `kvm: present`. (`msb doctor` runs at the first deploy, which stops if it fails.) If KVM is missing, the host can't run Airlock: pick an instance type with nested virtualisation or bare metal.

Point your domain's A record at the host now; Caddy needs it to resolve before it can get a certificate.

## 2. Sign-in: a GitHub OAuth App

GitHub → Settings → Developer settings → **OAuth Apps** → New OAuth App:

| Field | Value |
| --- | --- |
| Homepage URL | `https://airlock.example.com` |
| Authorization callback URL | `https://airlock.example.com/auth/callback` |

Generate a client secret. Save the client ID and secret in 1Password.

Airlock only asks GitHub who you are; access is decided by its own allowlist (step 6).

## 3. The merge gate: a GitHub App

GitHub → Settings → Developer settings → **GitHub Apps** → New GitHub App. The App is the identity that posts the `airlock` status and the PR comment, as `<app-name>[bot]`.

**Webhook**

| Field | Value |
| --- | --- |
| Webhook URL | `https://airlock.example.com/api/github/webhook` |
| Webhook secret | a long random string (`openssl rand -hex 32`), saved in 1Password |

The webhook starts a run on every push to a PR and receives `/airlock approve` and `/airlock reject` comments. Every delivery must carry GitHub's signature made with this secret, or it is refused. To run without the webhook (runs started from the web UI only), uncheck **Active** and leave the secret empty.

**Repository permissions.** Only these; everything else stays "No access":

| Permission | Level | Used for |
| --- | --- | --- |
| Metadata | read | Required for every App; looking up whether a commenter has write access |
| Contents | read | Downloading the PR head and merge-base archives |
| Pull requests | write | Reading the PR, its files and diff; posting the evidence comment |
| Commit statuses | write | The `airlock` status that branch protection requires |
| Issues | read | Needed to receive `issue_comment` events (the `/airlock` commands) |

The App can't push code, merge, change settings or read secrets.

**Subscribe to events:** Pull request, Issue comment, Pull request review.

**Where can this GitHub App be installed?** "Only on this account".

Create it, then:

1. Note the **App ID** (top of the App's page) and save it in 1Password.
2. **Generate a private key**. GitHub downloads a `.pem` file. Store its contents in 1Password (as a text field or a document), then delete the download.
3. **Install App** → choose **Only select repositories** → pick the repos Airlock should guard.

## 4. Configure `.env`

```bash
cp .env.example .env
```

Edit `.env`:

- **The secrets are `op://` references, not values.** Point each at the vault, item and field where you saved it in steps 2 and 3, plus your Vultr Inference key.
- **The settings are plain values.** `AIRLOCK_HOST` is the SSH target, `AIRLOCK_PUBLIC_URL` is `https://<your domain>`, `AIRLOCK_OWNERS` lists your GitHub login(s), and `AIRLOCK_GUEST_REPOS` lists the repos whose PRs run automatically. None of these has a default: without an owner list or the public URL the service refuses to start, and without guest repos there are no automatic PR runs and guests can't submit PRs.

`.env` is gitignored. Check each reference resolves before deploying:

```bash
op read "$(sed -n 's/^GITHUB_APP_ID="\(.*\)"$/\1/p' .env)"
```

## 5. Deploy

SSH to the host once by its DNS name, so its host key is known (the deploy runs ssh and rsync non-interactively):

```bash
ssh airlock@airlock.example.com true
```

Then:

```bash
scripts/deploy.sh
```

This:

1. rsyncs the working tree to `~/airlock` on the host;
2. reads the secrets with `op read` and pipes them over SSH to [`scripts/install-web.sh`](../scripts/install-web.sh) on the host. That script writes them only to `~/.config/airlock/web.env` (mode 600), generates a session secret once, installs the systemd units and the Caddyfile, and restarts the services.

It refuses to run if a secret is missing, or if `AIRLOCK_PUBLIC_URL` or `AIRLOCK_OWNERS` isn't set. It ends with:

```
active
active
active
app health: http 200
```

The three `active` lines are `airlock-sinkhole`, `airlock-web` and `caddy`. The service logs the access settings it started with; check them with `journalctl -u airlock-web | grep 'access:'`. On a fresh host the first deploy took 14 seconds, Python environment included. The first run on a new host pulls the VM images (`node`, `python:3.12-slim`) and is slower than later ones. Run it again after every change; it is safe to repeat.

## 6. Let people in

Owners (`AIRLOCK_OWNERS`) can always sign in. Everyone else needs to be on the allowlist, which the app re-reads on every request:

```bash
scripts/allow.sh add some-login      # allow a GitHub login
scripts/allow.sh rm some-login       # revoke; also ends their sessions
scripts/allow.sh                     # list
```

For people whose logins you don't know (judges, a workshop), mint an invite link:

```bash
scripts/invite.sh new --days 30 --max 50 --id workshop
scripts/invite.sh revoke workshop    # stops the link and removes everyone it admitted
```

Accounts other than owners are **guests**. Guests see their own runs and the owners' demo runs, submit PRs only from `AIRLOCK_GUEST_REPOS`, and are capped per day (see [Configuration](#configuration)).

## 7. Check it works

1. **Sign in** at `https://airlock.example.com` and click **Run self-test**. It analyses five known packages (three credential stealers, two benign) and scores each live. All five should pass: each stealer with exfiltration **proven** by a payload the sinkhole captured, each benign package with zero containment events. This exercises KVM, the watcher, the sinkhole and the model in about a minute.
2. **Open a test PR** in a repo where the App is installed (and listed in `AIRLOCK_GUEST_REPOS`). Within a few seconds the PR shows an `airlock` status of `pending` and a comment linking to the live run. When the run ends, the comment shows the evidence; approve or reject on the run page, or comment `/airlock approve` on the PR.

## 8. Make the status a merge requirement

Until branch protection requires it, the `airlock` status is advice. The status only appears in GitHub's list after it has been posted once, so do this after step 7's test PR.

In the repo: Settings → **Branches** → Add branch protection rule (or a ruleset) for your default branch:

- **Require status checks to pass before merging** → search for `airlock` → select it. **Pick the entry with your App's name as the source**, not "any source". Otherwise anyone who can write a commit status, for example with a personal token, could post a green `airlock` themselves.
- **Do not allow bypassing the above settings** (classic: "Include administrators"), so the gate applies to you too.

Check it from the CLI:

```bash
gh api repos/OWNER/REPO/branches/main/protection -q '.required_status_checks.checks, .enforce_admins.enabled'
```

You want your App's id next to `airlock`, and `true`.

## Configuration

`install-web.sh` writes the secrets and the settings above to `~/.config/airlock/web.env`. Everything else has a default; to change one, add a line to `web.env` on the host and run `sudo systemctl restart airlock-web`. (The next deploy rewrites `web.env` from `.env`, so add these to `install-web.sh` if you want them kept.)

| Variable | Default | What it does |
| --- | --- | --- |
| `AIRLOCK_AUTO_REJECT` | `1` | Reject a PR automatically when exfiltration is proven by a captured payload. `0` leaves every decision to a person. Nothing is ever approved automatically. |
| `AIRLOCK_SELF_APPROVAL` | `1` | `0` stops a PR's author approving their own change. |
| `AIRLOCK_USER_DAILY_RUNS` | `15` | Runs per guest per rolling 24 h (owners are exempt). |
| `AIRLOCK_GLOBAL_DAILY_RUNS` | `150` | Runs between all guests per rolling 24 h. |
| `AIRLOCK_WEBHOOK_DAILY_RUNS` | `50` | Automatic PR runs per rolling 24 h. |
| `AIRLOCK_SLOTS` | core count | Runs at once. Each VM has 2 vCPU and 2 GB; a PR run uses two VMs. CPU is the limit, not memory: past one per core, runs only get slower. |
| `AIRLOCK_QUEUED_PER_SLOT` | `10` | Guests are turned away (429, with `Retry-After`) once this many runs per slot are waiting. Owners and webhook PRs always get in. |
| `AIRLOCK_GUEST_UNFINISHED` | `5` | Runs one guest may have waiting or in progress at once (5 is one self-test). |
| `AIRLOCK_QUEUE_MAX_AGE` | `3600` | Seconds a queued run may wait and still be resumed after a restart. |
| `AIRLOCK_DRAIN_S` | `75` | On stop, seconds runs in progress get to finish; anything left is retried on the next start. Keep it under the unit's `TimeoutStopSec` (100). |
| `AIRLOCK_RUN_DEADLINE` | `600` | Seconds a run may take end to end, inference included. |
| `AIRLOCK_MAX_EVENTS` | `5000` | Events kept per run; past it the run is marked incomplete. |
| `AIRLOCK_LOG_BUDGET` | `33554432` | Bytes read from each in-VM log (32 MB). |
| `AIRLOCK_RETAIN_DAYS` | `30` | Days before runs that aren't demo runs are deleted with their events. |
| `AIRLOCK_DATA` | `~/.local/share/airlock` | Database, sinkhole log, uploads in flight. |

The model for each role is in [`roles.toml`](../roles.toml); [`evals/`](../evals/) is how we chose it.

## Operating it

- **Logs:** `journalctl -u airlock-web -f` (and `-u airlock-sinkhole`, `-u caddy`).
- **Versions:** the VM images are pinned by digest in `airlock/sandbox.py`, microsandbox by `uv.lock`, and uv, mitmproxy and Caddy in cloud-init. `scripts/check-pins.sh` compares a host with all of them. To move a pin, change it there, deploy, run the check, and rerun the self-test.
- **Updating:** pull, then `scripts/deploy.sh`. A restart fails any run in progress and releases its PR as `error` on GitHub (push again to rerun); startup also removes any VMs those runs left behind.
- **What is kept:** each run's evidence lives in SQLite. Uploads are deleted when their run ends. Runs that aren't demo runs are deleted after `AIRLOCK_RETAIN_DAYS`. The sinkhole log is rotated daily, keeping one previous file.
- **Rebuilding:** the host holds nothing that can't be recreated except `~/.local/share/airlock` (run history) and `~/.config/airlock` (allowlist, invites, share-link ledger, session secret). Copy those two directories if you want to keep them, recreate the instance from cloud-init, and deploy.
- **Running the CLI on the host** (for debugging): `scripts/remote.sh uv run airlock analyse left-pad@1.3.0` syncs the tree and runs a package analysis there with the inference key from 1Password. A PR also needs the App's credentials, so run it on the host with the service's environment: `ssh airlock@airlock.example.com 'set -a; . ~/.config/airlock/web.env; set +a; cd ~/airlock && uv run airlock analyse https://github.com/OWNER/REPO/pull/N'`. The CLI never posts to GitHub.

## Without 1Password

`install-web.sh` reads six lines on stdin, in this order: the inference API key, the OAuth client ID, the OAuth client secret, the App ID, the App private key (base64, one line) and the webhook secret (may be empty). `deploy.sh` is a thin wrapper that produces those lines with `op read`. To use another secret manager, write the same wrapper around its CLI. Keep the values on stdin rather than in a file or a command-line argument, where they could end up in shell history or process listings.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `deploy.sh` stops at `op read … authorization timeout` | 1Password is locked, or its CLI integration is off (1Password → Settings → Developer). Nothing on the host changes when the secrets can't be read. |
| The site has no certificate | DNS doesn't point at the host yet, or ports 80/443 are blocked. `journalctl -u caddy` says which. |
| Sign-in loops back to the login page | The OAuth App's callback URL doesn't match `AIRLOCK_PUBLIC_URL` + `/auth/callback` exactly. |
| `the Airlock GitHub App is not installed on owner/repo` | Install the App on that repo (step 3). |
| A PR gets no status and no run | The repo isn't in `AIRLOCK_GUEST_REPOS`, or the webhook isn't active. The App's Advanced tab lists recent deliveries and the response to each. |
| A self-test stealer shows malicious but not **proven** | The sinkhole isn't running: `systemctl status airlock-sinkhole`, and check `~/.mitmproxy/mitmproxy-ca-cert.pem` exists. |
| Runs fail with an `ObservationError` | The in-VM watcher didn't start. Usually KVM or microsandbox: run `msb doctor` on the host, and `scripts/check-pins.sh` from your laptop. |
