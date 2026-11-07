# After judging: clean-up

The demo host costs real money and won't stay up for long after the event, but the repo and the YouTube video will. Do these in order: point the public pages away from the host first, then revoke access, then remove DNS, and only then destroy the machines.

## 1. Public pages stop pointing at the live site

- [ ] **README:** change "Try it" to point at `docs/SELF_HOSTING.md`, and say that the hosted demo ran during the hackathon and has been retired (with the date). Check the "30 seconds for judges" section and the judging-criteria table for links to `airlock.darkflib.dev` and `/verify`.
- [ ] **Receipts stay checkable offline.** The `/verify` page goes with the host, but `airlock verify <bundle> --key <key>` works against the key pinned in `docs/SIGNING_KEY.md`. Add a line there saying the key was retired on that date and that its private half was destroyed with the host.
- [ ] **Cover image:** remove `airlock.darkflib.dev` from the footer of `assets/airlock-cover.html` and re-render it (the headless Chrome command is in BUILD_LOG, 5 Nov). Slide 1 has the URL too, so update the published deck as well.
- [ ] **YouTube description:** add "The live demo ran during the hackathon; to run your own, see `docs/SELF_HOSTING.md`." (A YouTube video can't be replaced after upload, so the YouTube cut should use a cover without the URL from the start.)
- [ ] **lablab:** if the submission can still be edited, change the demo link to the repo.
- [ ] **AGENTS.md:** the Environment section describes the live host. Mark it as retired.

## 2. Revoke access

- [ ] **GitHub App `airlocksandbox`:** uninstall it from `Darkflib/airlock-demo`, revoke its private key and turn off the webhook. Then delete the App, or keep it disabled if the old bot comments should stay attributed to it.
- [ ] **`airlock-demo` branch protection:** remove the rule that requires the `airlock` check, or nothing can ever merge there. Then archive the repo; its README already warns that PRs #3, #4 and #9 carry stealers.
- [ ] **GitHub OAuth App ("Airlock OAuth"):** delete it.
- [ ] **Vultr Serverless Inference key:** revoke it.
- [ ] **Vultr API keys** (`VULTR_API_KEY`, and `VULTR_DNS_API_KEY` for darkflib.dev): rotate them if they were made for this project.
- [ ] **1Password:** archive "Airlock", "Airlock OAuth" and "Airlock GitHub App" once everything above is done.

Share links, invites, sessions and the allowlist all die with the host. Nothing to do for those.

## 3. Keep what's worth keeping

- [ ] **Back up the host's data** (`~/.local/share/airlock`: SQLite runs, receipts, the sinkhole log) to a local archive. It holds canary values only, no real secrets, but it does hold judges' GitHub logins. Keep it private, and delete it once it's no longer needed.
- [ ] The eval results are already in `evals/results/`. Nothing else in the repo depends on the host.

## 4. DNS, before the machines

Remove DNS records **before** destroying the boxes. Vultr reuses IPs, and a record left pointing at a released address could end up serving someone else's machine under our name (subdomain takeover).

- [ ] Remove `airlock.darkflib.dev` (A and AAAA) from the darkflib.dev zone.
- [ ] Check that the outside catcher's records are gone: the `catch.darkflib.dev` NS delegation and the `ns-catch.darkflib.dev` glue. `scripts/catcher.sh down` removes them with the box; `scripts/catcher.sh status` shows what's left.

## 5. Destroy the machines

- [ ] **The VX1 host** (London): delete the instance. The signing key's private half and the GitHub App key copy go with it.
- [x] **The outside catcher** (`vc2-1c-1gb`, London): destroyed 7 Nov.
- [ ] **Anything left that bills:** snapshots, automatic backups, block storage, reserved IPs, and any leftover instance from rebuild tests.
- [ ] **Billing:** check a day later that nothing is still being charged.
