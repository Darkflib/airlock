# Authentication and authority review — 4 November 2026

Reviewed commit `cd889d5` with a clean application working tree. Focus: who authenticates, whose authority is used, which run/PR/commit receives a decision, and disposition of the two earlier reviews. This is a code review with safe local reproductions, not a production penetration test. No application changes, deployment, live GitHub writes, real credentials, or untrusted package execution were involved.

The earlier fixes materially improve the boundary, but approval concurrency and GitHub command targeting still allow decisions to apply beyond the reviewer's intended object. The demo visibility migration also has a remaining disclosure path.

## Findings

### A1. [P1] Decisions and supersession checks are not atomic across GitHub awaits

References: `airlock/web/app.py:536–557`, `582–607`; `airlock/store.py:119–140`.

`apply_decision` checks the loaded run's decision and whether a newer run exists, then awaits GitHub permission. When that await returns, it unconditionally writes its stale snapshot and posts the status. Another decision or a new run can complete in between. The same ordering problem exists around reposting, gate updates and status retries; `post_to_pr` has no final ownership check or serialization.

Reproduced with a fake permission lookup paused on an asyncio event:

- Approval starts and waits; rejection completes and posts `failure`; approval resumes, returns **200**, replaces the recorded rejection with approval and posts **success**. Both requests were authorized, but the documented immutable first decision did not stand.
- Approval starts and waits; a newer run of the same repository/SHA is created and posts `pending`; old approval resumes and posts **success**, overriding the newer review. The sequential stale-run test does not cover this interleaving.

This does not give a GitHub reader write permission. It lets an already-authorized action exceed the state/version against which it was accepted and defeats the latest-review gate.

Fix: serialize state transitions and outbound status writes per repository/SHA, including automatic gates and reposts. After permission lookup, re-read and atomically claim an undecided, current run using a conditional update/transaction. Protect the status write through completion/retries so an older in-flight write cannot land after a newer one. A lock only around the initial check is insufficient; an in-process lock also needs an explicit single-worker deployment constraint or a durable equivalent.

### A2. [P1] A review of an old commit can approve a newer head as the reviewer

Reference: `airlock/web/app.py:374–408`.

The `pull_request_review` handler extracts the review body but ignores `review.commit_id`. It fetches the PR's current head and selects that run. If a push and its analysis finish before a delayed review delivery is processed, `/airlock approve` from a review of commit A approves commit B instead, attributed to the original reviewer. The signature and repository permission checks authenticate the actor, but do not bind that actor's approval to the commit reviewed.

Reproduced with a correctly signed local webhook whose review and event head named `OLD-COMMIT`, a fake GitHub current head `abc1234def`, and a completed run for that current head: the handler returned `{"decided":"approved","run":"current"}` and posted success for **abc1234def**. GitHub's [review response documents the associated `commit_id`](https://docs.github.com/en/rest/pulls/reviews).

Fix: bind review commands to `review.commit_id`, require it to match the current PR head and selected run, and reject stale reviews with an explanation. For ordinary issue-comment commands, consider an explicit expected SHA/run identifier because those bodies have no intrinsic reviewed-commit binding. Recheck currentness as part of A1's serialized transition.

### A3. [P1] Legacy upload labels can be migrated into guest-visible demo runs

References: `airlock/store.py:76–84`; `airlock/web/app.py:219–226`.

`backfill_demo` infers public registry provenance from a display label: any label without `#` or a disqualifying slash and not ending in `.tgz` is treated as demo material. Before the demo column existed, the upload endpoint accepted any gzip filename, saved a `.tgz` on disk, but stored the **original filename** as the run target. A private upload named `acme-internal` or `acme-internal.tar.gz` therefore matches the migration's public-package heuristic. On upgrade/startup its owner-created analysis becomes readable to every allowlisted guest.

Reproduced by seeding a completed legacy owner run named `acme-internal` with `demo=NULL` and private evidence, then constructing the app: startup set **demo=1**, and a guest GET returned **200** with the private evidence. The historical upload behavior was checked in commit `255a83d`. This is conditional on matching legacy data; production database contents were not inspected. Newly submitted uploads correctly have `demo=False`.

Fix: default ambiguous legacy records to private. Use trusted provenance where available, or explicitly curate the old demo runs. A valid-looking npm label alone cannot distinguish a registry submission from an upload given the old filename rules. Also repair already-backfilled records: changing the NULL-only migration does not undo an incorrect `demo=1`.

### A4. [P2] Commands can decide another PR's run and bypass the intended self-approval check

References: `airlock/web/app.py:400–408`, `577–580`; `airlock/store.py:134–140`.

`run_of_commit` keys only on repository and head SHA, not PR number. A command on PR B can select a run from PR A when the two PRs share a head commit. The self-approval check uses A's cached author, and posting uses A's PR number. With `AIRLOCK_SELF_APPROVAL=0`, B's author can approve this shared SHA if A has a different author; the handler consults the wrong author and comments on the wrong PR. Separate PR contexts can also have different bases and hence different analysis context.

Reproduced with a completed run for PR #3 authored by someone else, PR #99's current head matching that SHA, and a signed command from #99's author. With self-approval disabled, the response approved **PR #3's run**, and the fake status became success for the shared SHA. The repository write requirement still applies.

Fix: select a run by repository, PR number and commit; validate the current PR's author when enforcing self-approval. Because statuses are shared by repository/SHA, define how different PR contexts sharing a SHA interact; PR-number filtering alone cannot make a shared status enforce independent PR-specific policies.

## Additional usability and operational gaps

- **A valid share link fails for a signed-in guest who lacks ordinary access.** `auth.py:339–345` returns early for sessions, never setting share state; `readable` then rejects the guest. Reproduced: identical share cookie gives anonymous **200**, signed-in other guest **404**. Evaluate session and share read grants together, retaining ordinary user checks for mutations; possession of a share must never grant write authority.
- **Revocation is checked when an SSE connection opens.** `app.py:495–520` does not recheck session/share expiry, revocation or allowlist removal during a live stream. Do not describe revocation as ending existing streams immediately without implementing rechecks or bounded reconnects. This was identified by inspection, not exercised against a live server.
- **Pending-write failure is surfaced locally, but GitHub comments still claim the gate holds.** `gate_pr` records `gate.synced=False` and a prominent local error, which is a real mitigation. `build_progress`/`how_to_decide` still assert pending/merge blocking independently of that result. Make the PR comment reflect failed synchronization too. GitHub API failure can preserve an earlier success; local application state cannot revoke that remotely.

## Earlier review disposition

| Earlier issue | Current assessment |
| --- | --- |
| Guests could decide/share arbitrary owner runs or submit arbitrary App repositories | Fixed on ordinary web paths: ownership checks, restricted guest repositories and GitHub write permission checks are present and tested. GitHub comment commands intentionally use repository permission without requiring Airlock membership. |
| All owner runs visible to guests | Fixed for new runs through explicit demo metadata, with the legacy migration exception A3. |
| Model-selected exec as root | Fixed: every agent exec passes `as_user=PKG_USER`. Root setup and observation remain part of the guest trust base; image/kernel privilege escalation was not tested. |
| Watcher startup/late failure and test timeout | Addressed: required readiness, guarded observer threads, malformed DNS handling, and coverage checks after investigation including interrupted tests. Existing regression tests pass. |
| Long VM names and misleading cleanup success | Addressed in source and fake-workspace tests; startup reaping is scoped by owner label. No independent KVM crash/rebuild check performed. |
| Wrong-run or guest-tracer evidence called PROVEN | Addressed: exact run token and host sinkhole/DNS provenance required; tracer evidence remains weaker. Subnet reservation is process-local. |
| Unquoted npm spec execution | Addressed through tighter validation and shell quoting. |
| Initial prompt screening / invented citations | Improved: initial task and read errors are screened; bad citations get a correction opportunity and then a visible warning. Citation existence is not semantic proof; pattern screening is explicitly limited. |
| Pending status, stale green and overlapping reviews | Pending/error updates and local sync-failure warnings implemented. Sequential stale-run checks work, but A1 remains. Required branch-rule/App-source configuration was not verified live. |
| Absolute homepage network/observation claims | Updated in local source to registry exceptions and observed activities. Deployed version was not inspected. |
| Pagination/snapshot consistency, retention, backpressure, overall deadline, fallback and self-host setup | Still documented limitations in `TECHNICAL_REPORT.md`; not silently treated as fixed. |

## Authority model checked

- OAuth proves the GitHub login; session cookies are HMAC signed, HttpOnly, Secure in production, SameSite=Lax and expiry checked. OAuth state is signed and matched before exchange. Token kinds prevent share/invite substitution for a session.
- Environment allowlist members are owners; file/invite members are guests. Both must remain allowlisted for new authenticated requests. Owners can read all runs; guests can read their own and owners' demo runs. Sharing delegates named read access to an anonymous bearer; it is separately revocable.
- Web decisions require owner-or-submitter status, then GitHub write/admin for PRs. GitHub command decisions intentionally skip the web ownership rule and use the comment sender's current repository permission. Both outward paths act through the App installation token, not the OAuth token, and attribute the decision to the human login.
- Automatic rejection is based on current-run host proof, not the model verdict; it never auto-approves. Self-approval is allowed by default and can be disabled. These are explicit policy choices, not accidental guest privilege grants.

## Validation and reproducibility

- Full existing suite: **138 passed in 5.66 s**. Initial restricted run: 133 passed, five failures from denied loopback binds; rerun with loopback enabled passed all tests.
- Six deterministic safe reproductions in `spikes/auth_review_20261104.py`: decision race, supersession race, stale review, cross-PR command, legacy visibility, signed-in share. Run from the repo root with `PYTHONPATH=. .venv/bin/python spikes/auth_review_20261104.py`. Assertions describe the observed bugs; this is review evidence, not a passing security regression suite.
- Reproductions use temporary databases, synthetic identities/secrets, in-process ASGI HTTP and fake GitHub responses. No VM is started, external API called, or package command executed.
- Review additions consist only of this report, the reproduction script and the required build-log entry. No fixes were deployed. Prioritize A1–A3 before trusting the service with private analyses and merge approvals.

## Fixes (4 Nov, after review)

All four findings and the three gaps are fixed; `tests/test_auth_review.py` turns each reproduction into a regression test that asserts the fixed behaviour (the spike still asserts the original bugs, so it now fails at each scenario).

| Finding | Fix |
| --- | --- |
| A1 decision and supersession races | `Store.claim_decision`: one conditional `UPDATE … WHERE decision IS NULL AND NOT EXISTS (newer run of the commit)` after the permission await; losers get 409. Auto-reject uses it too. All status/comment writes for a repo/SHA run under a per-commit `asyncio.Lock` and re-check "latest run" inside it (`gate_writes`, `post_to_pr`), retries included. Single uvicorn worker documented in `airlock-web.service`. |
| A2 old review approving the new head | Review commands must name the current head in `review.commit_id`; every command must be written (`created_at` / `submitted_at`) after the selected run finished, otherwise it is refused with a reply. |
| A3 legacy uploads backfilled as demo | `backfill_demo` marks only self-tests and guest-repo PRs as demo; ambiguous labels stay private. Production checked: every guest-visible non-PR, non-self-test run is `left-pad@1.3.0` (the public npm package); no upload was exposed, so nothing needed repair. |
| A4 cross-PR selection and self-approval author | `run_of_commit` filters by PR number (webhook dedupe too, so each PR gets its own run); self-approval checks the PR's current author from GitHub. Statuses stay shared per SHA: the latest run of that SHA, from any PR, sets it. |
| Share link for a signed-in guest | Middleware records a valid share alongside a session; `readable` accepts runs the share names. Mutations still require ownership (tested: 403 on decide and share). |
| Revocation during live streams | The event stream re-reads the cookies against current revocations and the allowlist, then re-applies this run's read rule, at least every 15 s and before sending each event it receives and the final `done`. (The first version only checked that some session was valid, which let a signed-in viewer keep a stream opened through a revoked share: recheck B1, fixed below.) |
| PR comment claiming the gate holds after a failed status write | Comments take `held`; when the pending write failed they say the check may still show an earlier result and not to merge on it. |
