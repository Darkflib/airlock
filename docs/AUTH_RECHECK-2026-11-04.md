# Authority fix recheck — 4 November 2026

Independent recheck of `aba4d25`, particularly fix commit `aebf7ef`, against [the authority review](AUTH_REVIEW-2026-11-04.md). Application working tree was clean. No application changes, production requests, deployments, real GitHub writes or untrusted package execution.

## Main findings disposition

| Finding | Recheck |
| --- | --- |
| A1 — decision/supersession races | **Fixed for the supported single-worker deployment.** Conditional SQL claims reject conflicting/stale decisions after permission awaits. Per-repository/SHA locks cover gate, decision and repost writes through retries. Existing new regression tests pass. An additional independent interleaving paused an old approval inside the outbound status call, then started a newer run: outbound order was `success, pending, pending`, leaving the newer review pending. |
| A2 — old review approves current head | **Fixed for the reproduced case.** A mismatching review `commit_id` is refused. Commands must also postdate the selected run's completion. Tests cover stale reviews and comments written before the result. |
| A3 — ambiguous legacy uploads become demo-visible | **Fixed in migration code.** Ambiguous labels now stay private. The builder records a production audit finding no incorrectly exposed uploads, so no repair was needed; that production audit was not independently repeated here. The migration still deliberately updates NULL flags only. |
| A4 — wrong PR's run selected | **Fixed for the reproduced case.** Command lookup and webhook deduplication include PR number, and command self-approval checks use GitHub's current PR author. Statuses remain shared per repository/SHA; the explicitly documented policy is that the latest run of that SHA, across PRs, controls the check. This does not create independent PR-specific statuses. |

Signed-in share reads now work without granting decide/share authority. Failed status synchronization is reflected in GitHub comments. Live-stream revocation has been implemented, but its authorization check has the remaining gap below.

## Remaining finding

### B1. [P2] A signed-in share viewer keeps streaming after the share is revoked

References: `airlock/web/auth.py:274–277`; `airlock/web/app.py:550–567`.

The stream's new `still_allowed` check returns true for **any valid allowlisted session**, without checking whether that user can read the streamed run. A guest who opens another guest's private run through a share link retains that session after the share is revoked. Ordinary requests now correctly return 404, but the existing stream remains authorized by `bool(user)` and continues sending private evidence even after its periodic credential recheck. Share expiry has the same issue.

Independently reproduced with a temporary database, synthetic cookies, an in-process API request and the actual stream response generator:

1. `judge-b` with a valid session and share for `judge-a`'s private run: normal GET **200**.
2. Revoke that share: normal GET **404**.
3. Advance the stream's clock beyond the recheck interval, then emit a new private event: the stream yields that event. `still_allowed` still returns **True** because `judge-b` remains signed in.

The test replaces only the web module's clock with a deterministic test clock and restores it afterward. It does not open a real network stream or call production.

Fix: refresh credentials **and re-evaluate run-level read authorization** against the current user/share before continuing the stream. A valid session alone is insufficient. Do not use stale `request.state.share` for that evaluation. Check before emitting queued/replayed events and the final run payload as appropriate, so revocation cannot be bypassed by a queued event or final `done` message. Add coverage for a signed-in guest whose only grant is the revoked share; the current regression checks session revocation alone.

## Validation and limits

- Full current suite: **148 passed in 5.91 s**, with loopback permitted for fake DNS tests.
- Additional independent safe checks: outbound write ordering passes; B1 reproduces. Retained in `spikes/auth_recheck_20261104.py`; run from the repository root with `PYTHONPATH=. .venv/bin/python spikes/auth_recheck_20261104.py`. The B1 assertion records the remaining bug, not desired behavior.
- No independent verification of deployed commit, branch rules, production migration audit or KVM isolation. Per-commit locks require the documented single uvicorn worker. A remote API outage can still preserve an earlier green status; that limitation is now disclosed locally and in PR comments.

The four main findings can be closed within those deployment and policy constraints. B1 remains open; the previous fix table's claim that share revocation ends live streams is too broad for signed-in share viewers.

## B1 fix (4 Nov)

The stream no longer asks "is any session valid"; it asks "may these credentials still read this run". `still_readable` (in the stream endpoint) re-reads the session and share cookies through `auth.credentials` (current allowlist, session and share revocations, expiry), then applies the same `can_read` rule as ordinary requests to the current run, with the fresh share rather than `request.state.share`. Anonymous share viewers are checked with `share_allows` for the stream path. It runs at most 15 s apart, always after an event arrives and before it is sent, on keepalives, and before the final `done` payload, so a queued event or the final run can't slip out after revocation. The clock starts when the stream starts sending. `auth.still_allowed` was removed.

Regression tests in `tests/test_auth_review.py`: a signed-in guest whose only grant is a share, with the share revoked (stream ends without sending the event that arrived after revocation); a guest's own run with the session revoked; and a stream that keeps going while access holds. `spikes/auth_recheck_20261104.py` now stops at its B1 step (`StopAsyncIteration` from the stream), as expected for a script that asserts the bug. 150 tests pass.
