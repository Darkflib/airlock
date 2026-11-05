"""Regressions for docs/AUTH_REVIEW-2026-11-04.md: the review's reproductions, asserting the fixed
behaviour (spikes/auth_review_20261104.py asserts the original bugs)."""
import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from airlock.store import Store
from airlock.web import auth as authmod
from airlock.web.app import create_app
from airlock.web.auth import SESSION_COOKIE, SHARE_COOKIE, AuthConfig, session_token, share_payload, sign
from tests.test_pr import META, FakeGitHub

SECRET = b"review-only-secret"
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class GitHub(FakeGitHub):
    """Write access for everyone; `pause` holds the next permission lookup until `release`."""
    def __init__(self, author="someone-else"):
        super().__init__()
        self.entered, self.release, self.pause, self.author = asyncio.Event(), asyncio.Event(), False, author

    async def permission(self, owner, repo, user):
        if self.pause:
            self.pause = False
            self.entered.set()
            await self.release.wait()
        return "write"

    async def pull_request(self, owner, repo, number, files=True):
        return SimpleNamespace(head_sha=META["head_sha"], author="Darkflib" if number == 99 else self.author)


async def never(*a, **k):
    raise AssertionError("no analysis in these tests")


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def seed(store, run_id, author="someone-else", number=3, user="Darkflib", demo=False, finished=None):
    store.create_run(run_id, f"Darkflib/airlock-demo#{number}", submitted_by=user, demo=demo)
    store.update_run(run_id, status="done", verdict="benign", finished=finished or time.time() - 60,
                     meta={**META, "author": author, "number": number})


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    allowed = tmp_path / "allowed_users"
    allowed.write_text("judge-a\njudge-b\n")
    cfg = AuthConfig("cid", "secret", SECRET, "https://airlock.test", frozenset({"darkflib"}), allowed, False)
    store = Store(tmp_path / "a.db")

    def client(gh=None, user="Darkflib"):
        app = create_app(store=store, analyse=never, auth=cfg, github=gh or GitHub(), webhook_secret="hook")
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://airlock.test")
        if user:
            c.cookies.set(SESSION_COOKIE, session_token(SECRET, user))
        return c
    return SimpleNamespace(store=store, cfg=cfg, client=client)


async def webhook(c, payload, event):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"hook", body, hashlib.sha256).hexdigest()
    return await c.post("/api/github/webhook", content=body, headers={"x-hub-signature-256": sig, "x-github-event": event})


def command(body="/airlock approve", number=3, at=None, login="Darkflib"):
    return {"action": "created", "repository": {"full_name": "Darkflib/airlock-demo"},
            "issue": {"number": number, "pull_request": {"url": "x"}},
            "comment": {"body": body, "created_at": iso(at or time.time())}, "sender": {"login": login, "type": "User"}}


def statuses(gh):
    return [x[2] for x in gh.calls if x[0] == "status"]


# A1: decisions and supersession are claimed atomically after the GitHub await

async def test_a1_first_decision_stands_when_a_slower_one_resumes(env):
    gh = GitHub()
    seed(env.store, "old")
    async with env.client(gh) as c:
        gh.pause = True
        approval = asyncio.create_task(c.post("/api/runs/old/decision", json={"decision": "approved"}))
        await asyncio.wait_for(gh.entered.wait(), 2)
        assert (await c.post("/api/runs/old/decision", json={"decision": "rejected"})).status_code == 200
        gh.release.set()
        r = await approval
    assert r.status_code == 409 and "already rejected" in r.json()["detail"]
    assert env.store.get_run("old")["decision"] == "rejected" and statuses(gh) == ["failure"]


async def test_a1_newer_run_during_the_await_wins(env):
    gh = GitHub()
    seed(env.store, "old")
    async with env.client(gh) as c:
        gh.pause = True
        approval = asyncio.create_task(c.post("/api/runs/old/decision", json={"decision": "approved"}))
        await asyncio.wait_for(gh.entered.wait(), 2)
        seed(env.store, "new")
        env.store.update_run("new", status="running")
        gh.release.set()
        r = await approval
    assert r.status_code == 409 and "new" in r.json()["detail"]
    assert env.store.get_run("old")["decision"] is None and "success" not in statuses(gh)


# A2: a command is bound to the commit and the result its author saw

async def test_a2_review_of_an_old_commit_does_not_decide_the_new_head(env):
    gh = GitHub()
    seed(env.store, "current")
    p = {"action": "submitted", "repository": {"full_name": "Darkflib/airlock-demo"}, "pull_request": {"number": 3},
         "review": {"body": "/airlock approve", "commit_id": "OLD-COMMIT", "submitted_at": iso(time.time())},
         "sender": {"login": "Darkflib", "type": "User"}}
    async with env.client(gh, user=None) as c:
        r = (await webhook(c, p, "pull_request_review")).json()
    assert "your review is of `OLD-COM`" in r["refused"] and env.store.get_run("current")["decision"] is None


async def test_a2_comment_written_before_the_result_does_not_decide_it(env):
    gh = GitHub()
    seed(env.store, "current", finished=time.time())
    async with env.client(gh, user=None) as c:
        r = (await webhook(c, command(at=time.time() - 30), "issue_comment")).json()
        assert "published after your comment" in r["refused"]
        assert (await webhook(c, command(at=time.time() + 1), "issue_comment")).json()["decided"] == "approved"


# A3: ambiguous legacy runs stay private

async def test_a3_legacy_upload_label_is_not_shown_to_guests(env):
    env.store.create_run("legacy-upload", "acme-internal", submitted_by="Darkflib")
    env.store.update_run("legacy-upload", status="done", demo=None, evidence=["private-source-evidence"])
    async with env.client(user="judge-b") as c:
        assert (await c.get("/api/runs/legacy-upload")).status_code == 404
    assert env.store.get_run("legacy-upload")["demo"] == 0


# A4: a command decides only its own PR's run, with that PR's author

async def test_a4_command_on_another_pr_sharing_the_head_finds_no_run(env, monkeypatch):
    monkeypatch.setenv("AIRLOCK_SELF_APPROVAL", "0")
    gh = GitHub()
    seed(env.store, "other-pr", number=3)
    async with env.client(gh, user=None) as c:
        r = (await webhook(c, command(number=99), "issue_comment")).json()
    assert "hasn't analysed" in r["refused"] and env.store.get_run("other-pr")["decision"] is None


async def test_a4_self_approval_uses_the_prs_current_author(env, monkeypatch):
    monkeypatch.setenv("AIRLOCK_SELF_APPROVAL", "0")
    gh = GitHub(author="Darkflib")   # the PR now says Darkflib wrote it, whatever the run cached
    seed(env.store, "run", author="someone-else")
    async with env.client(gh, user=None) as c:
        r = (await webhook(c, command(), "issue_comment")).json()
    assert "author can't approve" in r["refused"]


# Additional gaps

async def test_signed_in_guest_can_read_through_a_share_but_not_decide(env):
    seed(env.store, "guest-private", user="judge-a")
    token = sign(SECRET, share_payload(["guest-private"], by="judge-a"))
    async with env.client(user="judge-b") as c:
        assert (await c.get("/api/runs/guest-private")).status_code == 404
        c.cookies.set(SHARE_COOKIE, token)
        assert (await c.get("/api/runs/guest-private")).status_code == 200
        assert (await c.post("/api/runs/guest-private/decision", json={"decision": "approved"})).status_code == 403
        assert (await c.post("/api/runs/guest-private/share")).status_code == 403


async def open_stream(env, run_id, cookies, clock):
    """The real event-stream endpoint for `run_id`, driven directly, with the web module's clock replaced."""
    from starlette.requests import Request
    from airlock.events import EventLog
    from airlock.web import app as web
    app = create_app(store=env.store, analyse=never, auth=env.cfg, github=GitHub())
    header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    request = Request({"type": "http", "method": "GET", "scheme": "https", "path": f"/api/runs/{run_id}/events",
                       "query_string": b"", "headers": [(b"cookie", header.encode())], "server": ("airlock.test", 443)})
    request.state.user, request.state.share = authmod.credentials(env.cfg, request)
    log = EventLog(on_emit=lambda ev: env.store.add_event(run_id, ev))
    app.state.runner.live[run_id] = log
    endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/runs/{run_id}/events")
    web.time = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
    return await endpoint(run_id, request), log


@pytest.mark.parametrize("revoke", ["share", "session"])
async def test_live_stream_stops_when_its_only_grant_is_revoked(env, monkeypatch, revoke):
    """B1 (recheck): the stream re-checks this run's read rule, not just that some session is valid."""
    from airlock.web import app as web
    monkeypatch.setattr(web, "time", web.time)   # restored after the test
    session = session_token(SECRET, "judge-b")
    share = share_payload(["private"], by="judge-a")
    if revoke == "share":   # judge-b reads judge-a's private run only through the share
        seed(env.store, "private", user="judge-a")
        cookies = {SESSION_COOKIE: session, SHARE_COOKIE: sign(SECRET, share)}
    else:                   # judge-b's own run, through the session alone
        seed(env.store, "private", user="judge-b")
        cookies = {SESSION_COOKIE: session}
    clock = [0.0]
    response, log = await open_stream(env, "private", cookies, clock)
    body = response.body_iterator
    try:
        log.emit("note", "BEFORE")
        assert "BEFORE" in await asyncio.wait_for(anext(body), 2)
        if revoke == "share":
            env.cfg.revoke_share(share["id"])
        else:
            env.cfg.revoke_session(authmod.verify(SECRET, session))
        clock[0] = 16
        log.emit("note", "AFTER REVOCATION")
        with pytest.raises(StopAsyncIteration):   # ends without sending the event that arrived
            await asyncio.wait_for(anext(body), 2)
    finally:
        await body.aclose()


async def test_live_stream_keeps_going_while_access_holds(env, monkeypatch):
    from airlock.web import app as web
    monkeypatch.setattr(web, "time", web.time)
    seed(env.store, "mine", user="judge-b")
    clock = [0.0]
    response, log = await open_stream(env, "mine", {SESSION_COOKIE: session_token(SECRET, "judge-b")}, clock)
    body = response.body_iterator
    try:
        clock[0] = 16
        log.emit("note", "STILL HERE")
        assert "STILL HERE" in await asyncio.wait_for(anext(body), 2)
    finally:
        await body.aclose()


class FailingPending(GitHub):
    async def status(self, owner, repo, sha, state, description, target_url):
        if state == "pending":
            raise ConnectionError("github down")
        await super().status(owner, repo, sha, state, description, target_url)


async def test_comment_does_not_claim_the_merge_is_held_when_the_status_failed(env, monkeypatch):
    async def analyse(target, *, events, on_pr=None, **_):
        await on_pr(META)
        return SimpleNamespace(verdict="benign", evidence=[], model="m", meta=META)
    gh = FailingPending()
    app = create_app(store=env.store, analyse=analyse, github=gh)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://airlock.test") as c:
        run_id = (await c.post("/api/runs", data={"spec": "https://github.com/Darkflib/airlock-demo/pull/3"})).json()["id"]
        for _ in range(200):
            if env.store.get_run(run_id)["status"] in ("done", "error"):
                break
            await asyncio.sleep(0.01)
    comments = [x[2] for x in gh.calls if x[0] == "comment"]
    assert comments and all("could not set the `airlock` check" in b for b in comments)
    assert not any("stays pending" in b for b in comments)
