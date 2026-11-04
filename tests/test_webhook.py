import hashlib
import time
from datetime import datetime, timezone
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web.app import create_app
from tests.test_auth import cfg
from types import SimpleNamespace

from tests.test_pr import META, FakeGitHub, PermGitHub, fake_pr_analyse

SECRET = "hook-secret"


def pr_event(action="opened", repo="Darkflib/airlock-demo", sha="abc1234def", number=3):
    return {"action": action, "repository": {"full_name": repo}, "sender": {"login": "Darkflib"},
            "pull_request": {"number": number, "head": {"sha": sha}}}


def deliver(c, payload, event="pull_request", delivery="d1", secret=SECRET):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return c.post("/api/github/webhook", content=body, headers={
        "X-GitHub-Event": event, "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig,
        "Content-Type": "application/json"})


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    def _make(secret=SECRET, gh=None):
        app = create_app(store=Store(tmp_path / "w.db"), analyse=fake_pr_analyse, auth=cfg(tmp_path),
                         github=gh or FakeGitHub(), webhook_secret=secret)
        return TestClient(app, base_url="http://airlock.test")
    return _make


def test_signed_pr_opened_starts_a_held_run_without_sign_in(make):
    gh = FakeGitHub()
    with make(gh=gh) as c:
        r = deliver(c, pr_event())
        assert r.status_code == 202
        run_id = r.json()["id"]
        # nobody is signed in: the run is visible to the owner later, not to this client
        assert c.get(f"/api/runs/{run_id}").status_code == 401
        wait_done_store(c, run_id)
        run = c.app.state.runner.store.get_run(run_id)
    assert run["target"].endswith("(webhook)") and run["submitted_by"] == "Darkflib" and run["demo"]
    assert run["meta"]["head_sha"] == META["head_sha"]
    assert [x[2] for x in gh.calls if x[0] == "status"] == ["pending", "pending"]  # held; nobody decided


def test_bad_or_missing_signature_is_refused(make):
    with make() as c:
        assert deliver(c, pr_event(), secret="wrong").status_code == 401
        r = c.post("/api/github/webhook", json=pr_event(), headers={"X-GitHub-Event": "pull_request"})
        assert r.status_code == 401
        assert c.app.state.runner.store.list_runs() == []


def test_disabled_without_a_secret(make):
    with make(secret="") as c:
        assert deliver(c, pr_event(), secret="").status_code == 404


def test_ping_and_other_events_start_nothing(make):
    with make() as c:
        assert deliver(c, {"zen": "hi"}, event="ping").json() == {"ok": True}
        assert "ignored" in deliver(c, pr_event(action="closed"), delivery="d2").json()
        assert "ignored" in deliver(c, {"action": "created"}, event="issue_comment", delivery="d3").json()
        assert "ignored" in deliver(c, pr_event(repo="someone/else"), delivery="d4").json()
        assert c.app.state.runner.store.list_runs() == []


def test_redelivery_and_same_commit_do_not_run_twice(make):
    with make() as c:
        run_id = deliver(c, pr_event()).json()["id"]
        assert "ignored" in deliver(c, pr_event()).json()  # GitHub redelivering d1
        wait_done_store(c, run_id)
        r = deliver(c, pr_event(action="synchronize"), delivery="d2")  # same head commit again
        assert r.json() == {"ignored": "already analysed", "run": run_id}
        assert deliver(c, pr_event(action="synchronize", sha="new5678"), delivery="d3").status_code == 202


def test_daily_cap(make, monkeypatch):
    monkeypatch.setenv("AIRLOCK_WEBHOOK_DAILY_RUNS", "1")
    with make() as c:
        assert deliver(c, pr_event()).status_code == 202
        assert deliver(c, pr_event(sha="other"), delivery="d2").status_code == 429


class CommentGitHub(PermGitHub):
    """Knows each login's access, and the PR's current head commit."""
    def __init__(self, perms=None, head=META["head_sha"], author="Darkflib"):
        super().__init__(perms or {"Darkflib": "admin", "dev-writer": "write", "reader": "read"})
        self.head, self.author = head, author

    async def pull_request(self, owner, repo, number):
        return SimpleNamespace(head_sha=self.head, author=self.author)

    def replies(self):
        return [x[2] for x in self.calls if x[0] == "comment" and x[2].startswith("@")]


def now_iso(offset=0.0):
    return datetime.fromtimestamp(time.time() + offset, timezone.utc).isoformat().replace("+00:00", "Z")


def pr_comment(body, login="Darkflib", kind="User", number=3, at=None):
    return {"action": "created", "repository": {"full_name": "Darkflib/airlock-demo"},
            "issue": {"number": number, "pull_request": {"url": "x"}},
            "comment": {"body": body, "created_at": at or now_iso(1)}, "sender": {"login": login, "type": kind}}


def analysed(c):
    run_id = deliver(c, pr_event()).json()["id"]
    wait_done_store(c, run_id)
    return run_id


def test_comment_approves_from_github(make):
    gh = CommentGitHub()
    with make(gh=gh) as c:
        run_id = analysed(c)
        r = deliver(c, pr_comment("Checked the evidence.\n/airlock approve the vendored tgz is ours", "dev-writer"),
                    event="issue_comment", delivery="c1")
        assert r.json() == {"decided": "approved", "run": run_id}
        run = c.app.state.runner.store.get_run(run_id)
    assert run["decided_by"] == "dev-writer" and run["decision_note"] == "the vendored tgz is ours"
    assert run["meta"]["decided_via"] == "github"
    assert [x[2] for x in gh.calls if x[0] == "status"][-1] == "success"
    assert gh.replies() == []   # the evidence comment says who approved; no extra reply


def test_comment_needs_write_access_and_replies_why(make):
    gh = CommentGitHub()
    with make(gh=gh) as c:
        run_id = analysed(c)
        r = deliver(c, pr_comment("/airlock approve", "reader"), event="issue_comment", delivery="c1")
        assert "write access" in r.json()["refused"]
        assert c.app.state.runner.store.get_run(run_id)["decision"] is None
    assert gh.replies()[0].startswith("@reader not recorded:")
    assert "success" not in [x[2] for x in gh.calls if x[0] == "status"]


def test_comment_before_the_head_is_analysed(make):
    gh = CommentGitHub(head="feedbeef1234")
    with make(gh=gh) as c:
        analysed(c)   # an older commit
        r = deliver(c, pr_comment("/airlock reject"), event="issue_comment", delivery="c1")
    assert "hasn't analysed the head commit `feedbee`" in r.json()["refused"]


def test_other_comments_bots_and_redeliveries_are_ignored(make):
    gh = CommentGitHub()
    with make(gh=gh) as c:
        run_id = analysed(c)
        assert "ignored" in deliver(c, pr_comment("LGTM, but /airlock approve later?"), event="issue_comment",
                                    delivery="c1").json()
        assert "ignored" in deliver(c, pr_comment("/airlock approve", "airlocksandbox[bot]", "Bot"),
                                    event="issue_comment", delivery="c2").json()
        issue = pr_comment("/airlock approve")
        del issue["issue"]["pull_request"]   # a plain issue, not a PR
        assert "ignored" in deliver(c, issue, event="issue_comment", delivery="c3").json()
        assert deliver(c, pr_comment("/AIRLOCK Reject"), event="issue_comment", delivery="c4").json()["decided"] == "rejected"
        assert deliver(c, pr_comment("/airlock approve"), event="issue_comment", delivery="c4").json() == {
            "ignored": "already handled"}
        r = deliver(c, pr_comment("/airlock approve"), event="issue_comment", delivery="c5")
        assert r.json()["refused"].endswith("already rejected by @Darkflib.")
        assert c.app.state.runner.store.get_run(run_id)["decision"] == "rejected"


def test_author_can_be_barred_from_approving_their_own_pr(make, monkeypatch):
    monkeypatch.setenv("AIRLOCK_SELF_APPROVAL", "0")
    gh = CommentGitHub()
    with make(gh=gh) as c:
        analysed(c)   # META's author is Darkflib
        r = deliver(c, pr_comment("/airlock approve"), event="issue_comment", delivery="c1")
        assert "author can't approve" in r.json()["refused"]
        assert deliver(c, pr_comment("/airlock reject"), event="issue_comment", delivery="c2").json()["decided"] == "rejected"


def test_command_in_a_pr_review_body(make):
    gh = CommentGitHub()
    with make(gh=gh) as c:
        run_id = analysed(c)
        review = {"action": "submitted", "repository": {"full_name": "Darkflib/airlock-demo"},
                  "pull_request": {"number": 3}, "review": {"body": "/airlock approve ok", "state": "commented",
                                                            "commit_id": META["head_sha"], "submitted_at": now_iso(1)},
                  "sender": {"login": "dev-writer", "type": "User"}}
        assert "ignored" in deliver(c, {**review, "action": "edited"}, event="pull_request_review", delivery="r0").json()
        assert deliver(c, review, event="pull_request_review", delivery="r1").json() == {"decided": "approved", "run": run_id}


def wait_done_store(c, run_id, timeout=5.0):
    import time
    store = c.app.state.runner.store
    end = time.time() + timeout
    while time.time() < end and store.get_run(run_id)["status"] in ("queued", "running"):
        time.sleep(0.02)
