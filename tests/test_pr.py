import asyncio
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from airlock.github import parse_pr_url
from airlock.prcomment import build_comment
from airlock.store import Store
from airlock.web.app import create_app
from tests.test_web import wait_done

PR = "https://github.com/Darkflib/airlock-demo/pull/3"
META = {"kind": "pr", "owner": "Darkflib", "repo": "airlock-demo", "number": 3, "title": "feat: coloured startup log",
        "author": "Darkflib", "html_url": PR, "head_sha": "abc1234def", "head_ref": "feat/x", "base_ref": "main",
        "files": [{"filename": "vendor/x.tgz", "status": "added", "additions": 0, "deletions": 0}]}


async def fake_pr_analyse(target, *, events, on_pr=None, **_):
    if on_pr:
        await on_pr(META)
    events.emit("canary_exfil", "POST https://t.evil.invalid/v1 carried the canary credentials", stage="detonate",
                proven=True, payload="token=npm_AIRLOCKCANARYABC", method="POST", url="https://t.evil.invalid/v1")
    await asyncio.sleep(0.01)
    return SimpleNamespace(verdict="malicious", evidence=["exfil [E1]"], model="m", meta=META)


class FakeGitHub:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    async def status(self, owner, repo, sha, state, description, target_url):
        if self.fail:
            raise PermissionError("not installed")
        self.calls.append(("status", sha, state, description, target_url))

    async def comment(self, owner, repo, number, body):
        self.calls.append(("comment", number, body))
        return f"https://github.com/{owner}/{repo}/pull/{number}#issuecomment-1"


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    monkeypatch.setenv("AIRLOCK_PUBLIC_URL", "https://airlock.test")

    def _make(gh):
        return TestClient(create_app(store=Store(tmp_path / "p.db"), analyse=fake_pr_analyse, github=gh))
    return _make


def test_parse_pr_url():
    assert parse_pr_url(PR) == ("Darkflib", "airlock-demo", 3)
    assert parse_pr_url(PR + "/files") is None
    assert parse_pr_url("https://evil.com/Darkflib/airlock-demo/pull/3") is None


def test_pr_run_holds_merge_and_posts_decision_only_after_human(make):
    gh = FakeGitHub()
    with make(gh) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        run = wait_done(c, run_id)
        assert run["target"] == "Darkflib/airlock-demo#3" and run["meta"]["kind"] == "pr"
        # before a human decides, only `pending` statuses leave: no verdict state, no comment
        assert [(x[0], x[2]) for x in gh.calls] == [("status", "pending"), ("status", "pending")]
        assert "malicious" in gh.calls[1][3]
        out = c.post(f"/api/runs/{run_id}/decision", json={"decision": "rejected", "note": "steals creds"}).json()
    decided = gh.calls[2:]
    assert [x[0] for x in decided] == ["status", "comment"]
    assert decided[0][1:3] == ("abc1234def", "failure") and decided[0][4] == f"https://airlock.test/runs/{run_id}"
    body = decided[1][2]
    assert "**MALICIOUS**, rejected" in body and "**PROVEN**" in body and "AIRLOCKCANARYABC" in body
    assert out["meta"]["posted"]["comment_url"].endswith("#issuecomment-1")


def test_failed_pr_run_sets_error_status(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    async def broken(target, *, events, on_pr=None, **_):
        await on_pr(META)
        raise RuntimeError("VM failed")
    gh = FakeGitHub()
    with TestClient(create_app(store=Store(tmp_path / "e.db"), analyse=broken, github=gh)) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        run = wait_done(c, run_id)
    assert run["status"] == "error"
    assert [x[2] for x in gh.calls] == ["pending", "error"]


def test_failed_post_keeps_decision_and_records_error(make):
    with make(FakeGitHub(fail=True)) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        wait_done(c, run_id)
        out = c.post(f"/api/runs/{run_id}/decision", json={"decision": "approved"}).json()
        events = c.get(f"/api/runs/{run_id}").json()["events"]
    assert out["decision"] == "approved" and "not installed" in out["meta"]["posted"]["error"]
    assert events[-1]["kind"] == "error"


def test_comment_for_clean_pr_says_nothing_observed():
    run = {"verdict": "benign", "decision": "approved", "decided_by": "x", "meta": META, "evidence": [], "model": "m"}
    body = build_comment(run, [], "https://airlock.test/runs/1")
    assert "Nothing suspicious was observed" in body and "approved by @x" in body


class StickyGitHub(FakeGitHub):
    """GitHub that already holds an earlier success for the commit and rejects pending writes."""
    def __init__(self):
        super().__init__()
        self.state = "success"

    async def status(self, owner, repo, sha, state, description, target_url):
        if state == "pending":
            raise PermissionError("rate limited")
        self.state = state
        await super().status(owner, repo, sha, state, description, target_url)


def test_failed_pending_write_is_surfaced_not_claimed(make):
    gh = StickyGitHub()
    with make(gh) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        run = wait_done(c, run_id)
        events = c.get(f"/api/runs/{run_id}").json()["events"]
        assert run["meta"]["gate"]["synced"] is False and "rate limited" in run["meta"]["gate"]["error"]
        assert any(e["kind"] == "error" and "NOT held" in e["summary"] for e in events)
        assert gh.state == "success"  # unchanged, and the run says so instead of pretending
        c.post(f"/api/runs/{run_id}/decision", json={"decision": "rejected"})
    assert gh.state == "failure"  # the decision re-syncs it


def test_older_run_of_same_commit_cannot_decide_or_post(make):
    gh = FakeGitHub()
    with make(gh) as c:
        old = c.post("/api/runs", data={"spec": PR}).json()["id"]
        wait_done(c, old)
        new = c.post("/api/runs", data={"spec": PR}).json()["id"]
        wait_done(c, new)
        r = c.post(f"/api/runs/{old}/decision", json={"decision": "approved"})
        assert r.status_code == 409 and new in r.json()["detail"]
        assert c.post(f"/api/runs/{new}/decision", json={"decision": "approved"}).status_code == 200
    assert [x[2] for x in gh.calls if x[0] == "status"][-1] == "success"
