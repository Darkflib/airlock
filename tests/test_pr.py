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


async def fake_pr_analyse(target, *, events, **_):
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


def test_pr_run_posts_status_and_comment_only_after_decision(make):
    gh = FakeGitHub()
    with make(gh) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        run = wait_done(c, run_id)
        assert run["target"] == "Darkflib/airlock-demo#3" and run["meta"]["kind"] == "pr"
        assert gh.calls == []  # nothing leaves before a human decides
        out = c.post(f"/api/runs/{run_id}/decision", json={"decision": "rejected", "note": "steals creds"}).json()
    kinds = [x[0] for x in gh.calls]
    assert kinds == ["status", "comment"]
    assert gh.calls[0][1:3] == ("abc1234def", "failure") and gh.calls[0][4] == f"https://airlock.test/runs/{run_id}"
    body = gh.calls[1][2]
    assert "**MALICIOUS**, rejected" in body and "**PROVEN**" in body and "AIRLOCKCANARYABC" in body
    assert out["meta"]["posted"]["comment_url"].endswith("#issuecomment-1")


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
