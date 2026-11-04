import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web.app import create_app
from tests.test_auth import cfg
from tests.test_pr import META, FakeGitHub, fake_pr_analyse

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


def wait_done_store(c, run_id, timeout=5.0):
    import time
    store = c.app.state.runner.store
    end = time.time() + timeout
    while time.time() < end and store.get_run(run_id)["status"] in ("queued", "running"):
        time.sleep(0.02)
