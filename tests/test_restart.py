"""A restart of airlock-web leaves nothing half-done on GitHub: a PR held `pending` by a run that died is
released as `error`, a decision recorded but never posted is posted, and handled deliveries stay handled."""
import time

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web.app import create_app
from tests.test_pr import META, FakeGitHub, fake_pr_analyse
from tests.test_webhook import SECRET, deliver, pr_event, wait_done_store


@pytest.fixture
def boot(tmp_path, monkeypatch):
    """Start the service on a database a previous process left behind; returns (client, store)."""
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    monkeypatch.setenv("AIRLOCK_PUBLIC_URL", "https://airlock.test")
    path = tmp_path / "r.db"

    def _boot(gh):
        app = create_app(store=Store(path), analyse=fake_pr_analyse, github=gh, webhook_secret=SECRET)
        return TestClient(app, base_url="http://airlock.test")
    return _boot, path


def reconciled(c):
    end = time.time() + 5
    while time.time() < end and not c.app.state.reconcile.done():
        time.sleep(0.01)
    assert c.app.state.reconcile.done()


def left_running(path, run_id, meta=META, created=None):
    s = Store(path)
    s.create_run(run_id, "Darkflib/airlock-demo#3")
    s.update_run(run_id, status="running", meta=meta)
    if created:
        s.db.execute("UPDATE runs SET created = ? WHERE id = ?", (created, run_id))
        s.db.commit()


def test_a_pr_held_by_a_run_that_died_is_released_as_error(boot):
    make, path = boot
    left_running(path, "dead")
    gh = FakeGitHub()
    with make(gh) as c:
        reconciled(c)
        run, events = c.app.state.runner.store.get_run("dead"), c.app.state.runner.store.events("dead")
    assert run["status"] == "error" and "restarted" in run["error"]
    assert [x[2] for x in gh.calls if x[0] == "status"] == ["error"]
    assert "restarted" in next(x[2] for x in gh.calls if x[0] == "comment")
    assert run["meta"]["gate"] == {"state": "error", "synced": True}
    assert events[-1]["kind"] == "github_status" and events[-1]["id"] == 1


def test_a_newer_run_of_the_same_commit_keeps_its_status(boot):
    make, path = boot
    left_running(path, "older", created=time.time() - 60)
    s = Store(path)
    s.create_run("newer", "Darkflib/airlock-demo#3")
    s.update_run("newer", status="done", verdict="benign", meta=META)
    gh = FakeGitHub()
    with make(gh) as c:
        reconciled(c)
    assert gh.calls == []


def test_runs_that_never_fetched_a_pr_post_nothing(boot):
    make, path = boot
    left_running(path, "queued", meta={})
    gh = FakeGitHub()
    with make(gh) as c:
        reconciled(c)
    assert gh.calls == []


def test_a_decision_that_never_reached_github_is_posted(boot):
    make, path = boot
    s = Store(path)
    for run_id, decided in (("recent", time.time() - 60), ("old", time.time() - 3 * 86400)):
        s.create_run(run_id, "Darkflib/airlock-demo#3")
        s.update_run(run_id, status="done", verdict="malicious", meta={**META, "head_sha": run_id * 3})
        s.claim_decision(run_id, "rejected", "Darkflib")
        s.db.execute("UPDATE runs SET decided = ? WHERE id = ?", (decided, run_id))
        s.db.commit()
    gh = FakeGitHub()
    with make(gh) as c:
        reconciled(c)
        posted = c.app.state.runner.store.get_run("recent")["meta"]["posted"]
    assert [(x[1], x[2]) for x in gh.calls if x[0] == "status"] == [("recent" * 3, "failure")]  # old ones alone
    assert posted["status"] == "failure"
    with make(gh) as c:   # posted once: a second restart leaves it
        reconciled(c)
    assert sum(x[0] == "status" for x in gh.calls) == 1


def test_a_failing_github_doesnt_stop_startup(boot):
    make, path = boot
    left_running(path, "dead")
    with make(FakeGitHub(fail=True)) as c:
        reconciled(c)
        assert c.get("/healthz").status_code == 200
        events = c.app.state.runner.store.events("dead")
    assert "NOT held" in events[0]["summary"]


def test_a_redelivery_after_a_restart_is_still_ignored(boot):
    make, path = boot
    gh = FakeGitHub()
    with make(gh) as c:
        run_id = deliver(c, pr_event(), delivery="d1").json()["id"]
        wait_done_store(c, run_id)
        c.app.state.runner.store.update_run(run_id, status="error")  # failed runs don't block a new run
    with make(gh) as c:
        assert deliver(c, pr_event(), delivery="d1").json()["ignored"] == "already analysed"
        assert deliver(c, pr_event(), delivery="d2").status_code == 202


def test_old_deliveries_are_pruned(tmp_path):
    s = Store(tmp_path / "d.db")
    s.add_delivery("a")
    s.db.execute("UPDATE deliveries SET seen = ?", (time.time() - 8 * 86400,))
    s.add_delivery("b")
    assert not s.seen_delivery("a") and s.seen_delivery("b")
