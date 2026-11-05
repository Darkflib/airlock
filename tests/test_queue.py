"""The run queue survives restarts and deploys, and pushes back on guests before it grows long:
queued runs resume as they were, interrupted runs are retried once, a shutdown lets runs finish,
and a guest past the limits is told to come back instead of waiting."""
import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import airlock.web.app as webapp
from airlock.store import Store, data_dir
from airlock.web.app import Runner, create_app, recover
from tests.test_auth import cfg, sign_in
from tests.test_webhook import wait_done_store


async def quick(target, *, events, **_):
    events.emit("verdict", "verdict: benign", verdict="benign")
    return SimpleNamespace(verdict="benign", evidence=[], model="m")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    return tmp_path


def left(path, run_id, status, spec="left-pad@1.3.0", created=None, meta=None, target=None):
    s = Store(path)
    s.create_run(run_id, target or spec or "x", spec=spec, meta=meta)
    s.update_run(run_id, status=status)
    if created:
        s.db.execute("UPDATE runs SET created = ? WHERE id = ?", (created, run_id))
        s.db.commit()


def test_a_queued_run_resumes_after_a_restart_with_its_id(data):
    path = data / "q.db"
    left(path, "waiting", "queued")
    with TestClient(create_app(store=Store(path), analyse=quick)) as c:
        wait_done_store(c, "waiting")
        run = c.app.state.runner.store.get_run("waiting")
    assert run["status"] == "done" and run["verdict"] == "benign" and run["started"]


def test_an_interrupted_run_fails_and_is_retried_once(data):
    path = data / "r.db"
    left(path, "cut", "running", created=time.time() - 30)
    left(path, "cut-again", "running", spec="pypi:six==1.17.0", meta={"retry_of": "older"})
    with TestClient(create_app(store=Store(path), analyse=quick)) as c:
        store = c.app.state.runner.store
        cut = store.get_run("cut")
        again = cut["meta"]["retried_as"]
        wait_done_store(c, again)
        retry = store.get_run(again)
        assert store.get_run("cut-again")["status"] == "error"
        assert not store.get_run("cut-again")["meta"].get("retried_as")   # a retry is not retried
    assert cut["status"] == "error" and "restarted" in cut["error"]
    assert retry["status"] == "done" and retry["meta"]["retry_of"] == "cut" and retry["target"] == "left-pad@1.3.0"


def test_runs_that_cant_be_resumed_fail_with_the_reason(data):
    path = data / "f.db"
    left(path, "stale", "queued", created=time.time() - 2 * 3600)
    left(path, "upload", "queued", spec=str(data_dir() / "uploads" / "gone.tgz"))
    left(path, "old", "queued", spec="https://github.com/o/r/pull/1", created=time.time() - 60)
    left(path, "new", "done", spec="https://github.com/o/r/pull/1")
    left(path, "legacy", "queued", spec=None, target="left-pad")
    store = Store(path)
    stale, resume, retry = recover(store)
    errors = {i: store.get_run(i)["error"] for i in ("stale", "upload", "old", "legacy")}
    assert resume == [] and retry == [] and sorted(stale) == ["legacy", "old", "stale", "upload"]
    assert "over an hour" in errors["stale"] and "upload is gone" in errors["upload"]
    assert "run new of the same PR is newer" in errors["old"] and "predates" in errors["legacy"]


def test_self_test_probes_are_not_retried(data):
    path = data / "s.db"
    left(path, "probe", "running", target="self-test: Node credential stealer")
    stale, resume, retry = recover(Store(path))
    assert stale == ["probe"] and retry == []


def test_spec_stays_on_the_server(data):
    left(data / "p.db", "x", "queued", spec=str(data_dir() / "uploads" / "secret-name.tgz"))
    assert "spec" not in Store(data / "p.db").get_run("x")


@pytest.mark.anyio
async def test_drain_lets_runs_finish_and_leaves_the_rest_for_the_next_start(data):
    store = Store(data / "d.db")
    gate = asyncio.Event()

    async def slow(target, *, events, **_):
        if target == "finishes":
            await asyncio.sleep(0.05)
        else:
            await gate.wait()
        return SimpleNamespace(verdict="benign", evidence=[], model="m")
    upload = data_dir() / "uploads"
    upload.mkdir(exist_ok=True)
    (upload / "pkg.tgz").write_bytes(b"x")
    runner = Runner(store, slow, slots=2)
    done = runner.start("finishes", "a")
    cut = runner.start("hangs", "b", upload=upload / "pkg.tgz")
    waiting = runner.start("never-started", "c")
    await asyncio.sleep(0.01)
    await runner.drain(0.3)
    assert store.get_run(done)["status"] == "done"
    assert store.get_run(cut)["status"] == "running"     # cut off: the next start retries it
    assert (upload / "pkg.tgz").exists()                 # with its upload
    assert store.get_run(waiting)["status"] == "queued"  # never started: the next start resumes it
    assert not runner.tasks


@pytest.mark.anyio
async def test_slots_are_first_come_first_served_and_report_position(data):
    store = Store(data / "o.db")
    release, order = asyncio.Event(), []

    async def held(target, *, events, **_):
        order.append(target)
        await release.wait()
        return SimpleNamespace(verdict="benign", evidence=[], model="m")
    runner = Runner(store, held, slots=1)
    ids = [runner.start(t, t) for t in ("one", "two", "three")]
    await asyncio.sleep(0.01)
    assert [store.queue_ahead(store.get_run(i)) for i in ids[1:]] == [0, 1]
    release.set()
    await asyncio.wait_for(asyncio.gather(*runner.tasks), 5)
    assert order == ["one", "two", "three"]


def test_the_run_page_shows_queue_position(data, monkeypatch):
    monkeypatch.setattr(webapp, "SLOTS", 1)

    async def slow(target, *, events, **_):
        await asyncio.sleep(5)
    with TestClient(create_app(store=Store(data / "p.db"), analyse=slow, drain_s=0)) as c:
        ids = [c.post("/api/runs", data={"spec": "left-pad"}).json()["id"] for _ in range(3)]
        time.sleep(0.05)
        last = c.get(f"/api/runs/{ids[2]}").json()
        first = c.get(f"/api/runs/{ids[0]}").json()
    assert last["status"] == "queued" and last["queue_ahead"] == 1 and last["queue_eta_s"] == 60  # its turn is the 2nd: 2 x 30 s
    assert "queue_ahead" not in first


def guest_client(data, login):
    async def exchange(_cfg, code):
        return login

    async def slow(target, *, events, **_):
        await asyncio.sleep(5)
    app = create_app(store=Store(data / "g.db"), analyse=slow, auth=cfg(data), exchange=exchange, drain_s=0)
    return TestClient(app, base_url="http://airlock.test")


def test_a_guest_has_at_most_five_runs_unfinished_and_owners_no_limit(data, monkeypatch):
    monkeypatch.setattr(webapp, "SLOTS", 1)
    with guest_client(data, "some-judge") as c:
        sign_in(c)
        codes = [c.post("/api/runs", data={"spec": "left-pad"}).status_code for _ in range(6)]
        r = c.post("/api/runs", data={"spec": "left-pad"})
    assert codes == [200] * 5 + [429] and r.headers["retry-after"] == "60" and "at most 5" in r.json()["detail"]
    with guest_client(data, "Darkflib") as c:
        sign_in(c)
        assert all(c.post("/api/runs", data={"spec": "left-pad"}).status_code == 200 for _ in range(8))


def test_a_full_queue_turns_guests_away(data, monkeypatch):
    monkeypatch.setattr(webapp, "SLOTS", 1)
    monkeypatch.setattr(webapp, "QUEUED_PER_SLOT", 2)
    (data / "allowed_users").write_text("some-judge\nother-judge\n")
    with guest_client(data, "Darkflib") as c:   # an owner fills the queue: 1 running, 2 waiting
        sign_in(c)
        for _ in range(3):
            assert c.post("/api/runs", data={"spec": "left-pad"}).status_code == 200
        time.sleep(0.05)
    with guest_client(data, "other-judge") as c:
        sign_in(c)
        r = c.post("/api/runs", data={"spec": "left-pad"})
    assert r.status_code == 429 and "busy" in r.json()["detail"] and int(r.headers["retry-after"]) >= 30
