import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web.app import create_app


async def fake_analyse(target, *, events, **_):
    events.emit("vm_created", "microVM up in 0.6s", egress="default-deny", allow=[], cpus=2, memory_mb=2048)
    events.emit("canary_read", "postinstall.js read canary /root/.npmrc", path="/root/.npmrc")
    await asyncio.sleep(0.05)
    events.emit("verdict", "verdict: malicious", verdict="malicious", evidence=["reads ~/.npmrc [E2]"], turns=3)
    return SimpleNamespace(verdict="malicious", evidence=["reads ~/.npmrc [E2]"], model="fake-model")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    app = create_app(store=Store(tmp_path / "t.db"), analyse=fake_analyse)
    with TestClient(app) as c:
        yield c


def wait_done(c, run_id):
    for _ in range(100):
        run = c.get(f"/api/runs/{run_id}").json()
        if run["status"] in ("done", "error"):
            return run
        time.sleep(0.02)
    raise AssertionError("run never finished")


def test_spec_run_flows_to_verdict_and_decision(client):
    r = client.post("/api/runs", data={"spec": "left-pad@1.3.0"})
    assert r.status_code == 200
    run = wait_done(client, r.json()["id"])
    assert run["verdict"] == "malicious" and run["contained"] == 1
    assert [e["kind"] for e in run["events"]] == ["vm_created", "canary_read", "verdict"]

    d = client.post(f"/api/runs/{run['id']}/decision", json={"decision": "rejected", "note": "exfil"})
    assert d.json()["decision"] == "rejected"
    assert client.post(f"/api/runs/{run['id']}/decision", json={"decision": "approved"}).status_code == 409


def test_sse_replays_finished_run(client):
    run_id = client.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
    wait_done(client, run_id)
    body = client.get(f"/api/runs/{run_id}/events").text
    assert body.count("event: ev") == 3 and "event: done" in body


def test_rejects_bad_spec_and_non_gzip_upload(client):
    assert client.post("/api/runs", data={"spec": "left-pad; rm -rf /"}).status_code == 400
    r = client.post("/api/runs", files={"file": ("x.tgz", b"not a tarball", "application/gzip")})
    assert r.status_code == 400


def test_upload_tgz_is_accepted(client):
    r = client.post("/api/runs", files={"file": ("pkg.tgz", b"\x1f\x8b" + b"\0" * 20, "application/gzip")})
    assert r.status_code == 200
    assert wait_done(client, r.json()["id"])["target"] == "pkg.tgz"


def test_decision_before_verdict_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    async def slow(target, *, events, **_):
        await asyncio.sleep(5)

    with TestClient(create_app(store=Store(tmp_path / "s.db"), analyse=slow)) as c:
        run_id = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        assert c.post(f"/api/runs/{run_id}/decision", json={"decision": "approved"}).status_code == 409
