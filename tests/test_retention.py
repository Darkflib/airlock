"""Retention: uploads go when their run ends, old private runs are pruned, demo runs stay, and the
sinkhole log rotates only while no VM is running, without a live run losing its place in it."""
import asyncio
import json
import os
import time

from fastapi.testclient import TestClient

from airlock import retention, sandbox
from airlock.events import EventLog
from airlock.retention import rotate_sinkhole, sweep
from airlock.sandbox import Workspace
from airlock.store import Store
from airlock.web.app import create_app
from tests.test_web import fake_analyse, wait_done

DAY = 86400


def test_an_upload_is_deleted_when_its_run_ends(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    with TestClient(create_app(store=Store(tmp_path / "t.db"), analyse=fake_analyse)) as client:
        r = client.post("/api/runs", files={"file": ("pkg.tgz", b"\x1f\x8b" + b"\0" * 20, "application/gzip")})
        wait_done(client, r.json()["id"])
        end = time.time() + 2
        while time.time() < end and any((tmp_path / "uploads").iterdir()):
            time.sleep(0.01)
    assert list((tmp_path / "uploads").iterdir()) == []


def old_run(store, run_id, age_days, demo=False, status="done"):
    store.create_run(run_id, run_id, demo=demo)
    store.update_run(run_id, status=status)
    store.append_event(run_id, "verdict", "v")
    store.db.execute("UPDATE runs SET created = ? WHERE id = ?", (time.time() - age_days * DAY, run_id))
    store.db.commit()


def run_sweep(tmp_path, store, **kw):
    kw.setdefault("live", False)
    kw.setdefault("vms_active", None)
    return asyncio.run(sweep(store, tmp_path / "uploads", tmp_path / "sinkhole.jsonl", **kw))


def test_old_private_runs_are_pruned_and_demo_runs_kept(tmp_path):
    store = Store(tmp_path / "s.db")
    old_run(store, "private-old", 31)
    old_run(store, "private-new", 5)
    old_run(store, "demo-old", 90, demo=True)
    old_run(store, "running-old", 31, status="running")
    assert run_sweep(tmp_path, store)["runs"] == 1
    assert store.get_run("private-old") is None and store.events("private-old") == []
    assert all(store.get_run(i) for i in ("private-new", "demo-old", "running-old"))


def test_orphaned_uploads_are_swept_after_a_day(tmp_path):
    up = tmp_path / "uploads"
    up.mkdir()
    (up / "old.tgz").write_bytes(b"x")
    (up / "new.tgz").write_bytes(b"x")
    os.utime(up / "old.tgz", (time.time() - 2 * DAY,) * 2)
    assert run_sweep(tmp_path, Store(tmp_path / "s.db"))["uploads"] == 1
    assert [f.name for f in up.iterdir()] == ["new.tgz"]


def write_sink(log, *ts):
    with open(log, "a") as f:
        for t in ts:
            f.write(json.dumps({"ts": t, "dest": "198.18.1.5", "url": "https://x.invalid/"}) + "\n")


def test_sinkhole_rotates_when_a_day_old_or_big(tmp_path, monkeypatch):
    log = tmp_path / "sinkhole.jsonl"
    now = time.time()
    write_sink(log, now - 60)
    assert not rotate_sinkhole(log, now)
    assert rotate_sinkhole(log, now + DAY) and not log.exists() and (tmp_path / "sinkhole.jsonl.1").exists()
    write_sink(log, now)
    monkeypatch.setattr(retention, "SINKHOLE_MAX_BYTES", 10)
    assert rotate_sinkhole(log, now)                       # the older .1 is replaced
    assert len((tmp_path / "sinkhole.jsonl.1").read_text().splitlines()) == 1


def test_sinkhole_never_rotates_while_a_vm_or_run_is_live(tmp_path):
    store, log = Store(tmp_path / "s.db"), tmp_path / "sinkhole.jsonl"
    write_sink(log, time.time() - 2 * DAY)

    async def busy():
        return True

    async def idle():
        return False
    assert not run_sweep(tmp_path, store, vms_active=busy)["sinkhole_rotated"]
    assert not run_sweep(tmp_path, store, vms_active=idle, live=True)["sinkhole_rotated"]
    assert run_sweep(tmp_path, store, vms_active=idle)["sinkhole_rotated"]


def test_a_workspace_follows_the_sinkhole_log_across_a_rotation(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    log = sandbox.sinkhole_log()
    write_sink(log, 1.0)                     # someone else's run, before this one started
    ws = Workspace(EventLog(), label="r")
    ws.sinkhole = "198.18.1.0/24"
    st = log.stat()
    ws._sink_offset, ws._sink_inode = st.st_size, st.st_ino
    assert ws._read_sinkhole() == []
    log.replace(log.with_name("sinkhole.jsonl.1"))
    write_sink(log, 2.0)                     # this run's request lands in the new file
    assert len(ws._read_sinkhole()) == 1
