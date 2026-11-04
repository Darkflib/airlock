import asyncio
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from airlock.events import Event
from airlock.store import Store
from airlock.web import app as app_module
from airlock.web.app import create_app, judge_probe


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


async def fixture_analyse(target, *, events, **_):
    """Stealers show proven exfil; the benign fixture is quiet. "agent-only" proves exfil
    only during the agent's re-run, which must not count."""
    if "benign" in target:
        events.emit("verdict", "verdict: benign", verdict="benign")
        return SimpleNamespace(verdict="benign", evidence=[], model="fake-model")
    stage = "agent" if "agent-only" in target else "detonate"
    events.emit("canary_exfil", "POST carried the canary", proven=True, this_run=True, source_kind="sinkhole", stage=stage)
    return SimpleNamespace(verdict="malicious", evidence=["exfil [E1]"], model="fake-model")


def wait_selftest(c, test_id):
    for _ in range(200):
        t = c.get(f"/api/selftests/{test_id}").json()
        if t["done"]:
            return t
        time.sleep(0.02)
    raise AssertionError("self-test never finished")


@pytest.fixture
def fixtures(tmp_path, monkeypatch):
    d = tmp_path / "fixtures"
    d.mkdir()
    for f, _, _ in app_module.SELFTEST:
        (d / f).write_bytes(b"\x1f\x8b")
    monkeypatch.setattr(app_module, "FIXTURES", d)
    return d


def test_selftest_runs_fixtures_and_judges_them(tmp_path, monkeypatch, fixtures):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    with TestClient(create_app(store=Store(tmp_path / "t.db"), analyse=fixture_analyse)) as c:
        assert c.get("/api/selftests/latest").json() is None
        r = c.post("/api/selftests").json()
        t = wait_selftest(c, r["id"])
        assert (t["passed"], t["total"]) == (5, 5)
        assert [p["proven"] for p in t["probes"]] == [True, True, False, True, False]
        assert c.get("/api/selftests/latest").json()["id"] == r["id"]
        assert c.get(f"/selftests/{r['id']}").status_code == 200
        assert len(c.get("/api/runs").json()) == 5  # probes are ordinary runs


def test_selftest_in_progress_is_reused(tmp_path, monkeypatch, fixtures):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    async def slow(target, *, events, **_):
        await asyncio.sleep(5)

    with TestClient(create_app(store=Store(tmp_path / "s.db"), analyse=slow)) as c:
        first = c.post("/api/selftests").json()
        again = c.post("/api/selftests").json()
        assert again == {**first, "existing": True}


def test_selftest_needs_its_fixtures(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    monkeypatch.setattr(app_module, "FIXTURES", tmp_path / "nowhere")
    with TestClient(create_app(store=Store(tmp_path / "t.db"), analyse=fixture_analyse)) as c:
        assert c.post("/api/selftests").status_code == 503


def test_judge_probe_requires_proof_not_just_a_verdict():
    done = {"status": "done", "verdict": "malicious", "contained": 2}
    assert judge_probe(done, True, "malicious")[0] == "pass"
    assert judge_probe(done, False, "malicious") == ("fail", "malicious verdict, but no exfiltration proven by payload")
    assert judge_probe({**done, "verdict": "benign", "contained": 1}, False, "benign")[0] == "fail"
    assert judge_probe({**done, "verdict": "benign", "contained": 0}, False, "benign")[0] == "pass"
    assert judge_probe({**done, "status": "running"}, False, "benign")[0] == "pending"
    assert judge_probe({**done, "status": "error", "error": "boom"}, False, "benign") == ("fail", "boom")


def test_exfil_proven_only_by_the_agent_does_not_count(tmp_path):
    store = Store(tmp_path / "t.db")
    store.create_run("r1", "x")
    proof = {"proven": True, "this_run": True, "source_kind": "sinkhole"}
    store.add_event("r1", Event(kind="canary_exfil", summary="agent re-run", data={**proof, "stage": "agent"}, id=1))
    assert not store.proven_exfil("r1")
    store.add_event("r1", Event(kind="canary_exfil", summary="other run's token",
                                data={**proof, "this_run": False, "stage": "detonate"}, id=2))
    store.add_event("r1", Event(kind="canary_exfil", summary="guest tracer",
                                data={**proof, "source_kind": "node", "stage": "detonate"}, id=3))
    assert not store.proven_exfil("r1")
    store.add_event("r1", Event(kind="canary_exfil", summary="install", data={**proof, "stage": "detonate"}, id=4))
    assert store.proven_exfil("r1")


def test_spec_validation_rejects_shell_syntax_and_overlong_specs(client):
    for bad in ("left-pad@1|id|cat", "left-pad@>1", "left-pad@1<2", "a" * 215):
        assert client.post("/api/runs", data={"spec": bad}).status_code == 400, bad
    assert client.post("/api/runs", data={"spec": "@scope/pkg@^1.2.3"}).status_code == 200


def test_pypi_spec_is_accepted_and_shell_syntax_rejected(client):
    assert client.post("/api/runs", data={"spec": "pypi:six==1.17.0"}).status_code == 200
    for bad in ("pypi:six; id", "pypi:six==1|cat", "pypi:$(id)", "pypi:six>=1"):
        assert client.post("/api/runs", data={"spec": bad}).status_code == 400, bad


def test_sdist_uploads_keep_their_extension_so_routing_works(client):
    import io, zipfile
    r = client.post("/api/runs", files={"file": ("pkg.tar.gz", b"\x1f\x8b" + b"\0" * 20, "application/gzip")})
    assert wait_done(client, r.json()["id"])["target"].endswith(".tar.gz")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pkg/setup.py", "setup()")
    r = client.post("/api/runs", files={"file": ("pkg.zip", buf.getvalue(), "application/zip")})
    assert wait_done(client, r.json()["id"])["target"].endswith(".zip")


def test_backfill_marks_only_demo_material(tmp_path):
    from airlock.store import Store
    store = Store(tmp_path / "b.db")
    for i, target in enumerate(["self-test: Node credential stealer", "Darkflib/airlock-demo#3", "acme/private#9",
                                "left-pad@1.3.0", "@scope/pkg@1.0.0", "acme-internal.tgz"]):
        store.create_run(str(i), target)
    store.db.execute("UPDATE runs SET demo = NULL")
    store.backfill_demo(frozenset({"darkflib/airlock-demo"}))
    assert [bool(store.get_run(str(i))["demo"]) for i in range(6)] == [True, True, False, True, True, False]
