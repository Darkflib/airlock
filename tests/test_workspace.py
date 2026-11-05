"""Workspace setup and teardown against a fake microsandbox: fail closed, never leak a VM."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from airlock import pipeline, sandbox
from airlock.events import EventLog
from airlock.pipeline import apply_gaps
from airlock.sandbox import ACTIVE_SUBNETS, ObservationError, Workspace
from airlock.store import Store


class FakeSb:
    def __init__(self, watch_lines=(), fail_write=False):
        self.watch_lines, self.fail_write = list(watch_lines), fail_write
        self.fs = SimpleNamespace(mkdir=self._ok, write=self._write)

    async def _ok(self, *a, **k):
        pass

    async def _write(self, *a, **k):
        if self.fail_write:
            raise OSError("guest fs broke")

    async def shell(self, cmd, **k):
        if "watch_(ready|error)" in cmd:
            out = "\n".join(json.dumps(r) for r in self.watch_lines)
        elif "pgrep" in cmd:
            out = "up"
        else:
            out = ""
        return SimpleNamespace(stdout_text=out, exit_code=0)


class FakeCm:
    def __init__(self, sb, fail_exit=False):
        self.sb, self.fail_exit, self.exited = sb, fail_exit, False

    async def __aenter__(self):
        return self.sb

    async def __aexit__(self, *exc):
        self.exited = True
        if self.fail_exit:
            raise RuntimeError("msb would not stop")


READY = [{"ev": "watch_ready", "what": w} for w in ("dns", "fanotify", "watcher")]


@pytest.fixture
def fake_msb(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    monkeypatch.setattr(sandbox, "sinkhole_available", lambda: True)
    holder = {}

    async def create(name, **kw):
        holder["network"] = kw["network"]
        holder["labels"] = kw.get("labels")
        return holder["cm"]
    monkeypatch.setattr(sandbox.Sandbox, "create", create)
    return holder


def kinds(events):
    return [e.kind for e in events.events]


def test_ready_watcher_and_clean_teardown(fake_msb):
    fake_msb["cm"] = cm = FakeCm(FakeSb(READY))
    events = EventLog()

    async def run():
        async with Workspace(events, label="ok") as ws:
            assert ws._subnet in ACTIVE_SUBNETS
            assert fake_msb["network"].dns.nameservers[0].startswith("127.0.0.1:")
            return ws
    ws = asyncio.run(run())
    assert cm.exited and ws._subnet not in ACTIVE_SUBNETS and ws.dns.transport is None
    assert kinds(events)[-1] == "vm_destroyed" and "watcher_started" in kinds(events)
    assert fake_msb["labels"] == {sandbox.OWNER_LABEL: sandbox.VM_OWNER}


@pytest.mark.parametrize("lines", [READY[:2], READY + [{"ev": "watch_error", "what": "fanotify_mark /root", "err": "EPERM"}]])
def test_watcher_not_fully_ready_fails_closed_and_destroys_the_vm(fake_msb, lines, monkeypatch):
    real_sleep = asyncio.sleep
    monkeypatch.setattr(sandbox.asyncio, "sleep", lambda *_: real_sleep(0))
    fake_msb["cm"] = cm = FakeCm(FakeSb(lines))
    events = EventLog()

    async def run():
        async with Workspace(events, label="blind"):
            pytest.fail("a run must not start without every observer ready")
    with pytest.raises(ObservationError):
        asyncio.run(run())
    assert cm.exited and kinds(events)[-1] == "vm_destroyed"


def test_failed_setup_destroys_vm_and_failed_destroy_is_not_reported_as_destroyed(fake_msb):
    fake_msb["cm"] = cm = FakeCm(FakeSb(READY, fail_write=True), fail_exit=True)
    events = EventLog()

    async def run():
        async with Workspace(events, label="broken"):
            pass
    with pytest.raises(OSError, match="guest fs broke"):   # the setup failure, not masked by cleanup
        asyncio.run(run())
    assert cm.exited
    assert "vm_destroyed" not in kinds(events)
    assert "may not have been destroyed" in events.events[-1].summary


def test_dns_lookup_with_canary_is_proven_and_others_are_contained(monkeypatch):
    monkeypatch.setattr(sandbox, "sinkhole_available", lambda: False)
    ws = Workspace(EventLog(), label="x")
    ws.dns = sandbox.DnsGuard(())
    ws.dns.blocked = [{"name": f"{ws.canary_token.lower()}.evil.example", "ts": 0}, {"name": "probe.example", "ts": 0}]
    (k1, _, d1), (k2, _, d2) = ws._read_dns()
    assert k1 == "canary_exfil" and d1["proven"] and d1["this_run"] and d1["source_kind"] == "dns"
    assert k2 == "dns_blocked"


def test_incomplete_coverage_turns_benign_into_inconclusive():
    events = EventLog()
    assert apply_gaps("benign", ["ok"], [], events) == ("benign", ["ok"])
    verdict, evidence = apply_gaps("benign", ["ok"], ["the install exited 1"], events)
    assert verdict == "inconclusive" and evidence[0].startswith("Not a clean result")
    assert [e.kind for e in events.events] == ["coverage_incomplete", "verdict"]
    assert apply_gaps("malicious", ["x"], ["the install timed out"], EventLog())[0] == "malicious"


def test_runs_left_running_by_a_dead_server_are_failed_on_startup(tmp_path):
    store = Store(tmp_path / "s.db")
    store.create_run("a", "x")
    store.update_run("a", status="running")
    store.create_run("b", "y")
    store.update_run("b", status="done")
    assert store.fail_stale_runs() == ["a"]
    assert store.get_run("a")["status"] == "error" and store.get_run("b")["status"] == "done"


class GapWs:
    def __init__(self, healthy=True):
        self.healthy = healthy

    async def observation_ok(self):
        return (True, "") if self.healthy else (False, "the in-guest watcher stopped during the run")


def test_test_timeouts_and_kills_are_gaps_but_failing_asserts_are_not():
    ok, failed = sandbox.ExecResult(0, "", ""), sandbox.ExecResult(1, "", "")
    gaps = lambda **kw: asyncio.run(pipeline.coverage_gaps(GapWs(), ok, **kw))  # noqa: E731
    assert gaps(test=failed) == [] and gaps(test=ok) == [] and gaps() == []
    assert gaps(test=sandbox.ExecResult(124, "", "", timed_out=True)) == ["the tests timed out"]
    assert "killed (exit 137)" in gaps(test=sandbox.ExecResult(137, "", ""))[0]


def test_observer_dying_during_the_investigation_makes_benign_inconclusive(monkeypatch, tmp_path):
    """Observation is checked after the agent finishes, not just after the install."""
    ws = GapWs()

    class FakeWorkspace:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def write(self, *a):
            pass

        async def exec(self, *a, **kw):
            return sandbox.ExecResult(0, "", "")

        observation_ok = ws.observation_ok

    class FakeAgent:
        def __init__(self, *a, **kw):
            pass

        async def run(self, goal):
            ws.healthy = False  # the watcher dies mid-investigation
            return SimpleNamespace(verdict="benign", evidence=["quiet install [E1]"])

    monkeypatch.setattr(pipeline, "Workspace", FakeWorkspace)
    monkeypatch.setattr(pipeline, "TriageAgent", FakeAgent)
    monkeypatch.setattr(pipeline, "inference_client", lambda: None)
    pkg = tmp_path / "p.tgz"
    pkg.write_bytes(b"x")
    report = asyncio.run(pipeline.analyse(str(pkg), model="m"))
    assert report.verdict == "inconclusive" and "watcher stopped" in report.evidence[0]


class FakeHandle:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.destroyed = name, fail, False

    async def destroy(self, *, force=False, timeout=None):
        if self.fail:
            raise RuntimeError("busy")
        self.destroyed = force


def test_reap_leftovers_destroys_only_this_owners_sandboxes_across_pages(monkeypatch):
    pages = {None: ([FakeHandle("airlock-a"), FakeHandle("airlock-b", fail=True)], "p2"), "p2": ([FakeHandle("airlock-c")], None)}
    asked = []

    async def list_with(*, cursor=None, limit=None, labels=None):
        asked.append(labels)
        hs, nxt = pages[cursor]
        return SimpleNamespace(sandboxes=hs, next_cursor=nxt)
    monkeypatch.setattr(sandbox.Sandbox, "list_with", list_with)
    removed, failed = asyncio.run(sandbox.reap_leftovers("web"))
    assert removed == ["airlock-a", "airlock-c"] and failed == ["airlock-b: RuntimeError: busy"]
    assert asked == [{sandbox.OWNER_LABEL: "web"}] * 2
    assert all(h.destroyed for hs, _ in pages.values() for h in hs if not h.fail)
