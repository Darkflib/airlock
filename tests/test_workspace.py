"""Workspace setup and teardown against a fake microsandbox: fail closed, never leak a VM."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from airlock import sandbox
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
    assert store.fail_stale_runs() == 1
    assert store.get_run("a")["status"] == "error" and store.get_run("b")["status"] == "done"
