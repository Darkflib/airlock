"""Run, queue and output budgets: what a package controls (how much it prints, logs and triggers)
can't grow host memory, the database or the model's context without limit, and a run always ends."""
import asyncio
from types import SimpleNamespace

import pytest

from airlock import events as events_mod
from airlock import sandbox
from airlock.agent import NOTE_EVENTS, TriageAgent
from airlock.events import OVERFLOW, EventLog
from airlock.sandbox import Workspace
from airlock.store import Store
from airlock.web.app import Runner, create_app

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_event_cap_keeps_what_a_verdict_needs_and_marks_the_run_truncated():
    log = EventLog(max_events=5)
    for i in range(10):
        log.emit("exec", f"routine {i}")
    log.emit("canary_exfil", "proven", proven=True, this_run=True, source_kind="sinkhole")
    log.emit("canary_exfil", "proven again", proven=True, this_run=True, source_kind="sinkhole")
    dropped = log.emit("exec", "routine late")
    log.emit("verdict", "verdict: malicious", verdict="malicious")
    assert [e.kind for e in log.events] == ["exec"] * 5 + ["limit_hit", "canary_exfil", "verdict"]
    assert log.truncated == 7 and dropped.id == 0
    assert [e.id for e in log.events] == list(range(1, 9))


def test_event_cap_has_a_hard_ceiling(monkeypatch):
    monkeypatch.setattr(events_mod, "HARD_EXTRA", 3)
    log = EventLog(max_events=2)
    for _ in range(10):
        log.emit("verdict", "v")
    assert len(log.events) == 6 and log.events[-1].kind == "limit_hit" and log.truncated == 5


def test_a_slow_viewer_is_cut_off_instead_of_buffering(monkeypatch):
    monkeypatch.setattr(events_mod, "SUBSCRIBER_BACKLOG", 3)

    async def run():
        log = EventLog()
        slow, fast = log.subscribe(), log.subscribe()
        for i in range(5):
            log.emit("exec", str(i))
            while not fast.empty():
                fast.get_nowait()
        log.close()
        return log, slow, fast
    log, slow, fast = asyncio.run(run())
    assert slow.qsize() == 1 and slow.get_nowait() is OVERFLOW
    assert fast.get_nowait() is None and log._subscribers == [fast]


async def test_overflowed_stream_ends_without_done_so_the_browser_replays(tmp_path, monkeypatch):
    from starlette.requests import Request
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    monkeypatch.setattr(events_mod, "SUBSCRIBER_BACKLOG", 2)
    store = Store(tmp_path / "s.db")
    store.create_run("r", "x")
    app = create_app(store=store, analyse=None)
    log = EventLog(on_emit=lambda ev: store.add_event("r", ev))
    log.emit("vm_created", "up")
    app.state.runner.live["r"] = log
    endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/runs/{run_id}/events")
    request = Request({"type": "http", "method": "GET", "scheme": "https", "path": "/api/runs/r/events",
                       "query_string": b"", "headers": [], "server": ("airlock.test", 443)})
    body = (await endpoint("r", request)).body_iterator
    try:
        assert "vm_created" in await asyncio.wait_for(anext(body), 2)  # replayed; now subscribed
        for i in range(5):
            log.emit("exec", str(i))
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(anext(body), 2)
    finally:
        await body.aclose()


async def test_run_deadline_cancels_the_run_and_unwinds_its_vms(tmp_path):
    store = Store(tmp_path / "s.db")
    unwound = []

    class Vm:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            await asyncio.sleep(0)  # cleanup may await while the run is being cancelled
            unwound.append(exc[0])

    async def analyse(target, *, events, **_):
        async with Vm():
            await asyncio.sleep(60)
    runner = Runner(store, analyse, deadline=0.05)
    run_id = runner.start("x", "x")
    await asyncio.wait_for(asyncio.gather(*runner.tasks), 5)
    run = store.get_run(run_id)
    assert run["status"] == "error" and "deadline" in run["error"]
    assert unwound == [asyncio.CancelledError]
    assert [e["data"].get("limit") for e in store.events(run_id) if e["kind"] == "limit_hit"] == ["run_deadline"]


class LogSb:
    """Guest shell that understands the two commands Workspace sends: chunked log reads and exec."""

    def __init__(self, files=None, exec_out=(b"", b"", 0), raise_first=None):
        self.files, self.exec_out, self.raise_first, self.cmds = files or {}, exec_out, raise_first, []
        self.fs = SimpleNamespace(mkdir=self._ok)

    async def _ok(self, *a, **k):
        pass

    async def shell(self, cmd, **k):
        self.cmds.append(cmd)
        if cmd.startswith("tail -c +"):
            off, rest = cmd[len("tail -c +"):].split(" ", 1)
            path, n = rest.split(" ", 1)[0], int(rest.split("head -c ")[1].split(" ")[0])
            data = self.files.get(path, b"")[int(off) - 1:][:n]
            return SimpleNamespace(stdout_bytes=data, stdout_text=data.decode(errors="replace"), exit_code=0)
        if self.raise_first:
            exc, self.raise_first = self.raise_first, None
            raise exc
        out, err, rc = self.exec_out
        return SimpleNamespace(stdout_text=out.decode(), stderr_text=err.decode(), exit_code=rc)


def bare_ws(sb, monkeypatch):
    monkeypatch.setattr(sandbox, "sinkhole_available", lambda: False)
    ws = Workspace(EventLog(), label="b")
    ws.sb = sb
    return ws


async def test_guest_logs_are_read_in_chunks_and_only_complete_lines(monkeypatch):
    monkeypatch.setattr(sandbox, "LOG_CHUNK", 8)
    sb = LogSb({"/log": b"aaaa\nbbbb\ncccc\npart"})
    ws = bare_ws(sb, monkeypatch)
    ws._log_off["/log"] = 0
    assert await ws._read_log("/log") == "aaaa\nbbbb\ncccc"
    assert await ws._read_log("/log") == ""          # the half-written line waits
    sb.files["/log"] += b"ial\n"
    assert await ws._read_log("/log") == "partial"
    sb.files["/log"] += b"x" * 20 + b"\nok\n"        # a line longer than a chunk is skipped
    assert (await ws._read_log("/log")).endswith("ok")


async def test_guest_log_past_its_budget_stops_and_makes_the_run_incomplete(monkeypatch):
    monkeypatch.setattr(sandbox, "LOG_CHUNK", 8)
    monkeypatch.setattr(sandbox, "LOG_BUDGET", 16)
    sb = LogSb({"/log": b"line\n" * 20})
    ws = bare_ws(sb, monkeypatch)
    ws._log_off["/log"] = 0
    await ws._read_log("/log")
    await ws._read_log("/log")
    assert ws._log_off["/log"] < 16 + 8 and "/log" in ws._log_over
    assert [e.data["limit"] for e in ws.events.events] == ["log_budget"]

    async def no_errors():
        return set(), []
    ws._watch_status = no_errors
    sb.exec_out = (b"up", b"", 0)
    ok, why = await ws.observation_ok()
    assert not ok and "budget" in why


async def test_truncated_events_make_the_run_incomplete(monkeypatch):
    ws = bare_ws(LogSb(exec_out=(b"up", b"", 0)), monkeypatch)
    ws.events.truncated = 1

    async def no_errors():
        return set(), []
    ws._watch_status = no_errors
    ok, why = await ws.observation_ok()
    assert not ok and "events" in why


async def test_exec_returns_capped_tails_and_keeps_the_exit_code(monkeypatch):
    monkeypatch.setattr(Workspace, "collect_trace", lambda self, **k: asyncio.sleep(0))
    sb = LogSb(exec_out=(b"out", b"err", 3))
    ws = bare_ws(sb, monkeypatch)
    r = await ws.exec("npm install; echo 'quoted'", as_user="node")
    assert (r.exit_code, r.stdout, r.stderr) == (3, "out", "err")
    cmd = sb.cmds[-1]
    assert f"tail -c {sandbox.OUTPUT_CAP}" in cmd and "exit $rc" in cmd and "runuser -u node" in cmd


async def test_exec_timeout_still_returns_what_was_printed(monkeypatch):
    monkeypatch.setattr(Workspace, "collect_trace", lambda self, **k: asyncio.sleep(0))

    class ShellTimeout(Exception):
        pass
    sb = LogSb(exec_out=(b"partial output", b"", 0), raise_first=ShellTimeout("too slow"))
    ws = bare_ws(sb, monkeypatch)
    r = await ws.exec("sleep 999", timeout=1)
    assert r.timed_out and r.exit_code == 124 and r.stdout == "partial output"
    assert sb.cmds[-1].startswith("tail -c")


def test_agent_event_note_is_bounded_and_keeps_containment():
    log = EventLog()
    agent = TriageAgent(None, "m", None, log)
    log.emit("exec", "first")
    for i in range(NOTE_EVENTS + 40):
        log.emit("exec", f"routine {i}")
    log.emit("canary_read", "read ~/.npmrc")
    note = agent._new_events_note(1)
    assert "canary_read" in note and "...and 41 more routine events" in note
    assert note.count("\n[E") == NOTE_EVENTS
