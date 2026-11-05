"""Exercise: the agent picks what to call, Airlock runs it from a pristine copy with its own harness,
and only then does what the package sends count as proof."""
import asyncio
from types import SimpleNamespace

import pytest

from airlock.agent import TriageAgent
from airlock.events import EventLog
from airlock.exercise import PRISTINE, Exerciser, Request
from airlock.store import Store


def test_a_valid_request_is_kept_as_data():
    req = Request.parse({"package": "tinyconf", "call": "load", "args": [{"defaults": {"port": 1}}],
                         "env": {"NODE_ENV": "production"}, "wait_s": 99})
    assert (req.package, req.call, req.env, req.wait_s) == ("tinyconf", "load", {"NODE_ENV": "production"}, 15)
    assert req.describe() == "tinyconf.load(…) with NODE_ENV=production, waiting 15 s"
    assert Request.parse({"package": "@scope/pkg/sub"}).call is None and Request.parse({"package": "."}).package == "."


@pytest.mark.parametrize("raw, why", [
    ({"package": "x; curl evil"}, "package"),
    ({"package": "../../etc/passwd"}, "package"),
    ({"package": "x/../../../tmp/evil.js"}, "package"),
    ({"package": "x/./y"}, "package"),
    ({"package": "x", "call": "load(); require('child_process')"}, "call"),
    ({"package": "x", "call": "load.constructor"}, "call"),
    ({"package": "x", "call": "__proto__.x"}, "call"),
    ({"package": "x", "env": {"NODE_OPTIONS": "--require /tmp/evil.js"}}, "NODE_OPTIONS"),
    ({"package": "x", "env": {"PATH": "/tmp"}}, "PATH"),
    ({"package": "x", "env": {"NODE_ENV": "a\nb"}}, "single-line"),
    ({"package": "x", "args": ["a" * 3000]}, "args"),
    ({"package": "x", "args": "not a list"}, "args"),
])
def test_anything_that_could_carry_code_is_refused(raw, why):
    with pytest.raises(ValueError, match=why):
        Request.parse(raw)


def test_only_detonation_and_exercise_count_as_proof(tmp_path):
    store = Store(tmp_path / "p.db")
    proof = dict(proven=True, this_run=True, source_kind="sinkhole")
    for i, stage in enumerate(["agent", "exercise_setup", "unpack", None, "exercise"]):
        store.create_run(f"r{i}", "x")
        log = EventLog(on_emit=lambda ev, rid=f"r{i}": store.add_event(rid, ev))
        log.emit("canary_exfil", "POST carried the canary", **proof, **({"stage": stage} if stage else {}))
    assert [store.proven_exfil(f"r{i}") for i in range(5)] == [False, False, False, False, True]


class FakeWs:
    def __init__(self):
        self.calls, self.files = [], {}

    async def exec(self, cmd, **kw):
        self.calls.append(("exec", cmd, kw))
        return SimpleNamespace(exit_code=0, ok=True, stdout="loaded tinyconf", stderr="")

    async def collect_trace(self, stage="detonate", settle=False):
        self.calls.append(("collect", stage, settle))

    async def write(self, path, data):
        self.files[path] = data
        self.calls.append(("write", path, None))


def test_exercise_cleans_up_after_the_agent_then_runs_the_harness_from_a_fresh_copy():
    ws, log = FakeWs(), EventLog()
    req = Request.parse({"package": "tinyconf", "call": "load", "env": {"NODE_ENV": "production"}})
    out = asyncio.run(Exerciser(ws, log, "npm").run(req))
    kill, flush, setup = ws.calls[0], ws.calls[1], ws.calls[2]
    assert "pkill -KILL -u node" in kill[1] and kill[2]["source"] == "agent"   # in-flight traffic is the agent's
    assert flush == ("collect", "agent", True)
    assert f"npm install --ignore-scripts" in setup[1] and f"{PRISTINE}/package.tgz" in setup[1]
    assert "--userconfig /dev/null" in setup[1] and "mkdir /tmp/ex-" in setup[1] and setup[2]["as_user"] == "node"
    run = ws.calls[-1]
    assert run[1].startswith("env -i ") and f"node {PRISTINE}/exercise.js {PRISTINE}/exercise-" in run[1]
    assert "NODE_ENV=production" in run[1] and run[2]["source"] == "exercise" and run[2]["as_user"] == "node"
    assert "NODE_EXTRA_CA_CERTS=/.msb/tls/ca.pem" in run[1]   # or HTTPS fails before the payload is sent
    assert asyncio.run(Exerciser(FakeWs(), log, "npm").run(Request.parse({"package": "."}))).startswith("exercise refused")
    ev = next(e for e in log.events if e.kind == "exercise")
    assert ev.data["stage"] == "exercise" and "tinyconf.load(…) with NODE_ENV=production" in ev.summary
    assert "loaded tinyconf" in out


def test_the_tool_is_offered_only_with_an_exerciser_and_bad_requests_are_refused():
    plain = TriageAgent(None, "m", FakeWs(), EventLog())
    assert "exercise" not in [t["function"]["name"] for t in plain.tools]
    agent = TriageAgent(None, "m", FakeWs(), EventLog(), exerciser=Exerciser(FakeWs(), EventLog(), "npm"))
    assert [t["function"]["name"] for t in agent.tools][-2:] == ["exercise", "finish"]
    out = asyncio.run(agent._tool("exercise", {"package": "x", "env": {"NODE_OPTIONS": "--require /tmp/e.js"}}))
    assert out.startswith("exercise refused:")


def test_exercise_proof_is_labelled_in_the_pr_comment_and_coverage():
    from airlock.prcomment import build_comment, what_ran
    from tests.test_pr import META
    events = [{"id": 1, "kind": "exercise", "containment": False, "data": {"stage": "exercise"},
               "summary": "Airlock calls tinyconf.load(…) with NODE_ENV=production from a fresh copy (chosen by the agent)"},
              {"id": 2, "kind": "canary_exfil", "containment": True, "summary": "POST carried the canary credentials",
               "data": {"stage": "exercise", "proven": True}}]
    assert what_ran(events)["exercised"] == ["tinyconf.load(…) with NODE_ENV=production"]
    assert "only the calls listed were made" in what_ran(events)["not_exercised"]
    body = build_comment({"verdict": "malicious", "decision": None, "meta": META, "evidence": [], "model": "m"},
                         events, "https://airlock.test/runs/1")
    assert "**PROVEN** POST carried the canary credentials _(when Airlock called it as the reviewer asked)_" in body
    assert "Called by Airlock from a fresh copy, as the reviewer asked: `tinyconf.load(…) with NODE_ENV=production`" in body
