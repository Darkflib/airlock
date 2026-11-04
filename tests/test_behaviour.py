"""Base vs head behaviour diff: fingerprints ignore what differs between two runs of the same code."""
import asyncio
from types import SimpleNamespace

from airlock import behaviour, pipeline, sandbox
from airlock.events import EventLog
from airlock.prcomment import build_comment


def detonation(log: EventLog, *, pid: int, token: str, subnet: str, stealer: bool) -> EventLog:
    """What `npm ci` + `npm test` emit, modelled on a real PR #4 run."""
    d = dict(stage="detonate")
    log.emit("exec", "$ npm ci → exit 0", source="detonate", cmd="npm ci")
    log.emit("process_spawn", f"ran /usr/bin/dash", pid=pid, cmd="sh -c npm ci --no-audit --no-fund", exe="/usr/bin/dash", **d)
    log.emit("process_spawn", "ran node", pid=pid + 30, cmd="node test.js", exe="/usr/local/bin/node", **d)
    log.emit("file_read", "test.js read ~/.bashrc", path="/home/node/.bashrc", argv="/work/repo/test.js", pid=pid + 30, **d)
    if stealer:
        log.emit("canary_exfil", "POST carried the canary", host="telemetry.tinystamp.invalid", method="POST",
                 payload=f"token={token}", url=f"https://{subnet}/v1", proven=True, **d)
        log.emit("canary_read", "install.js read canary", path="/home/node/.npmrc", pid=pid + 16,
                 argv="/work/repo/node_modules/tinystamp/scripts/install.js", **d)
        log.emit("egress_blocked", "install.js tried to reach", host="telemetry.tinystamp.invalid", pid=pid + 16,
                 argv="/work/repo/node_modules/tinystamp/scripts/install.js", **d)
        log.emit("process_spawn", "ran node", pid=pid + 16, cmd="node scripts/install.js", exe="/usr/local/bin/node", **d)
    return log


def test_identical_code_has_no_new_behaviour_despite_run_noise():
    head = detonation(EventLog(), pid=531, token="AIRLOCKCANARYAAAA", subnet="198.18.4.9", stealer=False)
    base = detonation(EventLog(), pid=902, token="AIRLOCKCANARYBBBB", subnet="198.18.77.3", stealer=False)
    d = behaviour.diff(head.events, base.events)
    assert d["new"] == [] and d["gone"] == [] and len(d["unchanged"]) == 3


def test_stealer_added_by_the_pr_is_new_and_listed_first():
    head = detonation(EventLog(), pid=531, token="AIRLOCKCANARYAAAA", subnet="198.18.4.9", stealer=True)
    base = detonation(EventLog(), pid=902, token="AIRLOCKCANARYBBBB", subnet="198.18.77.3", stealer=False)
    d = behaviour.diff(head.events, base.events)
    kinds = [e["key"].split("|")[0] for e in d["new"]]
    assert set(kinds) == {"canary_exfil", "canary_read", "egress_blocked", "process_spawn"}
    assert all(e["containment"] for e in d["new"][:3]) and not d["new"][3]["containment"]
    assert "~/.npmrc" in next(e["label"] for e in d["new"] if e["key"].startswith("canary_read"))
    assert "AIRLOCKCANARY" not in str(d)  # no token in keys or labels
    assert set(d["new_ids"]) == {5, 6, 7, 8} and set(d["unchanged_ids"]) == {2, 3, 4}


def test_risky_behaviour_already_in_the_base_is_flagged_not_hidden():
    head = detonation(EventLog(), pid=531, token="AIRLOCKCANARYAAAA", subnet="198.18.4.9", stealer=True)
    base = detonation(EventLog(), pid=902, token="AIRLOCKCANARYBBBB", subnet="198.18.77.3", stealer=True)
    d = behaviour.diff(head.events, base.events)
    assert d["new"] == []
    assert sum(e["containment"] for e in d["unchanged"]) == 3
    assert "pre-existing" in behaviour.summary(d)
    text = behaviour.for_agent(d)
    assert "Already present in the base" in text and "telemetry.tinystamp.invalid" in text


def test_agent_activity_never_enters_the_diff():
    log = EventLog()
    log.emit("canary_read", "agent cat ~/.npmrc", path="/home/node/.npmrc", stage="agent", argv="cat")
    assert behaviour.fingerprints(log.events) == {}


def test_pr_comment_leads_with_new_behaviour():
    head = detonation(EventLog(), pid=531, token="AIRLOCKCANARYAAAA", subnet="198.18.4.9", stealer=True)
    base = detonation(EventLog(), pid=902, token="AIRLOCKCANARYBBBB", subnet="198.18.77.3", stealer=False)
    head.emit("behaviour_diff", "4 new", available=True, base_sha="0123456789", **behaviour.diff(head.events, base.events))
    run = {"verdict": "malicious", "decision": "rejected", "decided_by": "Darkflib", "meta": {"head_sha": "abcdef1"},
           "evidence": [], "model": "m"}
    body = build_comment(run, [e.to_dict() for e in head.events], "https://airlock.test/runs/x")
    assert "**New behaviour introduced by this PR**" in body and "`0123456`" in body
    assert "⚠ sent canary credentials to telemetry.tinystamp.invalid" in body


class FakeGitHub:
    async def pull_request(self, owner, repo, number):
        return SimpleNamespace(title="t", author="a", html_url="u", head_sha="h" * 40, head_ref="f", base_ref="main",
                               base_sha="b" * 40, files=[], slug=f"{owner}/{repo}#{number}")

    async def tarball(self, owner, repo, sha):
        return sha.encode()[:1]  # b"h" for the head, b"m" for the merge base

    async def diff(self, *a):
        return ""

    async def merge_base(self, owner, repo, base, head):
        return "m" * 40


def fake_pr_world(monkeypatch, *, base_fails=False):
    goals = []

    class FakeWorkspace:
        def __init__(self, events, **kw):
            self.events = events

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def write(self, path, data):
            if path == "/work/repo.tgz":
                self.side = data

        async def exec(self, cmd, **kw):
            if "npm ci" in cmd or "npm install" in cmd:
                if self.side == b"m" and base_fails:
                    return sandbox.ExecResult(1, "", "ERESOLVE")
                detonation(self.events, pid=500 if self.side == b"h" else 900, token="AIRLOCKCANARYX",
                           subnet="198.18.1.1", stealer=self.side == b"h")
            return sandbox.ExecResult(0, "package-lock.json", "")

        async def observation_ok(self):
            return True, ""

    class FakeAgent:
        def __init__(self, *a, **kw):
            pass

        async def run(self, goal):
            goals.append(goal)
            return SimpleNamespace(verdict="malicious", evidence=["steals [E9]"])

    monkeypatch.setattr(pipeline, "Workspace", FakeWorkspace)
    monkeypatch.setattr(pipeline, "TriageAgent", FakeAgent)
    monkeypatch.setattr(pipeline, "inference_client", lambda: None)
    monkeypatch.setattr(pipeline.GitHubApp, "from_env", classmethod(lambda cls: FakeGitHub()))
    return goals


def test_pr_run_detonates_the_merge_base_and_tells_the_agent_what_is_new(monkeypatch):
    goals = fake_pr_world(monkeypatch)
    events = EventLog()
    report = asyncio.run(pipeline.analyse_pr("https://github.com/o/r/pull/4", events=events, model="m", max_turns=4))
    diff = next(e for e in events.events if e.kind == "behaviour_diff")
    assert diff.data["available"] and diff.data["base_sha"] == "m" * 40 and report.meta["base_sha"] == "m" * 40
    assert len(diff.data["new"]) == 4
    # base events stayed out of the run's own timeline: only one side's stealer events are here
    assert sum(e.kind == "canary_exfil" for e in events.events) == 1
    assert "New in this PR compared with its merge base" in goals[0] and "telemetry.tinystamp.invalid" in goals[0]


def test_base_that_cannot_install_leaves_the_head_verdict_alone(monkeypatch):
    goals = fake_pr_world(monkeypatch, base_fails=True)
    events = EventLog()
    report = asyncio.run(pipeline.analyse_pr("https://github.com/o/r/pull/4", events=events, model="m", max_turns=4))
    diff = next(e for e in events.events if e.kind == "behaviour_diff")
    assert not diff.data["available"] and "base install exited 1" in diff.data["reason"]
    assert report.verdict == "malicious" and "Behaviour diff unavailable" in goals[0]
