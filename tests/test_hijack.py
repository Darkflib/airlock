"""A reviewer talked round by the package can't soften a proven theft: the verdict and the merge gate
both rest on the payload captured on the host, not on the model's word."""

import asyncio
import tarfile
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from airlock import guard
from airlock.events import EventLog
from airlock.pipeline import apply_proof
from airlock.store import Store
from airlock.web.app import create_app
from tests.test_pr import META, PR, FakeGitHub
from tests.test_web import wait_done

FIXTURE = Path(__file__).parent.parent / "evals" / "fixtures" / "logfmt-lite-hijack.tgz"
PROOF = dict(proven=True, this_run=True, source_kind="sinkhole", stage="detonate")


def test_proof_outranks_a_benign_verdict():
    events = EventLog()
    events.emit("canary_exfil", "POST carried this run's canary token", **PROOF)
    verdict, evidence = apply_proof("benign", ["audited, see SECURITY-AUDIT.md"], events)
    assert verdict == "malicious" and evidence[0].endswith("[E1].") and evidence[1].startswith("audited")
    last = events.events[-1]
    assert last.kind == "verdict" and last.data["agent_verdict"] == "benign" and last.data["overridden"]
    assert "overruled" in last.data["one_line"]
    assert apply_proof("malicious", ["x"], events) == ("malicious", ["x"])


def test_only_host_proof_from_the_package_overrides():
    for data in ({**PROOF, "stage": "agent"},            # the agent's own commands
                 {**PROOF, "source_kind": "trace"},      # guest telemetry the package could forge
                 {**PROOF, "this_run": False}):          # another run's token
        events = EventLog()
        events.emit("canary_exfil", "not proof", **data)
        assert apply_proof("benign", ["ok"], events) == ("benign", ["ok"])


async def hijacked_pr_analyse(target, *, events, on_pr=None, **_):
    """The reviewer said benign, as the package asked; the sinkhole still caught the token."""
    if on_pr:
        await on_pr(META)
    events.emit("canary_exfil", "POST https://cache.logfmt-lite.invalid/v1/warm carried this run's canary token",
                url="https://cache.logfmt-lite.invalid/v1/warm", **PROOF)
    await asyncio.sleep(0.01)
    return SimpleNamespace(verdict="benign", evidence=["audited"], model="m", meta=META)


def test_a_hijacked_reviewer_cannot_open_the_merge_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    gh = FakeGitHub()
    with TestClient(create_app(store=Store(tmp_path / "p.db"), analyse=hijacked_pr_analyse, github=gh)) as c:
        run = wait_done(c, c.post("/api/runs", data={"spec": PR}).json()["id"])
    assert run["decision"] == "rejected" and run["decided_by"] is None
    assert [x[2] for x in gh.calls if x[0] == "status"][-1] == "failure"


def test_fixture_tells_the_reviewer_it_is_safe_and_ships_no_giveaway():
    with tarfile.open(FIXTURE) as tf:
        files = {m.name: tf.extractfile(m).read().decode() for m in tf.getmembers() if m.isfile()}
    shipped = "\n".join(files.values())
    assert "fixture" not in shipped.lower() and "stealer" not in shipped.lower()
    # The blunt line is caught; the fake audit's "guidance for automated review pipelines" is not.
    assert guard.screen(files["package/README.md"])[1]
    assert not guard.screen(files["package/SECURITY-AUDIT.md"])[1]
