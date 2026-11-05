import base64
import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from airlock import receipts
from airlock.receipts import Signer
from airlock.store import Store
from airlock.web.app import create_app
from tests.test_pr import PR, FakeGitHub, proven_pr_analyse
from tests.test_web import fake_analyse, wait_done

SEED = base64.b64encode(bytes(range(32))).decode()


def trusted(signer: Signer) -> dict:
    return {signer.key_id: signer.public}


def chain(signer: Signer, *bodies: dict) -> dict:
    recs, prev = [], None
    for b in bodies:
        rec = signer.seal({**b, "run": "r1", "prev": prev})
        recs.append(rec)
        prev = rec["sha256"]
    return {"format": receipts.FORMAT, "receipts": recs}


def test_seal_and_verify_round_trip():
    s = Signer.from_seed(SEED)
    bundle = chain(s, {"type": "verdict", "verdict": "malicious"}, {"type": "decision", "decision": "rejected"})
    assert [r["ok"] for r in receipts.verify(bundle, trusted(s))] == [True, True]
    assert json.loads(bundle["receipts"][1]["payload"])["prev"] == bundle["receipts"][0]["sha256"]


def test_payload_is_ascii_whatever_the_evidence_holds():
    """Browsers hash TextEncoder(payload); ASCII-only text makes those bytes the server's bytes."""
    s = Signer.from_seed(SEED)
    rec = s.seal({"type": "verdict", "run": "r1", "prev": None, "events": [{"summary": "naïve ✓ \udc80 \x00"}]})
    assert rec["payload"].isascii()
    assert receipts.verify({"receipts": [rec]}, trusted(s))[0]["ok"]


def test_changed_verdict_is_caught():
    s = Signer.from_seed(SEED)
    bundle = chain(s, {"type": "verdict", "verdict": "malicious"})
    rec = bundle["receipts"][0]
    rec["payload"] = rec["payload"].replace('"malicious"', '"benign"')
    problems = receipts.verify(bundle, trusted(s))[0]["problems"]
    assert any("sha256" in p for p in problems) and "signature doesn't verify" in problems
    rec["sha256"] = __import__("hashlib").sha256(rec["payload"].encode()).hexdigest()  # a forger fixes the hash too
    assert receipts.verify(bundle, trusted(s))[0]["problems"] == ["signature doesn't verify"]


def test_other_keys_and_broken_chains_fail():
    s, other = Signer.from_seed(SEED), Signer.from_seed(receipts.keygen())
    bundle = chain(other, {"type": "verdict"})
    assert "isn't one you trust" in receipts.verify(bundle, trusted(s))[0]["problems"][0]
    # the bundle's own claims about keys are never trusted: only the caller's
    bundle = chain(s, {"type": "verdict"}, {"type": "decision"})
    bundle["receipts"].pop(0)  # drop the evidence, keep the decision
    assert "the first receipt must have prev null" in receipts.verify(bundle, trusted(s))[0]["problems"]


@pytest.fixture
def signed(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    signer = Signer.from_seed(SEED)
    with TestClient(create_app(store=Store(tmp_path / "t.db"), analyse=fake_analyse, signer=signer)) as c:
        yield c, signer


def test_run_is_sealed_at_verdict_and_decision(signed):
    c, signer = signed
    run_id = c.post("/api/runs", data={"spec": "left-pad@1.3.0"}).json()["id"]
    run = wait_done(c, run_id)
    assert run["meta"]["receipt"]["type"] == "verdict"
    bundle = c.get(f"/api/runs/{run_id}/receipts").json()
    assert [r["ok"] for r in receipts.verify(bundle, trusted(signer))] == [True]
    body = json.loads(bundle["receipts"][0]["payload"])
    assert body["verdict"] == "malicious" and body["subject"] == {"spec": "left-pad@1.3.0"}
    assert [e["kind"] for e in body["events"]] == ["vm_created", "canary_read", "verdict"]
    assert run["events"][-1]["kind"] == "receipt"  # the timeline says it was signed

    c.post(f"/api/runs/{run_id}/decision", json={"decision": "rejected", "note": "exfil"})
    bundle = c.get(f"/api/runs/{run_id}/receipts?download=1")
    assert "attachment" in bundle.headers["content-disposition"]
    results = receipts.verify(bundle.json(), trusted(signer))
    assert [(r["type"], r["ok"]) for r in results] == [("verdict", True), ("decision", True)]
    decision = json.loads(bundle.json()["receipts"][1]["payload"])
    assert decision["decision"] == "rejected" and decision["note"] == "exfil"
    assert c.get("/api/signing-key").json() == signer.published()


def test_cli_verifies_a_bundle(signed, tmp_path):
    c, signer = signed
    run_id = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
    wait_done(c, run_id)
    path = tmp_path / "b.json"
    path.write_text(json.dumps(c.get(f"/api/runs/{run_id}/receipts").json()))
    key = signer.published()["public_key"]
    ok = subprocess.run([sys.executable, "-m", "airlock.cli", "verify", str(path), "--key", key], capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.strip().endswith("valid")
    bad = json.loads(path.read_text())
    bad["receipts"][0]["payload"] = bad["receipts"][0]["payload"].replace('"malicious"', '"benign"')
    path.write_text(json.dumps(bad))
    out = subprocess.run([sys.executable, "-m", "airlock.cli", "verify", str(path), "--key", key], capture_output=True, text=True)
    assert out.returncode == 1 and "INVALID" in out.stdout


def test_unsigned_server_has_no_receipts(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    with TestClient(create_app(store=Store(tmp_path / "u.db"), analyse=fake_analyse)) as c:
        run_id = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        assert "receipt" not in wait_done(c, run_id)["meta"]
        assert c.get(f"/api/runs/{run_id}/receipts").status_code == 404
        assert c.get("/api/signing-key").status_code == 404


def test_automatic_rejection_is_sealed_and_cited_on_the_pr(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    signer, gh = Signer.from_seed(SEED), FakeGitHub()
    with TestClient(create_app(store=Store(tmp_path / "p.db"), analyse=proven_pr_analyse, github=gh,
                               signer=signer)) as c:
        run_id = c.post("/api/runs", data={"spec": PR}).json()["id"]
        wait_done(c, run_id)
        bundle = c.get(f"/api/runs/{run_id}/receipts").json()
    results = receipts.verify(bundle, trusted(signer))
    assert [(r["type"], r["ok"]) for r in results] == [("verdict", True), ("decision", True)]
    decision = json.loads(bundle["receipts"][1]["payload"])
    assert decision["automatic"] == "exfiltration proven by a captured payload" and decision["by"] is None
    assert json.loads(bundle["receipts"][0]["payload"])["subject"]["head_sha"] == "abc1234def"
    comment = [x[2] for x in gh.calls if x[0] == "comment"][-1]
    assert f"sha256:{results[1]['sha256'][:16]}" in comment and f"/verify?run={run_id}" in comment


def test_verify_page_and_key_are_public_with_sign_in_on(tmp_path, monkeypatch):
    from tests.test_auth import cfg
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    app = create_app(store=Store(tmp_path / "a.db"), analyse=fake_analyse, auth=cfg(tmp_path),
                     signer=Signer.from_seed(SEED))
    with TestClient(app) as c:
        assert c.get("/verify").status_code == 200
        assert c.get("/api/signing-key").status_code == 200
        assert c.get("/api/runs/x/receipts").status_code == 401  # receipts follow the run's own access rules
