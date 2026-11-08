from fastapi.testclient import TestClient

from airlock.sarif import RULES, to_sarif
from airlock.store import Store
from airlock.web.app import create_app
from tests.test_web import fake_analyse, wait_done

EVENTS = [
    {"id": 1, "kind": "vm_created", "summary": "microVM up", "data": {}},
    {"id": 2, "kind": "canary_read", "summary": "postinstall.js read canary /home/node/.npmrc",
     "data": {"stage": "detonate", "path": "/home/node/.npmrc"}},
    {"id": 3, "kind": "canary_exfil", "summary": "POST http://t.evil.invalid/c carried the canary credentials",
     "data": {"stage": "detonate", "host": "t.evil.invalid", "proven": True, "this_run": True, "encoding": "base64"}},
    {"id": 4, "kind": "egress_blocked", "summary": "base looked up x", "data": {"stage": "base", "host": "x"}},
    {"id": 5, "kind": "dns_blocked", "summary": "DNS lookup of y refused", "data": {"stage": "exercise", "host": "y"}},
]


def doc(target="left-pad@1.3.0", verdict="malicious"):
    return to_sarif(run_id="r1", target=target, verdict=verdict, evidence=["It steals the npm token [E3]."],
                    events=EVENTS, run_url="https://a.example/runs/r1")


def test_shape_is_sarif_2_1_0_with_every_rule_declared():
    d = doc()
    assert d["version"] == "2.1.0" and d["$schema"].endswith("sarif-2.1.0.json")
    [run] = d["runs"]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert declared == set(RULES)
    assert all(r["ruleId"] in declared for r in run["results"])
    assert run["automationDetails"]["id"] == "airlock/r1" and run["properties"]["runUrl"].endswith("/runs/r1")


def test_results_follow_the_events_and_skip_base_and_setup():
    results = doc()["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["AIRLOCK003", "AIRLOCK001", "AIRLOCK004", "AIRLOCK100"]
    proven = results[1]
    assert proven["level"] == "error" and proven["properties"]["encoding"] == "base64"
    assert proven["message"]["text"].endswith("[E3]")
    # every result needs a file for GitHub code scanning: the manifest that brought the code in
    assert {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results} == {"package.json"}
    assert all(r["partialFingerprints"] for r in results)


def test_verdict_levels_and_python_manifest():
    v = doc(target="pypi:six==1.17.0", verdict="benign")["runs"][0]["results"][-1]
    assert v["ruleId"] == "AIRLOCK100" and v["level"] == "none"
    assert v["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "setup.py"
    assert doc(verdict="malicious")["runs"][0]["results"][-1]["level"] == "error"


def test_observed_and_other_runs_tokens_are_not_proven():
    evs = [{"id": 9, "kind": "canary_exfil", "summary": "inferred", "data": {"stage": "detonate", "inferred": True}},
           {"id": 10, "kind": "canary_exfil", "summary": "not ours", "data": {"stage": "detonate", "proven": False,
                                                                            "this_run": False}}]
    results = to_sarif(run_id="r", target="x@1", verdict=None, evidence=[], events=evs)["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["AIRLOCK002", "AIRLOCK002"]


def test_web_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    with TestClient(create_app(store=Store(tmp_path / "s.db"), analyse=fake_analyse)) as c:
        run_id = c.post("/api/runs", data={"spec": "left-pad@1.3.0"}).json()["id"]
        wait_done(c, run_id)
        r = c.get(f"/api/runs/{run_id}/sarif?download=1")
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/sarif+json")
        assert "attachment" in r.headers["content-disposition"]
        results = r.json()["runs"][0]["results"]
        assert results[-1]["ruleId"] == "AIRLOCK100" and results[-1]["properties"]["verdict"] == "malicious"
        assert any(x["ruleId"] == "AIRLOCK003" for x in results)  # fake_analyse reads a canary
        assert c.get("/api/runs/nope/sarif").status_code == 404
