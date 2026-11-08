"""A run as SARIF 2.1.0, for GitHub code scanning and other security dashboards.

One result per containment event Airlock saw while the package ran (install, tests or the
agent's `exercise`), plus one for the verdict. SARIF wants a file for every result, and
behaviour has no line number, so results point at the manifest that brought the code in
(package.json or setup.py). The run page and the PR comment stay the place to read the
evidence; this file is so findings can live next to a team's other scanners.

Upload to GitHub with `github/codeql-action/upload-sarif`, or `gh api` on
/repos/{owner}/{repo}/code-scanning/sarifs.
"""

from __future__ import annotations

import hashlib

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/Darkflib/airlock"

# rule id -> (short name, description, SARIF level, security-severity for GitHub, 0-10)
RULES: dict[str, tuple[str, str, str, str]] = {
    "AIRLOCK001": ("ProvenCredentialExfiltration",
                   "The package sent this run's fake credentials out, and Airlock captured the request on the host.",
                   "error", "9.8"),
    "AIRLOCK002": ("ObservedCredentialExfiltration",
                   "Credentials appear to have left the package, seen inside the VM or inferred from reads plus "
                   "connections. Not proof: in-VM telemetry could be forged.", "error", "8.0"),
    "AIRLOCK003": ("CredentialFileRead", "The package read a credential file (fake ones Airlock planted).",
                   "warning", "6.5"),
    "AIRLOCK004": ("BlockedNetworkAccess",
                   "The package tried to reach a host outside the package registries; Airlock answered or refused it.",
                   "warning", "5.0"),
    "AIRLOCK005": ("PromptInjection", "Text in the package tried to instruct the AI reviewer.", "warning", "5.0"),
    "AIRLOCK006": ("ResourceLimit", "The package hit a time, memory or process limit.", "note", "3.0"),
    "AIRLOCK100": ("Verdict", "Airlock's overall verdict for this run.", "note", "0.0"),
}
VERDICT_LEVEL = {"malicious": ("error", "9.0"), "suspicious": ("warning", "6.0"),
                 "inconclusive": ("note", "3.0"), "benign": ("none", "0.0")}


def _rule(ev: dict) -> str | None:
    kind, data = ev["kind"], ev.get("data") or {}
    if kind == "canary_exfil":
        if data.get("this_run") is False:
            return "AIRLOCK002"
        return "AIRLOCK001" if data.get("proven") else "AIRLOCK002"
    return {"canary_read": "AIRLOCK003", "egress_blocked": "AIRLOCK004", "dns_blocked": "AIRLOCK004",
            "guard_flagged": "AIRLOCK005", "limit_hit": "AIRLOCK006"}.get(kind)


def _manifest(target: str) -> str:
    from .pipeline import is_python_target
    return "setup.py" if is_python_target(target) else "package.json"


def _location(uri: str) -> list[dict]:
    return [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}]


def _fingerprint(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def to_sarif(*, run_id: str, target: str, verdict: str | None, evidence: list[str], events: list[dict],
             run_url: str | None = None, version: str = "0.1.0") -> dict:
    uri = _manifest(target)
    results = []
    for ev in events:
        data = ev.get("data") or {}
        if data.get("stage") not in (None, "detonate", "exercise") or not (rule := _rule(ev)):
            continue
        detail = data.get("host") or data.get("path") or data.get("url") or ""
        props = {k: data[k] for k in ("stage", "host", "path", "url", "via", "encoding", "proven") if k in data}
        results.append({
            "ruleId": rule, "level": RULES[rule][2],
            "message": {"text": f"{ev['summary']} [E{ev.get('id', '?')}]"},
            "locations": _location(uri),
            "partialFingerprints": {"airlockBehaviour/v1": _fingerprint(target, rule, detail)},
            "properties": {"event": ev.get("id"), **props},
        })
    if verdict:
        level, sev = VERDICT_LEVEL.get(verdict, ("note", "3.0"))
        text = f"Airlock verdict: {verdict}." + ("".join(f" {p}" for p in evidence[:6]) if evidence else "")
        results.append({
            "ruleId": "AIRLOCK100", "level": level, "message": {"text": text[:4000]},
            "locations": _location(uri),
            "partialFingerprints": {"airlockVerdict/v1": _fingerprint(target, "verdict")},
            "properties": {"verdict": verdict, "security-severity": sev},
        })
    rules = [{"id": rid, "name": name, "shortDescription": {"text": name},
              "fullDescription": {"text": desc}, "defaultConfiguration": {"level": level},
              "helpUri": INFO_URI, "properties": {"security-severity": sev, "tags": ["security", "supply-chain"]}}
             for rid, (name, desc, level, sev) in RULES.items()]
    run = {
        "tool": {"driver": {"name": "Airlock", "informationUri": INFO_URI, "version": version, "rules": rules}},
        "automationDetails": {"id": f"airlock/{run_id}"},
        "results": results,
        "properties": {"target": target, "verdict": verdict, "evidence": evidence},
    }
    if run_url:
        run["properties"]["runUrl"] = run_url
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
