"""The verdict as a pull request comment, posted only after a human decision."""

from __future__ import annotations

MAX_ITEMS = 8


def build_comment(run: dict, events: list[dict], run_url: str) -> str:
    verdict, decision, who = run["verdict"] or "inconclusive", run["decision"], run.get("decided_by") or "a reviewer"
    head = run["meta"].get("head_sha", "")[:7]
    found = [e for e in events if e["containment"] and e["data"].get("stage") != "agent"]
    lines = [
        f"### Airlock: **{verdict.upper()}**, {decision} by @{who}",
        "",
        f"Airlock installed this PR's head (`{head}`) in a disposable microVM with fake credentials and no "
        "internet access, recorded everything it did, then had an AI reviewer investigate.",
        "",
    ]
    if found:
        lines += ["**What it did during install and test**", ""]
        lines += [f"- {'**PROVEN** ' if e['data'].get('proven') else ''}{e['summary']}" for e in found[:MAX_ITEMS]]
        if len(found) > MAX_ITEMS:
            lines.append(f"- …and {len(found) - MAX_ITEMS} more")
        lines.append("")
        payload = next((e["data"] for e in found if e["data"].get("payload")), None)
        if payload:
            lines += [f"<details><summary>Captured request: {payload.get('method', '')} {payload.get('url', '')}"
                      "</summary>", "", "```", payload["payload"][:1500].replace("```", "'''"), "```", "",
                      "The credentials above are Airlock's per-run canaries, not real secrets.", "</details>", ""]
    else:
        lines += ["Nothing suspicious was observed during install and test: no credential reads, no outbound "
                  "requests, no unexpected processes.", ""]
    if run.get("evidence"):
        lines += ["**Reviewer's evidence**", ""] + [f"- {p}" for p in run["evidence"][:MAX_ITEMS]] + [""]
    if run.get("decision_note"):
        lines += [f"> {run['decision_note']}", ""]
    lines.append(f"[Full run timeline]({run_url}) · reviewer model `{run.get('model') or '?'}`")
    return "\n".join(lines)
