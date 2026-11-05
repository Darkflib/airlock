"""Airlock's pull request comment: one per run, posted when the run starts and rewritten in
place as it progresses (testing, then the verdict with how to decide, then the decision)."""

from __future__ import annotations

MAX_ITEMS = 8


NOT_HELD = ("⚠ **Airlock could not set the `airlock` check on GitHub**, so the check may still show an earlier "
            "result for this commit, possibly a pass. Don't merge on it until it reads pending or shows a decision.")


def how_to_decide(run_url: str, held: bool = True) -> list[str]:
    gate = ("The `airlock` check stays pending and this PR can't merge" if held else NOT_HELD + " Nothing is final")
    return [f"**Waiting for a decision.** {gate} until someone with write access to the repository comments "
            "`/airlock approve` or `/airlock reject` (a note after it is kept with the decision), or decides on the "
            f"[run page]({run_url}).", ""]


def build_progress(run: dict, run_url: str, failed: str | None = None, held: bool = True,
                   queued: int | None = None) -> str:
    """The comment while the run waits for a slot (`queued`: runs ahead of it) or is in progress,
    or after it failed."""
    head = run["meta"].get("head_sha", "")[:7]
    if queued is not None:
        return "\n".join([
            "### Airlock: queued", "",
            f"Airlock will test this PR's head (`{head}`) as soon as a slot is free"
            + (f" ({queued} run{'s' if queued != 1 else ''} ahead)." if queued else "; it should start shortly.")
            + " This comment updates when testing starts; "
            + ("the `airlock` check stays pending meanwhile." if held else "\n\n" + NOT_HELD), "",
            f"[Run page]({run_url})"])
    if failed:
        return "\n".join([
            "### Airlock: run failed", "",
            f"Airlock couldn't finish testing this PR's head (`{head}`): {failed[:300]}", "",
            ("The `airlock` check is set to error, so this PR can't merge on Airlock's word." if held else NOT_HELD)
            + " Push again, or rerun it from Airlock, before merging.", "", f"[Run timeline]({run_url})"])
    return "\n".join([
        "### Airlock: testing this PR…", "",
        f"Airlock is installing and testing this PR's head (`{head}`) in a disposable microVM with fake "
        "credentials and no internet access beyond the package registries. This comment updates with the "
        "results, usually within a minute; " + ("the `airlock` check stays pending meanwhile." if held else "")
        + ("" if held else "\n\n" + NOT_HELD), "",
        f"[Watch it live]({run_url})"])


def build_comment(run: dict, events: list[dict], run_url: str, held: bool = True) -> str:
    verdict, decision, who = run["verdict"] or "inconclusive", run["decision"], run.get("decided_by") or "a reviewer"
    head = run["meta"].get("head_sha", "")[:7]
    found = [e for e in events if e["containment"] and e["data"].get("stage") != "agent"]
    lines = [
        f"### Airlock: **{verdict.upper()}**, "
        + ("waiting for a decision" if not decision
           else f"{decision} automatically: {run['meta']['auto_decision']}" if run["meta"].get("auto_decision")
           else f"{decision} by @{who}"),
        "",
        f"Airlock installed and tested this PR's head (`{head}`) in a disposable microVM with fake credentials "
        "and no internet access beyond the package registries, recorded what it did, then had an AI reviewer "
        "investigate.",
        "",
    ]
    snap = run["meta"].get("snapshot") or {}
    if snap and not snap.get("complete", True):
        lines += [f"_The reviewer saw part of this PR: {'; '.join(snap.get('notes') or [])}. "
                  "Install and tests ran on the full head._", ""]
    changes = next((e["data"] for e in events if e["kind"] == "behaviour_diff"), None)
    if changes and changes.get("available"):
        base = (changes.get("base_sha") or "")[:7]
        lines += [f"**New behaviour introduced by this PR** (compared with its merge base `{base}`, "
                  "run the same way in a separate microVM)", ""]
        new = changes.get("new") or []
        lines += [f"- {'⚠ ' if e['containment'] else ''}{e['label']}" for e in new[:MAX_ITEMS]] or ["- none"]
        if len(new) > MAX_ITEMS:
            lines.append(f"- …and {len(new) - MAX_ITEMS} more")
        pre = [e for e in changes.get("unchanged") or [] if e["containment"]]
        if pre:
            lines += ["", f"{len(pre)} risky behaviour{'s' if len(pre) != 1 else ''} already present in the base "
                      "branch: not introduced by this PR, but still there."]
        lines.append("")
    elif changes:
        lines += [f"_Behaviour diff against the base unavailable: {changes.get('reason')}._", ""]
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
    if not decision:
        lines += how_to_decide(run_url, held)
    if run.get("decision_note"):
        lines += [f"> {run['decision_note']}", ""]
    lines.append(f"[Full run timeline]({run_url}) · reviewer model `{run.get('model') or '?'}`")
    return "\n".join(lines)
