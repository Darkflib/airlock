"""Airlock's pull request comment: one per run, posted when the run starts and rewritten in
place as it progresses (testing, then the verdict with how to decide, then the decision)."""

from __future__ import annotations

import re

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


# How each verdict is shown to people. "benign" stays the stored value, but a quiet run only shows
# that nothing malicious happened in what ran, so it is never presented as "safe".
VERDICT_LABEL = {"benign": "No malicious behaviour observed", "malicious": "Malicious",
                 "suspicious": "Suspicious", "inconclusive": "Inconclusive"}
WATCHED = ("programs started, files opened in home directories (where the fake credentials are), DNS lookups, "
           "connections, and what was sent to Airlock's fake server")
NOT_EXERCISED = ("code your application runs after importing the package, and behaviour that waits, checks for "
                 "a sandbox, or needs real credentials or a real network")


def verdict_label(verdict: str | None) -> str:
    return VERDICT_LABEL.get(verdict or "inconclusive", (verdict or "inconclusive").capitalize())


def short_cmd(cmd: str) -> str:
    cmd = cmd.split("&&")[-1].strip()  # the step that ran the package, not its setup (npm init, venv)
    if "pip install" in cmd:
        return "pip install " + cmd.split()[-1].rsplit("/", 1)[-1]
    return cmd[:80]


def what_ran(events: list[dict]) -> dict:
    """What this verdict covers: the commands Airlock ran on the package, how many the agent ran,
    what was watched, and what a run like this never exercises."""
    ran = [f"{short_cmd(e['data'].get('cmd', ''))} (exit {e['data'].get('exit_code')})" for e in events
           if e["kind"] == "exec" and e["data"].get("source") == "detonate"]
    agent = sum(e["kind"] == "exec" and e["data"].get("source") == "agent" for e in events)
    exercised = [e["summary"].removeprefix("Airlock calls ").split(" from a fresh copy")[0]
                 for e in events if e["kind"] == "exercise"]
    not_exercised = NOT_EXERCISED if not exercised else NOT_EXERCISED.replace(
        "code your application runs after importing the package", "other code your application could call (only the calls listed were made)")
    return {"ran": ran, "agent_commands": agent, "exercised": exercised, "watched": WATCHED,
            "not_exercised": not_exercised}


ICON = {"malicious": "🚫", "suspicious": "⚠️", "inconclusive": "⚠️", "benign": "✅"}
REFS = re.compile(r"\[([^\]]*\bE\d+[^\]]*)\]")


def link_refs(text: str, run_url: str) -> str:
    """"[E57, E58]" in the reviewer's points → links to those events on the run page."""
    def group(m: re.Match) -> str:
        return "(" + re.sub(r"\bE(\d+)\b", lambda e: f"[E{e[1]}]({run_url}#E{e[1]})", m[1]) + ")"
    text = re.sub(r"(\bE\d+)\]\s*\[(?=E\d+)", r"\1, ", text)  # "[E33][E34][E35]" reads as one group
    return REFS.sub(group, text)


def build_comment(run: dict, events: list[dict], run_url: str, held: bool = True) -> str:
    """The PR comment once there is a verdict: what it is and why first, then the proof, then the
    details a reviewer may want, folded away."""
    verdict, decision, who = run["verdict"] or "inconclusive", run["decision"], run.get("decided_by") or "a reviewer"
    m = run["meta"]
    head = m.get("head_sha", "")[:7]
    found = [e for e in events if e["containment"] and e["data"].get("stage") != "agent"]
    proven = next((e for e in found if e["data"].get("proven")), None)
    summary = next((e["data"].get("one_line") for e in reversed(events) if e["kind"] == "verdict"), "") or ""
    lines = [
        f"### {ICON.get(verdict, '')} Airlock: **{verdict_label(verdict)}**, "
        + ("waiting for a decision" if not decision
           else f"{decision} automatically: {m['auto_decision']}" if m.get("auto_decision")
           else f"{decision} by @{who}"),
        ""]
    if summary:
        lines += [summary, ""]
    if proven:
        d = proven["data"]
        when = ("when Airlock ran the code the way a live app would (the AI reviewer chose how)"
                if d.get("stage") == "exercise" else "during install and tests")
        target = d.get("url") or d.get("host") or "an outside server"
        lines += [f"**PROVEN:** Airlock caught a {d.get('method') or 'request'} to `{target}` carrying this run's "
                  f"fake credentials, {when}. Nothing left the sandbox.", ""]
        if d.get("payload"):
            lines += ["<details><summary>The captured request</summary>", "", "```",
                      d["payload"][:1500].replace("```", "\'\'\'"), "```", "",
                      "Those credentials are fake and unique to this run.", "</details>", ""]
    elif found:
        lines += ["**What it did**", ""]
        lines += [f"- {e['summary']}" for e in found[:MAX_ITEMS]]
        if len(found) > MAX_ITEMS:
            lines.append(f"- …and {len(found) - MAX_ITEMS} more")
        lines.append("")
    else:
        lines += ["Nothing suspicious was observed during install and tests: no credential reads, no outbound "
                  "requests, no unexpected processes.", ""]
    if run.get("evidence"):
        lines += ["**Why** (AI reviewer)", ""] + [f"- {link_refs(p, run_url)}" for p in run["evidence"][:MAX_ITEMS]] + [""]
    snap = m.get("snapshot") or {}
    if snap and not snap.get("complete", True):
        lines += [f"_The reviewer saw part of this PR: {'; '.join(snap.get('notes') or [])}. "
                  "Install and tests ran on the full head._", ""]
    changes = next((e["data"] for e in events if e["kind"] == "behaviour_diff"), None)
    if changes and changes.get("available"):
        base = (changes.get("base_sha") or "")[:7]
        new = changes.get("new") or []
        if new:
            lines += [f"**New in this PR** (compared with the code before it, `{base}`, run the same way)", ""]
            lines += [f"- {'⚠ ' if e['containment'] else ''}{e['label']}" for e in new[:MAX_ITEMS]]
            if len(new) > MAX_ITEMS:
                lines.append(f"- …and {len(new) - MAX_ITEMS} more")
        else:
            lines.append(f"Install and tests behave the same as before this PR (`{base}`)"
                         + (", so the problem only shows when the code runs." if proven else "."))
        pre = [e for e in changes.get("unchanged") or [] if e["containment"]]
        if pre:
            lines += ["", f"{len(pre)} risky behaviour{'s' if len(pre) != 1 else ''} already present before this "
                      "PR: not introduced by it, but still there."]
        lines.append("")
    elif changes:
        lines += [f"_No comparison with the code before this PR: {changes.get('reason')}._", ""]
    cover = what_ran(events)
    lines += ["<details><summary>What this covers</summary>", "",
              f"- Tested `{head}` in a throwaway VM with fake credentials, reaching only the package registries",
              f"- Ran as an unprivileged user: {', '.join(f'`{c}`' for c in cover['ran']) or 'nothing (see the timeline)'}"
              + (f"; the AI reviewer then ran {cover['agent_commands']} command{'s' if cover['agent_commands'] != 1 else ''}"
                 if cover["agent_commands"] else ""),
              *([f"- Called by Airlock from a fresh copy, as the reviewer asked: "
                 f"{'; '.join(f'`{x}`' for x in cover['exercised'])}"] if cover["exercised"] else []),
              f"- Watched: {cover['watched']}",
              f"- Not exercised: {cover['not_exercised']}"]
    if proven and len(found) > 1:
        lines += ["- Everything it did:"] + [f"  - {e['summary']}" for e in found[:MAX_ITEMS]]
    lines += ["", "</details>", ""]
    if not decision:
        lines += how_to_decide(run_url, held)
    if run.get("decision_note"):
        lines += [f"> {run['decision_note']}", ""]
    lines.append(f"[Full run timeline]({run_url}) · reviewer model `{run.get('model') or '?'}`")
    return "\n".join(lines)
