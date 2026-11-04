"""Behaviour diff: what a pull request's head does that its merge base doesn't.

Both sides are detonated the same way, each in its own microVM. Their detonation events are
reduced to fingerprints with everything that differs between two runs of the same code removed
(pids, canary tokens, sinkhole addresses, checkout paths), then compared as sets.

The diff is context for the reviewer, never a filter: behaviour the base already has is
labelled "pre-existing", not hidden, and the diff never lowers a verdict.
"""

from __future__ import annotations

import re

from .events import Event

HOME = re.compile(r"^/(?:home/[^/]+|root)(?=/|$)")
CHECKOUT = re.compile(r"/work/repo/|/tmp/try/")
NOISE = [
    (re.compile(r"AIRLOCKCANARY\w*", re.I), "<canary>"),
    (re.compile(r"\b198\.(?:18|19)\.\d+\.\d+\b"), "<sinkhole>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"/tmp/[\w.-]+"), "/tmp/<tmp>"),
]
# Kinds that describe what the code did. Airlock's own bookkeeping (exec, vm_created, ...) is the
# same on both sides by construction and would only add noise.
BEHAVIOUR = {"process_spawn", "file_read", "canary_read", "canary_exfil", "egress_blocked", "egress_allowed",
             "dns_blocked", "limit_hit", "connect"}


def clean(text: str) -> str:
    text = CHECKOUT.sub("", text or "")
    for pattern, repl in NOISE:
        text = pattern.sub(repl, text)
    return text.strip()


def path(p: str) -> str:
    return HOME.sub("~", p or "")


def actor(data: dict) -> str:
    """Who did it: the script or command, relative to the checkout."""
    return clean(data.get("argv") or data.get("cmd") or data.get("exe") or "")


def fingerprint(ev: Event) -> tuple[str, str] | None:
    """(key, label) for a detonation event, or None if it isn't behaviour of the code."""
    d = ev.data
    if ev.kind not in BEHAVIOUR or d.get("stage") != "detonate":
        return None
    if ev.kind == "process_spawn":
        what = clean(d.get("cmd") or d.get("exe") or "")
        return f"process_spawn|{what}", f"ran `{what}`"
    if ev.kind in ("file_read", "canary_read"):
        p, who = path(d.get("path", "")), actor(d)
        verb = "read canary" if ev.kind == "canary_read" else "read"
        return f"{ev.kind}|{p}|{who}", f"{who or 'something'} {verb} {p}"
    if ev.kind == "canary_exfil":
        host, method = d.get("host") or "", d.get("method") or ""
        return f"canary_exfil|{host}|{method}", f"sent canary credentials to {host} ({method or 'request'})"
    if ev.kind in ("egress_blocked", "egress_allowed", "dns_blocked", "connect"):
        host = clean(d.get("host") or d.get("name") or d.get("dest") or "")
        verb = {"egress_allowed": "reached", "dns_blocked": "looked up"}.get(ev.kind, "tried to reach")
        return f"{ev.kind}|{host}|{actor(d)}", f"{actor(d) or 'something'} {verb} {host}"
    return f"{ev.kind}|{clean(ev.summary)}", clean(ev.summary)


def fingerprints(events: list[Event]) -> dict[str, dict]:
    """key -> {"label", "ids", "containment"}, for the detonation events of one side."""
    out: dict[str, dict] = {}
    for ev in events:
        fp = fingerprint(ev)
        if fp is None:
            continue
        key, label = fp
        entry = out.setdefault(key, {"label": label, "ids": [], "containment": False})
        entry["ids"].append(ev.id)
        entry["containment"] |= ev.containment
    return out


def diff(head: list[Event], base: list[Event]) -> dict:
    """New in the head, gone from the head, and unchanged, as data for the behaviour_diff event.
    Entries keep the head's event ids so the page and the agent can point at them."""
    h, b = fingerprints(head), fingerprints(base)
    new = [{"key": k, **v} for k, v in h.items() if k not in b]
    same = [{"key": k, **v} for k, v in h.items() if k in b]
    gone = [{"key": k, "label": v["label"], "containment": v["containment"]} for k, v in b.items() if k not in h]
    order = lambda e: (not e["containment"], e["label"])  # noqa: E731 - containment first
    return {"new": sorted(new, key=order), "unchanged": sorted(same, key=order), "gone": sorted(gone, key=order),
            "new_ids": sorted(i for e in new for i in e["ids"]),
            "unchanged_ids": sorted(i for e in same for i in e["ids"])}


def summary(d: dict) -> str:
    n, c = len(d["new"]), sum(e["containment"] for e in d["new"])
    pre = sum(e["containment"] for e in d["unchanged"])
    parts = [f"{n} new behaviour{'s' if n != 1 else ''} compared with the base"
             + (f" ({c} containment)" if c else ""), f"{len(d['unchanged'])} unchanged"]
    if pre:
        parts.append(f"{pre} containment already in the base: pre-existing, still present")
    if d["gone"]:
        parts.append(f"{len(d['gone'])} gone")
    return "; ".join(parts)


def for_agent(d: dict) -> str:
    """The diff in the agent's task. Pre-existing risky behaviour is called out, not dropped."""
    if not d.get("available", True):
        return f"Behaviour diff unavailable: {d.get('reason', 'the base could not be run')}. Judge the head on its own."
    lines = ["New in this PR compared with its merge base (ids are this run's events):"]
    lines += [f"- {e['label']} [{', '.join('E' + str(i) for i in e['ids'][:4])}]" for e in d["new"]] or ["- nothing"]
    pre = [e for e in d["unchanged"] if e["containment"]]
    if pre:
        lines.append("Already present in the base (not introduced by this PR, but still risky if merged):")
        lines += [f"- {e['label']} [{', '.join('E' + str(i) for i in e['ids'][:4])}]" for e in pre]
    return "\n".join(lines)
