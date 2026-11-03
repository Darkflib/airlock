"""Containment events: typed, timestamped records emitted by deterministic code.
The LLM explains events; it never decides what counts as one."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

# Kinds that represent containment (shown highlighted on the timeline).
CONTAINMENT = {"egress_blocked", "canary_read", "canary_exfil", "guard_flagged", "limit_hit"}


@dataclass
class Event:
    kind: str
    summary: str
    data: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: int = 0

    @property
    def containment(self) -> bool:
        return self.kind in CONTAINMENT

    def to_dict(self) -> dict:
        return {**asdict(self), "containment": self.containment}


class EventLog:
    """Append-only event list with async subscribers (for SSE later)."""

    def __init__(self, on_emit: Callable[[Event], None] | None = None) -> None:
        self.events: list[Event] = []
        self._subscribers: list[asyncio.Queue[Event | None]] = []
        self._on_emit = on_emit

    def emit(self, kind: str, summary: str, **data) -> Event:
        ev = Event(kind=kind, summary=summary, data=data, id=len(self.events) + 1)
        self.events.append(ev)
        if self._on_emit:
            self._on_emit(ev)
        for q in self._subscribers:
            q.put_nowait(ev)
        return ev

    def subscribe(self) -> asyncio.Queue[Event | None]:
        q: asyncio.Queue[Event | None] = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def close(self) -> None:
        """Tell subscribers the stream has ended."""
        for q in self._subscribers:
            q.put_nowait(None)

    def containment(self) -> list[Event]:
        return [e for e in self.events if e.containment]


def events_from_trace(jsonl: str, allowed_hosts: tuple[str, ...]) -> list[tuple[str, str, dict]]:
    """Translate guest tracer lines (airlock/guest/trace.js) into (kind, summary, data).

    Only activity from lifecycle scripts counts: npm itself legitimately reads
    ~/.npmrc and talks to the registry.
    """
    out: list[tuple[str, str, dict]] = []
    seen: set[tuple] = set()
    for line in jsonl.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        argv = rec.get("argv", "")
        if "npm-cli" in argv or "/bin/npm" in argv:
            continue
        ev, host, path = rec.get("ev"), rec.get("host", "?"), rec.get("path", "")
        key = (ev, host, path, argv)
        if key in seen:
            continue
        seen.add(key)
        script = argv.split("/")[-1] or argv
        if ev == "file_read" and (path.endswith(".npmrc") or "/.aws/" in path):
            out.append(("canary_read", f"{script} read canary {path}", {"path": path, "argv": argv}))
        elif ev == "file_read":
            out.append(("file_read", f"{script} read {path}", {"path": path, "argv": argv}))
        elif ev == "net_payload_canary":
            out.append(("canary_exfil", f"{script} tried to send canary credentials to {host}", {"host": host, "argv": argv}))
        elif ev == "net_request":
            bare = host.split(":")[0]
            if any(bare == h or bare.endswith("." + h) for h in allowed_hosts):
                out.append(("egress_allowed", f"{script} contacted allowlisted {host}", {"host": host, "argv": argv}))
            else:
                out.append(("egress_blocked", f"{script} tried to reach {host}; blocked by default-deny egress", {"host": host, "argv": argv}))
        elif ev == "exec":
            out.append(("process_spawn", f"{script} spawned: {rec.get('cmd', '')[:80]}", {"cmd": rec.get("cmd", ""), "argv": argv}))
    return out
