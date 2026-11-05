"""Containment events: typed, timestamped records emitted by deterministic code.
The LLM explains events; it never decides what counts as one."""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

# Kinds that represent containment (shown highlighted on the timeline).
CONTAINMENT = {"egress_blocked", "canary_read", "canary_exfil", "guard_flagged", "limit_hit", "dns_blocked"}


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


# Budgets. A package controls how many events its run produces (every file it opens, every name it
# looks up), so a run keeps at most MAX_EVENTS. Past that only the events a verdict depends on are
# kept, and the run is marked truncated, which makes a quiet result inconclusive (observation_ok).
MAX_EVENTS = int(os.environ.get("AIRLOCK_MAX_EVENTS", "5000"))
ALWAYS_KEEP = {"verdict", "error", "coverage_incomplete", "vm_destroyed", "behaviour_diff", "citation_invalid"}
HARD_EXTRA = 200  # what ALWAYS_KEEP may add past the cap
SUBSCRIBER_BACKLOG = 1000  # events a live viewer may fall behind by before its stream is ended
OVERFLOW = Event("stream_overflow", "this viewer fell too far behind; reconnect to replay")


class EventLog:
    """Append-only event list with async subscribers (for SSE later)."""

    def __init__(self, on_emit: Callable[[Event], None] | None = None, max_events: int | None = None) -> None:
        self.events: list[Event] = []
        self._subscribers: list[asyncio.Queue[Event | None]] = []
        self._on_emit = on_emit
        self.max_events = MAX_EVENTS if max_events is None else max_events
        self.truncated = 0  # events dropped past the cap
        self._kept_proof = False

    def _keep(self, kind: str, data: dict) -> bool:
        n = len(self.events)
        if n < self.max_events:
            return True
        if n >= self.max_events + HARD_EXTRA:
            return False
        if kind == "canary_exfil" and data.get("proven") and not self._kept_proof:
            self._kept_proof = True  # proof still decides the gate, however noisy the run was
            return True
        return kind in ALWAYS_KEEP

    def emit(self, kind: str, summary: str, **data) -> Event:
        if not self._keep(kind, data):
            self.truncated += 1
            if self.truncated == 1:
                self._append(Event("limit_hit", f"more than {self.max_events} events: Airlock stopped recording "
                                   "routine events for this run, so a quiet result can't be trusted",
                                   {"limit": "events", "max_events": self.max_events}))
            return Event(kind=kind, summary=summary, data=data)  # not recorded: id 0
        return self._append(Event(kind=kind, summary=summary, data=data))

    def _append(self, ev: Event) -> Event:
        ev.id = len(self.events) + 1
        self.events.append(ev)
        if self._on_emit:
            self._on_emit(ev)
        for q in list(self._subscribers):
            self._offer(q, ev)
        return ev

    def _offer(self, q: asyncio.Queue, item: Event | None) -> None:
        """A viewer that stopped reading must not grow memory: past the backlog its queue is emptied
        and ended with OVERFLOW. The stream closes and the browser reconnects, replaying from the store."""
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:
            self.unsubscribe(q)
            while not q.empty():
                q.get_nowait()
            q.put_nowait(OVERFLOW)

    def subscribe(self) -> asyncio.Queue[Event | None]:
        q: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=SUBSCRIBER_BACKLOG)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def close(self) -> None:
        """Tell subscribers the stream has ended."""
        for q in list(self._subscribers):
            self._offer(q, None)

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
        # Airlock's exercise harness runs the package's code: name the package, not the harness's spec file
        script = "the package" if "airlock-pristine/exercise.js" in argv else argv.split("/")[-1] or argv
        pid = rec.get("pid")
        if ev == "file_read" and (path.endswith(CANARY_SUFFIXES) or "/.aws/" in path):
            out.append(("canary_read", f"{script} read canary {path}", {"path": path, "argv": argv, "pid": pid, "source_kind": "node"}))
        elif ev == "file_read":
            out.append(("file_read", f"{script} read {path}", {"path": path, "argv": argv, "pid": pid, "source_kind": "node"}))
        elif ev == "net_payload_canary":
            bare = host.split(":")[0]
            where = " in a request URL" if rec.get("where") == "url" else ""
            if any(bare == h or bare.endswith("." + h) for h in allowed_hosts):
                # Allowed hosts aren't sinkholed: this one really got there (only that host can read it).
                out.append(("canary_exfil", f"{script} sent canary credentials to allowlisted {host}{where}: it reached that host",
                            {"host": host, "argv": argv, "pid": pid, "source_kind": "node", "allowlisted": True}))
            else:
                out.append(("canary_exfil", f"{script} tried to send canary credentials to {host}{where}",
                            {"host": host, "argv": argv, "pid": pid, "source_kind": "node"}))
        elif ev == "net_request":
            bare = host.split(":")[0]
            if any(bare == h or bare.endswith("." + h) for h in allowed_hosts):
                out.append(("egress_allowed", f"{script} contacted allowlisted {host}", {"host": host, "argv": argv, "pid": pid, "source_kind": "node"}))
            else:
                out.append(("egress_blocked", f"{script} tried to reach {host}; contained, never reached the internet", {"host": host, "argv": argv, "pid": pid, "source_kind": "node"}))
        elif ev == "exec":
            out.append(("process_spawn", f"{script} spawned: {rec.get('cmd', '')[:80]}", {"cmd": rec.get("cmd", ""), "argv": argv, "pid": pid, "source_kind": "node"}))
    return out


CANARY_SUFFIXES = (".npmrc", "/.aws/credentials", "/.pypirc")
CANARY_MARK = "airlockcanary"  # every canary token starts with it (airlock/sandbox.py)
NPM_MARKERS = ("npm-cli.js", "/bin/npm ", "npm install", "npm pack", "npm init")


def _is_npm(rec: dict) -> bool:
    cmd = rec.get("cmd", "")
    return any(m in cmd for m in NPM_MARKERS)


def _who(rec: dict) -> str:
    if rec.get("exe"):
        return rec["exe"].rsplit("/", 1)[-1]
    if rec.get("ev") == "exec" and rec.get("path"):
        return rec["path"].rsplit("/", 1)[-1]
    if rec.get("cmd"):
        return rec["cmd"].split()[0].rsplit("/", 1)[-1]
    return "a process"


def _allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    bare = host.split(":")[0].rstrip(".")
    return any(bare == h or bare.endswith("." + h) for h in allowed_hosts)


class WatchTranslator:
    """Turns in-guest watcher lines (airlock/guest/watch.py) into events.

    Only the unprivileged package user counts: root activity is Airlock itself or
    the agent. Exfiltration is inferred when one process both read a canary and
    tried to reach a non-allowlisted destination.
    """

    def __init__(self, allowed_hosts: tuple[str, ...]):
        self.allowed_hosts = allowed_hosts
        self.read_canary: dict[int, str] = {}   # pid or parent pid -> canary path
        self.blocked: dict[int, str] = {}       # pid or parent pid -> destination
        self.exfil_reported: set[int] = set()
        self.seen: set[tuple] = set()
        self.ip_names: dict[str, str] = {}      # resolved IP -> hostname, from DNS answers
        self.pid_exe: dict[int, str] = {}       # pid -> program path, from exec records
        self.pid_uid: dict[int, int] = {}       # pid -> uid, from exec records (captured at start)

    def feed(self, jsonl: str) -> list[tuple[str, str, dict]]:
        out: list[tuple[str, str, dict]] = []
        recs = []
        for line in jsonl.splitlines():
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        # npm re-execs through its shebang (npm-cli.js -> env -> node) under one pid;
        # only the last step shows npm's command line, so drop the whole pid.
        npm_pids = {r.get("pid") for r in recs if _is_npm(r) or "/node_modules/npm/" in r.get("path", "")}
        # Short-lived processes may be gone before their open/dns record is enriched;
        # their exec record still names the program.
        for r in recs:
            if r.get("ev") == "exec" and r.get("path"):
                self.pid_exe[r.get("pid")] = r["path"]
                if r.get("uid") is not None:
                    self.pid_uid[r.get("pid")] = r["uid"]
        for rec in recs:
            if rec.get("ev") == "dns_answer":
                for ip in rec.get("ips", []):
                    self.ip_names[ip] = rec.get("name", "")
        for rec in recs:
            ev, pid = rec.get("ev"), rec.get("pid")
            if ev == "connect_refused":
                n = rec.get("count", 1)
                out.append(("egress_blocked", f"{n} outbound connection attempt{'s' if n != 1 else ''} refused by the "
                            "egress policy (refused too fast to attribute to a process)",
                            {"count": n, "via": "tcp-counter", "source_kind": "watch", "ts_guest": rec.get("ts")}))
                continue
            if rec.get("uid") is None and pid in self.pid_uid:  # process exited before we could look
                rec = {**rec, "uid": self.pid_uid[pid]}
            if ev in ("watch_ready", "dns_answer", None) or rec.get("uid") in (0, None) or pid in npm_pids:
                continue
            if not rec.get("exe") and pid in self.pid_exe:
                rec = {**rec, "exe": self.pid_exe[pid]}
            who, cmd = _who(rec), rec.get("cmd", "")
            base = {"pid": pid, "cmd": cmd, "exe": rec.get("exe") or rec.get("path"), "source_kind": "watch"}
            key = (ev, rec.get("path") or rec.get("name") or rec.get("dest"), pid)
            if key in self.seen:
                continue
            self.seen.add(key)

            if ev == "exec":
                out.append(("process_spawn", f"ran {rec.get('path')}" + (f": {cmd[:100]}" if cmd else ""), base))
            elif ev == "open":
                path = rec["path"]
                if path.endswith(CANARY_SUFFIXES):
                    for k in (pid, rec.get("ppid")):
                        if k:
                            self.read_canary.setdefault(k, path)
                    out.append(("canary_read", f"{who} read canary {path}", {**base, "path": path}))
                else:
                    out.append(("file_read", f"{who} read {path}", {**base, "path": path}))
            elif ev == "dns":
                name = rec.get("name", "")
                if CANARY_MARK in name.lower():  # data smuggled in the name itself; resolvers may lowercase it
                    where = ("forwarded to the registry's DNS, so it left the VM" if _allowed(name, self.allowed_hosts)
                             else "answered by Airlock inside the VM, never left it")
                    out.append(("canary_exfil", f"{who} put the canary token in a DNS lookup of {name[:120]}: {where}",
                                {**base, "host": name, "via": "dns", "payload": name}))
                if _allowed(name, self.allowed_hosts):
                    continue
                for k in (pid, rec.get("ppid")):
                    if k:
                        self.blocked.setdefault(k, name)
                if rec.get("sinkholed"):
                    msg = f"{who} looked up {name}; answered with sinkhole address {rec['sinkholed']}"
                else:
                    msg = f"{who} looked up {name}; not allowlisted, blocked"
                out.append(("egress_blocked", msg, {**base, "host": name, "via": "dns"}))
            elif ev == "connect":
                dest = rec.get("dest", "?")
                ip = dest.rsplit(":", 1)[0].strip("[]").removeprefix("::ffff:")
                name = self.ip_names.get(ip)
                if name and _allowed(name, self.allowed_hosts):
                    out.append(("egress_allowed", f"{who} connected to {name} ({dest})", {**base, "host": name, "via": "connect"}))
                else:
                    for k in (pid, rec.get("ppid")):
                        if k:
                            self.blocked.setdefault(k, dest)
                    if ip.startswith(("198.18.", "198.19.")):
                        msg = f"{who} connected to {name or dest} via the sinkhole ({dest}); answered by Airlock"
                    else:
                        msg = f"{who} tried to connect to {name or 'raw IP'} {dest}; not allowlisted, refused by egress policy"
                    out.append(("egress_blocked", msg, {**base, "host": name or dest, "via": "connect"}))

            # Same process, or siblings under one parent (e.g. a script that cats the
            # credentials and then curls them out): likely exfiltration.
            for k in (pid, rec.get("ppid")):
                if k and k in self.read_canary and k in self.blocked and k not in self.exfil_reported:
                    self.exfil_reported.add(k)
                    scope = "same process" if k == pid else f"same parent process {k}"
                    out.append(("canary_exfil",
                                f"credentials {self.read_canary[k]} were read and {self.blocked[k]} contacted "
                                f"({scope}): likely credential exfiltration",
                                {**base, "host": self.blocked[k], "path": self.read_canary[k], "inferred": True,
                                 "scope": scope}))
                    break
        return out


def events_from_sinkhole(records: list[dict], canary_token: str) -> list[tuple[str, str, dict]]:
    """Requests the host sinkhole answered for this run. A body carrying the run's
    canary token is proven credential exfiltration, with the payload as evidence."""
    out: list[tuple[str, str, dict]] = []
    for rec in records:
        body, host, url = rec.get("body", ""), rec.get("host", "?"), rec.get("url", "?")
        data = {"host": host, "url": url, "method": rec.get("method"), "bytes": rec.get("bytes", 0),
                "payload": body[:2000], "user_agent": rec.get("user_agent", ""), "source_kind": "sinkhole"}
        if canary_token in body:
            out.append(("canary_exfil",
                        f"{rec.get('method')} {url} carried the canary credentials: captured by Airlock's sinkhole, "
                        "never reached the internet",
                        {**data, "proven": True, "this_run": True}))
        elif "AIRLOCKCANARY" in body:  # a canary, but not this run's: suspicious, never proof
            out.append(("canary_exfil",
                        f"{rec.get('method')} {url} carried a canary token that isn't this run's (not counted as proof): "
                        "answered by Airlock's sinkhole, never reached the internet",
                        {**data, "proven": False, "this_run": False}))
        else:
            out.append(("egress_blocked",
                        f"{rec.get('method')} {url} ({rec.get('bytes', 0)} bytes): answered by Airlock's sinkhole, "
                        "never reached the internet", data))
    return out
