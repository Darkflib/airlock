"""One disposable microVM per run: default-deny egress, canary credentials,
resource limits, and the guest tracer installed. Every exec is an event."""

from __future__ import annotations

import asyncio
import base64
import os
import re
import secrets
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from microsandbox import Action, Destination, Network, NetworkPolicy, Protocol, Rule, Sandbox
from microsandbox.types import TlsConfig

from .events import EventLog, WatchTranslator, events_from_trace

TRACER = Path(__file__).parent / "guest" / "trace.js"
WATCHER = Path(__file__).parent / "guest" / "watch.py"
TRACE_LOG = "/tmp/airlock-trace.jsonl"     # written by the Node tracer, as the package user
WATCH_LOG = "/opt/airlock/watch.jsonl"     # written by the root watcher; unreadable to the package user
PKG_USER, PKG_HOME = "node", "/home/node"   # the node image's unprivileged user
DEFAULT_ALLOW = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def egress_network(allow_hosts: tuple[str, ...]) -> Network:
    rules = [*Rule.allow_dns()]
    for host in allow_hosts:
        rules.append(Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain(host)))
    policy = NetworkPolicy(default_egress=Action.DENY, default_ingress=Action.ALLOW, rules=tuple(rules))
    return Network(policy=policy, tls=TlsConfig(), strict=True)


class Workspace:
    """Async context manager around a microsandbox VM."""

    def __init__(self, events: EventLog, image: str = "node", *, allow_hosts: tuple[str, ...] = DEFAULT_ALLOW,
                 cpus: int = 2, memory_mb: int = 2048, max_duration_s: int = 480, label: str = "run"):
        self.events, self.image, self.allow_hosts = events, image, allow_hosts
        self.cpus, self.memory_mb, self.max_duration_s = cpus, memory_mb, max_duration_s
        self.name = re.sub(r"[^a-z0-9-]", "-", f"airlock-{label}-{secrets.token_hex(3)}".lower())[:60]
        self.canary_token = "AIRLOCKCANARY" + secrets.token_hex(8).upper()
        self._trace_seen = 0
        self._watch_seen = 0
        self._watch = WatchTranslator(allow_hosts)
        self._emitted: set[tuple] = set()

    async def __aenter__(self) -> "Workspace":
        t0 = time.monotonic()
        self._cm = await Sandbox.create(
            self.name, image=self.image, cpus=self.cpus, memory=self.memory_mb,
            max_duration=self.max_duration_s, replace=True, network=egress_network(self.allow_hosts))
        self.sb = await self._cm.__aenter__()
        self.events.emit("vm_created", f"microVM {self.name} up in {time.monotonic() - t0:.2f}s",
                         image=self.image, cpus=self.cpus, memory_mb=self.memory_mb,
                         egress="default-deny", allow=list(self.allow_hosts))
        await self.sb.fs.mkdir("/work")
        await self.sb.fs.mkdir("/opt/airlock")
        await self.sb.fs.mkdir("/opt/airlock-trace")  # world-readable: the package user's Node loads it
        await self.sb.fs.write("/opt/airlock-trace/trace.js", TRACER.read_bytes())
        await self.sb.fs.write("/opt/airlock/watch.py", WATCHER.read_bytes())
        await self._seed_canaries()
        await self._start_watcher()
        return self

    async def __aexit__(self, *exc) -> None:
        try:
            await self._cm.__aexit__(*exc)
        finally:
            self.events.emit("vm_destroyed", f"microVM {self.name} destroyed")

    async def _seed_canaries(self) -> None:
        npmrc = f"//registry.npmjs.org/:_authToken=npm_{self.canary_token}\n"
        aws = (f"[default]\naws_access_key_id = AKIA{self.canary_token[-12:]}\n"
               f"aws_secret_access_key = {self.canary_token}/canary\n")
        b = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
        for home in (PKG_HOME, "/root"):
            await self.sb.shell(
                f"mkdir -p {home}/.aws && printf %s {b(npmrc)} | base64 -d > {home}/.npmrc"
                f" && printf %s {b(aws)} | base64 -d > {home}/.aws/credentials", timeout=20)
        await self.sb.shell(f"chown -R {PKG_USER}:{PKG_USER} {PKG_HOME} && mkdir -p /tmp/try && chown {PKG_USER} /tmp/try",
                            timeout=20)
        self.events.emit("canaries_seeded", "fake ~/.npmrc and ~/.aws/credentials planted",
                         files=["~/.npmrc", "~/.aws/credentials"], homes=[PKG_HOME, "/root"])

    async def _start_watcher(self) -> None:
        """Root watcher (fanotify, DNS, connects). The guest resolver is pointed at it,
        and its log lives in a root-only directory the package user can't touch."""
        await self.sb.shell(
            "chmod 700 /opt/airlock && chmod 755 /opt/airlock-trace && chmod 644 /opt/airlock-trace/trace.js && cp /etc/resolv.conf /etc/resolv.conf.airlock-orig"
            " && echo 'nameserver 127.0.0.1' > /etc/resolv.conf"
            f" && (setsid python3 /opt/airlock/watch.py {WATCH_LOG} {PKG_HOME} /root"
            " >/opt/airlock/watch.err 2>&1 </dev/null &)", timeout=20)
        for _ in range(40):
            out = await self.sb.shell(f"grep -c watch_ready {WATCH_LOG} 2>/dev/null || true", timeout=10)
            if out.stdout_text.strip() == "2":
                self.events.emit("watcher_started", "in-guest watcher up: programs run, dotfile reads, DNS, connects",
                                 user=PKG_USER)
                return
            await asyncio.sleep(0.1)
        err = (await self.sb.shell("cat /opt/airlock/watch.err 2>/dev/null", timeout=10)).stdout_text
        self.events.emit("error", f"in-guest watcher failed to start: {err[-200:]}")

    async def exec(self, cmd: str, *, cwd: str = "/work", timeout: float = 120, trace: bool = False,
                   source: str = "agent", as_user: str | None = None) -> ExecResult:
        """Run a shell command. as_user runs it unprivileged (the package user)."""
        env = {"NODE_OPTIONS": "--require=/opt/airlock-trace/trace.js"} if trace else None
        await self.sb.fs.mkdir(cwd)
        run = f"runuser -u {as_user} -- sh -c {shlex.quote(cmd)}" if as_user else cmd
        try:
            out = await self.sb.shell(run, cwd=cwd, env=env, timeout=timeout)
            res = ExecResult(out.exit_code, out.stdout_text, out.stderr_text)
        except Exception as e:  # noqa: BLE001 - surfaced as a result
            timed_out = "Timeout" in type(e).__name__
            res = ExecResult(124 if timed_out else 1, "", f"{type(e).__name__}: {e}", timed_out=timed_out)
            if timed_out:
                self.events.emit("limit_hit", f"command killed after {timeout:.0f}s", cmd=cmd[:200])
        self.events.emit("exec", f"$ {cmd[:120]} → exit {res.exit_code}", cmd=cmd, cwd=cwd,
                         exit_code=res.exit_code, source=source, user=as_user or "root")
        await self.collect_trace(stage=source, settle=bool(as_user) or "runuser" in cmd)
        return res

    async def collect_trace(self, stage: str = "detonate", settle: bool = False) -> None:
        """Turn new tracer and watcher lines into events (idempotent across calls).
        Both sources can see the same act; the first report wins."""
        if settle:  # package code ran: the watcher needs ~0.5s to call a dropped connect "blocked"
            await asyncio.sleep(0.6)
        out = await self.sb.shell(f"cat {TRACE_LOG} 2>/dev/null || true", timeout=10)
        lines = out.stdout_text.splitlines()
        new, self._trace_seen = lines[self._trace_seen:], len(lines)
        found = events_from_trace("\n".join(new), self.allow_hosts)
        out = await self.sb.shell(f"cat {WATCH_LOG} 2>/dev/null || true", timeout=10)
        lines = out.stdout_text.splitlines()
        new, self._watch_seen = lines[self._watch_seen:], len(lines)
        found += self._watch.feed("\n".join(new))
        for kind, summary, data in found:
            target = (data.get("path") or data.get("host") or data.get("cmd") or "").split(":")[0]
            if kind == "canary_exfil":
                target = ""  # one exfil per process: the tracer's proven report beats the watcher's inference
            key = (kind, target, data.get("pid"), data.get("ts_guest"))
            if key in self._emitted:
                continue
            self._emitted.add(key)
            self.events.emit(kind, summary, stage=stage, **data)

    async def write(self, path: str, data: bytes) -> None:
        await self.sb.fs.mkdir(os.path.dirname(path) or "/")
        await self.sb.fs.write(path, data)

    async def read_text(self, path: str) -> str:
        return await self.sb.fs.read_text(path)
