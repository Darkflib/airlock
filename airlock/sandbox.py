"""One disposable microVM per run: default-deny egress, canary credentials,
resource limits, and the guest tracer installed. Every exec is an event."""

from __future__ import annotations

import base64
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from microsandbox import Action, Destination, Network, NetworkPolicy, Protocol, Rule, Sandbox
from microsandbox.types import TlsConfig

from .events import EventLog, events_from_trace

TRACER = Path(__file__).parent / "guest" / "trace.js"
TRACE_LOG = "/tmp/airlock-trace.jsonl"
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
        await self.sb.fs.write("/opt/airlock/trace.js", TRACER.read_bytes())
        await self._seed_canaries()
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
        await self.sb.shell(
            f"mkdir -p ~/.aws && printf %s {b(npmrc)} | base64 -d > ~/.npmrc"
            f" && printf %s {b(aws)} | base64 -d > ~/.aws/credentials", timeout=20)
        self.events.emit("canaries_seeded", "fake ~/.npmrc and ~/.aws/credentials planted",
                         files=["~/.npmrc", "~/.aws/credentials"])

    async def exec(self, cmd: str, *, cwd: str = "/work", timeout: float = 120, trace: bool = False,
                   source: str = "agent") -> ExecResult:
        env = {"NODE_OPTIONS": "--require=/opt/airlock/trace.js"} if trace else None
        await self.sb.fs.mkdir(cwd)
        try:
            out = await self.sb.shell(cmd, cwd=cwd, env=env, timeout=timeout)
            res = ExecResult(out.exit_code, out.stdout_text, out.stderr_text)
        except Exception as e:  # noqa: BLE001 - surfaced as a result
            timed_out = "Timeout" in type(e).__name__
            res = ExecResult(124 if timed_out else 1, "", f"{type(e).__name__}: {e}", timed_out=timed_out)
            if timed_out:
                self.events.emit("limit_hit", f"command killed after {timeout:.0f}s", cmd=cmd[:200])
        self.events.emit("exec", f"$ {cmd[:120]} → exit {res.exit_code}", cmd=cmd, cwd=cwd,
                         exit_code=res.exit_code, source=source)
        await self.collect_trace(stage=source)
        return res

    async def collect_trace(self, stage: str = "detonate") -> None:
        """Turn new tracer lines into events (idempotent across calls)."""
        out = await self.sb.shell(f"cat {TRACE_LOG} 2>/dev/null || true", timeout=10)
        lines = out.stdout_text.splitlines()
        new, self._trace_seen = lines[self._trace_seen:], len(lines)
        for kind, summary, data in events_from_trace("\n".join(new), self.allow_hosts):
            self.events.emit(kind, summary, stage=stage, **data)

    async def write(self, path: str, data: bytes) -> None:
        await self.sb.fs.mkdir(os.path.dirname(path) or "/")
        await self.sb.fs.write(path, data)

    async def read_text(self, path: str) -> str:
        return await self.sb.fs.read_text(path)
