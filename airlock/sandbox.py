"""One disposable microVM per run: default-deny egress, canary credentials,
resource limits, the guest tracer and watcher installed. Every exec is an event.

With the sinkhole available (airlock-sinkhole service on the host), all guest TCP
is routed through it. The run gets its own fake /24 in 198.18.0.0/15: the guest's
DNS answers non-allowlisted names with addresses there, the egress policy allows
that /24 and the registries only, and the sinkhole answers those requests itself,
logging the full payload. Real internet destinations stay denied by microsandbox."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import re
import secrets
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from microsandbox import (Action, Destination, Network, NetworkPolicy, OutboundProxy, Protocol, Rule, Sandbox,
                          SandboxStatus)
from microsandbox.types import DnsConfig, TlsConfig

from .dnsguard import DnsGuard

from .events import EventLog, WatchTranslator, events_from_sinkhole, events_from_trace
from .store import data_dir

TRACER = Path(__file__).parent / "guest" / "trace.js"
WATCHER = Path(__file__).parent / "guest" / "watch.py"
TRACE_LOG = "/tmp/airlock-trace.jsonl"     # written by the Node tracer, as the package user
WATCH_LOG = "/opt/airlock/watch.jsonl"     # written by the root watcher; unreadable to the package user
PKG_USER, PKG_HOME = "node", "/home/node"   # the node image's unprivileged user; created in other images
# Pinned by digest (linux/amd64 manifests, pulled 3-4 Nov 2026: node 26.13.0, Python 3.12), so a rebuilt host
# detonates in the same guest userland. The stock node image has no pip (spikes/python_image_probe.py).
# To move a pin: `msb image pull node`, then `msb image inspect node` for the new digest; rerun the regression.
IMAGES = {
    "npm": "node@sha256:6c6f2679f5b655c7c6091a34b81372b5962ca9f25d897a501d613742f922567b",
    # Full image, not -slim: sdists with C extensions (psutil, PyYAML's) need gcc and headers to build,
    # and a build that can't run leaves the install failed and the run inconclusive.
    "pypi": "python:3.12@sha256:5ff8100ae55a3b9dca6b83c42256685ace77a0205071df19f5cc14902b30a984",
}
WATCH_READY = ("watcher", "dns", "fanotify")  # every observer must report ready before a run counts
ACTIVE_SUBNETS: set[int] = set()  # sinkhole /24s held by live Workspaces in this process
DEFAULT_ALLOW = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")
SINKHOLE_ADDR = os.environ.get("AIRLOCK_SINKHOLE", "127.0.0.1:1080")
SINKHOLE_CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
SINKHOLE_PORTS = (80, 443, 8080, 8443)
# Every VM carries its owner as a label, so the web service can clear its own leftovers at startup
# without touching a CLI run or a regression on the same host. airlock-web.service sets "web".
OWNER_LABEL = "airlock-owner"
VM_OWNER = os.environ.get("AIRLOCK_VM_OWNER", "cli")
# Output budgets. Package code decides how much it prints and how much its activity makes the tracer
# and watcher log, so nothing from the guest is read whole. Command output keeps each stream's tail
# (the agent sees the last 4 KB; the pipeline reads exit codes and last lines). Guest logs are read in
# chunks from where the last read stopped, up to a total per log; past it the run is marked incomplete.
OUTPUT_CAP = 64 * 1024
LOG_CHUNK = 1024 * 1024
LOG_BUDGET = int(os.environ.get("AIRLOCK_LOG_BUDGET", str(32 * 1024 * 1024)))


async def reap_leftovers(owner: str = VM_OWNER) -> tuple[list[str], list[str]]:
    """Destroy every sandbox labelled with this owner; returns (removed, failed) names.

    A VM doesn't outlive the process that started it: after a kill -9 microsandbox shows it as
    stopped (verified 4 Nov). Its record and root directory stay until removed, though. Call only
    when this owner has no live runs, i.e. at startup."""
    removed, failed, cursor = [], [], None
    while True:
        page = await Sandbox.list_with(cursor=cursor, labels={OWNER_LABEL: owner})
        for h in page.sandboxes:
            try:
                await h.destroy(force=True, timeout=30)
                removed.append(h.name)
            except Exception as e:
                failed.append(f"{h.name}: {type(e).__name__}: {e}"[:200])
        cursor = page.next_cursor
        if not cursor:
            return removed, failed


async def vms_active() -> bool:
    """Whether any VM on this host might be running, whoever started it (CLI and regression runs too)."""
    cursor = None
    while True:
        page = await Sandbox.list_with(cursor=cursor)
        if any(h.status not in (SandboxStatus.STOPPED, SandboxStatus.CRASHED) for h in page.sandboxes):
            return True
        cursor = page.next_cursor
        if not cursor:
            return False


def sinkhole_available() -> bool:
    if os.environ.get("AIRLOCK_SINKHOLE") == "off" or not SINKHOLE_CA.exists():
        return False
    host, port = SINKHOLE_ADDR.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=1):
            return True
    except OSError:
        return False


def sinkhole_log() -> Path:
    return data_dir() / "sinkhole.jsonl"


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class ObservationError(RuntimeError):
    """Airlock couldn't observe the run, so no verdict about it can be trusted."""


def egress_network(allow_hosts: tuple[str, ...], sinkhole: str | None = None, dns_port: int | None = None) -> Network:
    rules = [*Rule.allow_dns()]
    for host in allow_hosts:
        rules.append(Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain(host)))
    if sinkhole:  # only this run's fake range; the policy is checked before the proxy
        rules += [Rule.allow(protocol=Protocol.TCP, port=p, destination=Destination.cidr(sinkhole)) for p in SINKHOLE_PORTS]
        # microsandbox re-encrypts intercepted TLS towards the proxy; trust the sinkhole's CA for that hop
        tls = TlsConfig(upstream_ca_certs=(str(SINKHOLE_CA),))
    else:
        tls = TlsConfig()
    policy = NetworkPolicy(default_egress=Action.DENY, default_ingress=Action.ALLOW, rules=tuple(rules))
    # The gateway resolver forwards to this run's DnsGuard, never straight to the internet.
    dns = DnsConfig(nameservers=(f"127.0.0.1:{dns_port}",)) if dns_port else None
    return Network(policy=policy, tls=tls, strict=True, dns=dns)


class Workspace:
    """Async context manager around a microsandbox VM."""

    def __init__(self, events: EventLog, image: str = IMAGES["npm"], *, allow_hosts: tuple[str, ...] = DEFAULT_ALLOW,
                 cpus: int = 2, memory_mb: int = 2048, max_duration_s: int = 480, label: str = "run"):
        self.events, self.image, self.allow_hosts = events, image, allow_hosts
        self.cpus, self.memory_mb, self.max_duration_s = cpus, memory_mb, max_duration_s
        # Truncate the label, never the random suffix, so concurrent runs can't share a VM name.
        self.name = re.sub(r"[^a-z0-9-]", "-", f"airlock-{label}".lower())[:50] + f"-{secrets.token_hex(4)}"
        self.canary_token = "AIRLOCKCANARY" + secrets.token_hex(8).upper()
        self._log_off = {TRACE_LOG: 0, WATCH_LOG: 0}  # bytes of complete lines already read
        self._log_over: set[str] = set()  # logs that passed LOG_BUDGET
        self._execs = 0
        self._watch = WatchTranslator(allow_hosts)
        self._emitted: set[tuple] = set()
        self._proven_exfil: set[str] = set()
        self.sinkhole = None
        if sinkhole_available():
            # One /24 out of 198.18.0.0/15, never shared with a live run, so sinkhole records can't mix.
            n = secrets.choice([i for i in range(512) if i not in ACTIVE_SUBNETS])
            ACTIVE_SUBNETS.add(n)
            self._subnet = n
            self.sinkhole = str(ipaddress.ip_network("198.18.0.0/15").network_address + n * 256) + "/24"

    async def __aenter__(self) -> "Workspace":
        t0 = time.monotonic()
        extra = {"proxy": OutboundProxy.socks5(SINKHOLE_ADDR)} if self.sinkhole else {}
        log = sinkhole_log()
        st = log.stat() if log.exists() else None
        self._sink_offset, self._sink_inode = (st.st_size, st.st_ino) if st else (0, None)
        self.dns = DnsGuard(self.allow_hosts)
        try:
            dns_port = await self.dns.start()
            self._cm = await Sandbox.create(
                self.name, image=self.image, cpus=self.cpus, memory=self.memory_mb,
                max_duration=self.max_duration_s, replace=True, labels={OWNER_LABEL: VM_OWNER},
                network=egress_network(self.allow_hosts, self.sinkhole, dns_port), **extra)
            self.sb = await self._cm.__aenter__()
        except BaseException:
            self._release()
            raise
        # From here a VM exists: any failure must destroy it (Python won't call __aexit__ for us).
        try:
            self.events.emit("vm_created", f"microVM {self.name} up in {time.monotonic() - t0:.2f}s",
                             image=self.image, cpus=self.cpus, memory_mb=self.memory_mb,
                             egress="default-deny", allow=list(self.allow_hosts), sinkhole=self.sinkhole)
            await self.sb.fs.mkdir("/work")
            await self.sb.fs.mkdir("/opt/airlock")
            await self.sb.fs.mkdir("/opt/airlock-trace")  # world-readable: the package user's Node loads it
            await self.sb.fs.write("/opt/airlock-trace/trace.js", TRACER.read_bytes())
            await self.sb.fs.write("/opt/airlock/watch.py", WATCHER.read_bytes())
            await self._seed_canaries()
            await self._start_watcher()
        except BaseException as e:
            await self.__aexit__(type(e), e, e.__traceback__)
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        try:
            await self._cm.__aexit__(*exc)
        except Exception as e:
            self.events.emit("error", f"microVM {self.name} may not have been destroyed: {type(e).__name__}: {e}"[:300])
            if exc[0] is None:  # don't mask the run's own failure with the cleanup failure
                raise
        else:
            self.events.emit("vm_destroyed", f"microVM {self.name} destroyed")
        finally:
            self._release()

    def _release(self) -> None:
        ACTIVE_SUBNETS.discard(getattr(self, "_subnet", None))
        if getattr(self, "dns", None):
            self.dns.close()

    async def _seed_canaries(self) -> None:
        npmrc = f"//registry.npmjs.org/:_authToken=npm_{self.canary_token}\n"
        pypirc = f"[pypi]\nusername = __token__\npassword = pypi-{self.canary_token}\n"
        aws = (f"[default]\naws_access_key_id = AKIA{self.canary_token[-12:]}\n"
               f"aws_secret_access_key = {self.canary_token}/canary\n")
        b = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
        for home in (PKG_HOME, "/root"):
            await self.sb.shell(
                f"mkdir -p {home}/.aws && printf %s {b(npmrc)} | base64 -d > {home}/.npmrc"
                f" && printf %s {b(aws)} | base64 -d > {home}/.aws/credentials"
                f" && printf %s {b(pypirc)} | base64 -d > {home}/.pypirc", timeout=20)
        # Images other than node lack the user (and slim ones lack useradd): add it by hand.
        await self.sb.shell(f"(id -u {PKG_USER} >/dev/null 2>&1 || (echo '{PKG_USER}:x:1000:1000::{PKG_HOME}:/bin/sh' >> /etc/passwd"
                            f" && echo '{PKG_USER}:x:1000:' >> /etc/group)) && chown -R {PKG_USER}:{PKG_USER} {PKG_HOME} && mkdir -p /tmp/try && chown {PKG_USER} /tmp/try",
                            timeout=20)
        self.events.emit("canaries_seeded", "fake ~/.npmrc, ~/.aws/credentials and ~/.pypirc planted",
                         files=["~/.npmrc", "~/.aws/credentials", "~/.pypirc"], homes=[PKG_HOME, "/root"])

    async def _start_watcher(self) -> None:
        """Root watcher (fanotify, DNS, connects). The guest resolver is pointed at it,
        and its log lives in a root-only directory the package user can't touch."""
        await self.sb.shell(
            "chmod 700 /opt/airlock && chmod 755 /opt/airlock-trace && chmod 644 /opt/airlock-trace/trace.js && cp /etc/resolv.conf /etc/resolv.conf.airlock-orig"
            " && echo 'nameserver 127.0.0.1' > /etc/resolv.conf"
            f" && (setsid python3 /opt/airlock/watch.py {WATCH_LOG} {PKG_HOME} /root"
            + (f" --sinkhole {self.sinkhole} --allow {','.join(self.allow_hosts)}" if self.sinkhole else "")
            + " >/opt/airlock/watch.err 2>&1 </dev/null &)", timeout=20)
        for _ in range(40):
            ready, errors = await self._watch_status()
            if errors:
                break
            if set(WATCH_READY) <= ready:
                self.events.emit("watcher_started", "in-guest watcher up: programs run, dotfile reads, DNS, connects",
                                 user=PKG_USER)
                return
            await asyncio.sleep(0.1)
        err = (await self.sb.shell("cat /opt/airlock/watch.err 2>/dev/null", timeout=10)).stdout_text
        detail = "; ".join(errors) if errors else f"not ready: {sorted(set(WATCH_READY) - ready)} {err[-150:]}"
        self.events.emit("error", f"in-guest watcher failed to start: {detail}"[:300])
        raise ObservationError(f"in-guest watcher failed to start: {detail}"[:300])

    async def _watch_status(self) -> tuple[set[str], list[str]]:
        """Which observers reported ready, and any errors the watcher logged."""
        out = await self.sb.shell(f"grep -E '\"ev\": \"watch_(ready|error)\"' {WATCH_LOG} 2>/dev/null || true", timeout=10)
        ready, errors = set(), []
        for line in out.stdout_text.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("ev") == "watch_ready":
                ready.add(rec.get("what"))
            else:
                errors.append(f"{rec.get('what')}: {rec.get('err')}")
        return ready, errors

    async def observation_ok(self) -> tuple[bool, str]:
        """After the run: the watcher is still alive and logged no errors. Otherwise a quiet
        run may just mean Airlock went blind, and a clean verdict can't be trusted."""
        _, errors = await self._watch_status()
        # No pgrep in slim images; the [w] keeps this command's own cmdline from matching.
        alive = (await self.sb.shell("grep -qsa '/opt/airlock/[w]atch.py' /proc/[0-9]*/cmdline && echo up || echo down",
                                     timeout=10)).stdout_text.strip() == "up"
        if errors:
            return False, "watcher errors: " + "; ".join(errors)[:200]
        if self._log_over:
            return False, f"the guest logs passed Airlock's {LOG_BUDGET // 2**20} MB budget, so not all activity was read"
        if self.events.truncated:
            return False, f"the run produced more than {self.events.max_events} events, so not all were recorded"
        if not alive:
            return False, "the in-guest watcher stopped during the run"
        return True, ""

    async def exec(self, cmd: str, *, cwd: str = "/work", timeout: float = 120, trace: bool = False,
                   source: str = "agent", as_user: str | None = None) -> ExecResult:
        """Run a shell command. as_user runs it unprivileged (the package user)."""
        env = {"NODE_OPTIONS": "--require=/opt/airlock-trace/trace.js"} if trace else None
        await self.sb.fs.mkdir(cwd)
        run = f"runuser -u {as_user} -- sh -c {shlex.quote(cmd)}" if as_user else cmd
        # Output goes to root-only files in the guest and only each stream's tail comes back.
        self._execs += 1
        o, e = f"/opt/airlock/exec{self._execs}.out", f"/opt/airlock/exec{self._execs}.err"
        tails = f"tail -c {OUTPUT_CAP} {o} 2>/dev/null; tail -c {OUTPUT_CAP} {e} >&2 2>/dev/null; rm -f {o} {e}"
        try:
            out = await self.sb.shell(f"sh -c {shlex.quote(run)} >{o} 2>{e}; rc=$?; {tails}; exit $rc",
                                      cwd=cwd, env=env, timeout=timeout)
            res = ExecResult(out.exit_code, out.stdout_text, out.stderr_text)
        except Exception as ex:  # noqa: BLE001 - surfaced as a result
            timed_out = "Timeout" in type(ex).__name__
            res = ExecResult(124 if timed_out else 1, "", f"{type(ex).__name__}: {ex}", timed_out=timed_out)
            if timed_out:
                self.events.emit("limit_hit", f"command killed after {timeout:.0f}s", cmd=cmd[:200])
                try:  # what it printed before it was killed is still worth seeing
                    got = await self.sb.shell(tails, timeout=10)
                    res.stdout, res.stderr = got.stdout_text, got.stderr_text + "\n" + res.stderr
                except Exception:  # noqa: BLE001 - best effort
                    pass
        self.events.emit("exec", f"$ {cmd[:120]} → exit {res.exit_code}", cmd=cmd, cwd=cwd,
                         exit_code=res.exit_code, source=source, user=as_user or "root")
        await self.collect_trace(stage=source, settle=bool(as_user) or "runuser" in cmd)
        return res

    async def collect_trace(self, stage: str = "detonate", settle: bool = False) -> None:
        """Turn new tracer and watcher lines into events (idempotent across calls).
        Both sources can see the same act; the first report wins."""
        if settle:  # package code ran: the watcher needs ~0.5s to call a dropped connect "blocked"
            await asyncio.sleep(0.6)
        # Sinkhole first: when it captured the request, its report carries the payload.
        found = self._read_sinkhole() + self._read_dns()
        found += events_from_trace(await self._read_log(TRACE_LOG), self.allow_hosts)
        found += self._watch.feed(await self._read_log(WATCH_LOG))
        for kind, summary, data in found:
            target = (data.get("path") or data.get("host") or data.get("cmd") or "").split(":")[0]
            if kind == "canary_exfil":
                # One exfil report per destination: captured payload > Node tracer > inference.
                target, pid = (data.get("host") or "").split(":")[0], None
            else:
                pid = data.get("pid")
            key = (kind, target, pid, data.get("ts_guest"))
            if key in self._emitted:
                continue
            self._emitted.add(key)
            self.events.emit(kind, summary, stage=stage, **data)

    async def _read_log(self, path: str) -> str:
        """New complete lines of a guest log since the last read, in LOG_CHUNK pieces, never past
        LOG_BUDGET bytes in all. A line longer than a chunk is skipped (the package wrote it, or it's
        unparseable anyway)."""
        lines: list[str] = []
        while path not in self._log_over:
            off = self._log_off[path]
            if off >= LOG_BUDGET:
                self._log_over.add(path)
                self.events.emit("limit_hit", f"guest log {path} passed {LOG_BUDGET // 2**20} MB: the rest wasn't read",
                                 limit="log_budget", path=path)
                break
            out = await self.sb.shell(f"tail -c +{off + 1} {path} 2>/dev/null | head -c {LOG_CHUNK} || true", timeout=20)
            chunk = getattr(out, "stdout_bytes", None)
            chunk = out.stdout_text.encode() if chunk is None else chunk
            complete, nl, _ = chunk.rpartition(b"\n")
            if not nl:
                if len(chunk) >= LOG_CHUNK:  # one oversized line: skip past it
                    self._log_off[path] = off + len(chunk)
                    continue
                break  # nothing new, or a line still being written
            self._log_off[path] = off + len(complete) + 1
            lines.append(complete.decode(errors="replace"))
            if len(chunk) < LOG_CHUNK:
                break
        return "\n".join(lines)

    def _read_dns(self) -> list[tuple[str, str, dict]]:
        """Lookups that bypassed the watcher's resolver and reached this run's DnsGuard."""
        out = []
        for rec in self.dns.drain():
            name = rec["name"]
            data = {"host": name, "payload": name, "source_kind": "dns"}
            if self.canary_token.lower() in name.lower():
                out.append(("canary_exfil", f"DNS lookup of {name[:120]} carried the canary token: answered NXDOMAIN "
                            "by Airlock, never left the host", {**data, "proven": True, "this_run": True}))
            else:
                out.append(("dns_blocked", f"DNS lookup of {name[:120]} went straight to the gateway, bypassing "
                            "Airlock's resolver: refused, never left the host", data))
        return out

    def _read_sinkhole(self) -> list[tuple[str, str, dict]]:
        """This run's requests captured by the host sinkhole (matched by the run's /24)."""
        if not self.sinkhole:
            return []
        log = sinkhole_log()
        if not log.exists():
            return []
        with open(log) as f:
            if (ino := os.fstat(f.fileno()).st_ino) != self._sink_inode:  # rotated (airlock.retention)
                self._sink_offset, self._sink_inode = 0, ino
            f.seek(self._sink_offset)
            chunk = f.read()
        complete, _, _ = chunk.rpartition("\n")
        self._sink_offset += len(complete.encode()) + (1 if complete else 0)
        net = ipaddress.ip_network(self.sinkhole)
        mine = []
        for line in complete.splitlines():
            try:
                rec = json.loads(line)
                if ipaddress.ip_address(rec.get("dest", "")) in net:
                    mine.append(rec)
            except (json.JSONDecodeError, ValueError):
                continue
        return events_from_sinkhole(mine, self.canary_token)

    async def write(self, path: str, data: bytes) -> None:
        await self.sb.fs.mkdir(os.path.dirname(path) or "/")
        await self.sb.fs.write(path, data)

    async def read_text(self, path: str) -> str:
        return await self.sb.fs.read_text(path)
