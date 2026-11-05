"""Exercise: Airlock calls the package the way an app would, at the agent's request, and what it
does then counts as proof. Install and tests only run install-time code; code behind a function call
or an environment check stays quiet. The agent can already reproduce such code with its own exec,
but that can't count, because a misled agent could send the canaries itself. Here the agent picks
only data (which export to call, JSON arguments, a few environment variables) and Airlock runs it:

- from a pristine copy of the package, saved root-owned before the agent got a shell;
- in a fresh directory with an unguessable name, with its own npm cache, no user npm config and
  no install scripts;
- after flushing the agent's last events and killing every process the package user runs;
- with Airlock's own root-owned harness (airlock/guest/exercise.js) under a cleared environment.

Events from it carry stage "exercise", which proven_exfil, the contained count and the PR comment
treat like detonation, never like the agent's own commands."""

from __future__ import annotations

import json
import re
import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path

from .events import EventLog
from .sandbox import PKG_USER, Workspace

PRISTINE = "/opt/airlock-pristine"
HARNESS = Path(__file__).parent / "guest" / "exercise.js"
TRACER = "/opt/airlock-trace/trace.js"
# microsandbox intercepts TLS and has the guest trust its CA through these; without them HTTPS fails
# before the body is sent, and theft can't be proven from the payload.
GUEST_TLS = {"NODE_EXTRA_CA_CERTS": "/.msb/tls/ca.pem", "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
             "CURL_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
             "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt"}
PACKAGE = re.compile(r"^(\.|(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(/[\w.-]+)*)$", re.I)
CALL = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*){0,3}$")
# Variables an app's environment commonly switches on. Nothing that changes how node or the
# loader behaves (NODE_OPTIONS, NODE_PATH, PATH, HOME, LD_*), which could plant code.
ENV_ALLOWED = frozenset({"NODE_ENV", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_ID", "DEPLOY_ENV", "APP_ENV",
                         "ENV", "ENVIRONMENT", "STAGE", "DEBUG", "TZ", "LANG", "PORT", "HOSTNAME"})
MAX_ARGS = 2000
# The agent's data must not point the package at anything: a file outside the fresh copy (the fake
# credentials), a token, or an address. Otherwise an upload or HTTP library, doing what it was asked,
# would "send the credentials" or "reach out": the agent's doing, counted as the package's.
POINTS_AT = re.compile(r"^\s*[/~]|\.\.|[a-z][a-z0-9+.-]*://|AIRLOCKCANARY|AKIA|\.npmrc|\.aws|\.pypirc|/home/", re.I)


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in [str(k), *_strings(v)]]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []
MAX_WAIT = 15

TOOL = {"type": "function", "function": {
    "name": "exercise",
    "description": (
        "Have Airlock call the package the way an app would, from a fresh untouched copy, and record what "
        "it does. Use it for code that install and tests don't run: behind a function call, a condition on "
        "environment variables, or a delay. What happens during exercise counts as proof; what happens in "
        "your own exec does not. You choose only what to call and with what."),
    "parameters": {"type": "object", "properties": {
        "package": {"type": "string", "description": "what to require: the package name, or '.' for the repository itself"},
        "call": {"type": "string", "description": "export to call, e.g. 'load' or 'client.connect'; omit to only require it"},
        "args": {"type": "array", "description": "JSON arguments for the call", "items": {}},
        "env": {"type": "object", "additionalProperties": {"type": "string"},
                "description": f"environment variables, from: {', '.join(sorted(ENV_ALLOWED))}"},
        "wait_s": {"type": "integer", "description": f"seconds to keep running after the call, 0-{MAX_WAIT}, for delayed behaviour"}},
        "required": ["package"]}}}


@dataclass
class Request:
    package: str
    call: str | None
    args: list
    env: dict[str, str]
    wait_s: int

    @classmethod
    def parse(cls, raw: dict) -> "Request":
        """Validate the agent's request; ValueError says what to fix."""
        package = str(raw.get("package", "")).strip()
        # No ".." segments: a path out of node_modules could load a file the agent wrote, as package code.
        if not PACKAGE.match(package) or (package != "." and any(p in (".", "..") for p in package.split("/"))):
            raise ValueError("package must be an npm package name or '.'")
        call = raw.get("call") or None
        # Not through the prototype chain: from any export it reaches Function, which builds code from strings.
        if call is not None and (not CALL.match(str(call))
                                 or {"constructor", "__proto__", "prototype"} & set(str(call).split("."))):
            raise ValueError("call must be an export path like 'load' or 'client.connect'")
        args = raw.get("args") or []
        if not isinstance(args, list) or len(json.dumps(args)) > MAX_ARGS:
            raise ValueError(f"args must be a JSON array under {MAX_ARGS} characters")
        if any(POINTS_AT.search(s) for s in _strings(args)):
            raise ValueError("args can't name paths outside the fresh copy, credentials or network addresses: "
                             "what the package did with them would be your doing, not the package's")
        env = raw.get("env") or {}
        if not isinstance(env, dict):
            raise ValueError("env must be an object of strings")
        bad = sorted(k for k in env if k not in ENV_ALLOWED)
        if bad:
            raise ValueError(f"not allowed in env: {', '.join(bad)}; allowed: {', '.join(sorted(ENV_ALLOWED))}")
        env = {k: str(v)[:200] for k, v in env.items()}
        if any("\n" in v or "\0" in v for v in env.values()):
            raise ValueError("env values must be single-line strings")
        if any(POINTS_AT.search(v) for v in env.values()):
            raise ValueError("env values can't name paths, credentials or network addresses")
        try:
            wait_s = max(0, min(MAX_WAIT, int(raw.get("wait_s") or 0)))
        except (TypeError, ValueError):
            raise ValueError(f"wait_s must be a whole number of seconds, 0-{MAX_WAIT}") from None
        return cls(package, str(call) if call else None, args, env, wait_s)

    def describe(self) -> str:
        call = f"{self.package if self.package != '.' else 'the repository'}"
        call += f".{self.call}(…)" if self.call else " (require only)"
        env = ", ".join(f"{k}={v}" for k, v in self.env.items())
        return call + (f" with {env}" if env else "") + (f", waiting {self.wait_s} s" if self.wait_s else "")


class Exerciser:
    """One per run. `kind` is "npm" (a package archive: installed into an empty project) or "repo"
    (a repository snapshot: unpacked and its dependencies installed)."""

    def __init__(self, ws: Workspace, events: EventLog, kind: str):
        self.ws, self.events, self.kind = ws, events, kind

    @staticmethod
    async def save_pristine(ws: Workspace, src: str, kind: str) -> None:
        """Copy the archive somewhere the package user can read but never write, before the agent
        gets a shell, along with the harness."""
        name = "package.tgz" if kind == "npm" else "repo.tgz"
        await ws.write(f"{PRISTINE}/exercise.js", HARNESS.read_bytes())
        r = await ws.exec(f"cp {shlex.quote(src)} {PRISTINE}/{name} && chown -R root:root {PRISTINE}"
                          f" && chmod 755 {PRISTINE} && chmod 444 {PRISTINE}/*", source="unpack")
        if not r.ok:
            raise RuntimeError(f"saving the pristine copy failed: {r.stderr[-200:]}")

    async def run(self, req: Request) -> str:
        if req.package == "." and self.kind == "npm":
            return "exercise refused: '.' is for a repository; give the package's own name (from its package.json)"
        # Stop everything the agent started, then credit whatever was still in flight to the agent.
        await self.ws.exec(f"pkill -KILL -u {PKG_USER}; sleep 0.3; true", source="agent")
        await self.ws.collect_trace(stage="agent", settle=True)
        d = f"/tmp/ex-{secrets.token_hex(6)}"
        npm = f"--ignore-scripts --no-audit --no-fund --cache {d}/.npm-cache --userconfig /dev/null"
        if self.kind == "npm":
            setup = (f"mkdir {d} && cd {d} && npm init -y >/dev/null"
                     f" && npm install {npm} {PRISTINE}/package.tgz")
        else:
            setup = (f"mkdir {d} && tar xzf {PRISTINE}/repo.tgz -C {d} --strip-components=1 && cd {d}"
                     f" && if [ -f package-lock.json ]; then npm ci {npm}; else npm install {npm}; fi")
        r = await self.ws.exec(setup, cwd="/tmp", timeout=180, source="exercise_setup", as_user=PKG_USER)
        if not r.ok:
            return f"Airlock couldn't prepare a fresh copy (exit {r.exit_code}):\n{r.stderr[-1500:]}"
        spec = f"{PRISTINE}/exercise-{secrets.token_hex(4)}.json"  # the watcher labels the process by this name
        await self.ws.write(spec, json.dumps({"dir": d, "package": req.package, "call": req.call,
                                              "args": req.args, "wait_s": req.wait_s}).encode())
        await self.ws.exec(f"chmod 444 {spec}", source="exercise_setup")
        self.events.emit("exercise", f"Airlock calls {req.describe()} from a fresh copy (chosen by the agent)",
                         stage="exercise", package=req.package, call=req.call, args=req.args, env=req.env,
                         wait_s=req.wait_s)
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in {
            "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": f"/home/{PKG_USER}",
            "NODE_OPTIONS": f"--require={TRACER}", **GUEST_TLS, **req.env}.items())
        r = await self.ws.exec(f"env -i {env} node {PRISTINE}/exercise.js {spec}", cwd=d,
                               timeout=60 + req.wait_s, source="exercise", as_user=PKG_USER)
        return f"exit={r.exit_code}\nstdout:\n{r.stdout[-3000:]}\nstderr:\n{r.stderr[-1500:]}"
