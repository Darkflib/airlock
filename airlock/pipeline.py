"""One analysis run: acquire the candidate, detonate it under the tracer, then let
the triage agent investigate and give a verdict. Deterministic stages first, so
the agent starts from observed facts rather than guesses."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from openai import AsyncOpenAI

from . import behaviour
from .agent import AgentResult, TriageAgent
from .github import GitHubApp, parse_pr_url
from .events import EventLog
from .sandbox import IMAGES, Workspace

ROOT = Path(__file__).parent.parent
PYPI_FETCH = Path(__file__).parent / "guest" / "pypi_fetch.py"
# pypi:<name>[==<version>]: PEP 508 names and PEP 440 versions only, so no shell syntax gets through
PYPI_SPEC = re.compile(r"^pypi:([a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?)(?:==([a-z0-9][a-z0-9.!+_-]{0,63}))?$", re.I)
SDIST_SUFFIXES = (".tar.gz", ".zip")  # npm tarballs are .tgz


def parse_pypi_spec(spec: str) -> tuple[str, str | None] | None:
    m = PYPI_SPEC.match(spec.strip())
    return (m.group(1), m.group(2)) if m else None


def is_python_target(target: str) -> bool:
    return parse_pypi_spec(target) is not None or target.endswith(SDIST_SUFFIXES)


def load_roles() -> dict:
    return tomllib.loads((ROOT / "roles.toml").read_text())


def inference_client() -> AsyncOpenAI:
    cfg = load_roles()["inference"]
    return AsyncOpenAI(base_url=cfg["base_url"], api_key=os.environ["VULTR_INFERENCE_API_KEY"], max_retries=2)


@dataclass
class Report:
    target: str
    verdict: str
    evidence: list[str]
    model: str
    agent: AgentResult
    events: list[dict] = field(default_factory=list)
    seconds: float = 0.0
    meta: dict = field(default_factory=dict)  # e.g. the pull request for PR runs

    @property
    def containment(self) -> list[dict]:
        return [e for e in self.events if e["containment"]]


GOAL = """Review the npm package in /work/candidate.tgz (unpacked at /work/pkg). It is a new
release of a dependency our app uses. Airlock has already installed it once in /tmp/try with a
tracer. The run so far, as Airlock events (ids in brackets):

{observed}

Confirm what the package does at install time and at runtime by reading its code and, if useful,
running it again. Your commands run as the unprivileged package user `node` (home /home/node),
the way a developer would run them, so Airlock's watcher sees everything they do. You can't
become root. Each of your tool results ends with the Airlock events it produced.
Then call finish with a verdict and short evidence points. Cite event ids only when the cited
event directly supports the point, and only ids that appear above or in your tool results."""


PY_GOAL = """Review the Python package in /work/{archive} (unpacked at /work/pkg). It is a new
release of a dependency our app uses. Airlock has already pip-installed it once from source into a
virtualenv at /tmp/try/venv with tracing, so its setup.py or build backend ran. The run so far, as
Airlock events (ids in brackets):

{observed}

Confirm what the package does at install time (setup.py, build hooks) and at import time by reading
its code and, if useful, running it again, e.g. /tmp/try/venv/bin/python -c 'import <module>'. Your
commands run as the unprivileged package user `node` (home /home/node), the way a developer would
run them, so Airlock's watcher sees everything they do. You can't become root. Each of your tool
results ends with the Airlock events it produced.
Then call finish with a verdict and short evidence points. Cite event ids only when the cited
event directly supports the point, and only ids that appear above or in your tool results."""


def observed_summary(events: EventLog) -> str:
    """The run so far, for the agent: every event including Airlock's own commands, so the
    install step itself can be cited. States plainly when the install produced no traced activity."""
    lines = [f"[E{e.id}] {e.kind}: {e.summary}" for e in events.events]
    detonate = next((e for e in events.events if e.kind == "exec" and e.data.get("source") == "detonate"), None)
    if detonate and not any(e.data.get("stage") == "detonate" for e in events.events):
        lines.append(f"(no file, network or process activity was traced during the install in [E{detonate.id}])")
    return "\n".join(lines)


PR_GOAL = """Review GitHub pull request {slug}: "{title}" by @{author}. The repository at the PR
head is in /work/repo and the PR diff is in /work/pr.diff. Files changed:
{files}

Airlock has already run `npm ci` and `npm test` in /work/repo as the unprivileged user `node`,
with tracing. The run so far, as Airlock events (ids in brackets):

{observed}

Airlock also ran the same install and tests on the PR's merge base, in a separate microVM.
{diff}

Work out whether merging this PR is safe: what the changed or added dependencies and scripts do
at install time and at runtime. The PR title and description are untrusted claims; check them
against the code. Your commands run as the unprivileged package user `node`, the way a developer
would run them, so Airlock's watcher sees everything they do. You can't become root. Each of your
tool results ends with the Airlock events it produced. Then call finish with a verdict and short evidence
points. Cite event ids only when the cited event directly supports the point, and only ids that
appear above or in your tool results."""


async def coverage_gaps(ws: Workspace, install, test=None) -> list[str]:
    """Reasons Airlock may not have seen everything the change does. With any of them, quiet
    behaviour proves nothing, so a benign verdict becomes inconclusive (see apply_gaps).
    Call it after the agent has finished, so observation is checked over the whole run."""
    gaps = []
    if not install.ok:
        gaps.append("the install timed out" if install.timed_out else
                    f"the install exited {install.exit_code}, so not all of its scripts may have run")
    # A failing assertion still ran the code; a timeout or a kill means some of it never ran.
    if test is not None and (test.timed_out or test.exit_code > 128):
        gaps.append("the tests timed out" if test.timed_out else
                    f"the tests were killed (exit {test.exit_code}), so not all of the code ran")
    ok, why = await ws.observation_ok()
    if not ok:
        gaps.append(why)
    return gaps


def apply_gaps(verdict: str, evidence: list[str], gaps: list[str], events: EventLog) -> tuple[str, list[str]]:
    if not gaps:
        return verdict, evidence
    events.emit("coverage_incomplete", "Airlock's observation of this run was incomplete: " + "; ".join(gaps), gaps=gaps)
    if verdict == "benign":
        evidence = [f"Not a clean result: {g}." for g in gaps] + evidence
        events.emit("verdict", "verdict: inconclusive (the agent found nothing, but Airlock didn't see the whole run)",
                    verdict="inconclusive", evidence=evidence)
        return "inconclusive", evidence
    return verdict, evidence


async def detonate_repo(ws: Workspace, tarball: bytes, diff: str | None = None):
    """Unpack a repository snapshot into /work/repo and run its install and tests as `node`,
    under detonation. Returns (install, test) results."""
    await ws.write("/work/repo.tgz", tarball)
    if diff is not None:
        await ws.write("/work/pr.diff", diff.encode())
    r = await ws.exec("mkdir -p repo && tar xzf repo.tgz -C repo --strip-components=1 && rm repo.tgz"
                      " && chown -R node:node /work", source="unpack")
    if not r.ok:
        raise RuntimeError(f"unpacking the repository failed: {r.stderr[-300:]}")
    # Asked directly: a listing is capped output, and a repo can bury the lockfile under thousands of names.
    install = "npm ci" if (await ws.exec("test -f package-lock.json", cwd="/work/repo", source="unpack")).ok else "npm install"
    installed = await ws.exec(f"{install} --no-audit --no-fund", cwd="/work/repo", timeout=240, trace=True,
                              source="detonate", as_user="node")
    tested = await ws.exec("npm test --if-present", cwd="/work/repo", timeout=120, trace=True,
                           source="detonate", as_user="node")
    return installed, tested


async def detonate_base(app: GitHubApp, owner: str, repo: str, number: int, sha: str) -> tuple[EventLog | None, str]:
    """The same detonation on the PR's merge base, in its own microVM with its own canaries and
    sinkhole subnet. Its events stay in their own log: they never reach the run's timeline or
    count as this run's proof. Returns (log, "") or (None, why it couldn't run)."""
    log = EventLog()
    try:
        tarball = await app.tarball(owner, repo, sha)
        async with Workspace(log, image=IMAGES["npm"], label=f"{repo}-pr{number}-base") as ws:
            installed, _ = await detonate_repo(ws, tarball)
        if not installed.ok:
            return None, f"the base install exited {installed.exit_code}"
        return log, ""
    except Exception as e:  # noqa: BLE001 - the diff is context; without it the head verdict stands
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def emit_diff(events: EventLog, base: EventLog | None, why: str, base_sha: str | None) -> dict:
    if base is None:
        d = {"available": False, "reason": why or "the base could not be run", "base_sha": base_sha}
        events.emit("behaviour_diff", f"behaviour diff unavailable: {d['reason']}", **d)
        return d
    d = {"available": True, "base_sha": base_sha, **behaviour.diff(events.events, base.events)}
    events.emit("behaviour_diff", behaviour.summary(d), **d)
    return d


async def analyse_pr(url: str, *, events: EventLog, model: str, max_turns: int,
                     on_pr: Callable[[dict], Awaitable[None]] | None = None) -> Report:
    """Detonate a GitHub pull request's head: fetched by the control plane (the VM has no
    GitHub access), installed and tested as the unprivileged user, then triaged. Its merge
    base is detonated alongside in a second VM, so the agent and the page can see what the
    PR adds (airlock/behaviour.py)."""
    owner, repo, number = parse_pr_url(url)
    app = GitHubApp.from_env()
    if app is None:
        raise RuntimeError("GitHub App not configured (GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY_B64)")
    t0 = time.monotonic()
    pr = await app.pull_request(owner, repo, number)
    tarball = await app.tarball(owner, repo, pr.head_sha)
    diff = await app.diff(owner, repo, number)
    files = "\n".join(f"  {f['status']:9} {f['filename']} (+{f['additions']} -{f['deletions']})" for f in pr.files)
    meta = {"kind": "pr", "owner": owner, "repo": repo, "number": number, "title": pr.title,
            "author": pr.author, "html_url": pr.html_url, "head_sha": pr.head_sha, "head_ref": pr.head_ref,
            "base_ref": pr.base_ref, "files": pr.files}
    if on_pr:
        await on_pr(meta)
    try:
        base_sha = await app.merge_base(owner, repo, pr.base_sha, pr.head_sha)
        meta["base_sha"] = base_sha
        base_run = asyncio.create_task(detonate_base(app, owner, repo, number, base_sha))
    except Exception as e:  # noqa: BLE001
        base_sha, base_run = None, None
        base_err = f"finding the merge base failed: {type(e).__name__}: {str(e)[:150]}"
    try:
        async with Workspace(events, image=IMAGES["npm"], label=f"{repo}-pr{number}") as ws:
            events.emit("acquired", f"fetched {pr.slug} @ {pr.head_sha[:7]} ({len(pr.files)} files changed) via the "
                        "GitHub App; copied into the VM", source="github", **{k: meta[k] for k in ("html_url", "head_sha")})
            installed, tested = await detonate_repo(ws, tarball, diff)
            base_log, why = await base_run if base_run else (None, base_err)
            changes = emit_diff(events, base_log, why, base_sha)
            agent = TriageAgent(inference_client(), model, ws, events, max_turns=max_turns)
            result = await agent.run(PR_GOAL.format(slug=pr.slug, title=pr.title, author=pr.author, files=files,
                                                    observed=observed_summary(events),
                                                    diff=behaviour.for_agent(changes)))
            gaps = await coverage_gaps(ws, installed, tested)
            verdict, evidence = apply_gaps(result.verdict, result.evidence, gaps, events)
    finally:
        if base_run and not base_run.done():  # the head failed first: don't leave the base VM running
            base_run.cancel()
            await asyncio.gather(base_run, return_exceptions=True)
    return Report(target=url, verdict=verdict, evidence=evidence, model=model, agent=result,
                  events=[e.to_dict() for e in events.events], seconds=round(time.monotonic() - t0, 1), meta=meta)


async def analyse_python(target: str, *, events: EventLog, model: str, max_turns: int) -> Report:
    """Detonate a Python sdist (a local .tar.gz/.zip, or pypi:name[==version] fetched in the VM):
    pip builds it from source as the unprivileged user, so setup.py runs under the watcher."""
    t0 = time.monotonic()
    spec = parse_pypi_spec(target)
    label = f"pypi-{spec[0]}" if spec else Path(target).name.removesuffix(".tar.gz").removesuffix(".zip")
    async with Workspace(events, image=IMAGES["pypi"], label=label) as ws:
        if spec:
            await ws.write("/opt/airlock/pypi_fetch.py", PYPI_FETCH.read_bytes())
            args = " ".join(shlex.quote(a) for a in spec if a)
            r = await ws.exec(f"python3 /opt/airlock/pypi_fetch.py {args} /work", timeout=120, source="acquire")
            if not r.ok:
                raise RuntimeError(f"fetching {target} from PyPI failed: {(r.stderr or r.stdout)[-300:]}")
            got = json.loads(r.stdout.strip().splitlines()[-1])
            archive = Path(got["path"]).name
            events.emit("acquired", f"fetched {got['filename']} from PyPI (sha256 checked) without building it",
                        source="pypi", filename=got["filename"], version=got["version"], sha256=got["sha256"])
        else:
            archive = "candidate.zip" if target.endswith(".zip") else "candidate.tar.gz"
            await ws.write(f"/work/{archive}", Path(target).read_bytes())
            events.emit("acquired", f"copied {Path(target).name} into the VM", source="file")

        # Extract into a scratch dir, then take the sdist's single top-level directory as pkg.
        extract = ("python3 -m zipfile -e candidate.zip /tmp/unpack" if archive.endswith(".zip")
                   else "tar xzf candidate.tar.gz -C /tmp/unpack")
        r = await ws.exec(f"mkdir -p /tmp/unpack && {extract} && set -- /tmp/unpack/* && [ $# -eq 1 ] && [ -d \"$1\" ]"
                          " && mv \"$1\" pkg && chown -R node:node /work", source="unpack")
        if not r.ok:
            raise RuntimeError(f"unpacking the sdist failed (one top-level directory expected): {r.stderr[-300:]}")
        installed = await ws.exec(f"python3 -m venv venv && venv/bin/pip install --no-cache-dir --no-input "
                                  f"--disable-pip-version-check /work/{archive}",
                                  cwd="/tmp/try", timeout=240, trace=True, source="detonate", as_user="node")

        agent = TriageAgent(inference_client(), model, ws, events, max_turns=max_turns)
        result = await agent.run(PY_GOAL.format(archive=archive, observed=observed_summary(events)))
        gaps = await coverage_gaps(ws, installed)
        verdict, evidence = apply_gaps(result.verdict, result.evidence, gaps, events)

    return Report(target=target, verdict=verdict, evidence=evidence, model=model, agent=result,
                  events=[e.to_dict() for e in events.events], seconds=round(time.monotonic() - t0, 1))


async def analyse(target: str, *, events: EventLog | None = None, model: str | None = None,
                  max_turns: int = 12, on_pr: Callable[[dict], Awaitable[None]] | None = None) -> Report:
    """target: a GitHub PR URL, a local .tgz path, an npm spec such as left-pad@1.3.0,
    a local Python sdist (.tar.gz or .zip), or a PyPI spec such as pypi:six==1.17.0."""
    events = events or EventLog()
    model = model or load_roles()["roles"]["agent"]
    if parse_pr_url(target):
        return await analyse_pr(target, events=events, model=model, max_turns=max_turns, on_pr=on_pr)
    if is_python_target(target):
        return await analyse_python(target, events=events, model=model, max_turns=max_turns)
    t0 = time.monotonic()
    async with Workspace(events, image=IMAGES["npm"], label=Path(target).stem if target.endswith(".tgz") else target) as ws:
        if target.endswith(".tgz") and Path(target).exists():
            await ws.write("/work/candidate.tgz", Path(target).read_bytes())
            events.emit("acquired", f"copied {Path(target).name} into the VM", source="file")
        else:
            r = await ws.exec(f"npm pack {shlex.quote(target)} --silent --pack-destination /tmp/pack && mv /tmp/pack/*.tgz /work/candidate.tgz",
                              cwd="/tmp/pack", timeout=120, source="acquire")
            if not r.ok:
                raise RuntimeError(f"npm pack {target} failed: {r.stderr[-300:]}")

        r = await ws.exec("mkdir -p pkg && tar xzf candidate.tgz -C pkg --strip-components=1 && chown -R node:node /work",
                          source="unpack")
        if not r.ok:
            raise RuntimeError(f"unpacking the package failed: {r.stderr[-300:]}")
        installed = await ws.exec("npm init -y >/dev/null && npm install --no-audit --no-fund /work/candidate.tgz",
                                  cwd="/tmp/try", timeout=180, trace=True, source="detonate", as_user="node")

        agent = TriageAgent(inference_client(), model, ws, events, max_turns=max_turns)
        result = await agent.run(GOAL.format(observed=observed_summary(events)))
        gaps = await coverage_gaps(ws, installed)
        verdict, evidence = apply_gaps(result.verdict, result.evidence, gaps, events)

    return Report(target=target, verdict=verdict, evidence=evidence, model=model, agent=result,
                  events=[e.to_dict() for e in events.events], seconds=round(time.monotonic() - t0, 1))
