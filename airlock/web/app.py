"""Web control plane: submit a package, watch the run live over SSE, approve or
reject the verdict. Untrusted code never runs here, only in the run's microVM."""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Awaitable, Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..events import EventLog
from ..github import GitHubApp, parse_pr_url
from ..prcomment import build_comment
from ..store import Store, data_dir
from . import auth as authmod

STATIC = Path(__file__).parent / "static"
GUEST_REPOS = frozenset(r.strip().lower() for r in
                        os.environ.get("AIRLOCK_GUEST_REPOS", "Darkflib/airlock-demo").split(",") if r.strip())
SPEC = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~=*-]+)?$", re.I)  # no shell syntax
MAX_SPEC = 214  # npm's own package-name limit
MAX_UPLOAD = 20 * 1024 * 1024
FIXTURES = Path(os.environ.get("AIRLOCK_FIXTURES", Path(__file__).parents[2] / "evals" / "fixtures"))
# The containment self-test: known packages, and what a correct run must show for each.
SELFTEST = [
    ("left-padder-hostile.tgz", "Node credential stealer", "malicious"),
    ("colorful-logs-shell-stealer.tgz", "Shell credential stealer, no Node code", "malicious"),
    ("left-padder-benign.tgz", "Benign package with a postinstall", "benign"),
]

Analyse = Callable[..., Awaitable[object]]


class Runner:
    """Owns live runs: one EventLog per active run, at most `slots` at once."""

    def __init__(self, store: Store, analyse: Analyse, slots: int = 2):
        self.store, self.analyse = store, analyse
        self.live: dict[str, EventLog] = {}
        self.slots = asyncio.Semaphore(slots)
        self.tasks: set[asyncio.Task] = set()

    def start(self, target: str, label: str, user: str | None = None) -> str:
        run_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        self.store.create_run(run_id, label, submitted_by=user)
        log = EventLog(on_emit=lambda ev: self.store.add_event(run_id, ev))
        self.live[run_id] = log
        task = asyncio.create_task(self._run(run_id, target, log))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return run_id

    async def _run(self, run_id: str, target: str, log: EventLog) -> None:
        async with self.slots:
            self.store.update_run(run_id, status="running")
            try:
                report = await self.analyse(target, events=log)
                self.store.update_run(run_id, status="done", verdict=report.verdict, evidence=report.evidence,
                                      model=report.model, finished=time.time(), meta=getattr(report, "meta", {}) or {})
            except Exception as e:  # noqa: BLE001 - recorded on the run
                log.emit("error", f"run failed: {type(e).__name__}: {str(e)[:300]}")
                self.store.update_run(run_id, status="error", error=f"{type(e).__name__}: {e}"[:500],
                                      finished=time.time())
            finally:
                log.close()
                self.live.pop(run_id, None)


def judge_probe(run: dict, proven: bool, expect: str) -> tuple[str, str]:
    """(pass | fail | pending, why). A stealer passes only with exfil proven by payload;
    a benign package passes only with zero containment events."""
    if run["status"] in ("queued", "running"):
        return "pending", run["status"]
    if run["status"] == "error":
        return "fail", run.get("error") or "run failed"
    if run["verdict"] != expect:
        return "fail", f"verdict {run['verdict']}, expected {expect}"
    if expect == "malicious" and not proven:
        return "fail", "malicious verdict, but no exfiltration proven by payload"
    if expect == "benign" and run["contained"]:
        return "fail", f"{run['contained']} containment events on a benign package"
    return "pass", "exfil proven by captured payload" if expect == "malicious" else "zero containment events"


def selftest_summary(store: Store, test: dict) -> dict:
    probes = []
    for p in test["probes"]:
        run = store.get_run(p["run_id"])
        proven = store.proven_exfil(p["run_id"])
        result, why = judge_probe(run, proven, p["expect"])
        probes.append({**p, "status": run["status"], "verdict": run["verdict"], "contained": run["contained"],
                       "proven": proven, "result": result, "why": why})
    return {**test, "probes": probes, "total": len(probes), "passed": sum(p["result"] == "pass" for p in probes),
            "done": all(p["result"] != "pending" for p in probes)}


class Decision(BaseModel):
    decision: str
    note: str = ""


def create_app(store: Store | None = None, analyse: Analyse | None = None,
               auth: authmod.AuthConfig | None = None, exchange: authmod.GithubLogin | None = None,
               github: GitHubApp | None = None, user_daily: int | None = None,
               global_daily: int | None = None) -> FastAPI:
    """auth=None disables sign-in (tests only); app_factory always passes a config.

    Owners are the logins in AIRLOCK_ALLOWED_USERS; everyone else signed in is a guest (e.g. a
    judge admitted by an invite). Guests see their own runs and the owners' runs, decide and share
    only their own, may submit PRs only from AIRLOCK_GUEST_REPOS, and are capped per rolling 24 h,
    so an invite link that spreads can't run up the bill or speak for a repo through the App."""
    if analyse is None:
        from ..pipeline import analyse as real_analyse
        analyse = real_analyse
    store = store or Store()
    github = github or GitHubApp.from_env()
    public_url = auth.public_url if auth else os.environ.get("AIRLOCK_PUBLIC_URL", "https://airlock.darkflib.dev").rstrip("/")
    runner = Runner(store, analyse)
    user_daily = user_daily if user_daily is not None else int(os.environ.get("AIRLOCK_USER_DAILY_RUNS", 15))
    global_daily = global_daily if global_daily is not None else int(os.environ.get("AIRLOCK_GLOBAL_DAILY_RUNS", 150))
    owners = auth.allowed if auth else frozenset()

    def is_owner(user: str | None) -> bool:
        return not auth or (user or "").lower() in owners

    def mine(run: dict, user: str | None) -> bool:
        return (run.get("submitted_by") or "").lower() == (user or "").lower()

    def readable(run: dict, request: Request) -> bool:
        """Share-link viewers were already limited to their runs by the auth middleware."""
        user = authmod.current_user(request)
        if user is None or is_owner(user):
            return True
        return mine(run, user) or (run.get("submitted_by") or "").lower() in owners

    def get_readable(run_id: str, request: Request) -> dict:
        run = store.get_run(run_id)
        if not run or not readable(run, request):
            raise HTTPException(404)
        return run

    def check_quota(user: str | None, n: int) -> None:
        if is_owner(user):
            return
        since = time.time() - 86400
        if user and store.count_runs(since, user=user) + n > user_daily:
            raise HTTPException(429, f"daily limit of {user_daily} runs per account reached; try again tomorrow")
        if store.count_runs(since, exclude=owners) + n > global_daily:
            raise HTTPException(429, "Airlock's daily run limit for guests is used up; try again tomorrow")

    def share_url(runs: list[str], selftest: str | None = None) -> dict:
        if not auth:
            raise HTTPException(400, "share links need sign-in configured")
        token = authmod.share_token(auth.session_secret, runs, selftest)
        return {"url": f"{public_url}/s/{token}", "expires": time.time() + authmod.SHARE_TTL}
    uploads = data_dir() / "uploads"
    uploads.mkdir(exist_ok=True)

    app = FastAPI(title="Airlock")
    app.state.runner = runner
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    if auth:
        authmod.install(app, auth, exchange or authmod.github_login)

    @app.get("/login")
    async def login_page():
        return FileResponse(STATIC / "login.html")

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/api/me")
    async def me(request: Request):
        user = authmod.current_user(request)
        return {"login": user, "auth": bool(auth), "owner": bool(user) and is_owner(user),
                "share": authmod.current_share(request) is not None and not authmod.current_user(request)}

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/runs/{run_id}")
    async def run_page(run_id: str):
        if not store.get_run(run_id):
            raise HTTPException(404)
        return FileResponse(STATIC / "run.html")

    @app.post("/api/runs")
    async def submit(request: Request, spec: str = Form(""), file: UploadFile | None = File(None)):
        user = authmod.current_user(request)
        check_quota(user, 1)
        if file and file.filename:
            data = await file.read(MAX_UPLOAD + 1)
            if len(data) > MAX_UPLOAD:
                raise HTTPException(413, "tarball larger than 20 MB")
            if not data.startswith(b"\x1f\x8b"):
                raise HTTPException(400, "upload must be a gzipped tarball (.tgz)")
            name = re.sub(r"[^\w.-]", "_", Path(file.filename).name)
            path = uploads / f"{secrets.token_hex(4)}-{name}"
            if not path.name.endswith(".tgz"):
                path = path.with_name(path.name + ".tgz")
            path.write_bytes(data)
            run_id = runner.start(str(path), name, user)
        elif parse_pr_url(spec):
            if github is None:
                raise HTTPException(400, "GitHub App not configured on this server")
            owner, repo, number = parse_pr_url(spec)
            if not is_owner(user) and f"{owner}/{repo}".lower() not in GUEST_REPOS:
                raise HTTPException(403, f"guest accounts can analyse PRs from {', '.join(sorted(GUEST_REPOS))} only")
            run_id = runner.start(spec.strip(), f"{owner}/{repo}#{number}", user)
        else:
            spec = spec.strip()
            if len(spec) > MAX_SPEC or not SPEC.match(spec):
                raise HTTPException(400, "give a GitHub PR URL, an npm spec like left-pad@1.3.0, or upload a .tgz")
            run_id = runner.start(spec, spec, user)
        return {"id": run_id, "url": f"/runs/{run_id}"}

    @app.get("/selftests/{test_id}")
    async def selftest_page(test_id: str):
        if not store.get_selftest(test_id):
            raise HTTPException(404)
        return FileResponse(STATIC / "selftest.html")

    @app.post("/api/selftests")
    async def start_selftest(request: Request):
        """Detonate the bundled fixtures through the normal run path. One self-test at a time:
        while one is in progress, starting another returns it instead."""
        latest = store.get_selftest()
        if latest and not selftest_summary(store, latest)["done"]:
            return {"id": latest["id"], "url": f"/selftests/{latest['id']}", "existing": True}
        missing = [f for f, _, _ in SELFTEST if not (FIXTURES / f).is_file()]
        if missing:
            raise HTTPException(503, f"self-test fixtures missing on this server: {', '.join(missing)}")
        user = authmod.current_user(request)
        check_quota(user, len(SELFTEST))
        probes = [{"run_id": runner.start(str(FIXTURES / f), f"self-test: {label}", user), "label": label,
                   "expect": expect} for f, label, expect in SELFTEST]
        test_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        store.create_selftest(test_id, probes, user)
        return {"id": test_id, "url": f"/selftests/{test_id}", "existing": False}

    @app.get("/api/selftests/latest")
    async def latest_selftest():
        test = store.get_selftest()
        return selftest_summary(store, test) if test else None

    @app.get("/api/selftests/{test_id}")
    async def get_selftest(test_id: str):
        test = store.get_selftest(test_id)
        if not test:
            raise HTTPException(404)
        return selftest_summary(store, test)

    @app.post("/api/selftests/{test_id}/share")
    async def share_selftest(test_id: str, request: Request):
        test = store.get_selftest(test_id)
        if not test:
            raise HTTPException(404)
        user = authmod.current_user(request)
        if not is_owner(user) and (test.get("submitted_by") or "").lower() != (user or "").lower():
            raise HTTPException(403, "you can share only self-tests you started")
        return share_url([p["run_id"] for p in test["probes"]], test_id)

    @app.post("/api/runs/{run_id}/share")
    async def share_run(run_id: str, request: Request):
        run = get_readable(run_id, request)
        if not is_owner(authmod.current_user(request)) and not mine(run, authmod.current_user(request)):
            raise HTTPException(403, "you can share only runs you submitted")
        return share_url([run_id])

    @app.get("/api/runs")
    async def list_runs(request: Request):
        return [r for r in store.list_runs() if readable(r, request)]

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str, request: Request):
        run = get_readable(run_id, request)
        return {**run, "events": store.events(run_id)}

    @app.get("/api/runs/{run_id}/events")
    async def stream(run_id: str, request: Request):
        get_readable(run_id, request)

        async def gen():
            log = runner.live.get(run_id)
            q = log.subscribe() if log else None  # subscribe before replay so nothing is missed
            sent = 0
            try:
                for ev in store.events(run_id):
                    sent = ev["id"]
                    yield f"event: ev\ndata: {json.dumps(ev)}\n\n"
                while q is not None:
                    try:
                        ev = await asyncio.wait_for(q.get(), timeout=15)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            return
                        yield ": keepalive\n\n"
                        continue
                    if ev is None:
                        break
                    if ev.id > sent:
                        sent = ev.id
                        yield f"event: ev\ndata: {json.dumps(ev.to_dict(), default=str)}\n\n"
                yield f"event: done\ndata: {json.dumps(store.get_run(run_id))}\n\n"
            finally:
                if log and q:
                    log.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/api/runs/{run_id}/decision")
    async def decide(run_id: str, body: Decision, request: Request):
        run = get_readable(run_id, request)
        user = authmod.current_user(request)
        if not is_owner(user) and not mine(run, user):
            raise HTTPException(403, "only the person who submitted this run, or an Airlock owner, can decide it")
        if run["status"] != "done":
            raise HTTPException(409, "no verdict yet")
        if run["decision"]:
            raise HTTPException(409, f"already {run['decision']}")
        if body.decision not in {"approved", "rejected"}:
            raise HTTPException(400, "decision must be approved or rejected")
        store.update_run(run_id, decision=body.decision, decision_note=body.note[:500], decided=time.time(),
                         decided_by=authmod.current_user(request))
        run = store.get_run(run_id)
        if run["meta"].get("kind") == "pr" and github:
            await post_to_pr(run)
        return store.get_run(run_id)

    async def post_to_pr(run: dict) -> None:
        """The outward action, only after a human decision: commit status + comment as the App's bot."""
        m, run_url = run["meta"], f"{public_url}/runs/{run['id']}"
        state = "success" if run["decision"] == "approved" else "failure"
        desc = f"{run['decision']} by @{run['decided_by']} (verdict: {run['verdict']})"
        try:
            await github.status(m["owner"], m["repo"], m["head_sha"], state, desc, run_url)
            url = await github.comment(m["owner"], m["repo"], m["number"],
                                       build_comment(run, store.events(run["id"]), run_url))
            store.update_run(run["id"], meta={**m, "posted": {"comment_url": url, "status": state}})
            store.append_event(run["id"], "github_posted", f"posted to {m['owner']}/{m['repo']}#{m['number']}: "
                               f"commit status {state} and a comment", comment_url=url, status=state, source="github")
        except Exception as e:  # noqa: BLE001 - the decision stands; report the failed post
            store.update_run(run["id"], meta={**m, "posted": {"error": f"{type(e).__name__}: {e}"[:300]}})
            store.append_event(run["id"], "error", f"posting to GitHub failed: {type(e).__name__}: {str(e)[:200]}")

    return app


def app_factory() -> FastAPI:
    # Fails closed: refuses to start without OAuth config.
    return create_app(auth=authmod.AuthConfig.from_env())
