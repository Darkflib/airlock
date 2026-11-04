"""Web control plane: submit a package, watch the run live over SSE, approve or
reject the verdict. Untrusted code never runs here, only in the run's microVM."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Awaitable, Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..events import EventLog
from ..github import GitHubApp, parse_pr_url
from ..pipeline import parse_pypi_spec
from ..prcomment import build_comment, build_progress
from ..store import Store, data_dir
from . import auth as authmod

STATIC = Path(__file__).parent / "static"
GUEST_REPOS = frozenset(r.strip().lower() for r in
                        os.environ.get("AIRLOCK_GUEST_REPOS", "Darkflib/airlock-demo").split(",") if r.strip())
SPEC = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~=*-]+)?$", re.I)  # no shell syntax
MAX_SPEC = 214  # npm's own package-name limit
MAX_UPLOAD = 20 * 1024 * 1024
WEBHOOK_ACTIONS = {"opened", "synchronize", "reopened"}  # a new PR, a new push to it, a PR back from closed
WEBHOOK_LABEL = " (webhook)"
# `/airlock approve [note]` or `/airlock reject [note]` on its own line of a PR comment
COMMAND = re.compile(r"^\s*/airlock\s+(approve|reject)\b[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)
FIXTURES = Path(os.environ.get("AIRLOCK_FIXTURES", Path(__file__).parents[2] / "evals" / "fixtures"))
# The containment self-test: known packages, and what a correct run must show for each.
SELFTEST = [
    ("left-padder-hostile.tgz", "Node credential stealer", "malicious"),
    ("colorful-logs-shell-stealer.tgz", "Shell credential stealer, no Node code", "malicious"),
    ("left-padder-benign.tgz", "Benign package with a postinstall", "benign"),
    ("termcolour-utils-stealer.tar.gz", "Python credential stealer in setup.py", "malicious"),
    ("tinyslug-benign.tar.gz", "Benign Python sdist with setup.py work", "benign"),
]

Analyse = Callable[..., Awaitable[object]]
Gate = Callable[[str, str, EventLog], Awaitable[None]]


class Runner:
    """Owns live runs: one EventLog per active run, at most `slots` at once."""

    def __init__(self, store: Store, analyse: Analyse, slots: int = 2, gate: Gate | None = None):
        self.store, self.analyse, self.gate = store, analyse, gate
        self.live: dict[str, EventLog] = {}
        self.slots = asyncio.Semaphore(slots)
        self.tasks: set[asyncio.Task] = set()

    def start(self, target: str, label: str, user: str | None = None, demo: bool = False) -> str:
        run_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        self.store.create_run(run_id, label, submitted_by=user, demo=demo)
        log = EventLog(on_emit=lambda ev: self.store.add_event(run_id, ev))
        self.live[run_id] = log
        task = asyncio.create_task(self._run(run_id, target, log))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return run_id

    async def _run(self, run_id: str, target: str, log: EventLog) -> None:
        async with self.slots:
            self.store.update_run(run_id, status="running")

            async def on_pr(meta: dict) -> None:  # the PR is fetched: record it, then block its merge
                self.store.update_run(run_id, meta=meta)
                if self.gate:
                    await self.gate(run_id, "started", log)
            try:
                report = await self.analyse(target, events=log, on_pr=on_pr)
                end = dict(status="done", verdict=report.verdict, evidence=report.evidence, model=report.model,
                           meta=getattr(report, "meta", {}) or {})
            except Exception as e:  # noqa: BLE001 - recorded on the run
                log.emit("error", f"run failed: {type(e).__name__}: {str(e)[:300]}")
                end = dict(status="error", error=f"{type(e).__name__}: {e}"[:500])
            try:
                # the status reflects the outcome before the run reads as finished
                if "meta" in end:  # keep what the gate recorded while it ran (status sync, comment url)
                    end["meta"] = {**(self.store.get_run(run_id)["meta"] or {}), **end["meta"]}
                self.store.update_run(run_id, **{k: v for k, v in end.items() if k != "status"})
                if self.gate:
                    await self.gate(run_id, "verdict" if end["status"] == "done" else "error", log)
            finally:
                self.store.update_run(run_id, status=end["status"], finished=time.time())
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


def github_time(ts: str | None) -> float | None:
    """GitHub's ISO 8601 timestamps (`2026-11-04T23:05:32Z`) as epoch seconds."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else None
    except ValueError:
        return None


def create_app(store: Store | None = None, analyse: Analyse | None = None,
               auth: authmod.AuthConfig | None = None, exchange: authmod.GithubLogin | None = None,
               github: GitHubApp | None = None, user_daily: int | None = None,
               global_daily: int | None = None, webhook_secret: str | None = None,
               reap: Callable[[], Awaitable[tuple[list[str], list[str]]]] | None = None) -> FastAPI:
    """auth=None disables sign-in (tests only); app_factory always passes a config.

    Owners are the logins in AIRLOCK_ALLOWED_USERS; everyone else signed in is a guest (e.g. a
    judge admitted by an invite). Guests see their own runs and the owners' runs, decide and share
    only their own, may submit PRs only from AIRLOCK_GUEST_REPOS, and are capped per rolling 24 h,
    so an invite link that spreads can't run up the bill or speak for a repo through the App."""
    if analyse is None:
        from ..pipeline import analyse as real_analyse
        from ..sandbox import reap_leftovers
        analyse, reap = real_analyse, reap or reap_leftovers
    store = store or Store()
    store.fail_stale_runs()
    store.backfill_demo(GUEST_REPOS)  # nothing survives a restart: those runs' VMs and tasks are gone
    github = github or GitHubApp.from_env()
    public_url = auth.public_url if auth else os.environ.get("AIRLOCK_PUBLIC_URL", "https://airlock.darkflib.dev").rstrip("/")

    async def gate_pr(run_id: str, phase: str, log: EventLog) -> None:
        """Hold a PR's merge while it runs: a `pending` airlock status (which branch protection can
        require to be success) from the moment the head is fetched until a human decides. Only the
        decision posts success/failure and a comment; a failed run posts `error`."""
        run = store.get_run(run_id)
        m = run["meta"]
        if m.get("kind") != "pr" or not github:
            return
        if phase == "verdict" and auto_reject and store.proven_exfil(run_id):
            # Deterministic, not the model's word: a payload captured on the host carried this run's
            # canary token. Reject at once; anything short of proof still waits for a person.
            reason = "exfiltration proven by a captured payload"
            if store.claim_decision(run_id, "rejected", None, meta_patch={"auto_decision": reason}):
                log.emit("decision", f"rejected automatically: {reason}", source="airlock")
                await post_to_pr(store.get_run(run_id))
                return
        async with commit_lock(m):
            await gate_writes(run_id, phase, log)

    async def gate_writes(run_id: str, phase: str, log: EventLog) -> None:
        """gate_pr's GitHub writes, under the commit's lock: re-checked here, so a write for an older
        run can't land after a newer run's."""
        run = store.get_run(run_id)
        m = run["meta"]
        if newer := store.newer_run_of_commit(run):
            log.emit("github_status", f"not updating the GitHub status: run {newer} of the same commit is newer",
                     superseded_by=newer, source="github")
            return
        state, desc = {
            "started": ("pending", "Detonating in a microVM; merge waits for a human decision"),
            "verdict": ("pending", f"Verdict: {run['verdict']}; comment /airlock approve or /airlock reject to decide"),
            "error": ("error", "Airlock run failed; rerun it before merging"),
        }[phase]
        try:
            await github.status(m["owner"], m["repo"], m["head_sha"], state, desc, f"{public_url}/runs/{run_id}")
            log.emit("github_status", f"commit status on {m['owner']}/{m['repo']}#{m['number']}: {state} ({desc})",
                     state=state, source="github")
            gate = {"state": state, "synced": True}
        except Exception as e:  # noqa: BLE001 - never fails the run, but the page must say the PR isn't held
            # GitHub keeps whatever status it had: possibly an earlier review's success. Say so loudly.
            log.emit("error", f"setting the GitHub status failed, so {m['owner']}/{m['repo']}#{m['number']} is NOT held: "
                     f"it keeps any earlier airlock status, which may be a success. {type(e).__name__}: {str(e)[:150]}")
            gate = {"state": state, "synced": False, "error": f"{type(e).__name__}: {e}"[:200]}
        # One comment per run, rewritten as it goes, so the PR itself shows progress and how to decide.
        run_url, extra = f"{public_url}/runs/{run_id}", {}
        held = gate["synced"]  # the comment must not claim the merge is held when the status write failed
        body = (build_progress(run, run_url, held=held) if phase == "started"
                else build_progress(run, run_url, failed=run.get("error") or "unknown error", held=held)
                if phase == "error" else build_comment(run, store.events(run_id), run_url, held=held))
        try:
            extra["comment_url"] = await github.comment(m["owner"], m["repo"], m["number"], body,
                                                        edit=m.get("comment_url"))
        except Exception as e:  # noqa: BLE001 - the status is what holds the merge; the comment is a courtesy
            log.emit("error", f"commenting on {m['owner']}/{m['repo']}#{m['number']} failed: "
                     f"{type(e).__name__}: {str(e)[:150]}")
        store.update_run(run_id, meta={**store.get_run(run_id)["meta"], "gate": gate, **extra})
    auto_reject = os.environ.get("AIRLOCK_AUTO_REJECT", "1") != "0"
    # Outbound writes per commit are serialized in this process: statuses are per repo/SHA, so the
    # latest-run check and the write must happen together. One uvicorn worker (see airlock-web.service).
    locks: dict[tuple[str, str, str], asyncio.Lock] = {}

    def commit_lock(m: dict) -> asyncio.Lock:
        return locks.setdefault((m["owner"].lower(), m["repo"].lower(), m["head_sha"]), asyncio.Lock())
    self_approval = os.environ.get("AIRLOCK_SELF_APPROVAL", "1") != "0"
    runner = Runner(store, analyse, gate=gate_pr)
    user_daily = user_daily if user_daily is not None else int(os.environ.get("AIRLOCK_USER_DAILY_RUNS", 15))
    global_daily = global_daily if global_daily is not None else int(os.environ.get("AIRLOCK_GLOBAL_DAILY_RUNS", 150))
    owners = auth.allowed if auth else frozenset()
    webhook_secret = webhook_secret if webhook_secret is not None else os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    webhook_daily = int(os.environ.get("AIRLOCK_WEBHOOK_DAILY_RUNS", 50))
    deliveries: set[str] = set()  # GitHub redelivers on timeouts; one run per delivery

    def is_owner(user: str | None) -> bool:
        return not auth or (user or "").lower() in owners

    def mine(run: dict, user: str | None) -> bool:
        return (run.get("submitted_by") or "").lower() == (user or "").lower()

    def readable(run: dict, request: Request) -> bool:
        """Share-link viewers were already limited to their runs by the auth middleware. A signed-in
        guest holding a share link may also read the runs it names (reads only: every mutation checks
        ownership separately)."""
        user = authmod.current_user(request)
        if user is None or is_owner(user):
            return True
        if run["id"] in ((authmod.current_share(request) or {}).get("runs") or []):
            return True
        # An owner's run is shown to guests only when it is demo material: a self-test, a public
        # npm package or a PR from AIRLOCK_GUEST_REPOS. Uploads and other repos stay private.
        return mine(run, user) or (bool(run.get("demo")) and (run.get("submitted_by") or "").lower() in owners)

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

    def share_url(runs: list[str], selftest: str | None, by: str | None) -> dict:
        if not auth:
            raise HTTPException(400, "share links need sign-in configured")
        share = authmod.share_payload(runs, selftest, by)
        auth.record_share(share)
        return {"url": f"{public_url}/s/{authmod.sign(auth.session_secret, share)}", "id": share["id"],
                "expires": share["exp"]}
    uploads = data_dir() / "uploads"
    uploads.mkdir(exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Runs failed above were this service's last runs; clear the sandboxes they left behind.
        if reap:
            try:
                removed, failed = await reap()
                if removed or failed:
                    print(f"startup: removed {len(removed)} leftover sandbox(es) {removed}; failed {failed}", flush=True)
            except Exception as e:  # never block startup on cleanup
                print(f"startup: sandbox cleanup failed: {type(e).__name__}: {e}", flush=True)
        yield

    app = FastAPI(title="Airlock", lifespan=lifespan)
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
                raise HTTPException(413, "package larger than 20 MB")
            name = re.sub(r"[^\w.-]", "_", Path(file.filename).name)
            # npm tarball (.tgz) or Python sdist (.tar.gz gzip, or .zip). The suffix is how the
            # pipeline tells npm from Python, so keep it; default a gzip upload to .tgz.
            if data.startswith(b"\x1f\x8b"):
                ext = ".tar.gz" if name.endswith(".tar.gz") else ".tgz"
            elif data.startswith(b"PK\x03\x04") and name.endswith(".zip"):
                ext = ".zip"
            else:
                raise HTTPException(400, "upload a gzipped tarball (.tgz / .tar.gz) or a Python sdist .zip")
            path = uploads / f"{secrets.token_hex(4)}-{name}"
            if not path.name.endswith(ext):
                path = path.with_name(path.name + ext)
            path.write_bytes(data)
            run_id = runner.start(str(path), name, user)
        elif parse_pr_url(spec):
            if github is None:
                raise HTTPException(400, "GitHub App not configured on this server")
            owner, repo, number = parse_pr_url(spec)
            if not is_owner(user) and f"{owner}/{repo}".lower() not in GUEST_REPOS:
                raise HTTPException(403, f"guest accounts can analyse PRs from {', '.join(sorted(GUEST_REPOS))} only")
            run_id = runner.start(spec.strip(), f"{owner}/{repo}#{number}", user,
                                  demo=f"{owner}/{repo}".lower() in GUEST_REPOS)
        else:
            spec = spec.strip()
            if len(spec) > MAX_SPEC or not (SPEC.match(spec) or parse_pypi_spec(spec)):
                raise HTTPException(400, "give a GitHub PR URL, an npm spec like left-pad@1.3.0, "
                                    "a PyPI spec like pypi:requests==2.32.3, or upload a package")
            run_id = runner.start(spec, spec, user, demo=True)  # public registry packages only
        return {"id": run_id, "url": f"/runs/{run_id}"}

    @app.post("/api/github/webhook")
    async def github_webhook(request: Request):
        """Runs a PR automatically when it is opened, reopened or pushed to. Public (GitHub can't
        sign in), so every delivery must carry GitHub's HMAC signature made with our webhook
        secret. Acts only on AIRLOCK_GUEST_REPOS, under its own daily cap; the decision stays human."""
        if not webhook_secret or github is None:
            raise HTTPException(404)
        body = await request.body()
        sig = "sha256=" + hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, request.headers.get("x-hub-signature-256", "")):
            raise HTTPException(401, "bad signature")
        event = request.headers.get("x-github-event", "")
        if event == "ping":
            return {"ok": True}
        payload = json.loads(body)
        if event in ("issue_comment", "pull_request_review"):
            return await comment_command(event, payload, request.headers.get("x-github-delivery", ""))
        if event != "pull_request" or payload.get("action") not in WEBHOOK_ACTIONS:
            return {"ignored": f"{event}/{payload.get('action')}"}
        slug, pr = payload["repository"]["full_name"], payload["pull_request"]
        if slug.lower() not in GUEST_REPOS:
            return {"ignored": f"{slug} is not enabled for automatic runs"}
        delivery = request.headers.get("x-github-delivery", "")
        owner, repo = slug.split("/", 1)
        seen = bool(delivery) and delivery in deliveries
        if seen or (done := store.run_of_commit(owner, repo, pr["head"]["sha"], pr["number"])):
            return {"ignored": "already analysed", "run": None if seen else done}
        if store.count_targets(time.time() - 86400, WEBHOOK_LABEL) >= webhook_daily:
            raise HTTPException(429, f"daily limit of {webhook_daily} automatic runs reached")
        if delivery:
            deliveries.add(delivery)
        url = f"https://github.com/{slug}/pull/{pr['number']}"
        run_id = runner.start(url, f"{slug}#{pr['number']}{WEBHOOK_LABEL}", payload["sender"]["login"], demo=True)
        return JSONResponse({"id": run_id, "url": f"{public_url}/runs/{run_id}"}, status_code=202)

    async def comment_command(event: str, payload: dict, delivery: str) -> dict:
        """Decide from GitHub: `/airlock approve|reject [note]` in a PR comment (`issue_comment`,
        which needs the App's Issues permission) or in the body of a submitted PR review. GitHub's
        write access is the only authority here (the Airlock allowlist is for the web UI), and the
        same rules apply as on the run page: the latest run of the head commit, not after a decision."""
        sender = payload.get("sender") or {}
        if event == "pull_request_review":
            pr, text, wanted = payload.get("pull_request") or {}, (payload.get("review") or {}).get("body"), "submitted"
        else:
            issue = payload.get("issue") or {}
            pr = issue if issue.get("pull_request") else {}
            text, wanted = (payload.get("comment") or {}).get("body"), "created"
        cmd = COMMAND.search(text or "")
        if payload.get("action") != wanted or not pr.get("number") or not cmd:
            return {"ignored": "not an /airlock command on a pull request"}
        if sender.get("type") == "Bot":
            return {"ignored": "comments from bots"}
        if delivery and delivery in deliveries:
            return {"ignored": "already handled"}
        if delivery:
            deliveries.add(delivery)
        owner, repo = payload["repository"]["full_name"].split("/", 1)
        number, user = pr["number"], sender["login"]
        decision = "approved" if cmd.group(1).lower() == "approve" else "rejected"

        async def reply(text: str) -> dict:
            try:
                await github.comment(owner, repo, number, f"@{user} {text}")
            except Exception:  # noqa: BLE001 - nothing more to tell them through
                pass
            return {"refused": text}

        try:
            current = await github.pull_request(owner, repo, number)
        except Exception as e:  # noqa: BLE001
            return await reply(f"Airlock couldn't read this pull request from GitHub ({type(e).__name__}); try again.")
        head = current.head_sha
        # Bind the command to what its author saw: a review names the commit it reviewed, and any
        # command must be written after the verdict it decides was published. A delivery that arrives
        # after a new push and analysis must not approve a commit its author never looked at.
        reviewed = (payload.get("review") or {}).get("commit_id")
        if reviewed and reviewed != head:
            return await reply(f"not recorded: your review is of `{reviewed[:7]}`, but this PR's head is now "
                               f"`{head[:7]}`. Review the latest commit and decide again.")
        run_id = store.run_of_commit(owner, repo, head, number)
        if not run_id:
            return await reply(f"Airlock hasn't analysed the head commit `{head[:7]}` yet, so there's nothing to decide.")
        run = store.get_run(run_id)
        written = github_time((payload.get("review") or {}).get("submitted_at")
                              or (payload.get("comment") or {}).get("created_at"))
        if run["status"] == "done" and (written is None or not run.get("finished") or written < run["finished"]):
            return await reply(f"not recorded: Airlock's result for `{head[:7]}` was published after your comment, "
                               "so it may not be what you meant to decide. Read the updated result and comment again.")
        try:
            run = await apply_decision(run, decision, user, cmd.group(2).strip(), via="github",
                                       author=getattr(current, "author", None))
        except HTTPException as e:
            return await reply(f"not recorded: {e.detail}.")
        return {"decided": run["decision"], "run": run_id}

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
        probes = [{"run_id": runner.start(str(FIXTURES / f), f"self-test: {label}", user, demo=True), "label": label,
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
        return share_url([p["run_id"] for p in test["probes"]], test_id, user)

    @app.post("/api/runs/{run_id}/share")
    async def share_run(run_id: str, request: Request):
        run = get_readable(run_id, request)
        if not is_owner(authmod.current_user(request)) and not mine(run, authmod.current_user(request)):
            raise HTTPException(403, "you can share only runs you submitted")
        return share_url([run_id], None, authmod.current_user(request))

    def my_shares(request: Request) -> list[dict]:
        """Live share links the signed-in user may see and revoke: their own, or all for an owner."""
        user = authmod.current_user(request)
        if not auth or not user:
            raise HTTPException(401, "sign in required")
        return [s for s in auth.shares() if is_owner(user) or (s.get("by") or "").lower() == user.lower()]

    @app.get("/api/shares")
    async def list_shares(request: Request, run: str = "", selftest: str = ""):
        return [{k: s.get(k) for k in ("id", "by", "iat", "exp", "selftest")} for s in my_shares(request)
                if (run and run in (s.get("runs") or []) and not s.get("selftest"))
                or (selftest and s.get("selftest") == selftest) or not (run or selftest)]

    @app.delete("/api/shares/{share_id}")
    async def revoke_share(share_id: str, request: Request):
        if share_id not in {s["id"] for s in my_shares(request)}:
            raise HTTPException(404, "no live share link with that id that you can revoke")
        auth.revoke_share(share_id)
        return {"revoked": share_id}

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
                checked = time.monotonic()
                while q is not None:
                    if auth and time.monotonic() - checked > 15:
                        # A revoked session or share link, or an allowlist removal, ends a live stream too.
                        if not authmod.still_allowed(auth, request):
                            return
                        checked = time.monotonic()
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
        return await apply_decision(run, body.decision, user, body.note, via="web")

    async def apply_decision(run: dict, decision: str, user: str | None, note: str, via: str,
                             author: str | None = None) -> dict:
        """The decision rules shared by the run page and `/airlock` PR comments. `author` is the PR's
        current author when the caller fetched it from GitHub (the run's cached one otherwise)."""
        run_id = run["id"]
        if run["status"] != "done":
            raise HTTPException(409, "no verdict yet")
        if run["decision"]:
            auto = (run["meta"] or {}).get("auto_decision")
            raise HTTPException(409, f"already {run['decision']}" + (f" automatically: {auto}" if auto else
                                                                      f" by @{run['decided_by']}"))
        if decision not in {"approved", "rejected"}:
            raise HTTPException(400, "decision must be approved or rejected")
        if newer := store.newer_run_of_commit(run):
            raise HTTPException(409, f"run {newer} reviewed the same commit later; decide that one instead")
        no_self_approval(run, decision, user, author)
        await require_write(run, user, force=via == "github")
        # The checks above ran before an await; the claim re-checks undecided + latest atomically.
        if not store.claim_decision(run_id, decision, user, note, meta_patch={"decided_via": via}):
            latest = store.get_run(run_id)
            raise HTTPException(409, f"already {latest['decision']} by @{latest['decided_by']}" if latest["decision"]
                                else f"run {store.newer_run_of_commit(latest)} reviewed the same commit later; "
                                     "decide that one instead")
        store.append_event(run_id, "decision", f"{decision} by @{user}" + (" in a GitHub comment" if via == "github" else ""),
                           source="github" if via == "github" else "airlock")
        run = store.get_run(run_id)
        if run["meta"].get("kind") == "pr" and github:
            await post_to_pr(run)
        return store.get_run(run_id)

    async def require_write(run: dict, user: str | None, force: bool = False) -> None:
        """A decision sets the check that branch protection requires, so GitHub decides who may make
        it: only people with write access to the repo. Fails closed if GitHub can't say. Optionally
        (AIRLOCK_SELF_APPROVAL=0) the PR's author may not approve their own change."""
        m = run["meta"] or {}
        if m.get("kind") != "pr" or not github or not (auth or force):
            return
        slug = f"{m['owner']}/{m['repo']}"
        try:
            perm = await github.permission(m["owner"], m["repo"], user)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(503, f"couldn't confirm your access to {slug} on GitHub ({type(e).__name__}); "
                                     "try again") from e
        if perm not in ("admin", "write"):
            raise HTTPException(403, f"deciding this PR sets its merge check, so it needs write access to "
                                     f"{slug} on GitHub; @{user} has {perm}")

    def no_self_approval(run: dict, decision: str, user: str | None, author: str | None = None) -> None:
        author = (author or (run["meta"] or {}).get("author") or "").lower()
        if decision == "approved" and not self_approval and author and author == (user or "").lower():
            raise HTTPException(403, "the PR's author can't approve their own change here; ask another maintainer")

    @app.post("/api/runs/{run_id}/post")
    async def repost(run_id: str, request: Request):
        """Post a decision again after GitHub failed past the automatic retries (an outage)."""
        run = get_readable(run_id, request)
        user = authmod.current_user(request)
        m = run["meta"] or {}
        if m.get("kind") != "pr" or not github or not run["decision"]:
            raise HTTPException(409, "nothing to post: not a decided pull request run")
        if m.get("posted", {}).get("comment_url"):
            raise HTTPException(409, "already posted")
        if not is_owner(user) and not mine(run, user):
            raise HTTPException(403, "only the person who submitted this run, or an Airlock owner, can post it")
        if newer := store.newer_run_of_commit(run):
            raise HTTPException(409, f"run {newer} reviewed the same commit later; its status stands")
        await require_write(run, user)
        await post_to_pr(run)
        return store.get_run(run_id)

    async def post_to_pr(run: dict) -> None:
        """The outward action, only after a human decision: commit status + comment as the App's bot.
        Under the commit's lock, and only while this run is still the latest of its commit."""
        async with commit_lock(run["meta"]):
            run = store.get_run(run["id"])
            if newer := store.newer_run_of_commit(run):
                store.update_run(run["id"], meta={**run["meta"], "posted": {"error": f"superseded by run {newer}"}})
                store.append_event(run["id"], "github_status", f"not posting: run {newer} of the same commit is newer",
                                   superseded_by=newer, source="github")
                return
            await post_writes(run)

    async def post_writes(run: dict) -> None:
        m, run_url = run["meta"], f"{public_url}/runs/{run['id']}"
        state = "success" if run["decision"] == "approved" else "failure"
        desc = (f"rejected automatically: {m['auto_decision']}" if m.get("auto_decision")
                else f"{run['decision']} by @{run['decided_by']} (verdict: {run['verdict']})")
        try:
            await github.status(m["owner"], m["repo"], m["head_sha"], state, desc, run_url)
            url = await github.comment(m["owner"], m["repo"], m["number"],
                                       build_comment(run, store.events(run["id"]), run_url), edit=m.get("comment_url"))
            store.update_run(run["id"], meta={**m, "comment_url": url, "posted": {"comment_url": url, "status": state}})
            store.append_event(run["id"], "github_posted", f"posted to {m['owner']}/{m['repo']}#{m['number']}: "
                               f"commit status {state} and a comment", comment_url=url, status=state, source="github")
        except Exception as e:  # noqa: BLE001 - the decision stands; report the failed post
            store.update_run(run["id"], meta={**m, "posted": {"error": f"{type(e).__name__}: {e}"[:300]}})
            store.append_event(run["id"], "error", f"posting to GitHub failed: {type(e).__name__}: {str(e)[:200]}")

    return app


def app_factory() -> FastAPI:
    # Fails closed: refuses to start without OAuth config.
    return create_app(auth=authmod.AuthConfig.from_env())
