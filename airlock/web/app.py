"""Web control plane: submit a package, watch the run live over SSE, approve or
reject the verdict. Untrusted code never runs here, only in the run's microVM."""

from __future__ import annotations

import asyncio
import json
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
from ..store import Store, data_dir

STATIC = Path(__file__).parent / "static"
SPEC = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~<>=*|-]+)?$", re.I)
MAX_UPLOAD = 20 * 1024 * 1024

Analyse = Callable[..., Awaitable[object]]


class Runner:
    """Owns live runs: one EventLog per active run, at most `slots` at once."""

    def __init__(self, store: Store, analyse: Analyse, slots: int = 2):
        self.store, self.analyse = store, analyse
        self.live: dict[str, EventLog] = {}
        self.slots = asyncio.Semaphore(slots)
        self.tasks: set[asyncio.Task] = set()

    def start(self, target: str, label: str) -> str:
        run_id = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        self.store.create_run(run_id, label)
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
                                      model=report.model, finished=time.time())
            except Exception as e:  # noqa: BLE001 - recorded on the run
                log.emit("error", f"run failed: {type(e).__name__}: {str(e)[:300]}")
                self.store.update_run(run_id, status="error", error=f"{type(e).__name__}: {e}"[:500],
                                      finished=time.time())
            finally:
                log.close()
                self.live.pop(run_id, None)


class Decision(BaseModel):
    decision: str
    note: str = ""


def create_app(store: Store | None = None, analyse: Analyse | None = None) -> FastAPI:
    if analyse is None:
        from ..pipeline import analyse as real_analyse
        analyse = real_analyse
    store = store or Store()
    runner = Runner(store, analyse)
    uploads = data_dir() / "uploads"
    uploads.mkdir(exist_ok=True)

    app = FastAPI(title="Airlock")
    app.state.runner = runner
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/runs/{run_id}")
    async def run_page(run_id: str):
        if not store.get_run(run_id):
            raise HTTPException(404)
        return FileResponse(STATIC / "run.html")

    @app.post("/api/runs")
    async def submit(spec: str = Form(""), file: UploadFile | None = File(None)):
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
            run_id = runner.start(str(path), name)
        else:
            spec = spec.strip()
            if not SPEC.match(spec):
                raise HTTPException(400, "give an npm spec like left-pad@1.3.0, or upload a .tgz")
            run_id = runner.start(spec, spec)
        return {"id": run_id, "url": f"/runs/{run_id}"}

    @app.get("/api/runs")
    async def list_runs():
        return store.list_runs()

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        run = store.get_run(run_id)
        if not run:
            raise HTTPException(404)
        return {**run, "events": store.events(run_id)}

    @app.get("/api/runs/{run_id}/events")
    async def stream(run_id: str, request: Request):
        if not store.get_run(run_id):
            raise HTTPException(404)

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
    async def decide(run_id: str, body: Decision):
        run = store.get_run(run_id)
        if not run:
            raise HTTPException(404)
        if run["status"] != "done":
            raise HTTPException(409, "no verdict yet")
        if run["decision"]:
            raise HTTPException(409, f"already {run['decision']}")
        if body.decision not in {"approved", "rejected"}:
            raise HTTPException(400, "decision must be approved or rejected")
        store.update_run(run_id, decision=body.decision, decision_note=body.note[:500], decided=time.time())
        # Outward action (PR comment / commit status) goes here once PR targets exist.
        return store.get_run(run_id)

    return app


def app_factory() -> FastAPI:
    return create_app()
