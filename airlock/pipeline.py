"""One analysis run: acquire the candidate, detonate it under the tracer, then let
the triage agent investigate and give a verdict. Deterministic stages first, so
the agent starts from observed facts rather than guesses."""

from __future__ import annotations

import os
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from openai import AsyncOpenAI

from .agent import AgentResult, TriageAgent
from .events import EventLog
from .sandbox import Workspace

ROOT = Path(__file__).parent.parent


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

    @property
    def containment(self) -> list[dict]:
        return [e for e in self.events if e["containment"]]


GOAL = """Review the npm package in /work/candidate.tgz (unpacked at /work/pkg). It is a new
release of a dependency our app uses. Airlock has already installed it once in /tmp/try with a
tracer; these events were observed (ids in brackets):

{observed}

Confirm what the package does at install time and at runtime by reading its code and, if useful,
running it again. Then call finish with a verdict and short evidence points citing event ids."""


async def analyse(target: str, *, events: EventLog | None = None, model: str | None = None,
                  max_turns: int = 12) -> Report:
    """target: a local .tgz path or an npm spec such as left-pad@1.3.0."""
    events = events or EventLog()
    model = model or load_roles()["roles"]["agent"]
    t0 = time.monotonic()
    async with Workspace(events, image="node", label=Path(target).stem if target.endswith(".tgz") else target) as ws:
        if target.endswith(".tgz") and Path(target).exists():
            await ws.write("/work/candidate.tgz", Path(target).read_bytes())
            events.emit("acquired", f"copied {Path(target).name} into the VM", source="file")
        else:
            r = await ws.exec(f"npm pack {target} --silent --pack-destination /tmp/pack && mv /tmp/pack/*.tgz /work/candidate.tgz",
                              cwd="/tmp/pack", timeout=120, source="acquire")
            if not r.ok:
                raise RuntimeError(f"npm pack {target} failed: {r.stderr[-300:]}")

        await ws.exec("mkdir -p pkg && tar xzf candidate.tgz -C pkg --strip-components=1", source="unpack")
        await ws.exec("npm init -y >/dev/null && npm install --no-audit --no-fund /work/candidate.tgz",
                      cwd="/tmp/try", timeout=180, trace=True, source="detonate")

        observed = "\n".join(f"[E{e.id}] {e.kind}: {e.summary}" for e in events.events
                             if e.kind not in {"exec"}) or "(nothing notable)"
        agent = TriageAgent(inference_client(), model, ws, events, max_turns=max_turns)
        result = await agent.run(GOAL.format(observed=observed))

    return Report(target=target, verdict=result.verdict, evidence=result.evidence, model=model, agent=result,
                  events=[e.to_dict() for e in events.events], seconds=round(time.monotonic() - t0, 1))
