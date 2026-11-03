# /// script
# requires-python = ">=3.11"
# dependencies = ["openai>=1.40", "microsandbox"]
# ///
"""Airlock model eval harness. Runs on the dev host (needs KVM + msb).

  1. Capability smoke test per model: chat, tool call, JSON mode, image input.
  2. Agent tasks per model: a tool-calling loop drives a real microsandbox until
     the task's deterministic check passes or the turn budget runs out.

Usage (normally via evals/run.sh, which supplies VULTR_INFERENCE_API_KEY):
  uv run harness.py [--models a,b] [--tasks t1,t2] [--skip-smoke] [--skip-agent]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import statistics
import struct
import time
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from microsandbox import Action, Destination, Network, NetworkPolicy, Protocol, Rule, Sandbox
from microsandbox.types import TlsConfig
from openai import AsyncOpenAI

from tasks import TASKS, Task

HERE = Path(__file__).parent
BASE_URL = "https://api.vultrinference.com/v1"
GUARD_MODELS = {"nemotron-3.5-content-safety"}
ALLOWED_HOSTS = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")
OUTPUT_TAIL = 4000

SYSTEM = (
    "You are a software engineer working inside an isolated Linux sandbox. The project is in /work. "
    "Use the tools to inspect, change and run things. Only the npm and PyPI registries are reachable. "
    "Be efficient. When the goal is met and verified, call finish."
)

TOOLS = [
    {"type": "function", "function": {
        "name": "exec",
        "description": "Run a shell command in the sandbox and return exit code, stdout and stderr.",
        "parameters": {"type": "object", "properties": {
            "cmd": {"type": "string", "description": "Shell command"},
            "cwd": {"type": "string", "description": "Working directory, default /work"},
        }, "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Create or overwrite a file with the given content.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"},
        }, "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a text file.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "finish",
        "description": "Call when the goal is met.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}}},
]


# --- sandbox ----------------------------------------------------------------

SANDBOX_SLOTS = asyncio.Semaphore(4)


def egress_policy() -> Network:
    rules = [*Rule.allow_dns()]
    for host in ALLOWED_HOSTS:
        rules.append(Rule.allow(protocol=Protocol.TCP, port=443, destination=Destination.domain(host)))
    policy = NetworkPolicy(default_egress=Action.DENY, default_ingress=Action.ALLOW, rules=tuple(rules))
    return Network(policy=policy, tls=TlsConfig(), strict=True)


class _Slot:
    """Sandbox context manager that also holds a concurrency slot."""

    def __init__(self, image: str, label: str, gated: bool):
        self.image, self.label, self.gated = image, label, gated

    async def __aenter__(self):
        if self.gated:
            await SANDBOX_SLOTS.acquire()
        name = re.sub(r"[^a-z0-9-]", "-", f"ev-{self.label}-{time.monotonic_ns() % 10**8}".lower())[:60]
        try:
            self.cm = await Sandbox.create(name, image=self.image, cpus=1, memory=1024, replace=True, network=egress_policy())
            return await self.cm.__aenter__()
        except BaseException:
            if self.gated:
                SANDBOX_SLOTS.release()
            raise

    async def __aexit__(self, *exc):
        try:
            return await self.cm.__aexit__(*exc)
        finally:
            if self.gated:
                SANDBOX_SLOTS.release()


async def new_sandbox(image: str, label: str, gated: bool = True) -> _Slot:
    return _Slot(image, label, gated)


async def check_sandbox(image: str, label: str) -> _Slot:
    # A task's check may need a second VM while it still holds its own slot; not
    # gating it avoids deadlock when every slot is held by a waiting check.
    return _Slot(image, label, gated=False)


# --- smoke tests --------------------------------------------------------------

def red_png(size: int = 16) -> bytes:
    """A solid red PNG, so the vision answer can be checked."""
    row = b"\x00" + b"\xff\x00\x00" * size
    raw = zlib.compress(row * size)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


async def timed(coro):
    t0 = time.monotonic()
    try:
        return await coro, time.monotonic() - t0, None
    except Exception as e:  # noqa: BLE001 - every failure is a result here
        return None, time.monotonic() - t0, f"{type(e).__name__}: {str(e)[:200]}"


async def smoke(client: AsyncOpenAI, model: str) -> dict:
    res: dict = {"model": model}

    r, dt, err = await timed(client.chat.completions.create(
        model=model, messages=[{"role": "user", "content": "Reply with exactly the word: pong"}], max_tokens=2000))
    text = (r.choices[0].message.content or "") if r else ""
    res["chat"] = {"ok": "pong" in text.lower(), "s": round(dt, 2), "err": err}

    r, dt, err = await timed(client.chat.completions.create(
        model=model, tools=TOOLS[:1], max_tokens=2000,
        messages=[{"role": "user", "content": "List the files in /work using the exec tool."}]))
    ok = False
    if r and r.choices[0].message.tool_calls:
        tc = r.choices[0].message.tool_calls[0]
        try:
            ok = tc.function.name == "exec" and "cmd" in json.loads(tc.function.arguments)
        except json.JSONDecodeError:
            pass
    res["tool_call"] = {"ok": ok, "s": round(dt, 2), "err": err}

    r, dt, err = await timed(client.chat.completions.create(
        model=model, response_format={"type": "json_object"}, max_tokens=2000,
        messages=[{"role": "user", "content": 'Return a JSON object {"verdict": "benign"|"malicious", "reason": string} for: a package that only exports a leftPad function.'}]))
    ok = False
    if r:
        try:
            ok = isinstance(json.loads(r.choices[0].message.content or ""), dict)
        except json.JSONDecodeError:
            pass
    res["json_mode"] = {"ok": ok, "s": round(dt, 2), "err": err}

    img = "data:image/png;base64," + base64.b64encode(red_png()).decode()
    r, dt, err = await timed(client.chat.completions.create(
        model=model, max_tokens=2000,
        messages=[{"role": "user", "content": [
            {"type": "text", "text": "What single colour fills this image? Answer with one word."},
            {"type": "image_url", "image_url": {"url": img}}]}]))
    text = (r.choices[0].message.content or "") if r else ""
    res["vision"] = {"ok": "red" in text.lower(), "s": round(dt, 2), "err": err, "answer": text.strip()[:40]}
    return res


# --- agent loop ---------------------------------------------------------------

@dataclass
class Run:
    model: str
    task: str
    rep: int = 0
    passed: bool = False
    finished: bool = False
    summary: str = ""
    turns: int = 0
    tool_calls: int = 0
    invalid_calls: int = 0
    no_tool_turns: int = 0
    llm_latencies: list[float] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    wall_s: float = 0.0
    checks: dict = field(default_factory=dict)
    detail: str = ""
    error: str | None = None
    transcript: list = field(default_factory=list)


def tail(s: str) -> str:
    return s if len(s) <= OUTPUT_TAIL else "...[truncated]...\n" + s[-OUTPUT_TAIL:]


async def run_tool(sb, name: str, args: dict) -> str:
    if name == "exec":
        try:
            out = await sb.shell(args["cmd"], cwd=args.get("cwd") or "/work", timeout=180)
        except Exception as e:  # noqa: BLE001 - timeouts etc. go back to the model
            return f"error: {type(e).__name__}: {e}"
        return f"exit={out.exit_code}\nstdout:\n{tail(out.stdout_text)}\nstderr:\n{tail(out.stderr_text)}"
    if name == "write_file":
        path = args["path"]
        await sb.fs.mkdir(os.path.dirname(path) or "/")
        await sb.fs.write(path, args["content"].encode())
        return f"wrote {len(args['content'])} bytes to {path}"
    if name == "read_file":
        try:
            return tail(await sb.fs.read_text(args["path"]))
        except Exception as e:  # noqa: BLE001
            return f"error: {type(e).__name__}: {e}"
    raise KeyError(name)


async def agent_run(client: AsyncOpenAI, model: str, task: Task, results_dir: Path, rep: int = 0) -> Run:
    run = Run(model=model, task=task.name, rep=rep)
    t0 = time.monotonic()
    try:
        async with await new_sandbox(task.image, f"{task.name}-{model}") as sb:
            await sb.fs.mkdir("/work")
            for path, content in task.files.items():
                await sb.fs.mkdir(os.path.dirname(path))
                await sb.fs.write(path, content if isinstance(content, bytes) else content.encode())
            if task.setup:
                await sb.shell(task.setup, timeout=120)

            messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task.goal}]
            for _ in range(task.max_turns):
                run.turns += 1
                t1 = time.monotonic()
                resp = await client.chat.completions.create(
                    model=model, messages=messages, tools=TOOLS, temperature=0.2, max_tokens=8000, timeout=180)
                run.llm_latencies.append(round(time.monotonic() - t1, 2))
                if resp.usage:
                    run.prompt_tokens += resp.usage.prompt_tokens or 0
                    run.completion_tokens += resp.usage.completion_tokens or 0
                msg = resp.choices[0].message
                assistant = {"role": "assistant", "content": msg.content or ""}
                if msg.tool_calls:
                    assistant["tool_calls"] = [tc.model_dump() for tc in msg.tool_calls]
                messages.append(assistant)
                run.transcript.append({"assistant": msg.content, "tool_calls": assistant.get("tool_calls")})

                if not msg.tool_calls:
                    run.no_tool_turns += 1
                    if run.no_tool_turns >= 3:
                        break
                    messages.append({"role": "user", "content": "Continue using the tools. Call finish when the goal is met."})
                    continue

                for tc in msg.tool_calls:
                    run.tool_calls += 1
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                        if tc.function.name == "finish":
                            run.finished = True
                            run.summary = str(args.get("summary", ""))
                            result = "ok"
                        else:
                            result = await run_tool(sb, tc.function.name, args)
                    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
                        run.invalid_calls += 1
                        result = f"invalid tool call: {type(e).__name__}: {e}"
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                    run.transcript.append({"tool": tc.function.name, "result": result[:1500]})
                if run.finished:
                    break

            verdict = await task.check(sb, new_sandbox=check_sandbox, save_dir=results_dir / "packages",
                                       model=f"{model}-r{rep}", summary=run.summary)
            run.passed, run.checks, run.detail = verdict["passed"], verdict["checks"], verdict.get("detail", "")[:500]
    except Exception as e:  # noqa: BLE001
        run.error = f"{type(e).__name__}: {str(e)[:300]}"
    run.wall_s = round(time.monotonic() - t0, 1)
    print(f"  {model:40} {task.name:18} {'PASS' if run.passed else 'fail'} turns={run.turns} "
          f"calls={run.tool_calls} invalid={run.invalid_calls} {run.wall_s}s {run.error or ''}", flush=True)
    return run


# --- reporting ----------------------------------------------------------------

def tick(b: bool) -> str:
    return "yes" if b else "no"


def write_report(out: Path, smokes: list[dict], runs: list[Run], task_names: list[str]) -> str:
    lines = [f"# Model eval — {out.name}", ""]
    if smokes:
        lines += ["## Capability smoke test", "",
                  "| Model | Chat | Tool call | JSON mode | Vision (red?) | Tool-call latency (s) |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for s in smokes:
            lines.append(f"| `{s['model']}` | {tick(s['chat']['ok'])} | {tick(s['tool_call']['ok'])} | "
                         f"{tick(s['json_mode']['ok'])} | {tick(s['vision']['ok'])} ({s['vision']['answer'] or s['vision']['err'] or '-'}) | "
                         f"{s['tool_call']['s']} |")
        lines.append("")
    if runs:
        lines += ["## Agent tasks", "", "| Model | " + " | ".join(task_names) + " | Passed | Invalid calls | Median LLM s | Tokens (in/out) |",
                  "| --- | " + " | ".join("---" for _ in task_names) + " | --- | --- | --- | --- |"]
        for model in sorted({r.model for r in runs}):
            rs = [r for r in runs if r.model == model]
            cells = []
            for t in task_names:
                tr = [r for r in rs if r.task == t]
                if not tr:
                    cells.append("-")
                    continue
                errs = sum(1 for r in tr if r.error)
                turns = statistics.median(r.turns for r in tr)
                cells.append(f"{sum(r.passed for r in tr)}/{len(tr)} ({turns:g}t)" + (f" {errs}err" if errs else ""))
            lat = [x for r in rs for x in r.llm_latencies]
            lines.append(
                f"| `{model}` | " + " | ".join(cells) +
                f" | {sum(r.passed for r in rs)}/{len(rs)} | {sum(r.invalid_calls for r in rs)}/{sum(r.tool_calls for r in rs)} | "
                f"{round(statistics.median(lat), 2) if lat else '-'} | {sum(r.prompt_tokens for r in rs)}/{sum(r.completion_tokens for r in rs)} |")
        demo = [r for r in runs if r.task == "demo-package"]
        if demo:
            keys = sorted({k for r in demo for k in r.checks})
            lines += ["", "## Demo package checks", "", "| Model | " + " | ".join(keys) + " |",
                      "| --- | " + " | ".join("---" for _ in keys) + " |"]
            for r in sorted(demo, key=lambda r: (r.model, r.rep)):
                lines.append(f"| `{r.model}` | " + " | ".join(tick(r.checks.get(k, False)) for k in keys) + " |")
    md = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(md)
    return md


# --- main ---------------------------------------------------------------------

def default_models() -> list[str]:
    data = json.loads((HERE / "models.json").read_text())["data"]
    return [m["id"] for m in data if any(o["type"] == "text" for o in m.get("output_modalities", []))]


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", help="comma-separated; default: every text model in models.json")
    ap.add_argument("--tasks", help=f"comma-separated; default: {','.join(TASKS)}")
    ap.add_argument("--skip-smoke", action="store_true")
    ap.add_argument("--skip-agent", action="store_true")
    ap.add_argument("--runs", type=int, default=1, help="repeats per model x task")
    ap.add_argument("--llm-concurrency", type=int, default=6)
    args = ap.parse_args()

    models = args.models.split(",") if args.models else default_models()
    task_names = args.tasks.split(",") if args.tasks else list(TASKS)
    client = AsyncOpenAI(base_url=BASE_URL, api_key=os.environ["VULTR_INFERENCE_API_KEY"], max_retries=2)
    out = HERE / "results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    gate = asyncio.Semaphore(args.llm_concurrency)

    async def gated(coro):
        async with gate:
            return await coro

    smokes: list[dict] = []
    if not args.skip_smoke:
        print(f"smoke: {len(models)} models", flush=True)
        smokes = await asyncio.gather(*(gated(smoke(client, m)) for m in models))
        (out / "smoke.json").write_text(json.dumps(smokes, indent=2))

    runs: list[Run] = []
    if not args.skip_agent:
        agent_models = [m for m in models if m not in GUARD_MODELS]
        print(f"agent: {len(agent_models)} models x {len(task_names)} tasks x {args.runs} runs", flush=True)
        runs = await asyncio.gather(*(
            gated(agent_run(client, m, TASKS[t], out, rep))
            for rep in range(args.runs) for m in agent_models for t in task_names))
        (out / "runs.json").write_text(json.dumps([asdict(r) for r in runs], indent=2))

    print(write_report(out, smokes, runs, task_names))
    print(f"results: {out}")


if __name__ == "__main__":
    asyncio.run(main())
