"""Product regression: run the real pipeline (Workspace + watcher + sinkhole + agent)
on known targets and check the verdicts. Unlike harness.py, this exercises exactly
what the web app runs. Needs the host env (inference key, GitHub App for PRs):

  set -a; . ~/.config/airlock/web.env; set +a
  .venv/bin/python evals/product_regression.py [--runs 3] [--concurrency 3] [--prs]

As a load test, `--prs --concurrency N` runs only the demo PRs (two VMs each), N at once,
and the summary adds wall time, throughput and the host's peak load and lowest free memory.
"""

import argparse
import asyncio
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from airlock.events import EventLog
from airlock.pipeline import analyse

HERE = Path(__file__).parent
TARGETS = [
    ("evals/fixtures/left-padder-hostile.tgz", "malicious", "Node stealer (tarball)"),
    ("evals/fixtures/colorful-logs-shell-stealer.tgz", "malicious", "Shell stealer (tarball)"),
    ("evals/fixtures/left-padder-benign.tgz", "benign", "Benign with postinstall (tarball)"),
    ("evals/fixtures/tinyconf-runtime-stealer.tgz", "malicious", "Runtime-only stealer (needs the agent's exercise)"),
    ("left-pad@1.3.0", "benign", "Real npm package"),
    ("evals/fixtures/termcolour-utils-stealer.tar.gz", "malicious", "Python stealer sdist (setup.py)"),
    ("evals/fixtures/tinyslug-benign.tar.gz", "benign", "Benign sdist with setup.py work"),
    ("pypi:six==1.17.0", "benign", "Real PyPI package"),
    ("https://github.com/Darkflib/airlock-demo/pull/1", "benign", "Demo PR #1: left-pad bump"),
    ("https://github.com/Darkflib/airlock-demo/pull/3", "malicious", "Demo PR #3: vendored stealer"),
    ("https://github.com/Darkflib/airlock-demo/pull/4", "malicious", "Demo PR #4: hidden config-stealer"),
]


def diff_check(events: list[dict], expected: str) -> dict:
    """PR runs only: a stealer PR must show its exfiltration as new versus the base; a benign PR
    must show no new containment. Anything else is normalisation noise or a missed attack."""
    d = next((e["data"] for e in events if e["kind"] == "behaviour_diff"), None)
    if d is None:
        return {}
    if not d.get("available"):
        return {"diff_ok": False, "diff": f"unavailable: {d.get('reason')}"}
    risky = [e for e in d["new"] if e["containment"]]
    ok = any(e["key"].startswith("canary_exfil") for e in risky) if expected == "malicious" else not risky
    return {"diff_ok": ok, "diff": f"{len(d['new'])} new, {len(risky)} risky", "diff_new": len(d["new"]),
            "diff_risky": len(risky)}


async def one(target: str, expected: str, rep: int, gate: asyncio.Semaphore) -> dict:
    async with gate:
        t0 = time.monotonic()
        try:
            r = await analyse(target, events=EventLog())
            det = [e for e in r.events if e["containment"] and e["data"].get("stage") in ("detonate", "exercise")]
            row = {"verdict": r.verdict, "turns": r.agent.turns, "forced": r.agent.forced,
                   "invalid": r.agent.invalid_calls, "contained": len(det),
                   "proven": any(e["data"].get("proven") for e in det), "error": None,
                   "tokens": r.agent.prompt_tokens + r.agent.completion_tokens,
                   # enough to look into an unexpected result without the whole timeline
                   "exercised": sum(e["kind"] == "exercise" for e in r.events),
                   "agent_s": r.agent.seconds,  # agent loop time; with turns, shows inference slowing under load
                   "gaps": [g for e in r.events if e["kind"] == "coverage_incomplete" for g in e["data"].get("gaps", [])],
                   "found": [e["summary"][:160] for e in det][:8], "evidence": r.evidence}
            row.update(diff_check(r.events, expected))
        except Exception as e:  # noqa: BLE001
            row = {"verdict": "error", "error": f"{type(e).__name__}: {e}"[:200]}
        row.update(target=target, expected=expected, rep=rep, seconds=round(time.monotonic() - t0, 1),
                   ok=row["verdict"] == expected and row.get("diff_ok", True) is not False)
        print(f"  {'PASS' if row['ok'] else 'FAIL'} {target[-48:]:48} {row['verdict']:10} {row['seconds']}s "
              f"{row.get('diff') or ''} {row.get('error') or ''}", flush=True)
        return row


def diff_cell(rows: list[dict]) -> str:
    rs = [r for r in rows if "diff" in r]
    if not rs:
        return "–"
    return " · ".join(r["diff"] if not r.get("diff_ok") or "unavailable" in r["diff"] else
                      f"{r['diff_new']} ({r['diff_risky']})" for r in rs)


async def sample_host(peak: dict, stop: asyncio.Event) -> None:
    """Every second: the highest 1-minute load and the lowest MemAvailable (Linux only)."""
    while not stop.is_set():
        try:
            peak["load"] = max(peak.get("load", 0.0), os.getloadavg()[0])
            avail = next(int(line.split()[1]) for line in open("/proc/meminfo") if line.startswith("MemAvailable"))
            peak["min_avail_mb"] = min(peak.get("min_avail_mb", avail // 1024), avail // 1024)
        except (OSError, StopIteration):
            return
        try:
            await asyncio.wait_for(stop.wait(), 1)
        except TimeoutError:
            pass


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--prs", action="store_true", help="only the demo PRs (a load test: two VMs per run)")
    ap.add_argument("--targets", type=Path, help="TSV of target, expected verdict, label (e.g. evals/real_packages.tsv)")
    args = ap.parse_args()
    targets = [t for t in TARGETS if t[0].startswith("https://")] if args.prs else TARGETS
    if args.targets:
        targets = [tuple(line.split("\t")[:3]) for line in args.targets.read_text().splitlines()
                   if line.strip() and not line.startswith("#")]
    gate = asyncio.Semaphore(args.concurrency)
    peak: dict = {}
    stop = asyncio.Event()
    sampler = asyncio.create_task(sample_host(peak, stop))
    t0 = time.monotonic()
    rows = await asyncio.gather(*(one(t, exp, rep, gate) for rep in range(args.runs) for t, exp, _ in targets))
    wall = time.monotonic() - t0
    stop.set()
    await sampler

    kind = args.targets.stem.replace("_", "-") if args.targets else "product"
    out = HERE / "results" / (f"{kind}-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
    (out / "runs.json").write_text(json.dumps(rows, indent=2))
    lines = [f"# Product regression — {out.name}", "",
             "| Target | Expected | Correct | Verdicts | Median turns | Forced | Containment (install or exercise) | Proven exfil | Exercised | New vs base (risky) | Median s |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for target, expected, label in targets:
        rs = [r for r in rows if r["target"] == target]
        ok = sum(r["ok"] for r in rs)
        good = [r for r in rs if not r.get("error")]
        med = lambda k: statistics.median(r[k] for r in good) if good else "-"  # noqa: E731
        lines.append(f"| {label} | {expected} | {ok}/{len(rs)} | {', '.join(r['verdict'] for r in rs)} | {med('turns')} | "
                     f"{sum(r.get('forced', False) for r in good)} | "
                     f"{med('contained')} | {sum(r.get('proven', False) for r in good)}/{len(good)} | "
                     f"{sum(r.get('exercised', 0) > 0 for r in good)}/{len(good)} | {diff_cell(good)} | {med('seconds')} |")
    total = sum(r["ok"] for r in rows)
    lines += ["", f"**{total}/{len(rows)} correct.** Invalid tool calls: {sum(r.get('invalid', 0) for r in rows)}. "
              f"Inconclusive: {sum(r['verdict'] == 'inconclusive' for r in rows)}. Errors: {sum(bool(r.get('error')) for r in rows)}.",
              "", f"Concurrency {args.concurrency}: {len(rows)} runs in {wall:.0f} s wall, "
              f"{len(rows) / wall * 3600:.0f} runs/hour. Host peak 1-min load {peak.get('load', 0):.1f}, "
              f"lowest MemAvailable {peak.get('min_avail_mb', '?')} MB."]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"results: {out}")


if __name__ == "__main__":
    asyncio.run(main())
