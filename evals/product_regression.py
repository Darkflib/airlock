"""Product regression: run the real pipeline (Workspace + watcher + sinkhole + agent)
on known targets and check the verdicts. Unlike harness.py, this exercises exactly
what the web app runs. Needs the host env (inference key, GitHub App for PRs):

  set -a; . ~/.config/airlock/web.env; set +a
  .venv/bin/python evals/product_regression.py [--runs 3] [--concurrency 3]
"""

import argparse
import asyncio
import json
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
    ("left-pad@1.3.0", "benign", "Real npm package"),
    ("evals/fixtures/termcolour-utils-stealer.tar.gz", "malicious", "Python stealer sdist (setup.py)"),
    ("evals/fixtures/tinyslug-benign.tar.gz", "benign", "Benign sdist with setup.py work"),
    ("pypi:six==1.17.0", "benign", "Real PyPI package"),
    ("https://github.com/Darkflib/airlock-demo/pull/1", "benign", "Demo PR #1: left-pad bump"),
    ("https://github.com/Darkflib/airlock-demo/pull/3", "malicious", "Demo PR #3: vendored stealer"),
    ("https://github.com/Darkflib/airlock-demo/pull/4", "malicious", "Demo PR #4: hidden config-stealer"),
]


async def one(target: str, expected: str, rep: int, gate: asyncio.Semaphore) -> dict:
    async with gate:
        t0 = time.monotonic()
        try:
            r = await analyse(target, events=EventLog())
            det = [e for e in r.events if e["containment"] and e["data"].get("stage") == "detonate"]
            row = {"verdict": r.verdict, "turns": r.agent.turns, "forced": r.agent.forced,
                   "invalid": r.agent.invalid_calls, "contained": len(det),
                   "proven": any(e["data"].get("proven") for e in det), "error": None,
                   "tokens": r.agent.prompt_tokens + r.agent.completion_tokens}
        except Exception as e:  # noqa: BLE001
            row = {"verdict": "error", "error": f"{type(e).__name__}: {e}"[:200]}
        row.update(target=target, expected=expected, rep=rep, seconds=round(time.monotonic() - t0, 1),
                   ok=row["verdict"] == expected)
        print(f"  {'PASS' if row['ok'] else 'FAIL'} {target[-48:]:48} {row['verdict']:10} {row['seconds']}s "
              f"{row.get('error') or ''}", flush=True)
        return row


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--concurrency", type=int, default=3)
    args = ap.parse_args()
    gate = asyncio.Semaphore(args.concurrency)
    rows = await asyncio.gather(*(one(t, exp, rep, gate) for rep in range(args.runs) for t, exp, _ in TARGETS))

    out = HERE / "results" / ("product-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
    (out / "runs.json").write_text(json.dumps(rows, indent=2))
    lines = [f"# Product regression — {out.name}", "",
             "| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | Median s |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for target, expected, label in TARGETS:
        rs = [r for r in rows if r["target"] == target]
        ok = sum(r["ok"] for r in rs)
        good = [r for r in rs if not r.get("error")]
        med = lambda k: statistics.median(r[k] for r in good) if good else "-"  # noqa: E731
        lines.append(f"| {label} | {expected} | {ok}/{len(rs)} | {med('turns')} | {sum(r.get('forced', False) for r in good)} | "
                     f"{med('contained')} | {sum(r.get('proven', False) for r in good)}/{len(good)} | {med('seconds')} |")
    total = sum(r["ok"] for r in rows)
    lines += ["", f"**{total}/{len(rows)} correct.** Invalid tool calls: {sum(r.get('invalid', 0) for r in rows)}."]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"results: {out}")


if __name__ == "__main__":
    asyncio.run(main())
