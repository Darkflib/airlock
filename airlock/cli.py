"""airlock analyse <file.tgz | npm-spec | sdist.tar.gz | pypi:name==version | PR URL> — stream events, print the verdict."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict

from .events import Event, EventLog
from .pipeline import analyse

MARK = {True: "!!", False: "  "}


def _print(ev: Event) -> None:
    print(f"{MARK[ev.containment]} [E{ev.id:>2}] {ev.kind:16} {ev.summary}", flush=True)


async def _main(args: argparse.Namespace) -> int:
    events = EventLog()
    q = events.subscribe()

    async def pump() -> None:
        while True:
            _print(await q.get())

    printer = asyncio.create_task(pump())
    try:
        report = await analyse(args.target, events=events, model=args.model, max_turns=args.max_turns)
    finally:
        await asyncio.sleep(0)
        printer.cancel()

    print(f"\nverdict: {report.verdict.upper()}  ({report.model}, {report.agent.turns} turns, "
          f"{len(report.containment)} containment events, {report.seconds}s)")
    for point in report.evidence:
        print(f"  - {point}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({**{k: v for k, v in asdict(report).items() if k != "agent"},
                       "agent": asdict(report.agent)}, f, indent=2)
        print(f"report: {args.json}")
    return {"benign": 0, "suspicious": 2, "malicious": 3}.get(report.verdict, 1)


def main() -> None:
    ap = argparse.ArgumentParser(prog="airlock")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyse", help="detonate and triage an npm or Python package, or a GitHub PR")
    a.add_argument("target", help="a .tgz, an npm spec like left-pad@1.3.0, a Python sdist (.tar.gz/.zip), pypi:six==1.17.0, or a PR URL")
    a.add_argument("--model", help="override roles.toml agent model")
    a.add_argument("--max-turns", type=int, default=12)
    a.add_argument("--json", help="write the full report here")
    args = ap.parse_args()
    sys.exit(asyncio.run(_main(args)))


if __name__ == "__main__":
    main()
