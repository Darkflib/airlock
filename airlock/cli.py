"""airlock analyse <file.tgz | npm-spec | sdist.tar.gz | pypi:name==version | PR URL> — stream events, print the verdict.
airlock verify <bundle.json> --key <base64 public key> | --server <url> — check a run's signed receipts."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
import time
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
    if args.sarif:
        from .sarif import to_sarif
        with open(args.sarif, "w") as f:
            json.dump(to_sarif(run_id=f"cli-{int(time.time())}", target=report.target, verdict=report.verdict,
                               evidence=report.evidence, events=report.events), f, indent=2)
        print(f"sarif: {args.sarif}")
    return {"benign": 0, "suspicious": 2, "malicious": 3}.get(report.verdict, 1)


def _verify(args: argparse.Namespace) -> int:
    from . import receipts
    with open(args.bundle) as f:
        bundle = json.load(f)
    if args.key:
        public = base64.b64decode(args.key)
    else:  # fetching the key means trusting that server (and TLS) for it; --key pins it instead
        import httpx
        public = base64.b64decode(httpx.get(f"{args.server.rstrip('/')}/api/signing-key", timeout=10).json()["public_key"])
    print(f"trusted key {receipts.key_id(public)}")
    results = receipts.verify(bundle, {receipts.key_id(public): public})
    for r in results:
        print(f"{'OK ' if r['ok'] else 'BAD'} {r['type'] or 'receipt':9} sha256:{r['sha256']}")
        for p in r["problems"]:
            print(f"    {p}")
    ok = bool(results) and all(r["ok"] for r in results)
    print("valid" if ok else "INVALID" if results else "no receipts in this bundle")
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(prog="airlock")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyse", help="detonate and triage an npm or Python package, or a GitHub PR")
    a.add_argument("target", help="a .tgz, an npm spec like left-pad@1.3.0, a Python sdist (.tar.gz/.zip), pypi:six==1.17.0, or a PR URL")
    a.add_argument("--model", help="override roles.toml agent model")
    a.add_argument("--max-turns", type=int, default=12)
    a.add_argument("--json", help="write the full report here")
    a.add_argument("--sarif", help="write the findings here as SARIF 2.1.0, for GitHub code scanning")
    v = sub.add_parser("verify", help="check a run's signed receipts offline")
    v.add_argument("bundle", help="a .receipts.json file from a run page")
    who = v.add_mutually_exclusive_group(required=True)
    who.add_argument("--key", help="the server's Ed25519 public key, base64 (docs/SIGNING_KEY.md)")
    who.add_argument("--server", help="fetch the key from this Airlock server, e.g. https://airlock.darkflib.dev")
    args = ap.parse_args()
    sys.exit(_verify(args) if args.cmd == "verify" else asyncio.run(_main(args)))


if __name__ == "__main__":
    main()
