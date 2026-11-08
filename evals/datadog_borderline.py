"""How variable is Airlock on borderline packages? Five runs of each package whose verdict changed
between the two full Datadog runs: those two runs plus three reruns.

  python3 evals/datadog_borderline.py <run1 dir> <run2 dir> <reruns dir> [out.md]

It separates what the sandbox saw (containment events, a request captured at the sinkhole, proof),
which should be the same every time, from what the AI concluded, which may not be.
"""

import collections
import json
import sys
from pathlib import Path


def rows(d: Path) -> list[dict]:
    return [json.loads(x) for x in (d / "rows.jsonl").read_text().splitlines() if x.strip()]


def captured(r: dict) -> bool:
    return any("sinkhole" in s for s in r.get("found", []))


def main(d1: Path, d2: Path, d3: Path, out: Path | None) -> None:
    reruns = rows(d3)
    targets = sorted({r["target"] for r in reruns})
    runs: dict[str, list[dict]] = collections.defaultdict(list)
    for d in (d1, d2):
        for r in rows(d):
            if r["target"] in targets:
                runs[r["target"]].append(r)
    for r in reruns:
        runs[r["target"]].append(r)
    n = len(targets)
    k = min(len(v) for v in runs.values())

    def varies(f) -> int:
        return sum(len({f(r) for r in runs[t]}) > 1 for t in targets)

    verdicts = {t: collections.Counter(r["verdict"] for r in runs[t]) for t in targets}
    modal = {t: verdicts[t].most_common(1)[0] for t in targets}
    agree = collections.Counter(c for _, c in modal.values())
    majority_mal = sum(verdicts[t]["malicious"] * 2 > len(runs[t]) for t in targets)
    majority_flag = sum((verdicts[t]["malicious"] + verdicts[t]["suspicious"]) * 2 > len(runs[t]) for t in targets)
    ever_mal = sum(verdicts[t]["malicious"] > 0 for t in targets)
    never_flag = sum(verdicts[t]["malicious"] + verdicts[t]["suspicious"] == 0 for t in targets)
    pairs = collections.Counter(tuple(sorted(verdicts[t])) for t in targets)
    sandbox_any = varies(lambda r: r.get("contained", 0) > 0)
    sandbox_cap = varies(captured)
    sandbox_proof = varies(lambda r: bool(r.get("proven")))
    errors = sum(r["verdict"] == "error" for t in targets for r in runs[t])

    lines = [f"# Borderline packages, {k} runs each — {d3.name}", "",
             f"The {n} packages whose verdict changed between the two full runs, each run {k} times in all "
             "(the two full runs plus three reruns on the run-2 code). All are known malicious.", "",
             "## What the sandbox saw vs what the AI concluded", "",
             "| | Packages where it changed between runs |", "| --- | --- |",
             f"| Any containment event (blocked, captured, credential read) | {sandbox_any}/{n} |",
             f"| A request captured at the sinkhole | {sandbox_cap}/{n} |",
             f"| Proven credential theft | {sandbox_proof}/{n} |",
             f"| **The AI's verdict** | **{n}/{n}** (by selection) |", "",
             "## How the verdicts spread", "",
             "| Verdicts seen for a package | Packages |", "| --- | --- |"]
    lines += [f"| {' and '.join(p)} | {c} |" for p, c in pairs.most_common()]
    lines += ["", "| Agreement: the most common verdict in N of the runs | Packages |", "| --- | --- |"]
    lines += [f"| {c} of {k} | {agree[c]} |" for c in sorted(agree, reverse=True)]
    lines += ["", f"Majority of runs *malicious*: {majority_mal}/{n}. Majority *malicious or suspicious*: {majority_flag}/{n}. "
              f"*Malicious* at least once: {ever_mal}/{n}. Never flagged at all: {never_flag}/{n}. Errors: {errors}.", "",
              "## In plain terms", "",
              f"- **The sandbox was steady.** What Airlock saw a package do (blocked connections, captured requests, "
              f"proof) changed between runs for at most {max(sandbox_any, sandbox_cap, sandbox_proof)} of {n} packages"
              + (" — a package that does nothing at install does nothing every time." if max(sandbox_any, sandbox_cap) <= n // 10 else
                 ". Some packages behave differently from run to run (timing, randomness), which is worth knowing.")
              + " The wobble is in the AI's reading of what it saw.",
              f"- **Most of the wobble is between two neighbouring calls.** The usual pair is *suspicious* and *benign*, "
              "on packages that ran nothing at install: the reviewer is unsure whether a package that does nothing "
              "visible but is hiding in a malicious-looking name is suspicious or clean. Neither call approves anything: "
              "a person still decides, and Airlock never calls a quiet run safe.",
              f"- **Running a borderline package more than once helps.** Taking the majority of {k} runs, "
              f"{majority_flag} of {n} would be flagged malicious or suspicious. A cheap product fix is to re-run "
              "automatically when the verdict is *suspicious* and nothing was contained, and report the split."]
    text = "\n".join(lines) + "\n"
    if out:
        out.write_text(text)
    print(text)


if __name__ == "__main__":
    main(*(Path(a).expanduser() for a in sys.argv[1:4]), Path(sys.argv[4]).expanduser() if len(sys.argv) > 4 else None)
