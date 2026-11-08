"""Compare two runs of the same Datadog sample, package by package, and say how sure we can be.

  python3 evals/datadog_compare.py <run1 dir> <run2 dir> [out.md]

The same packages ran twice, so every comparison is paired: we count packages where the two runs
disagree. Stdlib only; the exact tests are small enough to compute directly.
"""

import json
import math
import sys
from pathlib import Path


def load(d: Path) -> dict[str, dict]:
    return {r["target"]: r for r in (json.loads(x) for x in (d / "rows.jsonl").read_text().splitlines() if x.strip())}


def mcnemar_p(b: int, c: int) -> float:
    """Exact two-sided McNemar test: of the b + c packages where the runs disagree, how likely is a split
    at least this lopsided if each disagreement were a coin toss (that is, if the change did nothing)?"""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% interval for a rate k/n (Wilson), as percentages."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (100 * (centre - half), 100 * (centre + half))


def fmt_p(p: float) -> str:
    return "below 0.0001" if p < 0.0001 else f"{p:.4f}" if p < 0.01 else f"{p:.2f}"


def main(d1: Path, d2: Path, out: Path | None) -> None:
    a, b = load(d1), load(d2)
    common = sorted(set(a) & set(b))
    n = len(common)
    tests = [
        ("Proven credential theft", lambda r: bool(r.get("proven"))),
        ("Called malicious", lambda r: r["verdict"] == "malicious"),
        ("Called malicious or suspicious", lambda r: r["verdict"] in ("malicious", "suspicious")),
        ("Called benign (a miss)", lambda r: r["verdict"] == "benign"),
    ]
    lines = [f"# Run 1 vs run 2 — {d1.name} vs {d2.name}", "",
             f"The same {n} packages, run twice. Run 1 had fake credentials in files only; run 2 added fake tokens "
             "in the install environment and a fake SSH key. Everything else was the same code.", "",
             "| | Run 1 | Run 2 | Only in run 1 | Only in run 2 | Run-to-run spread (1 SD) | p-value |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    notes = {}
    for label, f in tests:
        x = sum(f(a[t]) for t in common)
        y = sum(f(b[t]) for t in common)
        only1 = sum(f(a[t]) and not f(b[t]) for t in common)
        only2 = sum(f(b[t]) and not f(a[t]) for t in common)
        sd = 100 * math.sqrt(only1 + only2) / n        # spread of the difference, in percentage points
        p = mcnemar_p(only1, only2)
        lo1, hi1 = wilson(x, n)
        lo2, hi2 = wilson(y, n)
        notes[label] = (x, y, only1, only2, sd, p)
        lines.append(f"| {label} | {x} ({100 * x / n:.1f}%, {lo1:.0f}–{hi1:.0f}%) | {y} ({100 * y / n:.1f}%, {lo2:.0f}–{hi2:.0f}%) "
                     f"| {only1} | {only2} | ±{sd:.1f} points | {fmt_p(p)} |")
    changed = sum(a[t]["verdict"] != b[t]["verdict"] for t in common)
    px, py, p1, p2, _, pp = notes["Proven credential theft"]
    mx, my, m1, m2, msd, mp = notes["Called malicious"]
    lines += ["", "**In plain terms.**", "",
              f"- **Proven theft went from {px} to {py}.** {p2} packages were proven only with the new fake tokens and "
              f"{p1} only without them. The p-value, {fmt_p(pp)}, is the chance of a split that lopsided if the new "
              "tokens made no difference at all. "
              + ("That chance is tiny, so the tokens really do catch more." if pp < 0.01 else
                 "That's not small enough to rule out chance."),
              f"- **The AI's verdict wobbles between runs.** {changed} of {n} packages ({100 * changed / n:.0f}%) got a "
              f"different verdict the second time. For *called malicious* that's a spread of about ±{msd:.1f} percentage "
              f"points from one run to the next (one standard deviation, SD). The move from {100 * mx / n:.1f}% to "
              f"{100 * my / n:.1f}% has a p-value of {fmt_p(mp)}: "
              + ("small enough that it's probably real, and it matches the extra proof, since proven theft is malicious "
                 "whatever the AI says." if mp < 0.05 else "within normal wobble, so don't read much into it.")
              + " Proof doesn't wobble the same way: fixed rules decide it from the captured request, not the model.",
              "- **The ranges in brackets** (for example 74–79%) are 95% intervals: if we drew another sample of this "
              "size from the same dataset, the rate would usually land inside them.",
              "- **How to read a p-value:** below 0.05 is the usual bar for \"probably a real effect\"; below 0.01 is "
              "strong. Above that, treat the difference as noise."]
    text = "\n".join(lines) + "\n"
    if out:
        out.write_text(text)
    print(text)


if __name__ == "__main__":
    main(Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser(),
         Path(sys.argv[3]).expanduser() if len(sys.argv) > 3 else None)
