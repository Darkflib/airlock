"""Summarise a run of Datadog's malicious-package sample (evals/datadog_prep.py, product_regression.py).

  python3 evals/datadog_report.py evals/results/datadog-sample-<ts> [unsupported.tsv]

Every package in the sample is known malicious, so the question per package is what Airlock did:
called it malicious, caught it sending something to an attacker's server (captured at the sinkhole,
never delivered), proved credential theft with this run's fake token, or missed it.
"""

import collections
import json
import statistics
import sys
from pathlib import Path


def eco(r: dict) -> str:
    return "npm" if "/npm/" in r["target"] else "pypi"


def captured(r: dict) -> bool:
    return any("sinkhole" in s for s in r.get("found", []))


def main(out: Path, unsupported: Path | None) -> None:
    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines() if line.strip()]
    unsup = [line.split("\t") for line in unsupported.read_text().splitlines()] if unsupported else []
    lines = [f"# Datadog malicious-package sample — {out.name}", "",
             "Packages from [Datadog's malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) "
             "(commit 72c723be, 5 Nov 2026), `malicious_intent` only, one version per package, drawn with seed 20261108 "
             "(`~/datadog-sample.txt` on the host; `evals/datadog_prep.py`). Each ran once through the real pipeline: "
             "microVM, watcher, sinkhole, agent. Every package is known malicious, so anything but *malicious* is a miss.", "",
             "| | npm | PyPI | All |", "| --- | --- | --- | --- |"]

    def row(label: str, pred) -> None:
        n = {e: sum(1 for r in rows if eco(r) == e and pred(r)) for e in ("npm", "pypi")}
        tot = {e: sum(1 for r in rows if eco(r) == e) for e in ("npm", "pypi")}
        cell = lambda a, b: f"{a}/{b} ({100 * a / b:.0f}%)" if b else "–"  # noqa: E731
        lines.append(f"| {label} | {cell(n['npm'], tot['npm'])} | {cell(n['pypi'], tot['pypi'])} | "
                     f"{cell(n['npm'] + n['pypi'], tot['npm'] + tot['pypi'])} |")

    row("**Called malicious**", lambda r: r["verdict"] == "malicious")
    row("Called malicious or suspicious", lambda r: r["verdict"] in ("malicious", "suspicious"))
    row("Sent something to an attacker's server, captured at the sinkhole", captured)
    row("Proven credential theft (this run's fake token captured)", lambda r: r.get("proven"))
    row("Any containment event (blocked, captured, credential read)", lambda r: r.get("contained", 0) > 0)
    row("Inconclusive (install failed or blind spot)", lambda r: r["verdict"] == "inconclusive")
    row("Called benign (a miss)", lambda r: r["verdict"] == "benign")
    row("Error", lambda r: r["verdict"] == "error")

    good = [r for r in rows if not r.get("error")]
    gaps = collections.Counter(g.split(",")[0][:70] for r in rows if r["verdict"] == "inconclusive" for g in r.get("gaps", []))
    lines += ["", f"{len(rows)} packages ran. Median {statistics.median(r['seconds'] for r in rows):.0f} s per package, "
              f"median {statistics.median(r['tokens'] for r in good):,.0f} tokens per review. "
              f"Exercised by the agent: {sum(r.get('exercised', 0) > 0 for r in good)}.",
              ""]
    if unsup:
        why = collections.Counter(u[1] for u in unsup)
        lines.append(f"Not run, because Airlock doesn't take them: {len(unsup)} PyPI samples "
                     f"({', '.join(f'{n} {w}' for w, n in why.most_common())}).")
        lines.append("")
    if gaps:
        lines += ["Why runs were inconclusive: " + "; ".join(f"{n} × {g}" for g, n in gaps.most_common(5)) + ".", ""]
    lines += ["**Reading the numbers.** Most of this dataset is dependency-confusion and recon packages that send the "
              "machine's hostname, user and IP to a webhook, not ones that steal credential files, so *proven credential "
              "theft* is rare by design; the captured request is the evidence for those. Datadog notes the set leans "
              "towards what its GuardDog rules detect. A *benign* call is a miss and is listed in `runs.json`."]
    misses = [r for r in rows if r["verdict"] == "benign"]
    if misses:
        lines += ["", "Missed (called benign):", ""] + [f"- `{Path(r['target']).name}`: {(r.get('evidence') or [''])[0][:160]}"
                                                       for r in misses]
    (out / "datadog-summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:20]))


if __name__ == "__main__":
    main(Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser() if len(sys.argv) > 2 else None)
