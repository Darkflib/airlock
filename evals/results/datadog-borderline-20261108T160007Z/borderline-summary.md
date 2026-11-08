# Borderline packages, 5 runs each — datadog-borderline-20261108T160007Z

The 63 packages whose verdict changed between the two full runs, each run 5 times in all (the two full runs plus three reruns on the run-2 code). All are known malicious.

## What the sandbox saw vs what the AI concluded

| | Packages where it changed between runs |
| --- | --- |
| Any containment event (blocked, captured, credential read) | 1/63 |
| A request captured at the sinkhole | 2/63 |
| Proven credential theft | 0/63 |
| **The AI's verdict** | **63/63** (by selection) |

## How the verdicts spread

| Verdicts seen for a package | Packages |
| --- | --- |
| benign and suspicious | 38 |
| malicious and suspicious | 17 |
| inconclusive and suspicious | 4 |
| benign and malicious and suspicious | 1 |
| inconclusive and malicious and suspicious | 1 |
| benign and inconclusive | 1 |
| inconclusive and malicious | 1 |

| Agreement: the most common verdict in N of the runs | Packages |
| --- | --- |
| 4 of 5 | 21 |
| 3 of 5 | 42 |

Majority of runs *malicious*: 15/63. Majority *malicious or suspicious*: 50/63. *Malicious* at least once: 20/63. Never flagged at all: 1/63. Errors: 0.

## In plain terms

- **The sandbox was steady.** What Airlock saw a package do (blocked connections, captured requests, proof) changed between runs for at most 2 of 63 packages — a package that does nothing at install does nothing every time. The wobble is in the AI's reading of what it saw.
- **Most of the wobble is between two neighbouring calls.** The usual pair is *suspicious* and *benign*, on packages that ran nothing at install: the reviewer is unsure whether a package that does nothing visible but is hiding in a malicious-looking name is suspicious or clean. Neither call approves anything: a person still decides, and Airlock never calls a quiet run safe.
- **Running a borderline package more than once helps.** Taking the majority of 5 runs, 50 of 63 would be flagged malicious or suspicious. A cheap product fix is to re-run automatically when the verdict is *suspicious* and nothing was contained, and report the split.
