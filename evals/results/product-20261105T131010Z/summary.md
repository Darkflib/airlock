# Product regression — product-20261105T131010Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Demo PR #1: left-pad bump | benign | 6/6 | 4.0 | 0 | 0.0 | 0/6 | 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) | 22.85 |
| Demo PR #3: vendored stealer | malicious | 6/6 | 4.0 | 0 | 6.0 | 6/6 | 13 (6) · 12 (5) · 13 (7) · 12 (5) · 13 (6) · 13 (6) | 21.85 |
| Demo PR #4: hidden config-stealer | malicious | 5/6 | 5 | 0 | 5 | 5/5 | 10 (5) · 10 (5) · 10 (5) · 10 (5) · 10 (5) | 23.2 |

**17/18 correct.** Invalid tool calls: 0. Inconclusive: 0. Errors: 1.

Concurrency 4: 18 runs in 104 s wall, 623 runs/hour. Host peak 1-min load 3.4, lowest MemAvailable 13241 MB.
