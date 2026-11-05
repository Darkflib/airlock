# Product regression — product-20261105T131318Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Demo PR #1: left-pad bump | benign | 6/6 | 4.5 | 0 | 0.0 | 0/6 | 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) | 36.9 |
| Demo PR #3: vendored stealer | malicious | 6/6 | 4.0 | 0 | 6.0 | 6/6 | 13 (6) · 14 (7) · 14 (7) · 13 (6) · 13 (6) · 13 (6) | 36.55 |
| Demo PR #4: hidden config-stealer | malicious | 6/6 | 5.0 | 0 | 5.0 | 6/6 | 10 (5) · 10 (5) · 10 (5) · 10 (5) · 10 (5) · 10 (5) | 37.45 |

**18/18 correct.** Invalid tool calls: 0. Inconclusive: 0. Errors: 0.

Concurrency 8: 18 runs in 91 s wall, 714 runs/hour. Host peak 1-min load 13.1, lowest MemAvailable 11381 MB.
