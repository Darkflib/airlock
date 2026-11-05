# Product regression — product-20261105T131147Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Demo PR #1: left-pad bump | benign | 6/6 | 4.0 | 0 | 0.0 | 0/6 | 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) · 0 (0) | 30.45 |
| Demo PR #3: vendored stealer | malicious | 6/6 | 4.0 | 0 | 6.0 | 6/6 | 12 (5) · 13 (6) · 12 (6) · 12 (6) · 13 (6) · 13 (6) | 29.85 |
| Demo PR #4: hidden config-stealer | malicious | 6/6 | 5.0 | 0 | 5.0 | 6/6 | 10 (5) · 10 (5) · 10 (5) · 10 (5) · 10 (5) · 10 (5) | 31.1 |

**18/18 correct.** Invalid tool calls: 0. Inconclusive: 0. Errors: 0.

Concurrency 6: 18 runs in 96 s wall, 676 runs/hour. Host peak 1-min load 8.3, lowest MemAvailable 12323 MB.
