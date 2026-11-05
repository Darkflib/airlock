# Product regression — product-20261105T130555Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Demo PR #1: left-pad bump | benign | 3/3 | 4 | 0 | 0 | 0/3 | 0 (0) · 0 (0) · 0 (0) | 18.5 |
| Demo PR #3: vendored stealer | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 13 (6) · 13 (6) · 13 (6) | 19.3 |
| Demo PR #4: hidden config-stealer | malicious | 3/3 | 5 | 0 | 5 | 3/3 | 10 (5) · 10 (5) · 10 (5) | 21.8 |

**9/9 correct.** Invalid tool calls: 0. Inconclusive: 0. Errors: 0.

Concurrency 2: 9 runs in 101 s wall, 321 runs/hour. Host peak 1-min load 0.9, lowest MemAvailable 14226 MB.
