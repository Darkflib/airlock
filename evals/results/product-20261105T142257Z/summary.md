# Product regression — product-20261105T142257Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Node stealer (tarball) | malicious | 3/3 | 5 | 0 | 4 | 3/3 | – | 19.0 |
| Shell stealer (tarball) | malicious | 3/3 | 4 | 0 | 6 | 3/3 | – | 16.7 |
| Benign with postinstall (tarball) | benign | 3/3 | 5 | 0 | 0 | 0/3 | – | 16.9 |
| Runtime-only stealer (needs the agent's exercise) | malicious | 3/3 | 5 | 0 | 4 | 3/3 | – | 29.3 |
| Real npm package | benign | 3/3 | 5 | 0 | 0 | 0/3 | – | 19.3 |
| Python stealer sdist (setup.py) | malicious | 3/3 | 4 | 0 | 13 | 3/3 | – | 17.1 |
| Benign sdist with setup.py work | benign | 3/3 | 4 | 0 | 0 | 0/3 | – | 17.4 |
| Real PyPI package | benign | 3/3 | 6 | 0 | 0 | 0/3 | – | 34.5 |
| Demo PR #1: left-pad bump | benign | 3/3 | 5 | 0 | 0 | 0/3 | 0 (0) · 0 (0) · 0 (0) | 24.8 |
| Demo PR #3: vendored stealer | malicious | 3/3 | 5 | 0 | 6 | 3/3 | 13 (6) · 13 (6) · 13 (6) | 23.2 |
| Demo PR #4: hidden config-stealer | malicious | 3/3 | 6 | 0 | 5 | 3/3 | 11 (6) · 10 (5) · 10 (5) | 29.3 |

**33/33 correct.** Invalid tool calls: 0. Inconclusive: 0. Errors: 0.

Concurrency 4: 33 runs in 190 s wall, 626 runs/hour. Host peak 1-min load 2.8, lowest MemAvailable 13539 MB.
