# Product regression — product-20261104T030613Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Node stealer (tarball) | malicious | 3/3 | 4 | 0 | 4 | 3/3 | – | 12.5 |
| Shell stealer (tarball) | malicious | 3/3 | 4 | 0 | 6 | 3/3 | – | 13.2 |
| Benign with postinstall (tarball) | benign | 3/3 | 4 | 0 | 0 | 0/3 | – | 13.0 |
| Real npm package | benign | 3/3 | 4 | 0 | 0 | 0/3 | – | 12.3 |
| Python stealer sdist (setup.py) | malicious | 3/3 | 4 | 0 | 13 | 3/3 | – | 17.2 |
| Benign sdist with setup.py work | benign | 3/3 | 4 | 0 | 0 | 0/3 | – | 16.0 |
| Real PyPI package | benign | 3/3 | 7 | 0 | 0 | 0/3 | – | 30.7 |
| Demo PR #1: left-pad bump | benign | 3/3 | 6 | 0 | 0 | 0/3 | 0 (0) · 0 (0) · 0 (0) | 23.8 |
| Demo PR #3: vendored stealer | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 13 (6) · 13 (6) · 13 (6) | 16.2 |
| Demo PR #4: hidden config-stealer | malicious | 3/3 | 5 | 0 | 5 | 3/3 | 10 (5) · 10 (5) · 10 (5) | 18.2 |

**30/30 correct.** Invalid tool calls: 0.
