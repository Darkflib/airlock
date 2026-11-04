# Product regression — product-20261104T025132Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Node stealer (tarball) | malicious | 3/3 | 4 | 0 | 4 | 3/3 | 11.4 |
| Shell stealer (tarball) | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 12.9 |
| Benign with postinstall (tarball) | benign | 3/3 | 6 | 0 | 0 | 0/3 | 16.9 |
| Real npm package | benign | 3/3 | 4 | 0 | 0 | 0/3 | 12.1 |
| Python stealer sdist (setup.py) | malicious | 3/3 | 4 | 0 | 13 | 3/3 | 16.4 |
| Benign sdist with setup.py work | benign | 3/3 | 4 | 0 | 0 | 0/3 | 16.7 |
| Real PyPI package | benign | 3/3 | 8 | 0 | 0 | 0/3 | 33.3 |
| Demo PR #1: left-pad bump | benign | 3/3 | 4 | 0 | 0 | 0/3 | 15.7 |
| Demo PR #3: vendored stealer | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 16.0 |
| Demo PR #4: hidden config-stealer | malicious | 3/3 | 5 | 0 | 5 | 3/3 | 16.6 |

**30/30 correct.** Invalid tool calls: 0.
