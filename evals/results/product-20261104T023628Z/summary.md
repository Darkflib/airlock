# Product regression — product-20261104T023628Z

| Target | Expected | Correct | Median turns | Forced | Detonation containment | Proven exfil | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Node stealer (tarball) | malicious | 3/3 | 4 | 0 | 4 | 3/3 | 11.2 |
| Shell stealer (tarball) | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 12.6 |
| Benign with postinstall (tarball) | benign | 3/3 | 4 | 0 | 0 | 0/3 | 13.1 |
| Real npm package | benign | 3/3 | 5 | 0 | 0 | 0/3 | 16.0 |
| Python stealer sdist (setup.py) | malicious | 3/3 | 4 | 0 | 13 | 3/3 | 16.6 |
| Benign sdist with setup.py work | benign | 3/3 | 4 | 0 | 0 | 0/3 | 15.4 |
| Real PyPI package | benign | 3/3 | 6 | 1 | 0 | 0/3 | 27.3 |
| Demo PR #1: left-pad bump | benign | 3/3 | 5 | 0 | 0 | 0/3 | 17.4 |
| Demo PR #3: vendored stealer | malicious | 3/3 | 4 | 0 | 6 | 3/3 | 14.8 |

**27/27 correct.** Invalid tool calls: 0.
