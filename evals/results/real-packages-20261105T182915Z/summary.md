# Product regression — real-packages-20261105T182915Z

| Target | Expected | Correct | Verdicts | Median turns | Forced | Containment (install or exercise) | Proven exfil | Exercised | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lodash: utility library, no scripts | benign | 2/2 | benign, benign | 10.0 | 1 | 0.0 | 0/2 | 1/2 | – | 68.4 |
| express: web framework, ~30 dependencies | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 143.75 |
| axios: HTTP client | benign | 2/2 | benign, benign | 9.5 | 1 | 0.0 | 0/2 | 2/2 | – | 77.55 |
| chalk: ESM only | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 70.45 |
| react | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 2/2 | – | 84.80000000000001 |
| typescript: one large package | benign | 2/2 | benign, benign | 9.0 | 1 | 0.0 | 0/2 | 2/2 | – | 85.95 |
| webpack: ~80 dependencies | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 2/2 | – | 152.95 |
| nodemon: file watcher, spawns processes | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 82.45 |
| core-js: postinstall prints a banner | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 253.8 |
| husky: git hooks tool | benign | 2/2 | benign, benign | 5.5 | 0 | 0.0 | 0/2 | 2/2 | – | 43.3 |
| esbuild: postinstall checks its platform binary | benign | 1/2 | inconclusive, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 86.55 |
| sharp: install script, prebuilt native binary | benign | 2/2 | benign, benign | 10.5 | 1 | 0.0 | 0/2 | 2/2 | – | 114.05 |
| bcrypt: install downloads a binary from GitHub, else builds | benign | 0/2 | inconclusive, inconclusive | 11.0 | 1 | 4.0 | 0/2 | 2/2 | – | 100.65 |
| prisma: postinstall downloads engines from its CDN | benign | 1/2 | inconclusive, benign | 12.0 | 2 | 1.0 | 0/2 | 0/2 | – | 110.5 |
| puppeteer: postinstall downloads Chrome | benign | 0/2 | inconclusive, inconclusive | 7.0 | 0 | 4.0 | 0/2 | 2/2 | – | 150.10000000000002 |
| requests | benign | 2/2 | benign, benign | 9.5 | 1 | 0.0 | 0/2 | 0/2 | – | 77.0 |
| urllib3 | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 0/2 | – | 80.4 |
| click | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 0/2 | – | 72.05 |
| flask | benign | 2/2 | benign, benign | 8.0 | 0 | 0.0 | 0/2 | 0/2 | – | 64.2 |
| attrs | benign | 2/2 | benign, benign | 8.5 | 0 | 0.0 | 0/2 | 0/2 | – | 93.0 |
| PyYAML: optional C extension | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 0/2 | – | 105.85 |
| python-dateutil: setuptools_scm build | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 0/2 | – | 77.80000000000001 |
| tqdm | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 0/2 | – | 116.55 |
| psutil: C extension build | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 0/2 | – | 82.25 |

**42/48 correct.** Invalid tool calls: 2. Inconclusive: 6. Errors: 0.

Concurrency 12: 48 runs in 473 s wall, 365 runs/hour. Host peak 1-min load 14.6, lowest MemAvailable 10391 MB.
