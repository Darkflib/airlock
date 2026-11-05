# Product regression — real-packages-20261105T203134Z

| Target | Expected | Correct | Verdicts | Median turns | Forced | Containment (install or exercise) | Proven exfil | Exercised | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lodash: utility library, no scripts | benign | 2/2 | benign, benign | 10.5 | 0 | 0.0 | 0/2 | 2/2 | – | 65.25 |
| express: web framework, ~30 dependencies | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 2/2 | – | 84.75 |
| axios: HTTP client | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 64.75 |
| chalk: ESM only | benign | 2/2 | benign, benign | 7.5 | 0 | 0.0 | 0/2 | 2/2 | – | 38.849999999999994 |
| react | benign | 2/2 | benign, benign | 7.5 | 0 | 0.0 | 0/2 | 2/2 | – | 42.15 |
| typescript: one large package | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 2/2 | – | 57.400000000000006 |
| webpack: ~80 dependencies | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 108.94999999999999 |
| nodemon: file watcher, spawns processes | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 70.65 |
| core-js: postinstall prints a banner | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 72.4 |
| husky: git hooks tool | benign | 2/2 | benign, benign | 5.5 | 0 | 0.0 | 0/2 | 2/2 | – | 27.8 |
| esbuild: postinstall checks its platform binary | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 2/2 | – | 66.0 |
| sharp: install script, prebuilt native binary | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 2/2 | – | 59.550000000000004 |
| bcrypt: install downloads a binary from GitHub, else builds | benign | 0/2 | error, inconclusive | 9 | 0 | 4 | 0/1 | 1/1 | – | 49.8 |
| prisma: postinstall downloads engines from its CDN | benign | 2/2 | benign, benign | 12.0 | 2 | 2.0 | 0/2 | 0/2 | – | 61.35 |
| puppeteer: postinstall downloads Chrome | benign | 0/2 | inconclusive, inconclusive | 12.0 | 2 | 4.0 | 0/2 | 2/2 | – | 89.9 |
| requests | benign | 2/2 | benign, benign | 9.0 | 1 | 0.0 | 0/2 | 0/2 | – | 51.900000000000006 |
| urllib3 | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 0/2 | – | 71.1 |
| click | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 0/2 | – | 42.35 |
| flask | benign | 2/2 | benign, benign | 8.0 | 0 | 0.0 | 0/2 | 0/2 | – | 40.35 |
| attrs | benign | 2/2 | benign, benign | 10.5 | 0 | 0.0 | 0/2 | 0/2 | – | 48.85 |
| PyYAML: optional C extension | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 0/2 | – | 123.35 |
| python-dateutil: setuptools_scm build | benign | 2/2 | benign, benign | 11.0 | 1 | 0.0 | 0/2 | 0/2 | – | 55.2 |
| tqdm | benign | 2/2 | benign, benign | 10.5 | 1 | 0.0 | 0/2 | 0/2 | – | 55.7 |
| psutil: C extension build | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 0/2 | – | 60.6 |

**44/48 correct.** Invalid tool calls: 0. Inconclusive: 3. Errors: 1.

Concurrency 8: 48 runs in 543 s wall, 318 runs/hour. Host peak 1-min load 7.3, lowest MemAvailable 11498 MB.
