# Product regression — real-packages-20261105T164727Z

| Target | Expected | Correct | Verdicts | Median turns | Forced | Containment (install or exercise) | Proven exfil | Exercised | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lodash: utility library, no scripts | benign | 2/2 | benign, benign | 8.5 | 0 | 0.0 | 0/2 | 2/2 | – | 31.8 |
| express: web framework, ~30 dependencies | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 2/2 | – | 50.3 |
| axios: HTTP client | benign | 2/2 | benign, benign | 12.0 | 2 | 2.0 | 0/2 | 2/2 | – | 65.7 |
| chalk: ESM only | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 2/2 | – | 34.05 |
| react | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 2/2 | – | 40.099999999999994 |
| typescript: one large package | benign | 2/2 | benign, benign | 10.5 | 1 | 0.0 | 0/2 | 2/2 | – | 49.0 |
| webpack: ~80 dependencies | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 75.35 |
| nodemon: file watcher, spawns processes | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 1/2 | – | 53.900000000000006 |
| core-js: postinstall prints a banner | benign | 2/2 | benign, benign | 11.0 | 1 | 0.0 | 0/2 | 2/2 | – | 52.9 |
| husky: git hooks tool | benign | 2/2 | benign, benign | 7.0 | 0 | 0.0 | 0/2 | 2/2 | – | 27.4 |
| esbuild: postinstall checks its platform binary | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 2/2 | – | 44.3 |
| sharp: install script, prebuilt native binary | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 2/2 | – | 51.9 |
| bcrypt: install downloads a binary from GitHub, else builds | benign | 0/2 | inconclusive, inconclusive | 7.5 | 0 | 4.0 | 0/2 | 2/2 | – | 38.150000000000006 |
| prisma: postinstall downloads engines from its CDN | benign | 2/2 | benign, benign | 12.0 | 2 | 2.5 | 0/2 | 1/2 | – | 60.4 |
| puppeteer: postinstall downloads Chrome | benign | 0/2 | inconclusive, inconclusive | 11.0 | 1 | 4.0 | 0/2 | 1/2 | – | 56.35 |
| requests | benign | 2/2 | benign, benign | 11.0 | 0 | 0.0 | 0/2 | 0/2 | – | 46.349999999999994 |
| urllib3 | benign | 2/2 | benign, benign | 11.0 | 0 | 0.0 | 0/2 | 0/2 | – | 62.1 |
| click | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 0/2 | – | 38.05 |
| flask | benign | 2/2 | benign, benign | 8.0 | 0 | 0.0 | 0/2 | 0/2 | – | 33.1 |
| attrs | benign | 2/2 | benign, benign | 8.5 | 0 | 0.0 | 0/2 | 0/2 | – | 34.7 |
| PyYAML: optional C extension | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 0/2 | – | 60.2 |
| python-dateutil: setuptools_scm build | benign | 2/2 | benign, benign | 10.5 | 0 | 0.0 | 0/2 | 0/2 | – | 48.55 |
| tqdm | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 0/2 | – | 60.400000000000006 |
| psutil: C extension build | benign | 0/2 | inconclusive, inconclusive | 11.0 | 1 | 0.0 | 0/2 | 0/2 | – | 46.7 |

**42/48 correct.** Invalid tool calls: 1. Inconclusive: 6. Errors: 0.

Concurrency 4: 48 runs in 591 s wall, 292 runs/hour. Host peak 1-min load 2.4, lowest MemAvailable 13185 MB.
