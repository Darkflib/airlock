# Product regression — real-packages-20261105T182122Z

| Target | Expected | Correct | Verdicts | Median turns | Forced | Containment (install or exercise) | Proven exfil | Exercised | New vs base (risky) | Median s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| lodash: utility library, no scripts | benign | 2/2 | benign, benign | 11.0 | 1 | 0.0 | 0/2 | 2/2 | – | 58.7 |
| express: web framework, ~30 dependencies | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 2/2 | – | 81.55 |
| axios: HTTP client | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 62.8 |
| chalk: ESM only | benign | 2/2 | benign, benign | 8.5 | 0 | 0.0 | 0/2 | 2/2 | – | 45.2 |
| react | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 2/2 | – | 48.849999999999994 |
| typescript: one large package | benign | 2/2 | benign, benign | 9.0 | 0 | 0.0 | 0/2 | 2/2 | – | 58.6 |
| webpack: ~80 dependencies | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 102.5 |
| nodemon: file watcher, spawns processes | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 80.05 |
| core-js: postinstall prints a banner | benign | 2/2 | benign, benign | 11.0 | 1 | 0.0 | 0/2 | 2/2 | – | 91.2 |
| husky: git hooks tool | benign | 2/2 | benign, benign | 6.5 | 0 | 0.0 | 0/2 | 2/2 | – | 31.299999999999997 |
| esbuild: postinstall checks its platform binary | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 2/2 | – | 54.45 |
| sharp: install script, prebuilt native binary | benign | 2/2 | benign, benign | 12.0 | 2 | 0.0 | 0/2 | 2/2 | – | 62.75 |
| bcrypt: install downloads a binary from GitHub, else builds | benign | 0/2 | inconclusive, inconclusive | 12.0 | 2 | 4.0 | 0/2 | 2/2 | – | 71.55 |
| prisma: postinstall downloads engines from its CDN | benign | 2/2 | benign, benign | 12.0 | 2 | 2.5 | 0/2 | 1/2 | – | 75.5 |
| puppeteer: postinstall downloads Chrome | benign | 0/2 | inconclusive, inconclusive | 8.5 | 0 | 4.0 | 0/2 | 2/2 | – | 230.05 |
| requests | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 0/2 | – | 59.599999999999994 |
| urllib3 | benign | 2/2 | benign, benign | 8.5 | 0 | 0.0 | 0/2 | 0/2 | – | 44.45 |
| click | benign | 2/2 | benign, benign | 10.0 | 0 | 0.0 | 0/2 | 0/2 | – | 51.4 |
| flask | benign | 2/2 | benign, benign | 9.5 | 0 | 0.0 | 0/2 | 0/2 | – | 47.95 |
| attrs | benign | 2/2 | benign, benign | 11.0 | 1 | 0.0 | 0/2 | 0/2 | – | 51.05 |
| PyYAML: optional C extension | benign | 2/2 | benign, benign | 10.5 | 1 | 0.0 | 0/2 | 0/2 | – | 94.85 |
| python-dateutil: setuptools_scm build | benign | 2/2 | benign, benign | 10.5 | 1 | 0.0 | 0/2 | 0/2 | – | 54.7 |
| tqdm | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 0/2 | – | 59.95 |
| psutil: C extension build | benign | 2/2 | benign, benign | 11.5 | 1 | 0.0 | 0/2 | 0/2 | – | 56.2 |

**44/48 correct.** Invalid tool calls: 0. Inconclusive: 4. Errors: 0.

Concurrency 8: 48 runs in 655 s wall, 264 runs/hour. Host peak 1-min load 6.7, lowest MemAvailable 11661 MB.
