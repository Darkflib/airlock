# Datadog malicious-package sample — datadog-sample-20261108T123757Z

Packages from [Datadog's malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (commit 72c723be, 5 Nov 2026), `malicious_intent` only, one version per package, drawn with seed 20261108 (`~/datadog-sample.txt` on the host; `evals/datadog_prep.py`). Each ran once through the real pipeline: microVM, watcher, sinkhole, agent. Every package is known malicious, so anything but *malicious* is a miss.

| | npm | PyPI | All |
| --- | --- | --- | --- |
| **Called malicious** | 350/500 (70%) | 168/180 (93%) | 518/680 (76%) |
| Called malicious or suspicious | 421/500 (84%) | 172/180 (96%) | 593/680 (87%) |
| Sent something to an attacker's server, captured at the sinkhole | 223/500 (45%) | 23/180 (13%) | 246/680 (36%) |
| Proven credential theft (this run's fake token captured) | 6/500 (1%) | 0/180 (0%) | 6/680 (1%) |
| Any containment event (blocked, captured, credential read) | 262/500 (52%) | 30/180 (17%) | 292/680 (43%) |
| Inconclusive (install failed or blind spot) | 12/500 (2%) | 2/180 (1%) | 14/680 (2%) |
| Called benign (a miss) | 65/500 (13%) | 6/180 (3%) | 71/680 (10%) |
| Error | 2/500 (0%) | 0/180 (0%) | 2/680 (0%) |

680 packages ran. Median 42 s per package, median 25,722 tokens per review. Exercised by the agent: 412.

Not run, because Airlock doesn't take them: 20 PyPI samples (17 wheel only, 3 no setup.py or pyproject.toml).

Why runs were inconclusive: 13 × the install exited 1; 1 × the install timed out.

**Reading the numbers.** Most of this dataset is dependency-confusion and recon packages that send the machine's hostname, user and IP to a webhook, not ones that steal credential files, so *proven credential theft* is rare by design; the captured request is the evidence for those. Datadog notes the set leans towards what its GuardDog rules detect. A *benign* call is a miss and is listed in `runs.json`.

Missed (called benign):

- `2026-10-09-@aseppxyzz12_baileys-v0.0.0-stage.tgz`: The tarball contains exactly two files, README.md and package.json, with no other content [E18].
- `2026-08-24-@pilllesss_yorn-v1.0.107.tgz`: Install of the tarball produced no file, network or process activity traced [E7].
- `2026-09-22-@qwen-code_qwen-code-v0.24.3.tgz`: Install script @qwen-code/audio-capture/install.js spawns node-gyp-build then always exits 0, no network or file reads beyond prebuilds/ [E8][E11][E13]
- `2026-01-30-@skyeng_libs-v99.99.10.tgz`: The tarball contains exactly one file, package/package.json (98 bytes); the rest of the archive is zero padding [E71] [E18].
- `2025-09-11-@pixui-dev_pxw-v0.1.32.tgz`: Install-time postinstall.js only rmSync's node_modules/@types/react and preact, nothing else [E10][E11][E12][E13][E17][E18].
- `2026-09-05-@versacode_baileys-v1.4.5-beta.0.tgz`: The package's only install script is preinstall 'node ./engine-requirements.js', which just exits if Node < 20 [E8, E9, E15].
- `2025-11-27-accounts-base-v1.0.0.tgz`: The tarball contains only package/index.js and package.json; no scripts, dependencies, or bin entries [E20][E9].
- `2026-08-17-@toptal_picasso-calendar-v100.0.2.tgz`: package.json has no preinstall/install/postinstall/prepare scripts and no bin; only build:package (tsc) exists [E7, E130].
- `2025-09-18-@toptal_picasso-alert-v3.0.35.tgz`: package.json contains no preinstall/install/postinstall/prepare scripts, only a prepublishOnly build step [E9, E46].
- `2025-11-11-amazon-testpackage-v0.0.1.tgz`: 
- `2024-11-28-aries-bifold-root-v2.0.0.tgz`: The tarball holds exactly two files: a zero-byte index.js and a 268-byte package.json, with no hidden files or binaries [E11][E20].
- `2024-05-17-arif-kue96-riris-v1.3.4.tgz`: package.json defines no preinstall/postinstall/install scripts, no bin, and no main/exports, so installing runs nothing from this package [E7].
- `2024-05-20-budi-ubi72-sluey-v1.1.3.tgz`: Install ran with no traced file, network or process activity; package.json has no preinstall/install/postinstall scripts [E7].
- `2024-05-17-candra-ragi67-sluey-v2.1.2.tgz`: Install ran no lifecycle scripts and produced no file, network or process activity [E7].
- `2025-08-09-checkout-app-v1.5.4.tgz`: 
- `2025-11-13-com.unity.polyspatial.xr-v3.1.0.tgz`: The tarball contains exactly one file, package/package.json; no index.js or other code exists [E18].
- `2025-03-15-distylai-v0.0.0.tgz`: The tarball contains exactly one file, package/package.json; no other files, scripts, or binaries are shipped [E17].
- `2025-12-29-electra-web-player-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json (236 bytes); no other files exist in the archive [E18].
- `2025-12-03-elf-stats-festive-pantry-640-v1.0.0.tgz`: package.json has no scripts, no dependencies, and no lifecycle hooks; install ran clean with zero traced activity [E7].
- `2024-05-13-eko-bubur39-miaww-v4.3.1.tgz`: Install produced no file, network or process activity under the tracer [E7].
- `2025-08-13-epc-node-web-client-v1.0.1.tgz`: The tarball contains exactly one file, package/package.json (233 bytes), no other code or binaries [E18].
- `2025-03-25-epic-analytics-worker-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json (217 bytes); no index.js, no scripts, no binaries [E17].
- `2025-03-25-epic-comment-rating-frontend-v1.0.0.tgz`: The tarball lists exactly one file, package/package.json, with no scripts, dependencies, or code files [E18][E9].
- `2025-03-25-epic-graphql-types-v1.0.0.tgz`: The tarball holds exactly one file, package/package.json (214 bytes); no index.js or any other code exists [E18][E25].
- `2025-03-25-epic-ticket-loader-v1.0.0.tgz`: The tarball holds exactly one file, package/package.json (214 bytes); no index.js or other code exists [E18][E42].
- `2025-10-12-hemi-viem-stake-actions-v1.0.0.tgz`: index.js contains a single comment line and no executable code [E9], and the tarball holds only index.js and package.json [E17].
- `2024-05-20-ida-dodol60-breki-v1.3.4.tgz`: Install ran with no file, network, or process activity, and package.json has no install scripts, main, bin, or exports [E7][E99].
- `2024-05-16-indah-tongseng46-sluey-v1.1.3.tgz`: Install ran clean: npm install of the tarball produced no file, network or process activity [E7].
- `2024-05-09-jaja-kentang95-ruro-v2.3.3.tgz`: Install ran no lifecycle scripts: package.json has no preinstall/postinstall/prepare/bin/main, and the traced install showed zero file, network or process activ
- `2025-07-29-keccak256-helper-v1.3.4.tgz`: The tarball holds only README.md, index.js and package.json — no install or postinstall scripts, no dependencies [E4][E20].
- `2024-05-16-joko-tahutek53-breki-v4.3.4.tgz`: package.json has no install scripts, main, or bin; the install produced no file/network/process activity [E7].
- `2025-07-05-kiwi-module-search-v3.0.0.tgz`: The tarball contains only index.js and package.json, nothing hidden [E36].
- `2024-05-21-kresna-kue32-sluey-v4.3.3.tgz`: Install ran no scripts: package.json has no pre/postinstall or prepare hook, and the traced install produced no file, network or process activity [E7].
- `2024-05-18-kurniawan-martabak3-riris-v1.2.3.tgz`: package.json has no preinstall/postinstall/install scripts and no bin, so npm install executes nothing from the package [E7][E58].
- `2024-05-13-kurnia-rendang9-ruro-v2.1.1.tgz`: Install ran no lifecycle code: package.json has only dev/build/start/lint scripts, and the traced install produced no file, network, or process events [E7].
- `2024-05-21-lina-nasisayur20-ruro-v1.2.1.tgz`: package.json has no preinstall/postinstall scripts, no main or bin entry; the traced install produced no file, network or process activity [E7].
- `2024-05-17-lisa-brongkos38-breki-v4.3.2.tgz`: The package has no install scripts; the traced npm install produced no file, network, or process activity [E7].
- `2025-03-28-mms-thin-client-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json, and no JavaScript source at all [E17][E19].
- `2026-08-24-mcp-secure-server-v0.0.20-security.tgz`: Install ran with no traced file, network, or process activity, and package.json has no pre/postinstall scripts [E7].
- `2025-09-17-mutual-ssl-v7.7.7.tgz`: The tarball contains exactly two entries: package/ and package/package.json — no JavaScript files at all [E23][E57].
- `2024-05-07-mulyono-kolak58-sluey-v4.3.4.tgz`: Install ran no scripts and produced no file, network, or process activity: package.json has no install hooks, main, or bin [E7].
- `2024-05-08-nana-ongol-ongol85-riris-v1.2.4.tgz`: package.json has no preinstall/postinstall/bin/main/exports hooks, and the traced install [E7] produced no file, network or process activity.
- `2025-09-18-npj4-v1.0.55.tgz`: 
- `2024-05-12-nurul-rangi65-miaww-v1.3.4.tgz`: package.json has no preinstall/postinstall/prepare scripts, and the traced npm install showed no file, network, or process activity [E7].
- `2024-05-20-nurul-kue44-miaww-v2.2.1.tgz`: package.json has no preinstall/postinstall/prepare scripts, and the traced install produced no file, network or process activity [E7] [E60].
- `2025-09-25-openwhisk-probot-builder-v1.0.0.tgz`: The tarball contains only 4 small files (index.js, test.js, package.json, README.md); hashes match the unpacked copy [E10][E19].
- `2024-05-16-okta-mangut57-miaww-v1.4.3.tgz`: package.json has no preinstall/install/postinstall/prepare scripts and no main or bin, so npm install runs nothing [E7, E31].
- `2026-10-01-pflag29424-v0.0.0-stage.tgz`: The tarball contains exactly two files, package/README.md and package/package.json, nothing else [E17].
- `2024-10-12-phlex-core-ui-v0.88.1.tgz`: package.json has no preinstall/install/postinstall scripts; the install in [E7] produced zero file, network or process activity.
- `2025-10-11-scr-cloud-project-v1.0.0.tgz`: Install ran no scripts and produced no file/network/process activity; package.json has only a stub test script [E7].
- `2025-08-06-shmam-test-grape-v3.0.0.tgz`: The tarball holds exactly two entries: the folder and package/package.json (230 bytes); there is no index.js or any other file [E18, E46].
- `2025-09-23-sparo-completion-test-v7.7.7.tgz`: The tarball contains exactly one file, package.json; no index.js or any other code exists [E64][E10].
- `2025-10-12-terrain-sample-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json, and no index.js or other code [E17].
- `2026-01-13-ts-tweetnacl-utils-v0.0.3.tgz`: All shipped code files are zero bytes: index.js and scripts/postinstall.js are empty in the tarball [E18][E23].
- `2024-12-12-uber-gateway-v999.9.9.tgz`: The tarball holds exactly two files, index.js and package.json, with no preinstall/install/postinstall or lifecycle scripts [E20].
- `2024-05-14-tomi-bubur50-sluey-v2.3.4.tgz`: Install ran with zero file, network, or process activity; package.json has no pre/postinstall hooks [E7, E45].
- `2024-12-16-unisocks-v1.0.0.tgz`: Install ran clean: npm install produced no file, network or process activity [E7], because package.json defines no install scripts at all [E9].
- `2024-05-21-umi-nasi90-ruro-v3.3.3.tgz`: package.json has no install lifecycle scripts, main, or bin; the traced install produced zero file/network/process activity [E7].
- `2024-05-07-umi-pecel35-sumpek-v1.3.3.tgz`: package.json has only dev/build/start/lint scripts — no preinstall/install/postinstall — and the install traced zero activity [E7].
- `2025-10-12-usb_dev-v2.0.0.tgz`: The tarball holds exactly two entries: a directory and package/package.json (225 bytes); no index.js or any other file exists [E45].
- `2024-05-13-vera-oblok89-breki-v3.1.4.tgz`: Install produced no file, network or process activity at all; package.json has no pre/postinstall or any lifecycle scripts [E7].
- `2026-01-07-victim-package-c-v1.0.0.tgz`: The tarball contains only package.json and index.js; package.json has no preinstall/install/postinstall or other lifecycle scripts [E9, E18].
- `2025-11-18-workvivo-components-v0.0.1.tgz`: The tarball contains only package/index.js and package/package.json, matching the pristine copy [E23].
- `2024-05-17-vina-kemplang61-breki-v3.2.3.tgz`: package.json has no preinstall/postinstall/prepare scripts, and the install in [E7] produced no file, network or process activity.
- `2022-12-19-aiohtttps.tar.gz`: setup.py contains only a setup() call with metadata — no cmdclass, no exec/eval, no network code; AST dump confirms it [E48].
- `2024-05-20-zain-tek64-miaww-v1.2.4.tgz`: No install/postinstall/prepare scripts exist, and the traced install showed zero file, network, or process activity [E7].
- `2023-03-17-convocations-v0.22.tar.gz`: setup.py only reads README and extras .txt files and calls setuptools setup(); no cmdclass, no pyproject build hooks, no network code [E52].
- `2022-12-19-libssl.tar.gz`: setup.py is 14 lines of pure metadata (name, version, Discord URL, keywords); no cmdclass, ext_modules, entry_points, or install_requires [E91].
- `2022-12-19-pynalc.tar.gz`: 
- `2025-01-28-set-utils-v1.1.0.tar.gz`: setup.py's only dynamic action is exec() of para/about.py, which sets plain metadata strings; no network, subprocess, or file writes at install time [E27].
- `2025-08-20-vcdiff-py-v2.1.0.tar.gz`: setup.py is ordinary setuptools metadata with no cmdclass, custom build hooks, or install scripts; pyproject uses stock setuptools.build_meta [E33].
