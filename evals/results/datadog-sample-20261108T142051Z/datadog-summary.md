# Datadog malicious-package sample — datadog-sample-20261108T142051Z

Packages from [Datadog's malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (commit 72c723be, 5 Nov 2026), `malicious_intent` only, one version per package, drawn with seed 20261108 (`~/datadog-sample.txt` on the host; `evals/datadog_prep.py`). Each ran once through the real pipeline: microVM, watcher, sinkhole, agent. Every package is known malicious, so anything but *malicious* is a miss.

| | npm | PyPI | All |
| --- | --- | --- | --- |
| **Called malicious** | 361/500 (72%) | 168/180 (93%) | 529/680 (78%) |
| Called malicious or suspicious | 406/500 (81%) | 174/180 (97%) | 580/680 (85%) |
| Sent something to an attacker's server, captured at the sinkhole | 228/500 (46%) | 23/180 (13%) | 251/680 (37%) |
| Proven credential theft (this run's fake token captured) | 24/500 (5%) | 3/180 (2%) | 27/680 (4%) |
| Any containment event (blocked, captured, credential read) | 264/500 (53%) | 30/180 (17%) | 294/680 (43%) |
| Inconclusive (install failed or blind spot) | 13/500 (3%) | 2/180 (1%) | 15/680 (2%) |
| Called benign (a miss) | 79/500 (16%) | 4/180 (2%) | 83/680 (12%) |
| Error | 2/500 (0%) | 0/180 (0%) | 2/680 (0%) |

680 packages ran. Median 40 s per package, median 27,398 tokens per review. Exercised by the agent: 415.

Not run, because Airlock doesn't take them: 20 PyPI samples (17 wheel only, 3 no setup.py or pyproject.toml).

Why runs were inconclusive: 13 × the install exited 1; 1 × the install timed out.

**Reading the numbers.** Most of this dataset is dependency-confusion and recon packages that send the machine's hostname, user and IP to a webhook, not ones that steal credential files, so *proven credential theft* is rare by design; the captured request is the evidence for those. Datadog notes the set leans towards what its GuardDog rules detect. A *benign* call is a miss and is listed in `runs.json`.

Missed (called benign):

- `2026-10-09-@aseppxyzz12_baileys-v0.0.0-stage.tgz`: The tarball contains exactly two files, README.md and package.json; no JavaScript exists anywhere in the package [E18].
- `2026-08-24-@pilllesss_yorn-v1.0.107.tgz`: package.json has no preinstall/install/postinstall scripts, so npm install only unpacks files [E7].
- `2026-01-30-@skyeng_libs-v99.99.10.tgz`: The tarball holds exactly one file, package.json; no JS, no binaries, no dotfiles [E9][E42].
- `2026-09-22-@qwen-code_qwen-code-v0.24.3.tgz`: The package's package.json declares no scripts at all, so npm install runs no lifecycle code from qwen-code itself [E7][E46].
- `2026-09-05-@versacode_baileys-v1.4.5-beta.0.tgz`: Install script is preinstall "node ./engine-requirements.js", which only exits if Node < 20 [E8][E9][E23].
- `2025-11-27-accounts-base-v1.0.0.tgz`: The tarball holds exactly two files, index.js and package.json, with no pre/postinstall or other lifecycle scripts [E31].
- `2026-08-17-@toptal_picasso-calendar-v100.0.2.tgz`: package.json has no preinstall/postinstall/install/prepare scripts and no bin, so npm runs no code at install time [E7].
- `2025-09-18-@toptal_picasso-alert-v3.0.35.tgz`: package.json has no install/preinstall/postinstall/prepare scripts and no bin, and the install in [E7] traced zero file, network or process activity.
- `2025-11-11-amazon-testpackage-v0.0.1.tgz`: The tarball contains only package.json and index.js, 387 bytes total, no hidden files or binaries [E20].
- `2024-11-28-aries-bifold-root-v2.0.0.tgz`: The tarball holds exactly two files: package/package.json and a 0-byte package/index.js; od confirms index.js has no bytes at all [E11][E39].
- `2024-05-17-arif-kue96-riris-v1.3.4.tgz`: package.json has no preinstall/postinstall/main/bin fields, and the traced install showed no file, network or process activity [E7].
- `2024-05-13-bayu-bubursumsum91-sluey-v1.2.3.tgz`: package.json defines no preinstall/postinstall/install scripts, and the install produced zero file, network or process activity [E7].
- `2025-08-09-checkout-app-v1.5.4.tgz`: The tarball holds a single file, package/package.json; no index.js, no scripts beyond the default failing test stub [E18].
- `2025-11-13-com.unity.polyspatial.xr-v3.1.0.tgz`: The tarball contains exactly one file, package/package.json, 220 bytes; no index.js or other code exists [E18].
- `2024-05-17-citra-miemee33-sluey-v4.4.1.tgz`: Install traced no file, network, or process activity, and package.json defines no pre/postinstall scripts [E7].
- `2025-03-15-distylai-v0.0.0.tgz`: The tarball contains exactly one file, package/package.json, with no index.js or any other code [E18][E24].
- `2024-05-13-dewanto-rojak32-sluey-v3.2.3.tgz`: package.json has no preinstall/postinstall/prepare scripts and no main/bin, and the traced install showed zero file, network or process activity [E7].
- `2025-12-29-electra-web-player-v1.0.0.tgz`: The tarball lists exactly one file, package/package.json; no source files, no pre/postinstall scripts [E18].
- `2025-12-03-elf-stats-festive-pantry-640-v1.0.0.tgz`: The tarball holds exactly two files: index.js (11 bytes, `return 42`) and package.json, confirmed by tar listing and od dump [E18][E22].
- `2024-05-20-eka-rangi78-sluey-v2.2.1.tgz`: package.json has no main, bin, or install/prepare scripts, so npm install runs no package code; the traced install produced no file, network or process activity
- `2024-05-21-dono-kue5-riris-v3.1.2.tgz`: Install ran clean: npm install of the tarball produced no file, network or process activity [E7].
- `2025-08-13-epc-node-web-client-v1.0.1.tgz`: The tarball contains exactly one file, package/package.json, 233 bytes; no index.js or other code exists [E18].
- `2025-03-25-epic-analytics-worker-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json; tar listing shows no other entries [E18].
- `2025-03-25-epic-comment-rating-frontend-v1.0.0.tgz`: The tarball contains exactly two entries: package/ and package/package.json, nothing else [E18].
- `2024-05-21-eka-kupang72-sluey-v2.1.1.tgz`: 
- `2025-03-25-epic-ticket-loader-v1.0.0.tgz`: The tarball contains exactly one file, package/package.json, 214 bytes of npm-init defaults [E18].
- `2025-03-25-epic-graphql-types-v1.0.0.tgz`: The archive lists exactly one file, package/package.json (214 bytes), with no scripts, dependencies, or entry file [E17][E19].
- `2024-05-21-erick-empal57-sluey-v1.3.3.tgz`: package.json defines no install/postinstall/prepare scripts, only dev/build/start/lint, so npm install executes no package code [E33][E87][E7].
- `2024-05-17-fadhil-tahu77-riris-v1.4.4.tgz`: Install ran no code: package.json has no preinstall/install/postinstall scripts, and the traced install produced zero file, network or process activity [E7].
- `2025-10-12-hemi-viem-stake-actions-v1.0.0.tgz`: Install produced no file, network, or process activity beyond npm itself; package.json's preinstall/postinstall are empty strings [E7].
- `2024-05-07-hadianto-lapis63-kyuki-v2.3.3.tgz`: package.json defines only dev/build/start/lint scripts — no preinstall/postinstall/prepare — so install runs nothing, matching the silent install [E7].
- `2024-05-20-ida-dodol60-breki-v1.3.4.tgz`: package.json has no preinstall/postinstall scripts, no main or bin, so npm install runs nothing — the traced install produced no file, network or process activi
- `2024-05-10-ida-mendut13-breki-v4.1.3.tgz`: package.json has no preinstall/postinstall/prepare scripts and no main or bin entry, so npm install executes nothing from the package [E7][E45].
- `2024-05-10-indah-klentik1-ruro-v2.4.1.tgz`: package.json has no install lifecycle scripts and no main/bin; the traced install produced no file, network or process activity [E7][E9].
- `2024-05-21-joko-lapis98-ruro-v3.1.1.tgz`: package.json has no main, bin, or install/preinstall/postinstall scripts, so npm install runs nothing [E7].
- `2024-05-10-joko-nasi58-riris-v2.3.2.tgz`: package.json contains no preinstall/postinstall/prepare scripts, so npm install runs nothing of the package's own [E7].
- `2024-05-09-joko-dradag46-sluey-v2.3.2.tgz`: package.json defines no preinstall/install/postinstall/prepare scripts, and the traced install produced zero file, network or process activity [E7].
- `2025-07-29-keccak256-helper-v1.3.4.tgz`: The tarball contains only README.md, index.js, package.json; index.js is 49 bytes of a comment with no code [E9][E22].
- `2025-07-05-kiwi-module-search-v3.0.0.tgz`: package.json's only lifecycle hook is postinstall: echo 'PoC by ShadowMonarchX SRT - dependency confusion test triggered', which is what ran at install [E7][E8]
- `2024-05-16-joko-tahutek53-breki-v4.3.4.tgz`: Install ran no scripts: package.json has no preinstall/install/postinstall hooks, and the traced install produced no file, network or process activity [E7].
- `2024-05-13-kiki-naget36-miaww-v1.3.4.tgz`: package.json has no preinstall/postinstall/prepare scripts and no main/exports field, and the traced install showed zero file, network, or process activity [E7]
- `2024-05-18-kurniawan-martabak3-riris-v1.2.3.tgz`: Install ran no lifecycle scripts: package.json has only dev/build/start/lint, and the traced install showed no file, network, or process activity [E7].
- `2024-05-21-kiki-kembang17-riris-v2.1.4.tgz`: ["Install ran clean: npm install of the tarball produced no file, network or process activity [E7].", "package.json has no main, bin, exports, or install/preins
- `2024-05-13-kurnia-rendang9-ruro-v2.1.1.tgz`: Install executed no lifecycle scripts and produced no file, network, or process activity [E7]; package.json contains no main, bin, or install/preinstall/postins
- `2024-05-12-lisa-sego47-miaww-v2.3.4.tgz`: package.json has no preinstall/postinstall/prepare scripts, no main, and no bin, so npm install runs nothing [E7].
- `2024-05-21-lina-nasisayur20-ruro-v1.2.1.tgz`: Install traced no file, network, or process activity at all [E7].
- `2025-03-28-mms-thin-client-v1.0.0.tgz`: The tarball holds a single file, package/package.json (211 bytes); no index.js or other code exists [E17].
- `2026-08-24-mcp-secure-server-v0.0.20-security.tgz`: No install scripts in package.json (no postinstall/preinstall/prepare) and the install in [E7] traced zero file, network, or process activity.
- `2025-09-17-mutual-ssl-v7.7.7.tgz`: The tarball contains exactly one file, package/package.json; there is no index.js or any other code [E29].
- `2024-05-07-mulyono-kolak58-sluey-v4.3.4.tgz`: package.json has no install/preinstall/prepare scripts and no main/exports; npm install traced with zero file, network or process activity [E7].
- `2024-05-12-nana-sambel40-breki-v3.3.3.tgz`: package.json has no main, bin, exports, or install/prepare scripts, so nothing runs on install or import [E79, E44].
- `2025-09-18-npj4-v1.0.55.tgz`: The tarball holds exactly two files: a zero-byte index.js and package.json [E24].
- `2024-05-12-nurul-rangi65-miaww-v1.3.4.tgz`: package.json has no install/prepare/postinstall scripts, and the traced install showed zero file, network or process activity [E7].
- `2024-05-20-nurul-kue44-miaww-v2.2.1.tgz`: Install ran with no traced file, network, or process activity [E7].
- `2024-05-16-okta-mangut57-miaww-v1.4.3.tgz`: Install ran no lifecycle scripts and produced no file, network or process activity [E7].
- `2024-05-12-oktafian-tempe5-sluey-v2.2.3.tgz`: package.json has no main, bin, or install/preinstall/postinstall scripts — only dev/build/start/lint — so npm install runs nothing [E7], [E39].
- `2025-09-25-openwhisk-probot-builder-v1.0.0.tgz`: Install script is just `echo "takeover poc"` and ran harmlessly [E84].
- `2026-10-01-pflag29424-v0.0.0-stage.tgz`: The tarball contains exactly two files, README.md and package.json; no source, binaries, or hidden files [E18].
- `2024-10-12-phlex-core-ui-v0.88.1.tgz`: package.json has no preinstall/install/postinstall scripts, and the traced install produced no file, network, or process activity [E7].
- `2024-05-21-putri-nasi94-ruro-v1.4.4.tgz`: package.json has no preinstall/postinstall/install/prepare scripts, and the traced install produced zero file, network, or process activity [E7].
- `2025-10-11-scr-cloud-project-v1.0.0.tgz`: Install ran clean: npm install produced no file, network or process activity [E7], and package.json defines no install/preinstall/postinstall scripts [E9].
- `2025-08-06-shmam-test-grape-v3.0.0.tgz`: The tarball contains exactly one file, package/package.json, 230 bytes; no index.js or any other code exists [E25].
- `2025-09-23-sparo-completion-test-v7.7.7.tgz`: The tarball and /work/pkg contain exactly one file, package/package.json — no index.js, no binaries [E10][E27].
- `2024-05-11-siska-empal77-breki-v3.2.2.tgz`: package.json has no preinstall/postinstall scripts, no main, no bin, so npm install runs no package code; install traced zero activity [E7].
- `2025-10-12-terrain-sample-v1.0.0.tgz`: 
- `2026-01-13-ts-tweetnacl-utils-v0.0.3.tgz`: The tarball contains only package.json, a 0-byte index.js, and a 0-byte scripts/postinstall.js [E21].
- `2024-12-12-uber-gateway-v999.9.9.tgz`: ["The tarball holds exactly two files, package/index.js and package/package.json, with no install hooks (no preinstall/install/postinstall) [E32].", "index.js o
- `2024-05-14-tomi-bubur50-sluey-v2.3.4.tgz`: Install does nothing: package.json has no pre/postinstall scripts, and the traced install produced no file, network or process activity [E7].
- `2024-12-16-unisocks-v1.0.0.tgz`: package.json has no install/postinstall/preinstall script, so postinstall.js never executes — matching the clean install in [E7].
- `2024-05-21-umi-nasi90-ruro-v3.3.3.tgz`: ["Install ran clean: package.json has no install/prepare/preinstall scripts, and the traced install produced no file, network or process activity [E7].", "Requi
- `2025-10-12-usb_dev-v2.0.0.tgz`: The tarball holds exactly one file, package/package.json (225 bytes); no index.js or other code exists [E18].
- `2026-01-07-victim-package-c-v1.0.0.tgz`: package.json has no preinstall/install/postinstall scripts, and the install in [E7] produced no file, network, or process activity.
- `2024-05-16-utomo-kembang68-ruro-v1.3.4.tgz`: package.json defines no preinstall/postinstall/prepare scripts, so the install ran no package code; its only network was registry.npmjs.org fetching dependencie
- `2024-05-17-vina-kemplang61-breki-v3.2.3.tgz`: package.json defines no install/preinstall/postinstall/prepare scripts, and the traced install produced zero file, network, or process activity [E7].
- `2024-05-08-wawan-nasipecel28-sluey-v1.3.2.tgz`: package.json defines no install/postinstall/prepare scripts, and the traced npm install produced no file, network, or process activity [E7].
- `2025-11-18-workvivo-components-v0.0.1.tgz`: package.json declares preinstall and install scripts as empty strings, so no install-time code exists; the traced install produced no file, network, or process 
- `2024-05-21-wibowo-tahu53-riris-v2.2.3.tgz`: package.json has no preinstall/install/postinstall scripts, and the traced install showed no file, network, or process activity [E7].
- `2022-12-19-aiiohttp.tar.gz`: setup.py only calls setuptools.setup() with metadata; no cmdclass, exec, subprocess, or custom build steps [E32].
- `2024-05-20-xaver-nasipecel64-ruro-v3.1.1.tgz`: Install traced no file, network or process activity at all [E7].
- `2024-05-20-zain-tek64-miaww-v1.2.4.tgz`: package.json has no install/preinstall/postinstall scripts, and the traced install showed no file, network or process activity [E7].
- `2023-03-17-convocations-v0.22.tar.gz`: setup.py contains only setup() metadata, extras_require from .txt files, and console_scripts; no cmdclass, ext_modules, or setup_requires [E122].
- `2025-01-28-set-utils-v1.1.0.tar.gz`: setup.py's only code beyond setup() is exec() of para/about.py, which contains just version/author string constants [E57].
- `2025-08-20-vcdiff-py-v2.1.0.tar.gz`: setup.py contains only setuptools metadata, README read, and a click install_requires; no custom build hooks or exec/eval [E6][E18][E19][E21].
