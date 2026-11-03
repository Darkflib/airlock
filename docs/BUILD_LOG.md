# Build log

Raw notes on what worked, what didn't, and why. Material for the demo video and slides. Format and rules: see `AGENTS.md`. Times are UTC.

## Mon 2 Nov 2026

### evening — KVM on Vultr VX1
**Tried:** a throwaway VX1 instance, checking for `/dev/kvm`.
**Result:** present. VX1 exposes KVM, so microVMs run without bare metal.
**So:** microsandbox becomes the primary sandbox; gVisor is only a documented fallback.
Tags: #win #decision

## Tue 3 Nov 2026

### 17:28 — Dev host provisioned
**Tried:** `vx1-g-4c-16g-240s` in lhr, Ubuntu 24.04, booting from local NVMe (`--block-devices block-id:local,bootable:true`; VX1 refuses to create without a block device).
**Result:** active in under a minute. About $0.15/h.
**So:** develop in London; redeploy near the US late in the week using the same cloud-init.
Tags: #metric #decision

### 17:30 — cloud-init silently ignored
**Tried:** first boot with `infra/cloud-init.yaml`.
**Result:** cloud-init reported `done`, but the `airlock` user didn't exist. `cloud-init status --format json` showed `Failed loading yaml blob ... mapping values are not allowed here`. An unquoted `echo "kvm: present"` in `runcmd` parsed as a YAML mapping, and the whole file was dropped.
**So:** quote the command and run `cloud-init schema -c` before every upload. Reinstalling with the fixed file worked, which proves the rebuild path.
Tags: #fail

### 17:38 — microsandbox refuses its own storage root
**Tried:** `msb run python` straight after installing.
**Result:** `catalog ancestor /home/airlock/.microsandbox permits path substitution; use a storage root protected from other accounts`. Ubuntu's default umask 002 left the directory group-writable.
**So:** `chmod -R go-w ~/.microsandbox && chmod 700` after install, now in cloud-init. microsandbox is strict about its storage root, which is the kind of strictness we want from a security product.
Tags: #fail #demo

### 17:39 — First microVM
**Result:** the guest runs kernel 6.12 while the host runs 6.8, so it really is a separate kernel. First boot took 5.5 s (image pull); after that, 0.69 s. `msb doctor` warns that ext4 has no reflink, so every sandbox root is a full copy.
**So:** a separate kernel is the slide that answers "isn't this just Docker?". Reflink (XFS) is an optional speed-up for later.
Tags: #win #metric #demo

### 17:40 — Egress policy spike (`spikes/net_probe.py`)
**Tried:** default-deny `NetworkPolicy` with TLS inspection, allowing only registry.npmjs.org and pypi.org on 443.
**Result:** both allowed registries returned 200. HTTPS to example.com and HTTP to raw 1.1.1.1 both returned a JSON 403 `{"code":"network_policy_denied",...}`. DNS for a non-allowlisted name failed (exit 2). Boot took 0.58 s.
**So:** enforcement is built in, so we don't need our own nftables or proxy for blocking.
Tags: #win #decision #demo

### 17:42 — But denials leave no host-side trace
**Tried:** `--log-level debug`, then searched `~/.microsandbox` for any record of the denied requests.
**Result:** nothing. The 403 is visible only inside the guest.
**So:** the containment timeline needs our own observer. Plan: use microsandbox's outbound-proxy feature to send egress through a logging proxy on the host, with microsandbox still enforcing. Fallback: parse the 403 JSON and DNS failures from command output.
Tags: #fail #decision

### 17:50 — Rebuild check "hung" for 10 minutes
**Result:** the box was fine. The check ran `msb` over non-interactive SSH, where `~/.local/bin` isn't on PATH, so every retry failed silently.
**So:** cloud-init now symlinks `msb` and `uv` into `/usr/local/bin`. Lesson: retry loops must print their failures.
Tags: #fail

### 17:55 — Reserved IP and DNS
**Result:** converted the main IP to a reserved IPv4. `airlock.darkflib.dev` points at it.
**So:** a reserved IP is tied to its region, so a US redeploy needs a new reserved IP and a DNS change.
Tags: #decision

### 18:03 — Serverless Inference catalogue and first tool call
**Tried:** `GET /v1/models`, then a chat completion with one `exec` tool on `glm-5.3`.
**Result:** the catalogue says every text model supports `tools` and image input, except `nemotron-3.5-content-safety` (no tools, which is fine for the guard role). Context windows run from 131k to 1M. `glm-5.3` returned a well-formed `exec` tool call with `finish_reason: tool_calls`. Catalogue saved to `evals/models.json`.
**So:** the endpoint exposes function calling, and vision is available for Pattern B. The eval harness now measures reliability rather than whether features exist.
Tags: #win #metric

### 18:13 — Eval harness: first dry run (glm-5.3)
**Tried:** `evals/harness.py` on the host. A tool-calling loop (`exec`, `write_file`, `read_file`, `finish`) drives a real microVM with default-deny egress. Each task has a deterministic check. `evals/run.sh` pipes the inference key from 1Password over SSH stdin, so it never lands on disk.
**Result:** 3/3 engineering tasks passed with 0/44 invalid tool calls. On the demo-package task, glm-5.3 quietly made things safer: it read canaries bundled in the package instead of `~/.npmrc`, and left out the README injection line.
**So:** models soft-refuse "simulated malware" fixtures even inside an obviously sandboxed test. Measure it rather than assume.
Tags: #win #demo

### 18:16 — Full eval: 13 models, 4 tasks, 1 run each
**Result:** all 12 tool-capable models passed the basic agent tasks. 9/12 wrote a demo package that passed every check: it reads both canaries, posts to `*.invalid`, install still succeeds, and the README carries an injection comment. deepseek-v4.1-flash turned postinstall into a no-op ("performs no I/O"), qwen3.8-flash-next skipped the README line, and nemotron-omni got leftPad wrong. Vision was correct on every chat model except muse-glimmer-30b ("white" for a red square). mimo-v2.6-flash was cheapest and fastest: 4/4 with 14.5k input tokens, median 0.75 s per call. Full table in `evals/RESULTS.md`.
**So:** the agent-loop shortlist is mimo-v2.6-flash, qwen3.8-27b and glm-5.2. Repeat at n≥3 on harder tasks before committing.
Tags: #metric #decision #demo

### 18:20 — Harness bug: model sent JSON object as file content
**Result:** muse-glimmer-30b passed `write_file` `content` as a JSON object, not a string. `AttributeError: 'dict' object has no attribute 'encode'` crashed two runs.
**So:** schema-invalid arguments now go back to the model as an invalid tool call. The product's agent loop needs the same defence.
Tags: #fail

### 18:20 — npm prints install-scripts warnings, but postinstall still ran
**Result:** every `npm install` of the demo tarball printed `npm warn install-scripts ... approve <pkg>`, yet `trace.js` still saw postinstall execute and attempt egress.
**So:** check which npm version the demo uses. If a future npm blocks lifecycle scripts by default, the demo needs `--allow-scripts` or an approved list, and that also strengthens the "it ran anyway" story.
Tags: #demo
