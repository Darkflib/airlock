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
