"""The same PR without Airlock: what a plain CI job shows, and what the attacker gets.

A fresh microVM stands in for a CI runner (untrusted code still never runs on the host). It gets
the same kind of fake credentials Airlock plants, in the same files, but none of Airlock: no
watcher, no tracer, no sinkhole, no AI. The PR's head is checked out and `npm ci` and `npm test`
run as an unprivileged user, as a CI job would. The stealer's collection address deliberately
doesn't exist (a .invalid name), so a stand-in for the attacker's server listens inside the VM
under that name, with a certificate the VM trusts: whatever reaches it would have reached a real
attacker. Outbound traffic is still limited to the registries, which changes nothing here,
because the stand-in is local.

Needs the host env (GitHub App, for the PR head):

  set -a; . ~/.config/airlock/web.env; set +a
  .venv/bin/python evals/without_airlock.py https://github.com/Darkflib/airlock-demo/pull/3

Prints a JSON summary on stdout.
"""

import argparse
import asyncio
import datetime
import json
import secrets
import shlex
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from microsandbox import Sandbox

from airlock.github import GitHubApp, parse_pr_url
from airlock.sandbox import DEFAULT_ALLOW, IMAGES, OWNER_LABEL, egress_network

# The attacker's server: answers any HTTPS request and writes it down. Root-owned, so the package can't erase it.
CATCHER = r"""
const https = require('https'), fs = require('fs');
https.createServer({ key: fs.readFileSync('/opt/attacker/key.pem'), cert: fs.readFileSync('/opt/attacker/cert.pem') },
  (req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      fs.appendFileSync('/opt/attacker/received.jsonl', JSON.stringify(
        { at: new Date().toISOString(), method: req.method, host: req.headers.host, path: req.url, body }) + '\n');
      res.end('ok');
    });
  }).listen(443, '127.0.0.1', () => fs.writeFileSync('/opt/attacker/ready', ''));
"""


def stand_in_cert(host: str) -> tuple[bytes, bytes]:
    """A self-signed certificate for the attacker's hostname, like the real one an attacker would buy."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


async def sh(sb, cmd: str, timeout: float = 60) -> tuple[int, str]:
    out = await sb.shell(cmd, timeout=timeout)
    return out.exit_code, (out.stdout_text + out.stderr_text)


async def main(url: str, exfil_host: str) -> dict:
    owner, repo, number = parse_pr_url(url)
    app = GitHubApp.from_env()
    pr = await app.pull_request(owner, repo, number, files=False)
    tarball = await app.tarball(owner, repo, pr.head_sha)
    token = "CIBASELINE" + secrets.token_hex(8).upper()
    cert, key = stand_in_cert(exfil_host)
    name = f"airlock-without-{secrets.token_hex(4)}"
    t0 = time.monotonic()
    async with await Sandbox.create(name, image=IMAGES["npm"], cpus=2, memory=2048, max_duration=480, replace=True,
                                    labels={OWNER_LABEL: "cli"}, network=egress_network(DEFAULT_ALLOW)) as sb:
        await sh(sb, "mkdir -p /home/node/.aws /opt/attacker /work")
        # The CI job's secrets, where tools put them: the same files and shapes Airlock's canaries use.
        await sb.fs.write("/home/node/.npmrc", f"//registry.npmjs.org/:_authToken=npm_{token}\n".encode())
        await sb.fs.write("/home/node/.aws/credentials",
                          f"[default]\naws_access_key_id = AKIA{token[-12:]}\naws_secret_access_key = {token}/ci\n".encode())
        # The attacker's server, reachable under the name the stealer uses.
        for path, data in (("/opt/attacker/cert.pem", cert), ("/opt/attacker/key.pem", key),
                           ("/opt/attacker/catch.js", CATCHER.encode())):
            await sb.fs.write(path, data)
        rc, out = await sh(sb, "chmod 700 /opt/attacker && cp /opt/attacker/cert.pem /usr/local/share/ca-certificates/attacker.crt"
                               f" && update-ca-certificates >/dev/null && echo '127.0.0.1 {exfil_host}' >> /etc/hosts"
                               " && (setsid node /opt/attacker/catch.js >/opt/attacker/err 2>&1 </dev/null &)"
                               " && for i in $(seq 50); do [ -f /opt/attacker/ready ] && break; sleep 0.1; done;"
                               " [ -f /opt/attacker/ready ]")
        if rc:
            raise RuntimeError(f"the attacker stand-in didn't start: {out[-300:]}")
        # The checkout and the job, as CI runs them.
        await sb.fs.write("/work/repo.tgz", tarball)
        rc, out = await sh(sb, "mkdir -p /work/repo && tar xzf /work/repo.tgz -C /work/repo --strip-components=1"
                               " && chown -R node:node /work /home/node")
        if rc:
            raise RuntimeError(f"checkout failed: {out[-300:]}")
        steps = []
        for cmd in ("npm ci --no-audit --no-fund", "npm test --if-present"):
            t = time.monotonic()
            rc, out = await sh(sb, f"cd /work/repo && runuser -u node -- sh -c {shlex.quote(cmd)}", timeout=240)
            steps.append({"cmd": cmd, "exit_code": rc, "seconds": round(time.monotonic() - t, 1), "tail": out[-600:]})
        _, received = await sh(sb, "cat /opt/attacker/received.jsonl 2>/dev/null")
    got = [json.loads(line) for line in received.splitlines() if line.strip()]
    return {
        "pr": f"{owner}/{repo}#{number}", "head_sha": pr.head_sha, "vm": name,
        "seconds": round(time.monotonic() - t0, 1),
        "ci_result": "pass" if all(s["exit_code"] == 0 for s in steps) else "fail",
        "steps": steps,
        "attacker_received": got,
        "token_reached_attacker": any(token in r["body"] for r in got),
        "aws_secret_reached_attacker": any(f"{token}/ci" in r["body"] for r in got),
        "token": token,  # fake, made for this run
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pr_url")
    ap.add_argument("--exfil-host", default="telemetry.colorful-logs.invalid",
                    help="the name the PR's stealer posts to (PR #3 and the colorful-logs fixture)")
    a = ap.parse_args()
    print(json.dumps(asyncio.run(main(a.pr_url, a.exfil_host)), indent=2))
    sys.exit(0)
