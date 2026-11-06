#!/usr/bin/env python3
"""Scan every blob in a git repository's history (all refs, including PR refs in a mirror clone) for
credentials, Airlock's signed tokens and real canary tokens, before the repository is made public.
Vendored package archives (.tgz, .tar.gz) are unpacked and scanned too.

    python3 -I scripts/audit-history.py [repo-path ...]      # default: this repository
    git clone --mirror https://github.com/OWNER/REPO.git /tmp/r && python3 -I scripts/audit-history.py /tmp/r

Exits 1 if anything needs a look. Known fakes are allowed: the fixed canary strings, run canaries in tests/ and evals/results/,
and the deliberately unroutable collector hosts (*.invalid, 203.0.113.0/24) in the demo fixtures.
"""
import io
import re
import subprocess
import sys
import tarfile

PATTERNS = {
    "GitHub token": r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})",
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "AWS key": r"\bAKIA[0-9A-Z]{16}\b",
    "npm token": r"\bnpm_[A-Za-z0-9]{36}\b",
    "Slack token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
    "API key (sk-)": r"\bsk-[A-Za-z0-9_-]{20,}",
    "Vultr-style key": r"\b[A-Z0-9]{36}\b",
    "signed token (share/session/invite/JWT)": r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "share link": r"/s/[A-Za-z0-9_-]{30,}",
    "invite link": r"/auth/invite/[A-Za-z0-9_-]{20,}",
    "real canary token": r"AIRLOCKCANARY[0-9A-F]{16}",
    "credentials in URL": r"https?://[^/\s:@]+:[^/\s@]{6,}@",
    "secret assignment": r"(?i)\b(api[_-]?key|client_secret|secret|password|passwd|_authToken)\b[\"']?\s*[:=]\s*[\"']"
                         r"(?!op://)[^\"'\s$<{]{16,}[\"']",
}
# Hand-written fakes, not values from a run: fixed patterns that a real token never has.
ALLOWED = re.compile(r"AIRLOCKCANARY(0{16}|1{16}|0123456789ABCDEF|DEADBEEF0{8})|AKIAAIRLOCKCANARY001")
# Canary tokens from finished lab runs (evals/results) and hand-written ones in tests: a canary token is a
# fake credential, and PROVEN counts only the running run's own token, so an old one proves nothing.
CANARY_OK_PATHS = ("evals/results/", "tests/")


def blobs(repo):
    listing = subprocess.run(["git", "-C", repo, "rev-list", "--all", "--objects"], capture_output=True, text=True,
                             check=True).stdout
    check = subprocess.run(["git", "-C", repo, "cat-file", "--batch-check=%(objecttype) %(objectname) %(rest)"],
                           input=listing, capture_output=True, text=True, check=True).stdout
    for line in check.splitlines():
        kind, oid, *rest = line.split(" ", 2)
        if kind == "blob":
            yield oid, rest[0] if rest else "?"


def texts(repo, oid, path):
    data = subprocess.run(["git", "-C", repo, "cat-file", "-p", oid], capture_output=True, check=True).stdout
    if path.endswith((".tgz", ".tar.gz")):
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:  # read only; nothing is extracted to disk
                for m in tf.getmembers():
                    if m.isfile():
                        yield f"{path}!{m.name}", tf.extractfile(m).read().decode("utf-8", "replace")
            return
        except tarfile.TarError:
            pass
    yield path, data.decode("utf-8", "replace")


def audit(repo):
    found = {}
    for oid, path in blobs(repo):
        if path == "uv.lock":
            continue  # package hashes only
        for where, text in texts(repo, oid, path):
            for name, pattern in PATTERNS.items():
                if name == "real canary token" and path.startswith(CANARY_OK_PATHS):
                    continue
                for m in re.finditer(pattern, text):
                    if not ALLOWED.search(m.group(0)):
                        found.setdefault((name, m.group(0)[:12] + "…"), set()).add(where)
    log = subprocess.run(["git", "-C", repo, "log", "--all", "--format=%B"], capture_output=True, text=True).stdout
    for name, pattern in PATTERNS.items():
        for m in re.finditer(pattern, log):
            if not ALLOWED.search(m.group(0)):
                found.setdefault((name, m.group(0)[:12] + "…"), set()).add("(commit message)")
    return found


def main(repos):
    bad = False
    for repo in repos or ["."]:
        found = audit(repo)
        print(f"{repo}: {'clean' if not found else f'{len(found)} to check'}")
        for (name, prefix), where in sorted(found.items()):  # a prefix only: never print a whole secret
            print(f"  {name}: {prefix} in {', '.join(sorted(where)[:3])}")
        bad |= bool(found)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
