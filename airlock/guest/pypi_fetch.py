"""Airlock: fetch a package's source distribution from PyPI, inside the microVM, without
running any of it. Standard library only. `pip download` would build the sdist's metadata
(and so run its setup.py) as root before detonation; this only downloads the file.

  python3 pypi_fetch.py <name> [<version>] <dest-dir>   prints the saved path
"""

import hashlib
import json
import os
import sys
import urllib.request


def main() -> None:
    *spec, dest = sys.argv[1:]
    name, version = spec[0], (spec[1] if len(spec) > 1 else None)
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        meta = json.load(r)
    sdists = [u for u in meta["urls"] if u["packagetype"] == "sdist"]
    if not sdists:
        sys.exit(f"{name} {meta['info']['version']} has no source distribution on PyPI (wheels only): nothing runs at install")
    sdist = sdists[0]
    host = urllib.request.urlparse(sdist["url"]).hostname
    if host != "files.pythonhosted.org":
        sys.exit(f"unexpected download host {host}")
    with urllib.request.urlopen(sdist["url"], timeout=60) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"]:
        sys.exit("sha256 mismatch against PyPI's metadata")
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, "candidate.zip" if sdist["filename"].endswith(".zip") else "candidate.tar.gz")
    with open(path, "wb") as f:
        f.write(data)
    print(json.dumps({"path": path, "filename": sdist["filename"], "version": meta["info"]["version"],
                      "sha256": sdist["digests"]["sha256"]}))


if __name__ == "__main__":
    main()
