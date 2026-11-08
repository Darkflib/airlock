"""Turn a sample of Datadog's malicious-software-packages-dataset into Airlock targets.

Runs on the Airlock host, never on a laptop: it only unzips (password "infected") and
re-tars, nothing is executed here. npm samples become `package/` tarballs (.tgz); PyPI
samples become source distributions (.tar.gz). Samples that are only a built wheel, or
that have no package root, are listed as unsupported rather than silently dropped.

  python3 evals/datadog_prep.py ~/datadog-ds ~/datadog-sample.txt ~/datadog-x
Writes ~/datadog-x/targets.tsv (target, expected, label) and unsupported.tsv.
"""

import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def pack(src: Path, out: Path, arcname: str) -> None:
    with tarfile.open(out, "w:gz") as tar:
        tar.add(src, arcname=arcname)


def main(repo: Path, sample: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    targets, unsupported = [], []
    for rel in sample.read_text().split():
        eco, name, zpath = rel.split("/")[1], rel.split("/")[3], repo / rel
        label = f"{eco}:{name} ({zpath.stem})"
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run(["unzip", "-q", "-P", "infected", str(zpath), "-d", tmp], capture_output=True)
            if r.returncode not in (0, 1):
                unsupported.append((rel, f"unzip failed: {r.stderr.decode()[:80]}"))
                continue
            root = Path(tmp)
            if eco == "npm":
                pj = sorted(root.rglob("package.json"), key=lambda p: len(p.parts))
                if not pj:
                    unsupported.append((rel, "no package.json"))
                    continue
                out = dest / "npm" / f"{zpath.stem}.tgz"
                out.parent.mkdir(exist_ok=True)
                pack(pj[0].parent, out, "package")
            else:
                cands = sorted([p.parent for p in root.rglob("setup.py")] + [p.parent for p in root.rglob("pyproject.toml")],
                               key=lambda p: len(p.parts))
                if not cands:
                    why = "wheel only" if any(root.rglob("*.dist-info")) or any(root.rglob("*.whl")) else "no setup.py or pyproject.toml"
                    unsupported.append((rel, why))
                    continue
                pkg = cands[0]
                out = dest / "pypi" / f"{zpath.stem}.tar.gz"
                out.parent.mkdir(exist_ok=True)
                pack(pkg, out, pkg.name.replace(" ", "_") or "pkg")
            targets.append((str(out), "malicious", label))
    (dest / "targets.tsv").write_text("".join("\t".join(t) + "\n" for t in targets))
    (dest / "unsupported.tsv").write_text("".join("\t".join(u) + "\n" for u in unsupported))
    print(f"{len(targets)} targets ({sum('/npm/' in t[0] for t in targets)} npm, "
          f"{sum('/pypi/' in t[0] for t in targets)} pypi); {len(unsupported)} unsupported")


if __name__ == "__main__":
    main(Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser(), Path(sys.argv[3]).expanduser())
