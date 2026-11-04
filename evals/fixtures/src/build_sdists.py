"""Pack the Python fixtures into sdists without running their setup.py (which
`python -m build` would do, and one of them is a credential stealer).

  python3 evals/fixtures/src/build_sdists.py
"""

import io
import tarfile
from pathlib import Path

HERE = Path(__file__).parent
FIXTURES = HERE.parent
SDISTS = {"termcolour-utils": ("0.4.2", "Tiny ANSI colour helpers for terminals", "termcolour-utils-stealer"),
          "tinyslug": ("1.2.0", "Turn titles into URL slugs", "tinyslug-benign")}


def pkg_info(name: str, version: str, summary: str) -> bytes:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: {summary}\n".encode()


def add(tar: tarfile.TarFile, arcname: str, data: bytes) -> None:
    info = tarfile.TarInfo(arcname)
    info.size, info.mode, info.mtime = len(data), 0o644, 1762300800  # fixed mtime: reproducible
    tar.addfile(info, io.BytesIO(data))


for src, (version, summary, out) in SDISTS.items():
    root = f"{src}-{version}"
    with tarfile.open(FIXTURES / f"{out}.tar.gz", "w:gz") as tar:
        add(tar, f"{root}/PKG-INFO", pkg_info(src, version, summary))
        for f in sorted(p for p in (HERE / src).rglob("*") if p.is_file() and "__pycache__" not in p.parts):
            add(tar, f"{root}/{f.relative_to(HERE / src)}", f.read_bytes())
    print(FIXTURES / f"{out}.tar.gz")
