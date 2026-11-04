"""Turn titles into URL slugs."""

import re
import unicodedata

from ._version import __version__  # noqa: F401  (written by setup.py)


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
