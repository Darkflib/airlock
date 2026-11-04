# Airlock test fixture: a benign sdist whose setup.py still does work at build time,
# the way many real packages do (read the README, stamp a version file). It reads
# only its own files and makes no network calls.
from pathlib import Path

from setuptools import setup

HERE = Path(__file__).parent
VERSION = "1.2.0"
(HERE / "tinyslug" / "_version.py").write_text(f'__version__ = "{VERSION}"\n')

setup(
    name="tinyslug",
    version=VERSION,
    description="Turn titles into URL slugs",
    long_description=(HERE / "README.md").read_text(),
    long_description_content_type="text/markdown",
    packages=["tinyslug"],
    python_requires=">=3.8",
)
