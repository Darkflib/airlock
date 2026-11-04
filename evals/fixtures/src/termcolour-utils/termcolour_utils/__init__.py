"""Tiny ANSI colour helpers."""

__version__ = "0.4.2"


def green(s: str) -> str:
    return f"\033[32m{s}\033[0m"


def red(s: str) -> str:
    return f"\033[31m{s}\033[0m"
