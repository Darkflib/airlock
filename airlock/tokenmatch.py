"""Find this run's canary token in captured data, plain or encoded.

Stealers rarely send credentials as plain text: they base64 them, hex them, gzip the
whole body, XOR it, or tunnel it through DNS labels in base32. Rather than guessing
how to decode arbitrary traffic, we encode the token every common way and search for
each form. The token is random and unique to the run, so any match is still proof
that this run's credentials left the package, never a coincidence.

Covered: plain (any case), URL-encoded, base64 and base64url at every byte alignment,
hex (any case), base32 at every alignment (any case, as DNS lowercases it), single-byte
XOR, and all of these again inside a gzip/zlib body or a base64 blob that holds one.
"""

from __future__ import annotations

import base64
import re
import zlib
from urllib.parse import unquote_to_bytes

MAX_SCAN = 1 << 20  # never inflate or scan more than 1 MiB per item
B64_BLOB = re.compile(rb"[A-Za-z0-9+/_-]{24,}={0,2}")


def _aligned(token: bytes, encode, group_in: int, group_out: int) -> list[bytes]:
    """The encoded token at each byte offset inside a longer string, trimmed to the
    characters that depend on token bytes alone."""
    forms = []
    for pad in range(group_in):
        enc = encode(b"\0" * pad + token + b"\0" * group_in).rstrip(b"=")
        start = -(-pad * group_out // group_in)                       # ceil
        end = (pad + len(token)) * group_out // group_in              # floor
        forms.append(enc[start:end])
    return forms


def forms(token: str) -> list[tuple[str, bytes, bool]]:
    """(encoding name, pattern, case-insensitive) for every form we search."""
    t = token.encode()
    out: list[tuple[str, bytes, bool]] = [("plain", t, True), ("hex", t.hex().encode(), True)]
    out += [("base64", f, False) for f in _aligned(t, base64.b64encode, 3, 4)]
    out += [("base64url", f, False) for f in _aligned(t, base64.urlsafe_b64encode, 3, 4)
            if f not in {p for _, p, _ in out}]
    out += [("base32", f, True) for f in _aligned(t, base64.b32encode, 5, 8)]
    out += [("xor", bytes(b ^ k for b in t), False) for k in range(1, 256)]
    return out


def _inflate(data: bytes) -> bytes | None:
    for wbits in (47, -15):  # 47: auto-detect gzip or zlib header; -15: raw deflate
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data[:MAX_SCAN], MAX_SCAN)
            if out:
                return out
        except zlib.error:
            continue
    return None


def _search(data: bytes, pats: list[tuple[str, bytes, bool]]) -> str | None:
    low = data.lower()
    for name, pat, nocase in pats:
        if (pat.lower() in low) if nocase else (pat in data):
            return name
    return None


def find(data: bytes | str | None, token: str) -> str | None:
    """How `data` carries `token` ("plain", "base64", "gzip+base64", ...), or None."""
    if not data or not token:
        return None
    raw = (data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data)[:MAX_SCAN]
    pats = forms(token)
    candidates: list[tuple[str, bytes]] = [("", raw)]
    if b"%" in raw:
        candidates.append(("url+", unquote_to_bytes(raw)))
    if b"\n" in raw or b"\\n" in raw:  # a key file sent as-is or JSON-encoded: line breaks can split the token
        candidates.append(("", re.sub(rb"\s+|\\[nr]", b"", raw)))
    seen = len(candidates)
    for prefix, blob in candidates[:seen]:
        if (inflated := _inflate(blob)) is not None:
            candidates.append((prefix + "gzip+", inflated))
        for m in B64_BLOB.finditer(blob):
            chunk = m.group(0)
            try:
                dec = base64.b64decode(chunk + b"=" * (-len(chunk) % 4), altchars=b"-_" if b"-" in chunk or b"_" in chunk else None)
            except ValueError:
                continue
            if (inflated := _inflate(dec)) is not None:
                candidates.append((prefix + "gzip+base64+", inflated))
    for prefix, blob in candidates:
        if (name := _search(blob, pats)) is not None:
            return (prefix + name).rstrip("+")
    return None


def find_in_name(name: str, token: str) -> str | None:
    """DNS names: data tunnelled across labels, so search with the dots removed too."""
    return find(name, token) or find(name.replace(".", ""), token)
