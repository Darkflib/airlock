import base64
import codecs
import gzip
import json
import secrets
import zlib
from urllib.parse import quote

import pytest

from airlock import tokenmatch
from airlock.events import WatchTranslator, describe, events_from_sinkhole

TOKEN = "AIRLOCKCANARY0123456789ABCDEF"
OTHER = "AIRLOCKCANARYFEDCBA9876543210"
NPMRC = f"//registry.npmjs.org/:_authToken=npm_{TOKEN}\n".encode()


def b64(b: bytes) -> bytes:
    return base64.b64encode(b)


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"{\"k\":\"", b"npm_"])
@pytest.mark.parametrize("name,encode", [
    ("plain", lambda b: b),
    ("base64", b64),
    ("base64url", base64.urlsafe_b64encode),
    ("hex", lambda b: b.hex().encode()),
    ("hex", lambda b: b.hex().upper().encode()),
    ("base32", base64.b32encode),
    ("base32", lambda b: base64.b32encode(b).lower()),
    ("xor", lambda b: bytes(x ^ 0x5A for x in b)),
])
def test_each_encoding_at_every_alignment(prefix, name, encode):
    # the token sits at different offsets inside a longer secret, so every alignment is exercised
    got = tokenmatch.find(encode(prefix + NPMRC), TOKEN)
    # base64url differs from base64 only in '+' and '/'; when the token's encoding has neither, both name it base64
    assert got == name or (name == "base64url" and got == "base64")


def test_case_insensitive_plain_and_url_encoded():
    assert tokenmatch.find(NPMRC.lower(), TOKEN) == "plain"
    every_byte = "".join(f"%{b:02X}" for b in NPMRC)  # each byte percent-encoded, so no plain run survives
    assert tokenmatch.find(every_byte, TOKEN) == "url+plain"


def test_compressed_bodies():
    assert tokenmatch.find(gzip.compress(NPMRC), TOKEN) == "gzip+plain"
    assert tokenmatch.find(zlib.compress(b64(NPMRC)), TOKEN) == "gzip+base64"
    assert tokenmatch.find(b'{"d":"' + b64(gzip.compress(NPMRC)) + b'"}', TOKEN) == "gzip+base64+plain"


def test_dns_labels_split_across_dots():
    enc = base64.b32encode(NPMRC).decode().lower().rstrip("=")
    name = ".".join(enc[i:i + 30] for i in range(0, len(enc), 30)) + ".t.evil.invalid"
    assert tokenmatch.find_in_name(name, TOKEN) == "base32"
    assert tokenmatch.find_in_name(f"{TOKEN.lower()}.t.evil.invalid", TOKEN) == "plain"


@pytest.mark.parametrize("data", [
    b"", b"hello world", NPMRC.replace(TOKEN.encode(), OTHER.encode()),
    b64(NPMRC.replace(TOKEN.encode(), OTHER.encode())), gzip.compress(b"nothing here"),
    secrets.token_bytes(8000), json.dumps({"user": "node", "home": "/home/node"}).encode(),
])
def test_no_false_proof(data):
    assert tokenmatch.find(data, TOKEN) is None


def test_another_runs_token_is_never_this_runs():
    # every form of OTHER must miss TOKEN; tokens differ, so none of the patterns overlap
    for _, pat, _ in tokenmatch.forms(OTHER):
        assert tokenmatch.find(pat, TOKEN) is None


def test_sinkhole_proof_from_encoded_body_url_and_raw_bytes():
    rec = {"host": "t.evil.invalid", "method": "POST", "url": "https://t.evil.invalid/c", "bytes": 80}
    [(kind, summary, data)] = events_from_sinkhole([{**rec, "body": b64(NPMRC).decode()}], TOKEN)
    assert kind == "canary_exfil" and data["proven"] and data["encoding"] == "base64"
    assert "(base64-encoded)" in summary

    [(kind, _, data)] = events_from_sinkhole([{**rec, "body": "", "url": f"https://t.evil.invalid/c?d={NPMRC.hex()}"}], TOKEN)
    assert kind == "canary_exfil" and data["encoding"] == "hex"

    # a raw gzip body arrives mangled as text; the raw bytes still prove it
    raw = gzip.compress(NPMRC)
    mangled = raw.decode("latin-1").encode().decode("utf-8", "replace")
    [(kind, _, data)] = events_from_sinkhole([{**rec, "body": mangled, "raw_b64": b64(raw).decode()}], TOKEN)
    assert kind == "canary_exfil" and data["proven"] and data["encoding"] == "gzip+plain"


def test_plain_sinkhole_summary_is_unchanged():
    [(_, summary, data)] = events_from_sinkhole([{"host": "h", "method": "POST", "url": "u", "body": NPMRC.decode()}], TOKEN)
    assert data["encoding"] == "plain" and "carried the canary credentials: captured" in summary


def test_watcher_flags_encoded_token_in_dns_name():
    name = codecs.encode(NPMRC, "hex").decode()[:60] + "." + codecs.encode(NPMRC, "hex").decode()[60:] + ".x.invalid"
    t = WatchTranslator(("registry.npmjs.org",), TOKEN)
    out = t.feed(json.dumps({"ev": "dns", "name": name, "pid": 42, "uid": 1000, "exe": "/usr/bin/node"}) + "\n")
    exfil = [e for e in out if e[0] == "canary_exfil"]
    assert exfil and exfil[0][2]["encoding"] == "hex" and "(hex-encoded)" in exfil[0][1]


def test_describe():
    assert describe("plain") == "as plain text"
    assert describe("gzip+base64+plain") == "compressed, base64-encoded"


def test_ssh_key_canary_sent_as_is_is_proof():
    # the same construction as Workspace._seed_canaries: the token sits inside the key's base64 body
    for pad in range(3):
        blob = base64.b64encode(b"openssh-key-v1\0" + b"k" * (31 + pad) + TOKEN.encode() + b"z" * 170).decode()
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(blob[i:i + 70] for i in range(0, len(blob), 70))
        assert tokenmatch.find(key, TOKEN) == "base64"                      # sent as-is, line breaks and all
        assert tokenmatch.find(json.dumps({"k": key}), TOKEN) == "base64"   # JSON-encoded: literal \\n
