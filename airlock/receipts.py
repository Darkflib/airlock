"""Signed receipts: tamper-evident records of a run that anyone can check offline.

A run gets a `verdict` receipt when its verdict is in (the whole timeline up to that point,
the verdict, what was analysed) and a `decision` receipt when someone, or the automatic
rejection, decides it. Each receipt is:

  payload  canonical JSON text (sorted keys, no spaces, ASCII only), carried as a string so a
           verifier hashes and checks exactly these bytes without re-serialising anything
  sha256   hex SHA-256 of the payload's bytes
  key_id   first 16 hex digits of the SHA-256 of the raw Ed25519 public key
  sig      base64 Ed25519 signature over the payload's bytes

Each payload names the previous receipt's sha256 in `prev`, so the decision is chained to the
evidence it decided. The server's key is generated once on the host (scripts/install-web.sh),
like the session secret, so a host compromise could sign lies: receipts prove the record
hasn't changed since Airlock sealed it, not that the host was honest.
`python -m airlock.receipts keygen` prints a new seed; `airlock verify <bundle.json>` checks one."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FORMAT = "airlock-receipts/1"


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


def utc(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


@dataclass
class Signer:
    private: Ed25519PrivateKey

    @classmethod
    def from_seed(cls, seed_b64: str) -> "Signer":
        seed = base64.b64decode(seed_b64)
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_env(cls) -> "Signer | None":
        seed = os.environ.get("AIRLOCK_SIGNING_KEY", "").strip()
        return cls.from_seed(seed) if seed else None

    @property
    def public(self) -> bytes:
        return self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return key_id(self.public)

    def published(self) -> dict:
        return {"alg": "Ed25519", "key_id": self.key_id, "public_key": base64.b64encode(self.public).decode()}

    def seal(self, body: dict) -> dict:
        payload = canonical(body)
        data = payload.encode()
        return {"payload": payload, "sha256": hashlib.sha256(data).hexdigest(), "key_id": self.key_id,
                "sig": base64.b64encode(self.private.sign(data)).decode()}


def verify(bundle: dict, keys: dict[str, bytes]) -> list[dict]:
    """Check every receipt in a bundle against trusted public keys (key_id -> raw key). One result
    per receipt: {type, sha256, ok, problems}. Never trusts keys the bundle itself carries."""
    results, prev, run = [], None, None
    for i, rec in enumerate(bundle.get("receipts") or []):
        problems = []
        payload = rec.get("payload", "")
        data = payload.encode()
        if hashlib.sha256(data).hexdigest() != rec.get("sha256"):
            problems.append("payload doesn't match its sha256: it was changed after sealing")
        key = keys.get(rec.get("key_id", ""))
        if key is None:
            problems.append(f"signed by key {rec.get('key_id')!r}, which isn't one you trust")
        else:
            try:
                Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(rec.get("sig", "")), data)
            except (InvalidSignature, ValueError):
                problems.append("signature doesn't verify")
        try:
            body = json.loads(payload)
        except ValueError:
            body = {}
            problems.append("payload isn't JSON")
        if body.get("prev") != prev:
            problems.append("chain broken: prev doesn't name the receipt before it" if i
                            else "the first receipt must have prev null")
        if run is not None and body.get("run") != run:
            problems.append("receipt is for a different run")
        run, prev = body.get("run"), rec.get("sha256")
        results.append({"type": body.get("type"), "sha256": rec.get("sha256"), "ok": not problems,
                        "problems": problems})
    return results


def keygen() -> str:
    return base64.b64encode(os.urandom(32)).decode()


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["keygen"]:
        print(keygen())
    elif sys.argv[1:] == ["public"]:  # the public half of AIRLOCK_SIGNING_KEY, for pinning
        print(json.dumps(Signer.from_env().published()))
    else:
        sys.exit("usage: python -m airlock.receipts keygen | public")
