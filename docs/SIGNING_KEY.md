# Receipt signing key

Every verdict and decision on https://airlock.darkflib.dev is signed with this Ed25519 key (see `airlock/receipts.py`). It's published here, in the repository's history, so you can check a receipt without trusting the server that hands you both the receipt and the key.

| Key id | Public key (base64, raw 32 bytes) | In use from |
| --- | --- | --- |
| `475879ded052c017` | `AsxXXzQXoivBBDkkW94zAkkbZ+auBhE9CaVsrF5wZrw=` | 5 Nov 2026, 21:33 UTC |

The key id is the first 16 hex digits of the SHA-256 of the raw public key. The `/verify` page shows the id it checks against; it should match the table.

Check a downloaded bundle offline:

```sh
uv run airlock verify airlock-<run>.receipts.json --key AsxXXzQXoivBBDkkW94zAkkbZ+auBhE9CaVsrF5wZrw=
```

The private key is generated once on the host (`scripts/install-web.sh`) and never leaves it. If the host is rebuilt without `~/.config/airlock`, it gets a new key: add a row here, and keep the old one, since receipts signed before still verify against it. A receipt shows its record hasn't changed since the host sealed it; it can't show the host was honest.
