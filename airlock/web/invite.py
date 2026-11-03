"""Invite links for people whose GitHub logins we don't know in advance (judges).

Run on the host with the web env loaded (scripts/invite.sh does this):
  python -m airlock.web.invite new [--days 30] [--max 50] [--id lablab]
  python -m airlock.web.invite list
  python -m airlock.web.invite revoke <id>   # stops new sign-ups and removes everyone it admitted
"""

from __future__ import annotations

import argparse
import secrets
from collections import Counter

from .auth import AuthConfig, invite_token


def admitted(cfg: AuthConfig) -> Counter:
    """Logins admitted per invite id, from the `# invite <id>` tags in the allowlist file."""
    lines = cfg.allowed_file.read_text().splitlines() if cfg.allowed_file.exists() else []
    return Counter(line.split("#", 1)[1].split()[1] for line in lines
                   if "#" in line and line.split("#", 1)[1].split()[:1] == ["invite"])


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="airlock.web.invite")
    sub = ap.add_subparsers(dest="cmd", required=True)
    new = sub.add_parser("new")
    new.add_argument("--days", type=float, default=30)
    new.add_argument("--max", type=int, default=50, help="most accounts this link can admit")
    new.add_argument("--id", default=None, help="label for the invite (default: random)")
    sub.add_parser("list")
    rev = sub.add_parser("revoke")
    rev.add_argument("id")
    args = ap.parse_args(argv)
    cfg = AuthConfig.from_env()

    if args.cmd == "new":
        inv = args.id or secrets.token_hex(3)
        print(f"{cfg.public_url}/auth/invite/{invite_token(cfg.session_secret, inv, args.days, args.max)}")
        print(f"invite {inv}: up to {args.max} accounts, valid {args.days:g} days")
    elif args.cmd == "list":
        revoked = set(cfg.revoked_file.read_text().split()) if cfg.revoked_file.exists() else set()
        for inv, n in sorted(admitted(cfg).items()):
            print(f"{inv}\t{n} admitted{'  (revoked)' if inv in revoked else ''}")
    else:
        with cfg.revoked_file.open("a") as f:
            f.write(args.id + "\n")
        lines = cfg.allowed_file.read_text().splitlines(keepends=True)
        keep = [ln for ln in lines if not ("#" in ln and ln.split("#", 1)[1].split()[:2] == ["invite", args.id])]
        cfg.allowed_file.write_text("".join(keep))
        print(f"revoked invite {args.id}; removed {len(lines) - len(keep)} accounts")


if __name__ == "__main__":
    main()
