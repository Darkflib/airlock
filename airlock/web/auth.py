"""GitHub OAuth sign-in with an allowlist of GitHub logins.

Sessions are signed cookies (HMAC-SHA256). The allowlist is re-read on every
request, so removing a login from the file revokes access at once. Each session
carries an id: signing out revokes that one, "sign out everywhere" revokes every
session of the login issued so far (files `revoked_sessions` beside the allowlist).
Allowlist: AIRLOCK_ALLOWED_USERS (comma-separated) plus one login per line in
AIRLOCK_ALLOWED_USERS_FILE (default ~/.config/airlock/allowed_users).

Two more signed tokens share the session secret, each tagged with a kind `k` so
one can never stand in for another:
- share: read-only access to named runs (and a self-test), no sign-in needed. Each
  link is recorded in `shares.jsonl` and can be revoked on its own (`revoked_shares`).
- invite: whoever signs in with GitHub through it is appended to the allowlist
  file, tagged `# invite <id>`, so `scripts/allow.sh` still lists and revokes them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

SESSION_COOKIE = "airlock_session"
STATE_COOKIE = "airlock_oauth"
SESSION_TTL = 7 * 24 * 3600
STATE_TTL = 600
SHARE_COOKIE = "airlock_share"
SHARE_TTL = 60 * 24 * 3600
PUBLIC_PATHS = ("/auth/", "/static/", "/login", "/healthz", "/s/", "/api/me", "/api/github/webhook")


@dataclass
class AuthConfig:
    client_id: str
    client_secret: str
    session_secret: bytes
    public_url: str
    allowed: frozenset[str]
    allowed_file: Path | None = None
    secure_cookies: bool = True

    @classmethod
    def from_env(cls) -> "AuthConfig":
        missing = [k for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "AIRLOCK_SESSION_SECRET") if not os.environ.get(k)]
        if missing:
            raise RuntimeError(f"auth not configured, missing: {', '.join(missing)}")
        default_file = Path.home() / ".config" / "airlock" / "allowed_users"
        return cls(
            client_id=os.environ["GITHUB_CLIENT_ID"],
            client_secret=os.environ["GITHUB_CLIENT_SECRET"],
            session_secret=os.environ["AIRLOCK_SESSION_SECRET"].encode(),
            public_url=os.environ.get("AIRLOCK_PUBLIC_URL", "https://airlock.darkflib.dev").rstrip("/"),
            allowed=frozenset(u.strip().lower() for u in os.environ.get("AIRLOCK_ALLOWED_USERS", "").split(",") if u.strip()),
            allowed_file=Path(os.environ.get("AIRLOCK_ALLOWED_USERS_FILE", default_file)),
        )

    @property
    def revoked_file(self) -> Path | None:
        return self.allowed_file.with_name("revoked_invites") if self.allowed_file else None

    def _file(self, name: str) -> Path | None:
        return self.allowed_file.with_name(name) if self.allowed_file else None

    def _lines(self, name: str) -> list[str]:
        f = self._file(name)
        return f.read_text().splitlines() if f and f.exists() else []

    # share links: a ledger of what was minted, and the ids revoked since

    def record_share(self, share: dict) -> None:
        if f := self._file("shares.jsonl"):
            with f.open("a") as out:
                out.write(json.dumps({k: share.get(k) for k in ("id", "by", "runs", "selftest", "iat", "exp")}) + "\n")

    def revoke_share(self, share_id: str) -> None:
        if f := self._file("revoked_shares"):
            with f.open("a") as out:
                out.write(share_id + "\n")

    def share_revoked(self, share: dict) -> bool:
        # Links minted before ids existed can't be revoked one by one (rotate the secret for those).
        return bool(share.get("id")) and share["id"] in self._lines("revoked_shares")

    def shares(self) -> list[dict]:
        """Live share links: minted, unexpired and not revoked."""
        revoked, now = set(self._lines("revoked_shares")), time.time()
        out = []
        for line in self._lines("shares.jsonl"):
            try:
                s = json.loads(line)
            except json.JSONDecodeError:
                continue
            if s.get("exp", 0) > now and s.get("id") not in revoked:
                out.append(s)
        return out

    # sessions: "sid <id> <exp>" ends one session; "user <login> <ts>" ends all issued before ts

    def session_ok(self, session: dict) -> bool:
        sid, login, iat = session.get("sid"), session.get("login", "").lower(), session.get("iat", 0)
        if not sid:
            return False  # issued before sessions had ids: sign in again
        for line in self._lines("revoked_sessions"):
            kind, key, ts = (line.split() + ["", "", ""])[:3]
            if (kind == "sid" and key == sid) or (kind == "user" and key == login and iat <= float(ts or 0)):
                return False
        return True

    def revoke_session(self, session: dict, everywhere: bool = False) -> None:
        f = self._file("revoked_sessions")
        if not f:
            return
        now = time.time()
        keep = []
        for line in self._lines("revoked_sessions"):  # drop entries no live session can match any more
            kind, _, ts = (line.split() + ["", "", ""])[:3]
            expires = float(ts or 0) + (SESSION_TTL if kind == "user" else 0)
            if expires > now:
                keep.append(line)
        keep.append(f"user {session['login'].lower()} {now}" if everywhere else f"sid {session['sid']} {session['exp']}")
        f.write_text("\n".join(keep) + "\n")

    def admit(self, login: str, invite: dict) -> bool:
        """Add a login to the allowlist file through a valid, unrevoked invite with uses left."""
        if not self.allowed_file:
            return False
        inv = invite["id"]
        if self.revoked_file.exists() and inv in self.revoked_file.read_text().split():
            return False
        lines = self.allowed_file.read_text().splitlines() if self.allowed_file.exists() else []
        if sum(line.split("#", 1)[-1].split()[:2] == ["invite", inv] for line in lines if "#" in line) >= invite["max"]:
            return False
        with self.allowed_file.open("a") as f:
            f.write(f"{login}  # invite {inv} {time.strftime('%Y-%m-%d')}\n")
        return True

    def is_allowed(self, login: str) -> bool:
        login = login.lower()
        if login in self.allowed:
            return True
        if self.allowed_file and self.allowed_file.exists():
            for line in self.allowed_file.read_text().splitlines():
                if line.split("#")[0].strip().lower() == login:
                    return True
        return False


# --- signed tokens -------------------------------------------------------------

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(secret: bytes, payload: dict) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    mac = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def verify(secret: bytes, token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    body, mac = token.rsplit(".", 1)
    expected = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if payload.get("exp", 0) > time.time() else None


def share_payload(runs: list[str], selftest: str | None = None, by: str | None = None, ttl: int = SHARE_TTL) -> dict:
    now = time.time()
    return {"k": "share", "id": secrets.token_urlsafe(9), "by": by, "runs": runs, "selftest": selftest,
            "iat": now, "exp": now + ttl}


def share_token(secret: bytes, runs: list[str], selftest: str | None = None, ttl: int = SHARE_TTL) -> str:
    return sign(secret, share_payload(runs, selftest, ttl=ttl))


def session_token(secret: bytes, login: str, ttl: int = SESSION_TTL) -> str:
    now = time.time()
    return sign(secret, {"login": login, "sid": secrets.token_urlsafe(12), "iat": now, "exp": now + ttl})


def invite_token(secret: bytes, invite_id: str, days: float, max_uses: int) -> str:
    return sign(secret, {"k": "invite", "id": invite_id, "max": max_uses, "exp": time.time() + days * 86400})


def verify_kind(secret: bytes, token: str | None, kind: str | None) -> dict | None:
    """verify() plus the token kind; kind None means a session token (no `k`)."""
    payload = verify(secret, token)
    return payload if payload and payload.get("k") == kind else None


def share_allows(share: dict, method: str, path: str) -> bool:
    """A share token opens only reads of the runs and self-test it names."""
    if method not in ("GET", "HEAD"):
        return False
    allowed = set()
    for r in share.get("runs", []):
        allowed |= {f"/runs/{r}", f"/api/runs/{r}", f"/api/runs/{r}/events"}
    if share.get("selftest"):
        allowed |= {f"/selftests/{share['selftest']}", f"/api/selftests/{share['selftest']}"}
    return path in allowed


# --- GitHub ----------------------------------------------------------------------

async def github_login(cfg: AuthConfig, code: str) -> str:
    """Exchange an OAuth code for the user's GitHub login."""
    async with httpx.AsyncClient(timeout=15) as client:
        tok = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={"client_id": cfg.client_id, "client_secret": cfg.client_secret, "code": code,
                  "redirect_uri": f"{cfg.public_url}/auth/callback"})
        access = tok.json().get("access_token")
        if not access:
            raise PermissionError(tok.json().get("error", "token exchange failed"))
        user = await client.get("https://api.github.com/user", headers={
            "Authorization": f"Bearer {access}", "Accept": "application/vnd.github+json"})
        user.raise_for_status()
        return user.json()["login"]


GithubLogin = Callable[[AuthConfig, str], Awaitable[str]]


# --- wiring ------------------------------------------------------------------------

def current_user(request: Request) -> str | None:
    return getattr(request.state, "user", None)


def current_share(request: Request) -> dict | None:
    return getattr(request.state, "share", None)


def _safe_next(path: str | None) -> str:
    return path if path and path.startswith("/") and not path.startswith("//") else "/"


def credentials(cfg: AuthConfig, request: Request) -> tuple[str | None, dict | None]:
    """(signed-in login, share grant) from the request's cookies, each checked against the current
    allowlist and revocations. Re-run by long-lived responses (the event stream) to notice revocation."""
    session = verify_kind(cfg.session_secret, request.cookies.get(SESSION_COOKIE), None)
    user = (session["login"] if session and session.get("login") and cfg.is_allowed(session["login"])
            and cfg.session_ok(session) else None)
    share = verify_kind(cfg.session_secret, request.cookies.get(SHARE_COOKIE), "share")
    return user, (share if share and not cfg.share_revoked(share) else None)


def install(app, cfg: AuthConfig, exchange: GithubLogin = github_login) -> None:
    router = APIRouter()

    def cookie(resp: Response, name: str, value: str, max_age: int) -> None:
        resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=cfg.secure_cookies, samesite="lax", path="/")

    @router.get("/auth/login")
    async def login(next: str = "/", invite: str = ""):
        state = secrets.token_urlsafe(24)
        url = "https://github.com/login/oauth/authorize?" + urlencode({
            "client_id": cfg.client_id, "redirect_uri": f"{cfg.public_url}/auth/callback",
            "state": state, "allow_signup": "false"})
        resp = RedirectResponse(url, status_code=302)
        cookie(resp, STATE_COOKIE, sign(cfg.session_secret, {"state": state, "next": _safe_next(next), "invite": invite,
                                                             "exp": time.time() + STATE_TTL}), STATE_TTL)
        return resp

    @router.get("/auth/invite/{token}")
    async def invite(token: str):
        if not verify_kind(cfg.session_secret, token, "invite"):
            return RedirectResponse("/login?error=invite", status_code=302)
        return RedirectResponse("/auth/login?" + urlencode({"invite": token}), status_code=302)

    @router.get("/s/{token}")
    async def shared(token: str):
        share = verify_kind(cfg.session_secret, token, "share")
        if not share or cfg.share_revoked(share):
            return RedirectResponse("/login?error=share", status_code=302)
        target = f"/selftests/{share['selftest']}" if share.get("selftest") else f"/runs/{share['runs'][0]}"
        resp = RedirectResponse(target, status_code=302)
        cookie(resp, SHARE_COOKIE, token, int(share["exp"] - time.time()))
        return resp

    @router.get("/auth/callback")
    async def callback(request: Request, code: str = "", state: str = ""):
        saved = verify(cfg.session_secret, request.cookies.get(STATE_COOKIE))
        if not saved or saved.get("k") or not code or not hmac.compare_digest(saved.get("state", ""), state):
            return RedirectResponse("/login?error=state", status_code=302)
        try:
            login_name = await exchange(cfg, code)
        except Exception:  # noqa: BLE001 - any GitHub failure is a failed login
            return RedirectResponse("/login?error=github", status_code=302)
        inv = verify_kind(cfg.session_secret, saved.get("invite"), "invite")
        if not cfg.is_allowed(login_name) and not (inv and cfg.admit(login_name, inv)):
            resp = RedirectResponse(f"/login?error={'invite_closed' if inv else 'not_allowed'}", status_code=302)
            resp.delete_cookie(STATE_COOKIE, path="/")
            return resp
        resp = RedirectResponse(saved.get("next", "/"), status_code=302)
        cookie(resp, SESSION_COOKIE, session_token(cfg.session_secret, login_name), SESSION_TTL)
        resp.delete_cookie(STATE_COOKIE, path="/")
        return resp

    async def end(request: Request, everywhere: bool) -> Response:
        """Sign out: revoke this session (a copied cookie stops working too), or every session of the login."""
        session = verify_kind(cfg.session_secret, request.cookies.get(SESSION_COOKIE), None)
        if session and session.get("sid"):
            cfg.revoke_session(session, everywhere)
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @router.post("/auth/logout")
    async def logout(request: Request):
        return await end(request, everywhere=False)

    @router.post("/auth/logout-everywhere")
    async def logout_everywhere(request: Request):
        return await end(request, everywhere=True)

    app.include_router(router)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        user, share = credentials(cfg, request)
        if share:  # also for a signed-in guest: a share adds read access to its runs, never write
            request.state.share = share
        if user:
            request.state.user = user
            return await call_next(request)
        if share and share_allows(share, request.method, path):
            return await call_next(request)
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)
        if path.startswith("/api/"):
            return JSONResponse({"detail": "sign in required"}, status_code=401)
        return RedirectResponse("/login?" + urlencode({"next": path}), status_code=302)
