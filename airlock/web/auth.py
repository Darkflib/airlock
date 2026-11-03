"""GitHub OAuth sign-in with an allowlist of GitHub logins.

Sessions are stateless signed cookies (HMAC-SHA256). The allowlist is re-read
on every request, so removing a login from the file revokes access at once.
Allowlist: AIRLOCK_ALLOWED_USERS (comma-separated) plus one login per line in
AIRLOCK_ALLOWED_USERS_FILE (default ~/.config/airlock/allowed_users).
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
PUBLIC_PATHS = ("/auth/", "/static/", "/login", "/healthz")


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


def _safe_next(path: str | None) -> str:
    return path if path and path.startswith("/") and not path.startswith("//") else "/"


def install(app, cfg: AuthConfig, exchange: GithubLogin = github_login) -> None:
    router = APIRouter()

    def cookie(resp: Response, name: str, value: str, max_age: int) -> None:
        resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=cfg.secure_cookies, samesite="lax", path="/")

    @router.get("/auth/login")
    async def login(next: str = "/"):
        state = secrets.token_urlsafe(24)
        url = "https://github.com/login/oauth/authorize?" + urlencode({
            "client_id": cfg.client_id, "redirect_uri": f"{cfg.public_url}/auth/callback",
            "state": state, "allow_signup": "false"})
        resp = RedirectResponse(url, status_code=302)
        cookie(resp, STATE_COOKIE, sign(cfg.session_secret, {"state": state, "next": _safe_next(next),
                                                             "exp": time.time() + STATE_TTL}), STATE_TTL)
        return resp

    @router.get("/auth/callback")
    async def callback(request: Request, code: str = "", state: str = ""):
        saved = verify(cfg.session_secret, request.cookies.get(STATE_COOKIE))
        if not saved or not code or not hmac.compare_digest(saved["state"], state):
            return RedirectResponse("/login?error=state", status_code=302)
        try:
            login_name = await exchange(cfg, code)
        except Exception:  # noqa: BLE001 - any GitHub failure is a failed login
            return RedirectResponse("/login?error=github", status_code=302)
        if not cfg.is_allowed(login_name):
            resp = RedirectResponse("/login?error=not_allowed", status_code=302)
            resp.delete_cookie(STATE_COOKIE, path="/")
            return resp
        resp = RedirectResponse(saved.get("next", "/"), status_code=302)
        cookie(resp, SESSION_COOKIE, sign(cfg.session_secret, {"login": login_name, "exp": time.time() + SESSION_TTL}),
               SESSION_TTL)
        resp.delete_cookie(STATE_COOKIE, path="/")
        return resp

    @router.post("/auth/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    app.include_router(router)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        session = verify(cfg.session_secret, request.cookies.get(SESSION_COOKIE))
        if session and cfg.is_allowed(session["login"]):
            request.state.user = session["login"]
            return await call_next(request)
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)
        if path.startswith("/api/"):
            return JSONResponse({"detail": "sign in required"}, status_code=401)
        return RedirectResponse("/login?" + urlencode({"next": path}), status_code=302)
