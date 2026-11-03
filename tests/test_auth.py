import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web import auth
from airlock.web.app import create_app
from tests.test_web import fake_analyse, wait_done

SECRET = b"test-secret"


def cfg(tmp_path, allowed=("Darkflib",)):
    f = tmp_path / "allowed_users"
    f.write_text("# judges\nsome-judge\n")
    return auth.AuthConfig(client_id="cid", client_secret="csecret", session_secret=SECRET,
                           public_url="https://airlock.test", allowed=frozenset(a.lower() for a in allowed),
                           allowed_file=f, secure_cookies=False)


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    def make(login="Darkflib"):
        async def exchange(_cfg, code):
            assert code == "good-code"
            return login
        app = create_app(store=Store(tmp_path / "a.db"), analyse=fake_analyse, auth=cfg(tmp_path), exchange=exchange)
        return TestClient(app, base_url="http://airlock.test")
    return make


def sign_in(c):
    r = c.get("/auth/login", follow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["client_id"] == ["cid"] and q["redirect_uri"] == ["https://airlock.test/auth/callback"]
    return c.get("/auth/callback", params={"code": "good-code", "state": q["state"][0]}, follow_redirects=False)


def test_signed_out_is_redirected_or_401(make_client):
    with make_client() as c:
        assert c.get("/api/runs").status_code == 401
        r = c.get("/runs/abc", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"].startswith("/login?next=")
        assert c.get("/login").status_code == 200
        assert c.get("/static/style.css").status_code == 200


def test_allowed_user_signs_in_and_is_recorded(make_client):
    with make_client() as c:
        r = sign_in(c)
        assert r.status_code == 302 and r.headers["location"] == "/"
        assert c.get("/api/me").json()["login"] == "Darkflib"
        run_id = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        wait_done(c, run_id)
        d = c.post(f"/api/runs/{run_id}/decision", json={"decision": "rejected"}).json()
        assert d["submitted_by"] == "Darkflib" and d["decided_by"] == "Darkflib"


def test_allowlist_file_user_can_sign_in(make_client):
    with make_client(login="Some-Judge") as c:
        assert sign_in(c).headers["location"] == "/"


def test_unlisted_user_is_refused(make_client):
    with make_client(login="random-person") as c:
        r = sign_in(c)
        assert r.headers["location"] == "/login?error=not_allowed"
        assert c.get("/api/runs").status_code == 401


def test_bad_state_is_refused(make_client):
    with make_client() as c:
        c.get("/auth/login", follow_redirects=False)
        r = c.get("/auth/callback", params={"code": "good-code", "state": "forged"}, follow_redirects=False)
        assert r.headers["location"] == "/login?error=state"


def test_removing_user_from_allowlist_revokes_session(make_client, tmp_path):
    with make_client(login="some-judge") as c:
        sign_in(c)
        assert c.get("/api/runs").status_code == 200
        (tmp_path / "allowed_users").write_text("")
        assert c.get("/api/runs").status_code == 401


def test_tampered_or_expired_tokens_fail():
    tok = auth.sign(SECRET, {"login": "x", "exp": time.time() + 60})
    assert auth.verify(SECRET, tok)["login"] == "x"
    assert auth.verify(b"other", tok) is None
    assert auth.verify(SECRET, tok[:-2] + "AA") is None
    assert auth.verify(SECRET, auth.sign(SECRET, {"login": "x", "exp": time.time() - 1})) is None


def test_open_redirect_is_blocked():
    assert auth._safe_next("//evil.com") == "/"
    assert auth._safe_next("https://evil.com") == "/"
    assert auth._safe_next("/runs/1") == "/runs/1"


def test_app_factory_fails_closed(monkeypatch):
    for k in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "AIRLOCK_SESSION_SECRET"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError, match="auth not configured"):
        auth.AuthConfig.from_env()
