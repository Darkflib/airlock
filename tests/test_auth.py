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
    if not f.exists():  # keep what a test (or an invite) wrote
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


def test_share_link_opens_only_that_run_read_only(make_client):
    with make_client() as c:
        sign_in(c)
        a = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        b = c.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        wait_done(c, a), wait_done(c, b)
        url = c.post(f"/api/runs/{a}/share").json()["url"]
        assert url.startswith("https://airlock.test/s/")
    with make_client() as anon:  # fresh client: no session cookie
        r = anon.get(urlparse(url).path, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == f"/runs/{a}"
        assert anon.get(f"/runs/{a}").status_code == 200
        assert anon.get(f"/api/runs/{a}").json()["id"] == a
        assert "event: done" in anon.get(f"/api/runs/{a}/events").text
        assert anon.get("/api/me").json()["share"] is True
        assert anon.get(f"/api/runs/{b}").status_code == 401          # another run
        assert anon.get("/api/runs").status_code == 401               # the run list
        assert anon.post(f"/api/runs/{a}/decision", json={"decision": "approved"}).status_code == 401
        assert anon.post("/api/runs", data={"spec": "left-pad"}).status_code == 401


def test_bad_or_wrong_kind_tokens_are_refused(make_client):
    session = auth.sign(SECRET, {"login": "Darkflib", "exp": time.time() + 60})
    share = auth.share_token(SECRET, ["r1"])
    with make_client() as c:
        assert c.get(f"/s/{session}", follow_redirects=False).headers["location"] == "/login?error=share"
        assert c.get(f"/auth/invite/{share}", follow_redirects=False).headers["location"] == "/login?error=invite"
        c.cookies.set(auth.SESSION_COOKIE, share)   # a share token is not a session
        assert c.get("/api/runs").status_code == 401
        c.cookies.set(auth.SESSION_COOKIE, auth.invite_token(SECRET, "x", 1, 5))
        assert c.get("/api/runs").status_code == 401


def invite_sign_in(c, token):
    r = c.get(f"/auth/invite/{token}", follow_redirects=False)
    r = c.get(r.headers["location"], follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    return c.get("/auth/callback", params={"code": "good-code", "state": q["state"][0]}, follow_redirects=False)


def test_invite_admits_unknown_judge_and_tags_them(make_client, tmp_path):
    token = auth.invite_token(SECRET, "lablab", days=1, max_uses=1)
    with make_client(login="New-Judge") as c:
        assert invite_sign_in(c, token).headers["location"] == "/"
        assert c.get("/api/me").json()["login"] == "New-Judge"
    assert "New-Judge  # invite lablab" in (tmp_path / "allowed_users").read_text()
    with make_client(login="second-judge") as c:   # max_uses=1: used up
        assert invite_sign_in(c, token).headers["location"] == "/login?error=invite_closed"


def test_revoked_or_expired_invite_admits_nobody(make_client, tmp_path):
    (tmp_path / "revoked_invites").write_text("gone\n")
    with make_client(login="late-judge") as c:
        r = invite_sign_in(c, auth.invite_token(SECRET, "gone", days=1, max_uses=9))
        assert r.headers["location"] == "/login?error=invite_closed"
        r = c.get(f"/auth/invite/{auth.invite_token(SECRET, 'old', days=-1, max_uses=9)}", follow_redirects=False)
        assert r.headers["location"] == "/login?error=invite"
    assert "late-judge" not in (tmp_path / "allowed_users").read_text()


def test_invite_cli_revoke_removes_admitted_accounts(tmp_path, monkeypatch, capsys):
    from airlock.web import invite
    f = tmp_path / "allowed_users"
    f.write_text("darkflib\njudge-a  # invite lablab 2026-11-04\njudge-b  # invite other 2026-11-04\n")
    for k, v in {"GITHUB_CLIENT_ID": "c", "GITHUB_CLIENT_SECRET": "s", "AIRLOCK_SESSION_SECRET": "x",
                 "AIRLOCK_ALLOWED_USERS_FILE": str(f)}.items():
        monkeypatch.setenv(k, v)
    invite.main(["revoke", "lablab"])
    assert f.read_text() == "darkflib\njudge-b  # invite other 2026-11-04\n"
    assert "lablab" in (tmp_path / "revoked_invites").read_text()
    invite.main(["new", "--days", "2", "--max", "3", "--id", "x"])
    link = capsys.readouterr().out.splitlines()[-2]
    payload = auth.verify(b"x", link.rsplit("/", 1)[1])
    assert payload["k"] == "invite" and payload["max"] == 3


def test_guests_are_capped_owners_are_not(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))

    def client(login, store):
        async def exchange(_cfg, code):
            return login
        app = create_app(store=store, analyse=fake_analyse, auth=cfg(tmp_path), exchange=exchange,
                         user_daily=2, global_daily=3)
        return TestClient(app, base_url="http://airlock.test")

    store = Store(tmp_path / "q.db")
    with client("some-judge", store) as c:
        sign_in(c)
        assert [c.post("/api/runs", data={"spec": "left-pad"}).status_code for _ in range(3)] == [200, 200, 429]
    with client("Darkflib", store) as c:   # owner: no cap
        sign_in(c)
        assert all(c.post("/api/runs", data={"spec": "left-pad"}).status_code == 200 for _ in range(4))
    (tmp_path / "allowed_users").write_text("some-judge\nother-judge\n")
    with client("other-judge", store) as c:  # 2 guest runs so far + 1 = global cap of 3
        sign_in(c)
        assert c.post("/api/runs", data={"spec": "left-pad"}).status_code == 200
        r = c.post("/api/runs", data={"spec": "left-pad"})
        assert r.status_code == 429 and "guests" in r.json()["detail"]


def test_selftest_share_link_opens_its_probe_runs(make_client, tmp_path, monkeypatch):
    from airlock.web import app as app_module
    d = tmp_path / "fx"
    d.mkdir()
    for f, _, _ in app_module.SELFTEST:
        (d / f).write_bytes(b"\x1f\x8b")
    monkeypatch.setattr(app_module, "FIXTURES", d)
    with make_client() as c:
        sign_in(c)
        test_id = c.post("/api/selftests").json()["id"]
        probes = c.get(f"/api/selftests/{test_id}").json()["probes"]
        url = c.post(f"/api/selftests/{test_id}/share").json()["url"]
    with make_client() as anon:
        assert anon.get(urlparse(url).path, follow_redirects=False).headers["location"] == f"/selftests/{test_id}"
        assert anon.get(f"/api/selftests/{test_id}").status_code == 200
        assert all(anon.get(f"/api/runs/{p['run_id']}").status_code == 200 for p in probes)
        assert anon.post("/api/selftests").status_code == 401



class FakeGitHub:
    def __init__(self):
        self.posts = []

    async def status(self, *a):
        self.posts.append(("status", a))

    async def comment(self, *a):
        self.posts.append(("comment", a))
        return "https://github.test/c/1"


def test_guests_cannot_act_for_owners_or_each_other(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    store, gh = Store(tmp_path / "g.db"), FakeGitHub()
    (tmp_path / "allowed_users").write_text("judge-a\njudge-b\n")

    def client(login):
        async def exchange(_cfg, code):
            return login
        c = TestClient(create_app(store=store, analyse=fake_analyse, auth=cfg(tmp_path), exchange=exchange, github=gh),
                       base_url="http://airlock.test")
        return c

    with client("Darkflib") as owner:
        sign_in(owner)
        owner_run = owner.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        wait_done(owner, owner_run)
        store.update_run(owner_run, meta={"kind": "pr", "owner": "Darkflib", "repo": "airlock-demo", "number": 3,
                                          "head_sha": "abc"})
        private = owner.post("/api/runs", files={"file": ("acme-internal.tgz", b"\x1f\x8b" + b"\0" * 20,
                                                          "application/gzip")}).json()["id"]
        wait_done(owner, private)
    with client("judge-a") as a:
        sign_in(a)
        a_run = a.post("/api/runs", data={"spec": "left-pad"}).json()["id"]
        wait_done(a, a_run)
        assert a.get(f"/api/runs/{owner_run}").status_code == 200          # owners' demo runs are visible
        assert a.get(f"/api/runs/{private}").status_code == 404            # an owner's upload is not
        assert a.get(f"/api/runs/{private}/events").status_code == 404
        assert private not in [r["id"] for r in a.get("/api/runs").json()]
        assert a.post(f"/api/runs/{owner_run}/decision", json={"decision": "approved"}).status_code == 403
        assert a.post(f"/api/runs/{owner_run}/share").status_code == 403
        assert a.post(f"/api/runs/{a_run}/decision", json={"decision": "rejected"}).status_code == 200
        assert a.post(f"/api/runs/{a_run}/share").status_code == 200
        r = a.post("/api/runs", data={"spec": "https://github.com/Darkflib/airlock/pull/1"})
        assert r.status_code == 403 and "airlock-demo" in r.json()["detail"]
    assert gh.posts == []   # nothing was posted on the owner's PR
    with client("judge-b") as b:
        sign_in(b)
        assert b.get(f"/api/runs/{a_run}").status_code == 404              # another guest's run
        assert a_run not in [r["id"] for r in b.get("/api/runs").json()]
        assert owner_run in [r["id"] for r in b.get("/api/runs").json()]
    with client("Darkflib") as owner:
        sign_in(owner)
        assert owner.get(f"/api/runs/{a_run}").status_code == 200          # owners see everything


def test_vm_names_stay_unique_for_long_labels(monkeypatch):
    monkeypatch.setenv("AIRLOCK_SINKHOLE", "off")
    from airlock.events import EventLog
    from airlock.sandbox import Workspace
    a, b = (Workspace(EventLog(), label="x" * 80) for _ in range(2))
    assert a.name != b.name and len(a.name) <= 63
