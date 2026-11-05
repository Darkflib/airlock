"""Who may do what, as one table: every kind of viewer against every route that reads or changes a run,
a self-test or a share link. The rules live in several places (the auth middleware, `can_read`, each
route's ownership check); this is the one place that states them together, so a change to any of them
that moves a cell fails here.

Viewers:
  anon      signed out
  share_D   signed out, holding a share link to D
  share_S   signed out, holding a share link to self-test S (whose probe run is D)
  owner     Darkflib, in AIRLOCK_ALLOWED_USERS
  guest_a   judge-a, on the allowlist file
  guest_b   judge-b, on the allowlist file
  a_shareP  judge-a, also holding a share link to P

Runs:
  D  the owner's demo run (a self-test probe, npm package or demo-repo PR)
  P  the owner's private run (an upload)
  A  judge-a's run
  B  judge-b's run
"""
import time

import pytest
from fastapi.testclient import TestClient

from airlock.store import Store
from airlock.web import auth
from airlock.web.app import create_app
from tests.test_auth import SECRET, cfg
from tests.test_web import fake_analyse

RUNS = "DPAB"
VIEWERS = ("anon", "share_D", "share_S", "owner", "guest_a", "guest_b", "a_shareP")

# Reading a run through the API (GET /api/runs/{id}, and its event stream).
READ = {          # D    P    A    B
    "anon":     (401, 401, 401, 401),
    "share_D":  (200, 401, 401, 401),
    "share_S":  (200, 401, 401, 401),
    "owner":    (200, 200, 200, 200),
    "guest_a":  (200, 404, 200, 404),
    "guest_b":  (200, 404, 404, 200),
    "a_shareP": (200, 200, 200, 404),
}
# The run page (/runs/{id}): signed-out viewers are sent to sign in, others match READ.
PAGE = {          # D    P    A    B
    "anon":     (302, 302, 302, 302),
    "share_D":  (200, 302, 302, 302),
    "share_S":  (200, 302, 302, 302),
    "owner":    (200, 200, 200, 200),
    "guest_a":  (200, 404, 200, 404),
    "guest_b":  (200, 404, 404, 200),
    "a_shareP": (200, 200, 200, 404),
}
# Deciding, sharing, and posting a decision again: only an owner or whoever submitted the run.
# A share link never grants a change, even to a signed-in guest. 404 where the run isn't readable.
ACT = {           # D    P    A    B
    "anon":     (401, 401, 401, 401),
    "share_D":  (401, 401, 401, 401),
    "share_S":  (401, 401, 401, 401),
    "owner":    (200, 200, 200, 200),
    "guest_a":  (403, 404, 200, 404),
    "guest_b":  (403, 404, 404, 200),
    "a_shareP": (403, 403, 200, 404),
}
# What each viewer's run list shows.
LISTED = {"owner": "DPAB", "guest_a": "DA", "guest_b": "DB", "a_shareP": "DPA"}
# The self-test S (started by the owner): its API and page, and minting a share link to it.
SELFTEST = {      # read  page  share
    "anon":     (401, 302, 401),
    "share_D":  (401, 302, 401),
    "share_S":  (200, 200, 401),
    "owner":    (200, 200, 200),
    "guest_a":  (200, 200, 403),
    "guest_b":  (200, 200, 403),
    "a_shareP": (200, 200, 403),
}
# Starting a run or a self-test, and listing share links: any signed-in account.
SIGNED_IN = {v: (200 if v in ("owner", "guest_a", "guest_b", "a_shareP") else 401) for v in VIEWERS}


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A fresh store with D, P, A, B and S, and a signed client for each viewer."""
    monkeypatch.setenv("AIRLOCK_DATA", str(tmp_path))
    (tmp_path / "allowed_users").write_text("judge-a\njudge-b\n")
    config = cfg(tmp_path)
    store = Store(tmp_path / "m.db")
    for run_id, user, demo in (("D", "Darkflib", True), ("P", "Darkflib", False),
                               ("A", "judge-a", False), ("B", "judge-b", False)):
        store.create_run(run_id, f"run {run_id}", submitted_by=user, demo=demo)
        store.update_run(run_id, status="done", verdict="benign", finished=time.time())
    store.create_selftest("S", [{"run_id": "D", "label": "probe", "expect": "benign"}], "Darkflib")
    app = create_app(store=store, analyse=fake_analyse, auth=config)

    def share(runs, selftest=None, by="Darkflib"):
        payload = auth.share_payload(runs, selftest, by)
        config.record_share(payload)
        return auth.sign(SECRET, payload), payload["id"]

    def session(login):
        return auth.session_token(SECRET, login)

    shares = {"D": share(["D"]), "S": share(["D"], "S"), "P": share(["P"])}
    cookies = {
        "anon": {},
        "share_D": {auth.SHARE_COOKIE: shares["D"][0]},
        "share_S": {auth.SHARE_COOKIE: shares["S"][0]},
        "owner": {auth.SESSION_COOKIE: session("Darkflib")},
        "guest_a": {auth.SESSION_COOKIE: session("judge-a")},
        "guest_b": {auth.SESSION_COOKIE: session("judge-b")},
        "a_shareP": {auth.SESSION_COOKIE: session("judge-a"), auth.SHARE_COOKIE: shares["P"][0]},
    }
    with TestClient(app, base_url="http://airlock.test", follow_redirects=False) as c:
        def as_(viewer):
            c.cookies.clear()
            for k, v in cookies[viewer].items():
                c.cookies.set(k, v)
            return c
        yield as_, store, {k: v[1] for k, v in shares.items()}


def cells(table):
    return [(v, r, table[v][i]) for v in VIEWERS for i, r in enumerate(RUNS)]


@pytest.mark.parametrize("viewer,run,code", cells(READ))
def test_read(world, viewer, run, code):
    as_, _, _ = world
    assert as_(viewer).get(f"/api/runs/{run}").status_code == code
    assert as_(viewer).get(f"/api/runs/{run}/events").status_code == code


@pytest.mark.parametrize("viewer,run,code", cells(PAGE))
def test_page(world, viewer, run, code):
    as_, _, _ = world
    r = as_(viewer).get(f"/runs/{run}")
    assert r.status_code == code
    if code == 302:
        assert r.headers["location"].startswith("/login")


@pytest.mark.parametrize("viewer,run,code", cells(ACT))
def test_decide(world, viewer, run, code):
    as_, store, _ = world
    assert as_(viewer).post(f"/api/runs/{run}/decision", json={"decision": "rejected"}).status_code == code
    assert (store.get_run(run)["decision"] == "rejected") == (code == 200)


@pytest.mark.parametrize("viewer,run,code", cells(ACT))
def test_share_run(world, viewer, run, code):
    as_, _, _ = world
    assert as_(viewer).post(f"/api/runs/{run}/share").status_code == code


@pytest.mark.parametrize("viewer,run,code", cells(ACT))
def test_post_again(world, viewer, run, code):
    as_, _, _ = world
    # None of these is a decided PR run, so a viewer allowed to post is told there is nothing to post
    assert as_(viewer).post(f"/api/runs/{run}/post").status_code == (409 if code == 200 else code)


@pytest.mark.parametrize("viewer", VIEWERS)
def test_run_list(world, viewer):
    as_, _, _ = world
    r = as_(viewer).get("/api/runs")
    if viewer not in LISTED:
        assert r.status_code == 401
        return
    assert sorted(x["id"] for x in r.json()) == sorted(LISTED[viewer])


@pytest.mark.parametrize("viewer", VIEWERS)
def test_selftest(world, viewer):
    as_, _, _ = world
    read, page, share = SELFTEST[viewer]
    assert as_(viewer).get("/api/selftests/S").status_code == read
    assert as_(viewer).get("/selftests/S").status_code == page
    assert as_(viewer).post("/api/selftests/S/share").status_code == share


@pytest.mark.parametrize("viewer", VIEWERS)
def test_signed_in_only(world, viewer):
    as_, _, _ = world
    code = SIGNED_IN[viewer]
    assert as_(viewer).post("/api/runs", data={"spec": "left-pad"}).status_code == code
    assert as_(viewer).get("/api/shares").status_code == code
    assert as_(viewer).get("/api/selftests/latest").status_code == code


@pytest.mark.parametrize("viewer", VIEWERS)
def test_share_links_are_listed_and_revoked_by_their_maker_or_an_owner(world, viewer):
    as_, _, ids = world
    c = as_(viewer)
    if SIGNED_IN[viewer] == 401:
        assert c.delete(f"/api/shares/{ids['D']}").status_code == 401
        return
    own = c.post("/api/runs/A/share").json()["id"] if viewer in ("guest_a", "a_shareP") else None
    listed = {s["id"] for s in c.get("/api/shares").json()}
    if viewer == "owner":
        assert set(ids.values()) <= listed
        assert c.delete(f"/api/shares/{ids['D']}").status_code == 200
    else:  # a guest sees and revokes only links they made, never the owner's
        assert listed == ({own} if own else set())
        assert c.delete(f"/api/shares/{ids['D']}").status_code == 404
        if own:
            assert c.delete(f"/api/shares/{own}").status_code == 200


@pytest.mark.parametrize("viewer", VIEWERS)
def test_me_is_public_and_says_who(world, viewer):
    as_, _, _ = world
    me = as_(viewer).get("/api/me").json()
    assert me["login"] == {"owner": "Darkflib", "guest_a": "judge-a", "guest_b": "judge-b",
                           "a_shareP": "judge-a"}.get(viewer)
    assert me["owner"] == (viewer == "owner")
    assert me["share"] == viewer.startswith("share_")
