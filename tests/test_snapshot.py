"""PR snapshots: the file list, diff and archive describe one head commit, and a partial view says so."""
import asyncio

import httpx
import pytest

from airlock import github as gh_mod
from airlock.github import Diff, GitHubApp, PullRequest
from airlock.pipeline import snapshot_for_agent, snapshot_info
from airlock.prcomment import build_comment
from tests.test_github_retry import KEY


def fake_github(heads, n_files=3, changed=None, diff=(200, "diff --git a/x b/x\n")):
    """GitHub serving PR 7: each read of the PR returns the next head in `heads` (the last one repeats)."""
    seen = []
    heads = list(heads)

    def handle(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.endswith("/installation"):
            return httpx.Response(200, json={"id": 1})
        if path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "t"})
        seen.append((path, dict(req.url.params), req.headers.get("accept")))
        if path.endswith("/pulls/7"):
            head = heads.pop(0) if len(heads) > 1 else heads[0]
            return httpx.Response(200, json={
                "title": "t", "user": {"login": "a"}, "html_url": "u", "base": {"ref": "main", "sha": "b" * 40},
                "head": {"ref": "f", "sha": head}, "changed_files": n_files if changed is None else changed})
        if path.endswith("/pulls/7/files"):
            page, per = int(req.url.params["page"]), int(req.url.params["per_page"])
            names = [f"f{i}" for i in range(n_files)][(page - 1) * per:page * per]
            return httpx.Response(200, json=[{"filename": f, "status": "added", "additions": 1, "deletions": 0}
                                             for f in names])
        if "/compare/" in path:
            return httpx.Response(diff[0], text=diff[1])
        return httpx.Response(404)
    return GitHubApp("1", KEY, wait=0, transport=httpx.MockTransport(handle)), seen


def test_file_list_reads_every_page_and_is_complete():
    app, seen = fake_github(["h" * 40], n_files=250)
    pr = asyncio.run(app.pull_request("o", "r", 7))
    assert len(pr.files) == 250 and pr.changed_files == 250 and pr.files_complete and not pr.head_moved
    assert [p["page"] for path, p, _ in seen if path.endswith("/files")] == ["1", "2", "3"]


def test_file_list_past_githubs_page_limit_is_marked_partial(monkeypatch):
    monkeypatch.setattr(gh_mod, "FILE_PAGES", 2)
    app, _ = fake_github(["h" * 40], n_files=340)
    pr = asyncio.run(app.pull_request("o", "r", 7))
    assert len(pr.files) == 200 and not pr.files_complete
    assert snapshot_info(pr, Diff("d", chars=1))["notes"] == ["the file list shows 200 of 340 changed files"]


def test_head_that_moves_while_listing_is_reread_until_it_holds():
    app, seen = fake_github(["1" * 40, "2" * 40, "2" * 40])
    pr = asyncio.run(app.pull_request("o", "r", 7))
    assert pr.head_sha == "2" * 40 and not pr.head_moved and pr.files_complete
    assert sum(path.endswith("/files") for path, _, _ in seen) == 2


def test_head_that_keeps_moving_is_flagged():
    app, _ = fake_github([str(i) * 40 for i in range(1, 9)])
    pr = asyncio.run(app.pull_request("o", "r", 7))
    assert pr.head_moved and not pr.files_complete
    assert "kept moving" in snapshot_info(pr, Diff("d", chars=1))["notes"][0]


def test_command_lookups_skip_the_file_list():
    app, seen = fake_github(["h" * 40])
    asyncio.run(app.pull_request("o", "r", 7, files=False))
    assert [path for path, _, _ in seen] == ["/repos/o/r/pulls/7"]


def test_diff_is_pinned_to_both_commits_and_cut_with_a_marker():
    app, seen = fake_github(["h" * 40], diff=(200, "x" * 50))
    d = asyncio.run(app.diff("o", "r", "b" * 40, "h" * 40, limit=20))
    assert seen[-1][0] == f"/repos/o/r/compare/{'b' * 40}...{'h' * 40}" and "diff" in seen[-1][2]
    assert (d.text, d.chars, d.truncated) == ("x" * 20, 50, True)


@pytest.mark.parametrize("code", [406, 422])
def test_diff_github_refuses_leaves_the_run_going(code):
    app, _ = fake_github(["h" * 40], diff=(code, "too large"))
    d = asyncio.run(app.diff("o", "r", "b" * 40, "h" * 40))
    assert d.text == "" and str(code) in d.unavailable


def test_other_diff_errors_still_fail():
    app, _ = fake_github(["h" * 40], diff=(500, "boom"))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(app.diff("o", "r", "b" * 40, "h" * 40))


def pr(files=1, changed=1, moved=False):
    return PullRequest("o", "r", 7, "t", "a", "u", "main", "b" * 40, "f", "h" * 40,
                       files=[{}] * files, changed_files=changed, head_moved=moved)


def test_complete_snapshot_says_nothing_to_the_agent():
    snap = snapshot_info(pr(), Diff("d", chars=1))
    assert snap["complete"] and snap["notes"] == [] and snapshot_for_agent(snap) == ""


def test_partial_snapshot_is_told_to_the_agent_and_in_the_pr_comment():
    snap = snapshot_info(pr(files=100, changed=340), Diff("x" * 10, chars=500_000, truncated=True))
    assert snap["notes"] == ["the file list shows 100 of 340 changed files",
                             "the diff is cut at 10 of 500,000 characters"]
    assert "/work/repo" in snapshot_for_agent(snap)
    run = {"verdict": "benign", "decision": None, "meta": {"head_sha": "h" * 40, "snapshot": snap}, "evidence": []}
    body = build_comment(run, [], "https://airlock.test/runs/1")
    assert "The reviewer saw part of this PR: the file list shows 100 of 340" in body
    run["meta"]["snapshot"] = snapshot_info(pr(), Diff("d", chars=1))
    assert "saw part" not in build_comment(run, [], "https://airlock.test/runs/1")


def test_unavailable_diff_is_noted():
    snap = snapshot_info(pr(), Diff("", unavailable="GitHub would not produce the diff (HTTP 406)"))
    assert snap["notes"] == ["no diff: GitHub would not produce the diff (HTTP 406)"]
