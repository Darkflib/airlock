import asyncio

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from airlock.github import GitHubApp

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def app_with(replies):
    """A GitHubApp whose status/comment POSTs get `replies` in turn (a status code or an exception)."""
    writes = []

    def handle(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/installation"):
            return httpx.Response(200, json={"id": 1})
        if req.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "t"})
        writes.append(req.url.path)
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return httpx.Response(reply, json={"html_url": "https://github.com/c"})
    return GitHubApp("1", KEY, wait=0, transport=httpx.MockTransport(handle)), writes


def status(gh):
    return asyncio.run(gh.status("o", "r", "sha", "failure", "rejected", "https://airlock.test/runs/1"))


def comment(gh):
    return asyncio.run(gh.comment("o", "r", 4, "body"))


def test_status_retries_through_github_errors_and_network_blips():
    gh, writes = app_with([502, httpx.ConnectError("reset"), httpx.ReadTimeout("slow"), 201])
    status(gh)
    assert len(writes) == 4


def test_gives_up_after_four_attempts():
    gh, writes = app_with([503] * 5)
    with pytest.raises(httpx.HTTPStatusError):
        status(gh)
    assert len(writes) == 4


def test_client_errors_are_not_retried():
    gh, writes = app_with([422])
    with pytest.raises(httpx.HTTPStatusError):
        status(gh)
    assert len(writes) == 1


def test_comment_retries_only_when_it_cannot_have_landed():
    gh, writes = app_with([500, httpx.ConnectError("refused"), 201])
    assert comment(gh) == "https://github.com/c" and len(writes) == 3
    gh, writes = app_with([httpx.ReadTimeout("slow"), 201])   # may have posted: no duplicate comment
    with pytest.raises(httpx.ReadTimeout):
        comment(gh)
    assert len(writes) == 1
