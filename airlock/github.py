"""GitHub App client: reads pull requests and, after a human decision, posts the
verdict back as `<app>[bot]`. The server holds only the App private key and mints
installation tokens scoped to one repository, valid for an hour.

Writes (statuses, comments) are retried on network errors, 5xx and rate limits, so a
GitHub blip doesn't leave a decided PR stuck at pending."""

from __future__ import annotations

import base64
import os
import re
import time
from dataclasses import dataclass

import httpx
import jwt
from tenacity import AsyncRetrying, retry_if_exception, stop_after_attempt, wait_exponential

API = "https://api.github.com"
PR_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)/?(?:[?#].*)?$")
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def transient(e: BaseException, idempotent: bool = True) -> bool:
    """Worth another try: the network, GitHub's side, or a rate limit. Not 4xx we caused.
    A write that isn't idempotent (a comment) is not retried once the request may have landed."""
    if isinstance(e, (httpx.ReadTimeout, httpx.ReadError, httpx.RemoteProtocolError)):
        return idempotent
    if isinstance(e, httpx.TransportError):
        return True
    if isinstance(e, httpx.HTTPStatusError):
        r = e.response
        return r.status_code >= 500 or r.status_code == 429 or (
            r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0")
    return False


def parse_pr_url(url: str) -> tuple[str, str, int] | None:
    m = PR_URL.match(url.strip())
    return (m.group(1), m.group(2), int(m.group(3))) if m else None


@dataclass
class PullRequest:
    owner: str
    repo: str
    number: int
    title: str
    author: str
    html_url: str
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    files: list[dict]

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"


class GitHubApp:
    def __init__(self, app_id: str, private_key_pem: str, attempts: int = 4, wait: float = 1.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.app_id, self.key = app_id, private_key_pem
        self._tokens: dict[str, tuple[str, float]] = {}
        self.attempts, self.wait, self.transport = attempts, wait, transport  # about 7 s of backoff by default

    async def _retry(self, fn, idempotent: bool = True):
        """Run a write with backoff on transient failures (also covers minting the token)."""
        async for attempt in AsyncRetrying(retry=retry_if_exception(lambda e: transient(e, idempotent)), reraise=True,
                                           stop=stop_after_attempt(self.attempts),
                                           wait=wait_exponential(multiplier=self.wait, max=10 * self.wait)):
            with attempt:
                return await fn()

    @classmethod
    def from_env(cls) -> "GitHubApp | None":
        app_id, key_b64 = os.environ.get("GITHUB_APP_ID"), os.environ.get("GITHUB_APP_PRIVATE_KEY_B64")
        if not app_id or not key_b64:
            return None
        return cls(app_id, base64.b64decode(key_b64).decode())

    def _jwt(self) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self.key, algorithm="RS256")

    async def _token(self, owner: str, repo: str) -> str:
        cached = self._tokens.get(f"{owner}/{repo}")
        if cached and cached[1] > time.time() + 300:
            return cached[0]
        auth = {**HEADERS, "Authorization": f"Bearer {self._jwt()}"}
        async with httpx.AsyncClient(base_url=API, timeout=20, transport=self.transport) as c:
            inst = await c.get(f"/repos/{owner}/{repo}/installation", headers=auth)
            if inst.status_code == 404:
                raise PermissionError(f"the Airlock GitHub App is not installed on {owner}/{repo}")
            inst.raise_for_status()
            tok = await c.post(f"/app/installations/{inst.json()['id']}/access_tokens", headers=auth,
                               json={"repositories": [repo]})
            tok.raise_for_status()
        token = tok.json()["token"]
        self._tokens[f"{owner}/{repo}"] = (token, time.time() + 3600)
        return token

    async def _client(self, owner: str, repo: str) -> httpx.AsyncClient:
        token = await self._token(owner, repo)
        return httpx.AsyncClient(base_url=API, timeout=30, follow_redirects=True, transport=self.transport,
                                 headers={**HEADERS, "Authorization": f"Bearer {token}"})

    async def pull_request(self, owner: str, repo: str, number: int) -> PullRequest:
        async with await self._client(owner, repo) as c:
            pr = (await c.get(f"/repos/{owner}/{repo}/pulls/{number}")).raise_for_status().json()
            files = (await c.get(f"/repos/{owner}/{repo}/pulls/{number}/files", params={"per_page": 100})).raise_for_status().json()
        return PullRequest(
            owner=owner, repo=repo, number=number, title=pr["title"], author=pr["user"]["login"],
            html_url=pr["html_url"], base_ref=pr["base"]["ref"], base_sha=pr["base"]["sha"],
            head_ref=pr["head"]["ref"], head_sha=pr["head"]["sha"],
            files=[{"filename": f["filename"], "status": f["status"], "additions": f["additions"],
                    "deletions": f["deletions"]} for f in files])

    async def tarball(self, owner: str, repo: str, sha: str) -> bytes:
        async with await self._client(owner, repo) as c:
            r = await c.get(f"/repos/{owner}/{repo}/tarball/{sha}")
            r.raise_for_status()
            return r.content

    async def merge_base(self, owner: str, repo: str, base: str, head: str) -> str:
        """The commit the PR branched from: comparing against it isolates what the PR itself adds
        (the base branch tip may have moved on since)."""
        async with await self._client(owner, repo) as c:
            r = (await c.get(f"/repos/{owner}/{repo}/compare/{base}...{head}", params={"per_page": 1})).raise_for_status()
            return r.json()["merge_base_commit"]["sha"]

    async def diff(self, owner: str, repo: str, number: int, limit: int = 200_000) -> str:
        async with await self._client(owner, repo) as c:
            r = await c.get(f"/repos/{owner}/{repo}/pulls/{number}", headers={"Accept": "application/vnd.github.diff"})
            r.raise_for_status()
            return r.text[:limit]

    async def comment(self, owner: str, repo: str, number: int, body: str, edit: str | None = None) -> str:
        """Post a comment, or rewrite the one at `edit` (its html_url) in place; returns its html_url.
        Editing is idempotent, so it retries like a status; if that comment was deleted, post anew."""
        cid = re.search(r"#issuecomment-(\d+)$", edit or "")
        if cid:
            async def patch():
                async with await self._client(owner, repo) as c:
                    r = await c.patch(f"/repos/{owner}/{repo}/issues/comments/{cid.group(1)}", json={"body": body})
                    return None if r.status_code == 404 else r.raise_for_status().json()["html_url"]
            if url := await self._retry(patch):
                return url

        async def post():
            async with await self._client(owner, repo) as c:
                r = (await c.post(f"/repos/{owner}/{repo}/issues/{number}/comments", json={"body": body})).raise_for_status()
                return r.json()["html_url"]
        return await self._retry(post, idempotent=False)

    async def permission(self, owner: str, repo: str, login: str) -> str:
        """The user's access to the repo: admin, write, read or none (maintain counts as write)."""
        async with await self._client(owner, repo) as c:
            r = await c.get(f"/repos/{owner}/{repo}/collaborators/{login}/permission")
            if r.status_code == 404:
                return "none"
            return r.raise_for_status().json()["permission"]

    async def status(self, owner: str, repo: str, sha: str, state: str, description: str, target_url: str) -> None:
        async def post():  # idempotent: the latest status for the context wins
            async with await self._client(owner, repo) as c:
                (await c.post(f"/repos/{owner}/{repo}/statuses/{sha}", json={
                    "state": state, "description": description[:140], "target_url": target_url,
                    "context": "airlock"})).raise_for_status()
        await self._retry(post)
