"""Who may do what, in one place. A `Viewer` is whoever is asking: a signed-in login, a share grant,
or both. Every route asks it the same questions, and tests/test_access_matrix.py states the same rules
as tables.

- Owners (AIRLOCK_ALLOWED_USERS) read and change everything.
- Guests (anyone else on the allowlist) read their own runs and the owners' demo runs (self-tests,
  public packages, PRs from AIRLOCK_GUEST_REPOS), change only what they made, and submit PRs only
  from AIRLOCK_GUEST_REPOS.
- A share grant adds reading the runs it names, never a change, whether or not its holder is signed in.
  (The auth middleware has already limited a signed-out holder to those runs' own pages.)
- With sign-in not configured (tests, a local CLI-only setup), everyone is an owner.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Viewer:
    user: str | None
    share: dict | None
    owners: frozenset[str]  # lower-case logins
    signed_in_required: bool = True

    @property
    def owner(self) -> bool:
        return not self.signed_in_required or (self.user or "").lower() in self.owners

    def made(self, item: dict, by: str = "submitted_by") -> bool:
        """This signed-in viewer made the run, self-test or share link (`by` names its maker field)."""
        return bool(self.user) and (item.get(by) or "").lower() == self.user.lower()

    def can_read(self, run: dict) -> bool:
        if self.owner or run["id"] in ((self.share or {}).get("runs") or []):
            return True
        demo = bool(run.get("demo")) and (run.get("submitted_by") or "").lower() in self.owners
        return bool(self.user) and (self.made(run) or demo)

    def can_change(self, item: dict, by: str = "submitted_by") -> bool:
        """Decide, share or post a run; share a self-test; see or revoke a share link (by="by")."""
        return self.owner or self.made(item, by)

    def can_submit_pr(self, slug: str, guest_repos: frozenset[str]) -> bool:
        return self.owner or slug.lower() in guest_repos
