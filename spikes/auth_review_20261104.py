"""Safe review reproductions: temporary SQLite, ASGI HTTP, fake GitHub only."""
import asyncio
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import httpx
from airlock.store import Store
from airlock.web.app import create_app
from airlock.web.auth import AuthConfig, SESSION_COOKIE, session_token, share_payload, sign, SHARE_COOKIE
from tests.test_pr import META, FakeGitHub

SECRET = b'review-only-secret'

class GitHub(FakeGitHub):
    def __init__(self):
        super().__init__()
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.pause = False

    async def permission(self, owner, repo, user):
        if self.pause:
            self.pause = False
            self.entered.set()
            await self.release.wait()
        return 'write'

    async def pull_request(self, owner, repo, number):
        return SimpleNamespace(head_sha=META['head_sha'], author='Darkflib' if number == 99 else 'someone-else')

async def fake_analyse(*args, **kwargs):
    raise AssertionError('Reproductions must never start an analysis')

def seed(store, run_id, author='Darkflib', number=3, user='Darkflib', demo=False):
    store.create_run(run_id, f'Darkflib/airlock-demo#{number}', submitted_by=user, demo=demo)
    store.update_run(run_id, status='done', verdict='benign', meta={**META, 'author': author, 'number': number})

async def webhook(c, payload, event):
    body = json.dumps(payload).encode()
    sig = 'sha256=' + hmac.new(b'hook', body, hashlib.sha256).hexdigest()
    return await c.post('/api/github/webhook', content=body, headers={
        'x-hub-signature-256': sig, 'x-github-event': event})

async def scenario(which):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td)
        os.environ['AIRLOCK_DATA'] = td
        os.environ['AIRLOCK_SELF_APPROVAL'] = '0'
        allowed = path / 'allowed_users'
        allowed.write_text('judge-a\njudge-b\n')
        cfg = AuthConfig('cid', 'secret', SECRET, 'https://airlock.test', frozenset({'darkflib'}), allowed, False)
        gh, store = GitHub(), Store(path / 'a.db')
        if which == 'legacy_upload':
            store.create_run('legacy-upload', 'acme-internal', submitted_by='Darkflib')
            store.update_run('legacy-upload', status='done', demo=None, evidence=['private-source-evidence'])
        app = create_app(store=store, analyse=fake_analyse, auth=cfg, github=gh, webhook_secret='hook')
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://airlock.test') as c:
            c.cookies.set(SESSION_COOKIE, session_token(SECRET, 'Darkflib'))
            if which in ('race_decision', 'race_newer'):
                seed(store, 'old', author='someone-else')
                gh.pause = True
                approval = asyncio.create_task(c.post('/api/runs/old/decision', json={'decision': 'approved'}))
                await asyncio.wait_for(gh.entered.wait(), 2)
                if which == 'race_decision':
                    rejection = await c.post('/api/runs/old/decision', json={'decision': 'rejected'})
                    assert rejection.status_code == 200
                    assert store.get_run('old')['decision'] == 'rejected'
                else:
                    seed(store, 'new', author='someone-else')
                    store.update_run('new', status='running')
                    await gh.status('Darkflib', 'airlock-demo', META['head_sha'], 'pending', 'newer run', '')
                gh.release.set()
                response = await approval
                assert response.status_code == 200
                assert gh.calls[-2][0:3] == ('status', META['head_sha'], 'success')
                print(which, {'http': response.status_code, 'old_decision': store.get_run('old')['decision'],
                              'statuses': [x[2] for x in gh.calls if x[0] == 'status']})
            elif which == 'stale_review':
                seed(store, 'current', author='someone-else')
                p = {'action': 'submitted', 'repository': {'full_name': 'Darkflib/airlock-demo'},
                     'pull_request': {'number': 3, 'head': {'sha': 'OLD-COMMIT'}},
                     'review': {'body': '/airlock approve', 'commit_id': 'OLD-COMMIT', 'state': 'approved'},
                     'sender': {'login': 'Darkflib', 'type': 'User'}}
                r = await webhook(c, p, 'pull_request_review')
                assert r.json()['decided'] == 'approved'
                print(which, {'review_commit': p['review']['commit_id'], 'approved_commit': META['head_sha'],
                              'response': r.json()})
            elif which == 'cross_pr_self_approval':
                seed(store, 'other-pr', author='someone-else', number=3)
                p = {'action': 'created', 'repository': {'full_name': 'Darkflib/airlock-demo'},
                     'issue': {'number': 99, 'pull_request': {'url': 'https://github.com/Darkflib/airlock-demo/pull/99'}},
                     'comment': {'body': '/airlock approve'}, 'sender': {'login': 'Darkflib', 'type': 'User'}}
                r = await webhook(c, p, 'issue_comment')
                assert r.json()['decided'] == 'approved'
                print(which, {'command_pr': 99, 'decided_pr': store.get_run('other-pr')['meta']['number'],
                              'self_approval_setting': os.environ['AIRLOCK_SELF_APPROVAL'], 'response': r.json()})
            elif which == 'signed_in_share':
                seed(store, 'guest-private', user='judge-a')
                share = share_payload(['guest-private'], by='judge-a')
                token = sign(SECRET, share)
                c.cookies.set(SHARE_COOKIE, token)
                c.cookies.delete(SESSION_COOKIE)
                anonymous = await c.get('/api/runs/guest-private')
                c.cookies.set(SESSION_COOKIE, session_token(SECRET, 'judge-b'))
                signed_in = await c.get('/api/runs/guest-private')
                assert (anonymous.status_code, signed_in.status_code) == (200, 404)
                print(which, {'anonymous_with_share': anonymous.status_code, 'signed_in_with_same_share': signed_in.status_code})
            elif which == 'legacy_upload':
                c.cookies.set(SESSION_COOKIE, session_token(SECRET, 'judge-b'))
                r = await c.get('/api/runs/legacy-upload')
                assert r.status_code == 200 and r.json()['evidence'] == ['private-source-evidence']
                print(which, {'guest_http': r.status_code, 'demo_after_startup': r.json()['demo'], 'evidence': r.json()['evidence']})

async def main():
    for which in ('race_decision', 'race_newer', 'stale_review', 'cross_pr_self_approval', 'legacy_upload', 'signed_in_share'):
        await scenario(which)

if __name__ == '__main__':
    asyncio.run(main())
