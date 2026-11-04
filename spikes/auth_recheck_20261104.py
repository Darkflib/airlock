"""Safe authority recheck: fake GitHub, temporary SQLite, no VM or network calls.

The stream assertion records remaining finding B1; it is not desired behavior.
"""
import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace
import httpx
from starlette.requests import Request
from airlock.events import EventLog
from airlock.store import Store
from airlock.web import app as web, auth
from tests.test_pr import META, FakeGitHub

SECRET = b'recheck-only'
class GitHub(FakeGitHub):
    def __init__(self):
        super().__init__()
        self.entered, self.release = asyncio.Event(), asyncio.Event()
    async def permission(self, *a):
        return 'write'
    async def status(self, *a):
        if a[3] == 'success':
            self.entered.set()
            await self.release.wait()
        await super().status(*a)

async def main():
    with tempfile.TemporaryDirectory() as td:
        import os
        os.environ['AIRLOCK_DATA'] = td
        allowed = Path(td) / 'allowed_users'
        allowed.write_text('judge-a\njudge-b\n')
        cfg = auth.AuthConfig('cid','fake',SECRET,'https://airlock.test',frozenset({'darkflib'}),allowed,False)
        store, gh = Store(Path(td) / 'r.db'), GitHub()
        async def analyse(target, *, events, on_pr=None):
            await on_pr(META)
            return SimpleNamespace(verdict='benign',evidence=[],model='fake',meta=META)
        app = web.create_app(store=store, analyse=analyse, auth=cfg, github=gh)
        store.create_run('old','old',submitted_by='Darkflib')
        store.update_run('old',status='done',verdict='benign',meta={**META,'author':'someone-else'})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://airlock.test') as c:
            c.cookies.set(auth.SESSION_COOKIE,auth.session_token(SECRET,'Darkflib'))
            approval = asyncio.create_task(c.post('/api/runs/old/decision',json={'decision':'approved'}))
            await asyncio.wait_for(gh.entered.wait(),2)
            response = await c.post('/api/runs',data={'spec':'https://github.com/Darkflib/airlock-demo/pull/3'})
            await asyncio.sleep(0)
            tasks = list(app.state.runner.tasks)
            gh.release.set()
            await approval
            await asyncio.gather(*tasks)
            states = [x[2] for x in gh.calls if x[0]=='status']
            assert states == ['success','pending','pending'], states
            print('in-flight old write serialized before newer gates:',states)

            store.create_run('private','private',submitted_by='judge-a')
            session = auth.session_token(SECRET,'judge-b')
            share = auth.share_payload(['private'],by='judge-a')
            token = auth.sign(SECRET,share)
            c.cookies.set(auth.SESSION_COOKIE,session)
            c.cookies.set(auth.SHARE_COOKIE,token)
            assert (await c.get('/api/runs/private')).status_code == 200
            cookie = f'{auth.SESSION_COOKIE}={session}; {auth.SHARE_COOKIE}={token}'
            request = Request({'type':'http','method':'GET','scheme':'https','path':'/api/runs/private/events',
                               'query_string':b'', 'headers':[(b'cookie',cookie.encode())], 'server':('airlock.test',443)})
            request.state.user, request.state.share = auth.credentials(cfg,request)
            log = EventLog(on_emit=lambda ev:store.add_event('private',ev))
            app.state.runner.live['private'] = log
            endpoint = next(r.endpoint for r in app.routes if getattr(r,'path','')=='/api/runs/{run_id}/events')
            response = await endpoint('private',request)
            clock = [0]
            real_time = web.time
            web.time = SimpleNamespace(monotonic=lambda:clock[0])
            try:
                pending = asyncio.create_task(anext(response.body_iterator))
                await asyncio.sleep(0)
                auth_id = share['id']
                cfg.revoke_share(auth_id)
                assert (await c.get('/api/runs/private')).status_code == 404
                clock[0] = 16
                log.emit('private-evidence','AFTER REVOCATION 1')
                await pending
                clock[0] = 32
                log.emit('private-evidence','AFTER REVOCATION 2')
                leaked = await asyncio.wait_for(anext(response.body_iterator),2)
                assert 'AFTER REVOCATION 2' in leaked
                assert auth.still_allowed(cfg,request)
                print('revoked share with valid unrelated session: new GET=404; stream after recheck=',leaked.strip())
            finally:
                await response.body_iterator.aclose()
                web.time = real_time

if __name__ == '__main__':
    asyncio.run(main())
