from airlock.agent import parse_finish


def test_parse_finish_normal():
    assert parse_finish({"verdict": "Malicious", "evidence": ["reads ~/.npmrc [E5]"]}) == ("malicious", ["reads ~/.npmrc [E5]"])


def test_parse_finish_recovers_verdict_and_string_evidence():
    assert parse_finish({"verdict": "looks benign to me", "evidence": "only pads strings"}) == (
        "benign", ["only pads strings"])


def test_parse_finish_inconclusive_when_missing():
    assert parse_finish({}) == ("inconclusive", [])


def test_agent_commands_never_run_as_root():
    import asyncio
    from types import SimpleNamespace
    from airlock.agent import TriageAgent
    from airlock.events import EventLog

    calls = []

    class FakeWs:
        async def exec(self, cmd, **kw):
            calls.append(kw)
            return SimpleNamespace(exit_code=0, stdout="", stderr="")

    agent = TriageAgent(client=None, model="m", ws=FakeWs(), events=EventLog())
    asyncio.run(agent._tool("exec", {"cmd": "node postinstall.js"}))
    assert calls and calls[0]["as_user"] == "node"
