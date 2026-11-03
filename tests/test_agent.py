from airlock.agent import parse_finish


def test_parse_finish_normal():
    assert parse_finish({"verdict": "Malicious", "evidence": ["reads ~/.npmrc [E5]"]}) == ("malicious", ["reads ~/.npmrc [E5]"])


def test_parse_finish_recovers_verdict_and_string_evidence():
    assert parse_finish({"verdict": "looks benign to me", "evidence": "only pads strings"}) == (
        "benign", ["only pads strings"])


def test_parse_finish_inconclusive_when_missing():
    assert parse_finish({}) == ("inconclusive", [])
