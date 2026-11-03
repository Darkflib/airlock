from airlock.events import events_from_sinkhole

TOKEN = "AIRLOCKCANARY0123456789ABCDEF"


def test_payload_with_canary_is_proven_exfil():
    out = events_from_sinkhole([{"dest": "198.18.7.9", "host": "t.evil.invalid", "method": "POST",
                                 "url": "https://t.evil.invalid/v1", "bytes": 60,
                                 "body": f"//registry.npmjs.org/:_authToken=npm_{TOKEN}\n"}], TOKEN)
    kind, summary, data = out[0]
    assert kind == "canary_exfil" and data["proven"] and data["this_run"]
    assert TOKEN in data["payload"] and "never reached the internet" in summary


def test_payload_without_canary_is_contained_egress():
    out = events_from_sinkhole([{"dest": "198.18.7.9", "host": "t.evil.invalid", "method": "GET",
                                 "url": "http://t.evil.invalid/ping", "bytes": 0, "body": ""}], TOKEN)
    assert out[0][0] == "egress_blocked" and "GET http://t.evil.invalid/ping" in out[0][1]
