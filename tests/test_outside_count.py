from evals.outside_count import count


def report():
    return {"catcher": {"zone": "catch.example"}, "control": {"marker": "CONTROLABC"},
            "runs": [{"probe_token": "TOKEN123", "window": [100.0, 200.0], "probe": [{"id": "catcher-v4-http"}, {"id": "dns-resolver"}]}]}


def test_quiet_catcher_is_contained_and_control_is_seen():
    hits = [{"kind": "dns", "proto": "udp", "peer": "8.8.4.4", "t": 50, "name": "controlabc.res.catch.example"},
            {"kind": "tcp", "port": 80, "peer": "203.0.113.9", "t": 150, "data": "GET / HTTP/1.1"}]  # a scanner
    out = count(report(), hits, {"192.0.2.1"})
    assert out["control_seen"] == ["dns:udp"] and not out["escaped"]
    assert out["runs"][0]["catcher_probes"] == 1


def test_token_from_anywhere_or_host_contact_in_window_counts():
    hits = [{"kind": "dns", "proto": "udp", "peer": "172.253.0.1", "t": 999, "name": "token123.g.catch.example"}]
    assert count(report(), hits, set())["escaped"]
    icmp = [{"kind": "icmp", "peer": "198.51.100.1", "t": 150, "data": b"xxTOKEN123".hex()}]
    assert count(report(), icmp, set())["escaped"]
    host = [{"kind": "tcp", "port": 443, "peer": "192.0.2.1", "t": 150, "data": ""}]
    assert count(report(), host, {"192.0.2.1"})["escaped"]
    assert not count(report(), [{**host[0], "t": 300}], {"192.0.2.1"})["escaped"]


def test_control_traffic_inside_a_window_is_not_an_escape_and_icmp_matches_its_pattern():
    hits = [{"kind": "tcp", "port": 4444, "peer": "192.0.2.1", "t": 100.001, "data": "CONTROLABC"},
            {"kind": "icmp", "peer": "192.0.2.1", "t": 100.002, "data": (b"\x00" * 8 + b"CONTROLABC" * 2).hex()}]
    out = count(report(), hits, {"192.0.2.1"})
    assert not out["escaped"] and out["control_seen"] == ["icmp:", "tcp:4444"]
