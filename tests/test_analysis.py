from pathlib import Path

import pytest

from netlens.config import Settings
from netlens.detectors import analyze
from netlens.parsing import CaptureError, Packet, ParsedCapture, parse_capture

CAPTURES = Path("demo/captures")


@pytest.mark.parametrize(
    "name,detector,refs",
    [
        ("healthy", None, []),
        ("dns_failure", "dns.nxdomain", [1, 2]),
        ("dns_other_error", "dns.error", [1, 2]),
        ("unanswered", "dns.unanswered", [1]),
        ("tcp_reset", "tcp.reset", [1]),
        ("incomplete", "tcp.incomplete_handshake", [1]),
        ("slow_dns", "dns.slow_response", [1, 2]),
        ("ipv6", None, []),
        ("empty", None, []),
    ],
)
def test_scenarios(name, detector, refs):
    parsed = parse_capture(CAPTURES / f"{name}.pcap", Settings())
    stats, findings = analyze(parsed)
    if detector:
        assert len(findings) == 1
        assert findings[0].detector == detector
        assert findings[0].packet_refs == refs
    else:
        assert not findings
    assert stats.total_packets == len(parsed.packets)
    assert stats.captured_bytes == sum(p.captured_bytes for p in parsed.packets)


def test_pcapng_timing_and_ipv6():
    stats, findings = analyze(parse_capture(CAPTURES / "ipv6.pcapng", Settings()))
    assert stats.duration_seconds == pytest.approx(0.02, abs=1e-6)
    assert stats.dns_matched_responses == 1
    assert "2001:db8::1" in stats.top_sources
    assert not findings


@pytest.mark.parametrize("name", ["malformed", "truncated"])
def test_invalid(name):
    with pytest.raises(CaptureError):
        parse_capture(CAPTURES / f"{name}.pcap", Settings())


def test_snaplen_and_limits(monkeypatch):
    parsed = parse_capture(CAPTURES / "snaplen.pcap", Settings())
    assert any("truncated" in w for w in parsed.warnings)
    with pytest.raises(CaptureError, match="Packet count"):
        parse_capture(CAPTURES / "healthy.pcap", Settings(max_packets=1))
    ticks = iter([0, 2])
    monkeypatch.setattr("netlens.parsing.time.monotonic", lambda: next(ticks))
    with pytest.raises(CaptureError, match="time limit"):
        parse_capture(CAPTURES / "healthy.pcap", Settings(max_parse_seconds=1e-12))


def test_dns_matching_port_question_and_time():
    q = Packet(1, 1, 50, "a", "b", "DNS", 123, 53, dns_id=1, dns_question=(b"x",))
    wrong = Packet(
        2, 1.1, 50, "b", "a", "DNS", 53, 124, dns_id=1, dns_response=True, dns_question=(b"x",)
    )
    _, findings = analyze(ParsedCapture("pcap", [q, wrong]))
    assert [f.detector for f in findings] == ["dns.unanswered"]
    wrong.dport = 123
    wrong.timestamp = 0.5
    _, findings = analyze(ParsedCapture("pcap", [q, wrong]))
    assert findings[0].detector == "dns.unanswered"
    wrong.timestamp = 1.5
    stats, findings = analyze(ParsedCapture("pcap", [q, wrong]), 400)
    assert stats.dns_matched_responses == 1
    assert findings[0].measurements["response_ms"] == 500
