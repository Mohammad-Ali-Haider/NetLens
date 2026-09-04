import struct

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netlens.api import create_app
from netlens.config import Settings
from netlens.detectors import analyze
from netlens.parsing import CaptureError, Packet, ParsedCapture, parse_capture
from netlens.schemas import Finding


def test_ack_retransmission_and_reset_do_not_fake_completion():
    syn = Packet(1, 1, 60, "a", "b", "TCP", 1, 2, flags=2, seq=100)
    synack = Packet(2, 2, 60, "b", "a", "TCP", 2, 1, flags=18, seq=200, ack=101)
    ack = Packet(3, 3, 60, "a", "b", "TCP", 1, 2, flags=16, seq=101, ack=201)
    repeat = Packet(4, 4, 60, "a", "b", "TCP", 1, 2, flags=16, seq=101, ack=201)
    _, findings = analyze(ParsedCapture("pcap", [syn, synack, ack, repeat]))
    assert not findings
    ack.flags = 20
    _, findings = analyze(ParsedCapture("pcap", [syn, synack, ack]))
    assert {f.detector for f in findings} == {"tcp.reset", "tcp.incomplete_handshake"}
    ack.flags, ack.timestamp = 16, 1.5
    _, findings = analyze(ParsedCapture("pcap", [syn, synack, ack]))
    assert findings[0].detector == "tcp.incomplete_handshake"


def test_dns_question_interface_and_threshold():
    q = Packet(1, 1, 60, "a", "b", "DNS", 123, 53, dns_id=7, dns_question=(b"x",))
    r = Packet(
        2, 1.25, 60, "b", "a", "DNS", 53, 123, dns_id=7, dns_response=True, dns_question=(b"y",)
    )
    _, findings = analyze(ParsedCapture("pcap", [q, r]))
    assert findings[0].detector == "dns.unanswered"
    r.dns_question, r.interface = q.dns_question, 1
    _, findings = analyze(ParsedCapture("pcap", [q, r]))
    assert findings[0].detector == "dns.unanswered"
    r.interface = 0
    stats, findings = analyze(ParsedCapture("pcap", [q, r]), dns_slow_ms=250)
    assert stats.dns_matched_responses == 1 and not findings


def test_huge_record_rejected_before_allocation(tmp_path):
    path = tmp_path / "huge.pcap"
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 2**32 - 1, 1)
        + struct.pack("<IIII", 1, 0, 2**32 - 1, 2**32 - 1)
    )
    with pytest.raises(CaptureError, match="bound"):
        parse_capture(path, Settings())


def block(kind, body, endian="<"):
    size = 12 + len(body)
    assert size % 4 == 0
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_resolution_offset_and_simple_packet(tmp_path, endian):
    from scapy.all import IP, UDP, Ether

    raw = bytes(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP())
    pad = raw + b"\0" * (-len(raw) % 4)
    section = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    options = struct.pack(endian + "HH", 9, 1) + b"\x09\0\0\0"
    options += struct.pack(endian + "HHq", 14, 8, 10) + b"\0" * 4
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + options, endian)
    enhanced = block(
        6, struct.pack(endian + "IIIII", 0, 0, 500000000, len(raw), len(raw)) + pad, endian
    )
    simple = block(3, struct.pack(endian + "I", len(raw)) + pad, endian)
    path = tmp_path / "x.pcapng"
    path.write_bytes(section + interface + enhanced + simple)
    parsed = parse_capture(path, Settings())
    assert parsed.packets[0].timestamp == 10.5
    assert parsed.packets[1].timestamp is None
    assert parsed.packets[1].index == 2
    assert any("no timestamps" in w for w in parsed.warnings)
    path.write_bytes(section + interface + enhanced[:-4] + b"bad!")
    with pytest.raises(CaptureError, match="lengths"):
        parse_capture(path, Settings())


def test_one_based_evidence_schema():
    with pytest.raises(ValidationError):
        Finding(
            id="x",
            detector="x",
            severity="info",
            observation="x",
            measurements={},
            packet_refs=[0],
            limitations=[],
            alternatives=[],
        )


def test_asgi_body_limit_and_openapi_auth(tmp_path):
    app = create_app(Settings(storage_dir=tmp_path, max_upload_bytes=24))
    with TestClient(app) as client:
        response = client.post(
            "/v1/captures",
            content=b"x" * 70000,
            headers={
                "X-API-Key": "change-me-local-only",
                "Content-Type": "multipart/form-data; boundary=test",
            },
        )
        assert response.status_code == 413, response.text
        assert response.json()["error"]["code"] == "upload_limit"
        schema = client.get("/openapi.json").json()
        assert schema["components"]["securitySchemes"]["APIKeyHeader"]["name"] == "X-API-Key"
        assert "security" in schema["paths"]["/v1/analyses"]["post"]


def test_raw_ip_decoding(tmp_path):
    from scapy.all import IP, UDP

    raw = bytes(IP(src="192.0.2.1", dst="192.0.2.2") / UDP())
    path = tmp_path / "raw.pcap"
    path.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        + struct.pack("<IIII", 1, 0, len(raw), len(raw))
        + raw
    )
    assert parse_capture(path, Settings()).packets[0].source == "192.0.2.1"
