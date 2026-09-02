"""Only synthetic reserved addresses and names. No network access is used."""

import json
import struct
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, IPv6, PcapNgWriter, wrpcap

ROOT = Path(__file__).resolve().parents[2]


def fixtures():
    ether = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    def dns(ipv6=False, rcode=0, delay=0.02):
        a, b = ("2001:db8::1", "2001:db8::53") if ipv6 else ("192.0.2.1", "192.0.2.53")
        layer = IPv6 if ipv6 else IP
        q = (
            ether
            / layer(src=a, dst=b)
            / UDP(sport=53000, dport=53)
            / DNS(id=42, qd=DNSQR(qname="example.test"))
        )
        r = (
            ether
            / layer(src=b, dst=a)
            / UDP(sport=53, dport=53000)
            / DNS(id=42, qr=1, rcode=rcode, qd=DNSQR(qname="example.test"))
        )
        q.time, r.time = 1700000000, 1700000000 + delay
        return [q, r]

    syn = (
        ether
        / IP(src="192.0.2.1", dst="198.51.100.2")
        / TCP(sport=50000, dport=443, flags="S", seq=100)
    )
    synack = (
        ether
        / IP(src="198.51.100.2", dst="192.0.2.1")
        / TCP(sport=443, dport=50000, flags="SA", seq=200, ack=101)
    )
    ack = (
        ether
        / IP(src="192.0.2.1", dst="198.51.100.2")
        / TCP(sport=50000, dport=443, flags="A", seq=101, ack=201)
    )
    reset = ack.copy()
    reset[TCP].flags = "RA"
    for i, p in enumerate([syn, synack, ack, reset]):
        p.time = 1700000001 + i * 0.01
    return {
        "healthy": (dns() + [syn, synack, ack], []),
        "dns_failure": (dns(rcode=3), [("dns.nxdomain", [1, 2])]),
        "dns_other_error": (dns(rcode=2), [("dns.error", [1, 2])]),
        "unanswered": (dns()[:1], [("dns.unanswered", [1])]),
        "tcp_reset": ([reset], [("tcp.reset", [1])]),
        "incomplete": ([syn, synack], [("tcp.incomplete_handshake", [1])]),
        "slow_dns": (dns(delay=0.5), [("dns.slow_response", [1, 2])]),
        "ipv6": (dns(ipv6=True), []),
        "empty": ([], []),
    }


def generate():
    captures = ROOT / "demo/captures"
    expected = ROOT / "demo/expected"
    captures.mkdir(parents=True, exist_ok=True)
    expected.mkdir(parents=True, exist_ok=True)
    scenarios = []
    for name, (packets, findings) in fixtures().items():
        path = captures / f"{name}.pcap"
        if packets:
            wrpcap(str(path), packets)
        else:
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        result = [{"detector": d, "packet_refs": refs} for d, refs in findings]
        (expected / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        scenarios.append(
            {
                "id": name,
                "path": f"demo/captures/{name}.pcap",
                "expected": result,
                "limitations": ["Synthetic, small, single vantage point."],
            }
        )
    with PcapNgWriter(str(captures / "ipv6.pcapng")) as writer:
        for p in fixtures()["ipv6"][0]:
            writer.write(p)
    scenarios.append(
        {
            "id": "pcapng",
            "path": "demo/captures/ipv6.pcapng",
            "expected": [],
            "limitations": ["Single interface."],
        }
    )
    healthy = (captures / "healthy.pcap").read_bytes()
    (captures / "malformed.pcap").write_bytes(b"not a capture")
    (captures / "truncated.pcap").write_bytes(healthy[:-5])
    # Valid snaplen truncation: complete record but missing bytes from original packet.
    snap = bytearray((captures / "tcp_reset.pcap").read_bytes())
    struct.pack_into("<I", snap, 36, len(snap) - 40 + 10)
    (captures / "snaplen.pcap").write_bytes(snap)
    for name in ("malformed", "truncated"):
        scenarios.append(
            {
                "id": name,
                "path": f"demo/captures/{name}.pcap",
                "expected_error": True,
                "limitations": ["Rejected during ingestion."],
            }
        )
    manifest = {"version": 1, "scenarios": scenarios}
    (ROOT / "evaluation").mkdir(exist_ok=True)
    (ROOT / "evaluation/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    generate()
