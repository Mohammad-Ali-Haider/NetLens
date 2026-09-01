"""Bounded binary framing followed by Scapy decoding; payloads are never retained."""

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from scapy.all import DNS, IP, TCP, UDP, IPv6, conf

from netlens.config import Settings


class CaptureError(ValueError):
    def __init__(self, message: str, code: str = "malformed_capture"):
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class Packet:
    index: int
    timestamp: float | None
    captured_bytes: int
    source: str = ""
    destination: str = ""
    protocol: str = "other"
    sport: int = 0
    dport: int = 0
    flags: int = 0
    seq: int = 0
    ack: int = 0
    dns_id: int | None = None
    dns_response: bool = False
    dns_rcode: int = 0
    dns_question: tuple = ()
    interface: int = 0


@dataclass
class ParsedCapture:
    format: str
    packets: list[Packet] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CaptureError("Incomplete capture header or record.")
    return data


def parse_capture(path: Path, settings: Settings) -> ParsedCapture:
    started = time.monotonic()
    result = ParsedCapture(format="pcap")

    def budget():
        if time.monotonic() - started > settings.max_parse_seconds:
            raise CaptureError("Capture processing time limit exceeded.", "processing_limit")

    def add(raw, timestamp, original, link, interface=0):
        budget()
        if len(result.packets) >= settings.max_packets:
            raise CaptureError("Packet count limit exceeded.", "packet_limit")
        if original < len(raw):
            raise CaptureError("Captured length exceeds original packet length.")
        if original > len(raw):
            result.warnings.append("Some packets are truncated; bytes count captured bytes only.")
        if link not in conf.l2types:
            raise CaptureError(f"Unsupported link type {link}.", "unsupported_link_type")
        p = Packet(len(result.packets) + 1, timestamp, len(raw), interface=interface)
        try:
            decoded = conf.l2types[link](raw)
            network = decoded.getlayer(IP) or decoded.getlayer(IPv6)
            if network:
                p.source, p.destination = network.src, network.dst
                p.protocol = "IPv4" if isinstance(network, IP) else "IPv6"
                # Do not interpret fragments as complete transport messages.
                fragmented = isinstance(network, IP) and (network.frag or network.flags.MF)
                fragmented = fragmented or decoded.haslayer("IPv6ExtHdrFragment")
                if fragmented:
                    result.warnings.append("Fragmented IP traffic is not reassembled.")
                elif TCP in network or UDP in network:
                    transport = network[TCP] if TCP in network else network[UDP]
                    p.protocol = "TCP" if TCP in network else "UDP"
                    p.sport, p.dport = int(transport.sport), int(transport.dport)
                    if p.protocol == "TCP":
                        p.flags, p.seq, p.ack = (
                            int(transport.flags),
                            int(transport.seq),
                            int(transport.ack),
                        )
                    # DNS over TCP needs stream reassembly, intentionally not inferred.
                    if DNS in transport and p.protocol == "UDP":
                        dns = transport[DNS]
                        p.dns_id, p.dns_response, p.dns_rcode = (
                            int(dns.id),
                            bool(dns.qr),
                            int(dns.rcode),
                        )
                        p.dns_question = tuple(
                            (bytes(q.qname).lower(), int(q.qtype), int(q.qclass)) for q in dns.qd
                        )
                        p.protocol = "DNS"
        except Exception:
            result.warnings.append("Some packet headers could not be decoded completely.")
        result.packets.append(p)

    with path.open("rb") as stream:
        magic = exact(stream, 4)
        magics = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e6),
            b"\xa1\xb2\xc3\xd4": (">", 1e6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e9),
            b"\xa1\xb2\x3c\x4d": (">", 1e9),
        }
        if magic in magics:
            endian, resolution = magics[magic]
            major, minor, _, _, snap, link = struct.unpack(endian + "HHIIII", exact(stream, 20))
            if (major, minor) != (2, 4) or snap == 0:
                raise CaptureError("Unsupported pcap header version or snapshot length.")
            while header := stream.read(16):
                budget()
                if len(header) != 16:
                    raise CaptureError("Incomplete pcap packet header.")
                sec, frac, size, original = struct.unpack(endian + "IIII", header)
                if size > settings.max_record_bytes or size > snap:
                    raise CaptureError("Packet record exceeds configured bound.", "record_limit")
                if frac >= resolution:
                    raise CaptureError("Invalid pcap timestamp fraction.")
                add(exact(stream, size), sec + frac / resolution, original, link & 0xFFFF)
        elif magic == b"\x0a\x0d\x0d\x0a":
            result.format = "pcapng"
            stream.seek(0)
            endian = "<"
            interfaces = []
            section = -1
            while header := stream.read(8):
                budget()
                if len(header) != 8:
                    raise CaptureError("Incomplete pcapng block header.")
                is_section = header[:4] == magic
                prefix = b""
                if is_section:
                    prefix = exact(stream, 4)
                    if prefix not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                        raise CaptureError("Invalid pcapng byte order magic.")
                    endian = "<" if prefix[0] == 0x4D else ">"
                kind, size = struct.unpack(endian + "II", header)
                if size < 12 + len(prefix) or size % 4 or size > settings.max_record_bytes + 65536:
                    raise CaptureError("Invalid or oversized pcapng block.", "record_limit")
                data = prefix + exact(stream, size - 8 - len(prefix))
                if struct.unpack(endian + "I", data[-4:])[0] != size:
                    raise CaptureError("Inconsistent pcapng block lengths.")
                body = data[:-4]
                if is_section:
                    if len(body) < 16 or struct.unpack(endian + "HH", body[4:8]) != (1, 0):
                        raise CaptureError("Unsupported pcapng section version.")
                    section += 1
                    interfaces = []
                elif kind == 1:
                    if len(body) < 8 or len(interfaces) >= 1024:
                        raise CaptureError("Invalid or excessive interface descriptions.")
                    link, _, snap = struct.unpack(endian + "HHI", body[:8])
                    resolution, offset = 1e6, 0
                    pos = 8
                    while pos + 4 <= len(body):
                        code, length = struct.unpack(endian + "HH", body[pos : pos + 4])
                        value = body[pos + 4 : pos + 4 + length]
                        if len(value) != length:
                            raise CaptureError("Malformed interface option.")
                        if code == 9 and length == 1:
                            exponent = value[0] & 0x7F
                            resolution = (2 if value[0] & 0x80 else 10) ** exponent
                        if code == 14 and length == 8:
                            offset = struct.unpack(endian + "q", value)[0]
                        pos += 4 + ((length + 3) // 4) * 4
                        if code == 0:
                            break
                    interfaces.append((link, snap, resolution, offset))
                elif kind in (6, 3):
                    if kind == 6:
                        if len(body) < 20:
                            raise CaptureError("Incomplete enhanced packet block.")
                        iface, hi, lo, caplen, original = struct.unpack(endian + "IIIII", body[:20])
                        start = 20
                    else:
                        if len(body) < 4 or not interfaces:
                            raise CaptureError("Invalid simple packet block.")
                        iface, original, start = 0, struct.unpack(endian + "I", body[:4])[0], 4
                        caplen = min(original, interfaces[0][1] or original)
                    if iface >= len(interfaces):
                        raise CaptureError("Packet references an unknown interface.")
                    link, snap, resolution, offset = interfaces[iface]
                    if caplen > settings.max_record_bytes or (snap and caplen > snap):
                        raise CaptureError("Oversized packet record.", "record_limit")
                    if start + ((caplen + 3) // 4) * 4 > len(body):
                        raise CaptureError("Incomplete pcapng packet data.")
                    ts = ((hi << 32) + lo) / resolution + offset if kind == 6 else None
                    if ts is None:
                        result.warnings.append(
                            "Some packets have no timestamps; timing is incomplete."
                        )
                    add(body[start : start + caplen], ts, original, link, section * 1024 + iface)
                elif kind == 2:
                    raise CaptureError("Obsolete pcapng packet blocks are unsupported.")
        else:
            raise CaptureError("Content is neither pcap nor pcapng.", "invalid_format")
    if not result.packets:
        result.warnings.append("The capture contains no packets.")
    result.warnings.append("Capture boundaries and capture location limit observations.")
    result.warnings = sorted(set(result.warnings))
    return result
