from collections import Counter, defaultdict

from netlens.parsing import ParsedCapture
from netlens.schemas import Conversation, Finding, TrafficStats


def analyze(parsed: ParsedCapture, dns_slow_ms: float = 250) -> tuple[TrafficStats, list[Finding]]:
    findings = []
    pending_dns = defaultdict(list)
    syns = {}
    synacks = {}
    conversations = {}
    sources, destinations, protocols = Counter(), Counter(), Counter()
    requests = responses = matched = 0
    timestamps = []
    warnings = set(parsed.warnings)

    def finding(detector, observation, refs, measurements, alternatives=(), severity="warning"):
        findings.append(
            Finding(
                id=f"f-{len(findings) + 1:06d}",
                detector=detector,
                severity=severity,
                observation=observation,
                measurements=measurements,
                packet_refs=sorted(set(refs)),
                limitations=["Only traffic visible in this capture is considered."],
                alternatives=list(alternatives),
            )
        )

    for p in parsed.packets:
        if p.timestamp is not None:
            if timestamps and p.timestamp < timestamps[-1]:
                warnings.add(
                    "Packet timestamps are out of order; timing matches may be incomplete."
                )
            timestamps.append(p.timestamp)
        protocols[p.protocol] += 1
        if p.source:
            sources[p.source] += 1
            destinations[p.destination] += 1
        if p.protocol in ("TCP", "UDP", "DNS"):
            proto = "UDP" if p.protocol == "DNS" else p.protocol
            ends = sorted([f"[{p.source}]:{p.sport}", f"[{p.destination}]:{p.dport}"])
            key = (proto, *ends)
            if key not in conversations:
                conversations[key] = Conversation(
                    protocol=proto, endpoints=ends, packets=0, captured_bytes=0
                )
            conversations[key].packets += 1
            conversations[key].captured_bytes += p.captured_bytes
        if p.dns_id is not None:
            forward = (
                p.interface,
                p.source,
                p.destination,
                p.sport,
                p.dport,
                p.dns_id,
                p.dns_question,
            )
            reverse = (
                p.interface,
                p.destination,
                p.source,
                p.dport,
                p.sport,
                p.dns_id,
                p.dns_question,
            )
            if not p.dns_response:
                requests += 1
                pending_dns[forward].append(p)
            else:
                responses += 1
                # FIFO matching; identical outstanding retransmissions remain explicitly ambiguous.
                candidates = pending_dns[reverse]
                request = next(
                    (
                        q
                        for q in candidates
                        if q.timestamp is None or p.timestamp is None or q.timestamp <= p.timestamp
                    ),
                    None,
                )
                refs = [p.index]
                if request:
                    candidates.remove(request)
                    matched += 1
                    refs.insert(0, request.index)
                    if request.timestamp is not None and p.timestamp is not None:
                        ms = round((p.timestamp - request.timestamp) * 1000, 6)
                        if ms > dns_slow_ms:
                            finding(
                                "dns.slow_response",
                                "Observed DNS response time exceeds threshold.",
                                refs,
                                {"response_ms": ms, "threshold_ms": dns_slow_ms},
                                ["Capture timing or resolver processing may contribute."],
                            )
                if p.dns_rcode:
                    name = "NXDOMAIN" if p.dns_rcode == 3 else f"RCODE {p.dns_rcode}"
                    finding(
                        "dns.nxdomain" if p.dns_rcode == 3 else "dns.error",
                        f"Observed DNS {name} response.",
                        refs,
                        {"rcode": p.dns_rcode},
                        ["The negative response may be expected for the requested name."],
                    )
        if p.protocol == "TCP":
            forward = (p.interface, p.source, p.destination, p.sport, p.dport)
            reverse = (p.interface, p.destination, p.source, p.dport, p.sport)
            if p.flags & 4:
                finding(
                    "tcp.reset",
                    "Observed a TCP reset flag.",
                    [p.index],
                    {},
                    ["A reset can be an intentional application or endpoint action."],
                )
                # An RST/ACK is not evidence of an established connection.
                continue
            if p.flags & 2 and not p.flags & 16:
                key = (*forward, p.seq)
                syns.setdefault(key, []).append(p)
            elif p.flags & 2 and p.flags & 16:
                key = (*reverse, (p.ack - 1) % (2**32))
                if key in syns:
                    first = syns[key][0]
                    if (
                        first.timestamp is None
                        or p.timestamp is None
                        or p.timestamp >= first.timestamp
                    ):
                        synacks[(*reverse, p.ack, (p.seq + 1) % (2**32))] = (key, p.timestamp)
            elif p.flags & 16:
                match = synacks.get((*forward, p.seq, p.ack))
                if match is not None:
                    key, synack_time = match
                    if key in syns and (
                        synack_time is None or p.timestamp is None or p.timestamp >= synack_time
                    ):
                        del syns[key]
                    # Retransmitted ACKs remain harmless after a completed handshake.
    for queries in pending_dns.values():
        for query in queries:
            finding(
                "dns.unanswered",
                "No matching DNS response was observed for this request.",
                [query.index],
                {"transaction_id": query.dns_id},
                ["Response may fall outside capture, use another path, or match a retransmission."],
            )
    for packets in syns.values():
        finding(
            "tcp.incomplete_handshake",
            "No completed TCP handshake was observed for this attempt.",
            [p.index for p in packets],
            {"syn_packets": len(packets)},
            ["Capture may end early or miss one direction; this does not prove packet loss."],
        )
    stats = TrafficStats(
        total_packets=len(parsed.packets),
        captured_bytes=sum(p.captured_bytes for p in parsed.packets),
        duration_seconds=round(max(timestamps) - min(timestamps), 9) if timestamps else 0,
        protocols=dict(sorted(protocols.items())),
        top_sources=dict(sources.most_common(10)),
        top_destinations=dict(destinations.most_common(10)),
        conversations=sorted(conversations.values(), key=lambda c: (-c.packets, c.endpoints))[:100],
        dns_requests=requests,
        dns_responses=responses,
        dns_matched_responses=matched,
        warnings=sorted(warnings),
    )
    return stats, findings
