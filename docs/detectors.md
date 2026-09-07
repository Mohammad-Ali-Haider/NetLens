# Detector methodology

Packets are indexed from 1 in file order across pcapng sections and interfaces. Evidence indexes refer to the original uploaded file, including undecodable packets. Detector version `1.0.0` belongs to each finding. IDs such as `f-000001` are local to an analysis and stable for the same file and configuration.

Byte totals count bytes actually stored in packet records, including captured link headers and excluding capture-container headers. They do not reconstruct original wire length, omitted snaplen bytes, Ethernet preamble, or inter-frame gaps. Duration is maximum minus minimum available packet timestamp. Missing or out-of-order timestamps produce warnings and limit timing interpretation.

| Detector | Matching and observation | Important limits |
|---|---|---|
| `dns.nxdomain` / `dns.error` | UDP DNS response RCODE 3 is NXDOMAIN; other nonzero RCODEs are errors. A matching request is included when available. | Negative DNS answers can be intentional. DNSSEC extended RCODE interpretation is outside scope. |
| `dns.unanswered` | Request has no matching observed response. Match interface, reverse IP addresses/UDP ports, transaction ID, normalized question bytes/type/class, and nonnegative time ordering. | Identical retransmissions use FIFO; one response satisfies one request. Ambiguous repeats can appear unanswered. |
| `tcp.reset` | TCP RST flag was observed. Each reset packet produces a finding. | Does not prove a failure or identify the responsible application. |
| `tcp.incomplete_handshake` | SYN tracked by interface, addresses, ports, initial sequence. Reverse SYN/ACK must acknowledge SYN+1; final ACK must match both next sequences. Retransmitted identical SYNs share a finding. | Asymmetric capture, capture boundaries, simultaneous open, TCP Fast Open, sequence reuse, and unusual handshakes limit inference. |
| `dns.slow_response` | Observed matched response minus request timestamp exceeds `dns_slow_ms` (strict `>`). Default 250 ms. | Measures observation interval at the capture point, not solely resolver work or user latency. |

Statistics include packet/byte totals, duration, a mutually exclusive protocol distribution (`DNS` is decoded UDP DNS; otherwise TCP/UDP/IPv4/IPv6/other), top 10 sources/destinations, top 100 bidirectional transport conversations, and DNS request/response/matched counts. Conversations merge a canonical endpoint pair for the whole capture and do not represent distinct TCP sessions. Counts may include retransmissions and duplicate captured packets.

Scapy decodes headers only after bounded binary framing validates record sizes. Basic Ethernet, raw IP, and link types supported by Scapy's registered decoders can work; an unregistered link type fails explicitly when a packet uses it. IPv4/IPv6 fragments are counted but not reassembled or analyzed as complete transport messages. DNS over TCP and encrypted DNS require reassembly/decryption and are excluded. No raw payload, DNS name, or application content is stored in findings.

Container truncation (partial headers/records or inconsistent lengths) is rejected. A valid snaplen-truncated packet is accepted with a warning; partial decoding may limit detectors. Simple pcapng blocks have no timestamp, so they cannot establish response time. Capture boundaries always produce a visibility warning. Nonpacket pcapng metadata is not interpreted as proof of completeness.

Memory is bounded by file size, per-record limits, and packet count. Parsing keeps lightweight metadata for at most the configured number of packets; no list of Scapy packet objects is retained. Time checks occur between records and before decoding. These are cooperative checks; worker timeouts and container limits provide a second bound. Upload decoding runs in a synchronous request thread and should also be protected by a reverse-proxy timeout.
