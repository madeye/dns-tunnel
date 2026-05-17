---
title: Protocol
layout: default
---

# Protocol

`dns-tunnel` is built on three layers:

1. **QUIC + ALPN `doq`** — the transport. Same as a real DoQ resolver.
2. **Per-message DNS** — each QUIC bidirectional stream carries exactly one
   DNS query and one response. No multi-message streams.
3. **Session header** — a thin multiplexing layer inside each DNS payload so
   the server can attribute messages to TCP connections.

## QUIC layer

Standard QUIC with TLS 1.3. ALPN advertised in the ClientHello and accepted by
the server is `doq` (`b"\x03doq"`). This matches RFC 9250 §4.1.1 verbatim,
so a passive observer comparing handshakes to public DoQ resolvers sees
identical ALPN, identical certificate validation paths, and identical
0-RTT/1-RTT timing.

## DNS query (client → server)

```
+----------------+
| ID = 0         |   (RFC 9250 §4.2.1 — MUST be zero)
| Flags = 0x0100 |   QR=0, OPCODE=0, RD=1
| QDCOUNT = 1    |
| ANCOUNT = 0    |   (no answers in a query)
| NSCOUNT = 0    |
| ARCOUNT = 1    |   (one OPT pseudo-record below)
+----------------+
| Question                                         |
|   QNAME  = "<random-prefix>.<popular-suffix>."   |
|   QTYPE  = 1 (A) | 28 (AAAA) | 65 (HTTPS)        |
|   QCLASS = 1 (IN)                                |
+----------------+
| Additional (OPT, RFC 6891)                       |
|   NAME  = 0 (root)                               |
|   TYPE  = 41 (OPT)                               |
|   CLASS = 4096 (requestor UDP payload size)      |
|   TTL   = 0                                      |
|   RDATA = OPTION-CODE = 12 (PADDING, RFC 7830)   |
|           OPTION-LEN  = N                        |
|           OPTION-DATA = N bytes of tunnel payload|
+----------------+
```

* The QNAME's prefix label is a short random run of `a..z` characters; the
  suffix is rotated from a pool of CDN domains (`googleapis.com`,
  `cloudfront.net`, `akamaiedge.net`, `fastly.net`, …).
* The `PADDING` option (`OPTION-CODE = 12`) is what modern browsers send to
  pad DNS messages to block boundaries — its presence in a query is normal.
  We just happen to put real bytes there.

The maximum payload per query is **2048 bytes** (`MAX_QUERY_PAYLOAD`).

## DNS response (server → client)

```
+----------------+
| ID = 0         |
| Flags = 0x8180 |   QR=1, RD=1, RA=1, RCODE=0
| QDCOUNT = 1    |
| ANCOUNT = 1    |
| NSCOUNT = 0    |
| ARCOUNT = 0    |
+----------------+
| Question (echoed from the query, byte-for-byte)  |
+----------------+
| Answer                                           |
|   NAME  = 0xC00C (compression pointer to qname)  |
|   TYPE  = 65 (HTTPS)                             |
|   CLASS = 1 (IN)                                 |
|   TTL   = 300                                    |
|   RDATA = SvcPriority(u16 = 0)                   |
|           TargetName(u8 = 0, root)               |
|           N bytes of tunnel payload              |
+----------------+
```

Real HTTPS RRs (RFC 9460) carry priority + target + arbitrary SvcParams;
strict parsers will reject our SvcParams tail as malformed, but DNS-layer
inspection (header counts, RR type, RDLEN) passes.

The maximum payload per response is **3800 bytes** (`MAX_RESPONSE_PAYLOAD`).

## Session header

Every payload (query OPT data **and** response RDATA tail) starts with:

```
+-------------+---------+-----+
|  session    |  flags  | seq |
|  u64        |  u8     | u16 |
+-------------+---------+-----+
   (then opaque payload bytes...)
```

| Field   | Meaning                                                       |
| ------- | ------------------------------------------------------------- |
| session | Random `u64` picked by client on TCP-accept; lifetime of session |
| flags   | bit 0 = `OPEN` (first frame of session), bit 1 = `CLOSE`      |
| seq     | Monotonically increasing per direction (advisory — single-flight) |

`OPEN` triggers the server to `connect()` upstream TCP. `CLOSE` in either
direction half-closes the corresponding write side; both directions closed →
the server drops the session.

## Throughput model

Per session, the client runs single-flight: one query at a time, fresh QUIC
stream per query, blocks until response arrives.

Empty queries serve as **downstream polls**. The server holds an empty
upstream query for 80–160 ms while it waits for bytes from the upstream TCP
target; if any arrive, it returns them immediately, otherwise it returns an
empty response so the client can re-poll.

Effective single-stream throughput ≈ `(2 KB upstream + 3.8 KB downstream) ÷ RTT`.
On a 30 ms-RTT path that's ~70 KB/s upstream, ~130 KB/s downstream — enough
for normal browsing, modest for large transfers. Multiple parallel TCP
connections each get their own session and run independently.
