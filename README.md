# dns-tunnel

[![CI](https://github.com/madeye/dns-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/madeye/dns-tunnel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Project site: <https://madeye.github.io/dns-tunnel/>

A [SIP003](https://shadowsocks.org/doc/sip003.html) Shadowsocks plugin written
in Rust that obfuscates SS traffic as a stream of DNS query / response messages
on top of **DNS-over-QUIC** ([RFC 9250](https://www.rfc-editor.org/rfc/rfc9250)).

```
Shadowsocks (TCP) <-> dns-tunnel client <-- QUIC, ALPN "doq" --> dns-tunnel server <-> Shadowsocks (TCP)
                                            [u16 len][DNS msg]…
                                            (TXT records carrying payload)
```

### Wire-level shape (strict-conformance mode)

Each query/response pair gets its own QUIC bidirectional stream (true RFC 9250
framing — not multi-message per stream). On the DNS layer:

* **Queries** look like a browser's DNS lookup with EDNS0 padding:
  - `ID = 0` (mandatory per RFC 9250 §4.2.1)
  - QNAME = a short random prefix + a popular suffix from a pool
    (`googleapis.com`, `cloudfront.net`, `akamaiedge.net`, …)
  - QTYPE rotated among `A`, `AAAA`, `HTTPS`
  - Additional section carries an OPT pseudo-record (RFC 6891) whose
    OPTION-CODE is `12` (PADDING, RFC 7830). The "padding" is the actual
    tunneled bytes — modern browsers always send DNS padding to block-align
    queries, so this hides ~2 KB of payload per message in normal-looking
    traffic.
* **Responses** echo the question section verbatim and carry one answer
  record of type `HTTPS` (`TYPE 65`); the response payload sits in the
  SvcParams tail of the RDATA. ~3.8 KB of payload per response.

### Session multiplexing

Because each QUIC stream carries one query and one response, multiple
shadowsocks TCP connections multiplexing through the tunnel need their own
session identity. Every TCP connection gets a random `u64` session ID. Each
DNS payload starts with `[session:u64][flags:u8][seq:u16]` so the server can
demux. Flags carry OPEN/CLOSE half-close semantics.

The client uses single-flight per session: one outstanding query at a time,
new query opens a fresh QUIC stream. When the client has no upstream data to
send it issues empty queries on an ~80 ms cadence so the server can drain
downstream bytes back (the server holds empty polls for ~80–160 ms instead of
returning an empty response immediately).

## Build

```
cargo build --release
```

The binary is `target/release/dns-tunnel`.

## Usage as a SIP003 plugin

`dns-tunnel` reads its configuration from the standard SIP003 environment
variables and from `SS_PLUGIN_OPTIONS` (semicolon separated `k=v` pairs).

Recognized plugin options:

| key       | meaning                                              | default          |
| --------- | ---------------------------------------------------- | ---------------- |
| `mode`    | `client` or `server`                                 | `client`         |
| `sni`     | TLS SNI                                              | `SS_REMOTE_HOST` |
| `insecure`| skip TLS verification (client only, dev/test only)   | off              |
| `cert`    | PEM cert chain (server only; ephemeral if omitted)   | —                |
| `key`     | PEM private key (server only)                        | —                |
| `decoy`             | enable decoy DoQ traffic to public resolvers (client only) | off                                                  |
| `decoy-resolvers`   | comma-separated `host:port` list (client only)             | `dns.adguard-dns.com:853,dns.quad9.net:853`          |
| `decoy-interval-ms` | mean sleep between queries per resolver task, jittered ±50% | `5000`                                              |
| `decoy-domains`     | A-record query targets, comma-separated                    | `example.com,wikipedia.org,github.com,cloudflare.com,apple.com` |

`decoy` makes the host look like a normal DoQ client by maintaining real
sessions to public recursive resolvers (e.g. AdGuard, Quad9) and periodically
issuing legitimate A-record queries; responses are discarded. The intent is
mimicry — the real tunnel (also DoQ) blends into a population of DoQ flows
rather than standing alone.

The QUIC port is `SS_REMOTE_PORT` — the IANA-assigned DoQ port is **853**.

### shadowsocks-rust example

Client `config.json`:

```json
{
  "server": "your.server.example",
  "server_port": 853,
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "password": "secret",
  "method": "chacha20-ietf-poly1305",
  "plugin": "dns-tunnel",
  "plugin_opts": "mode=client;sni=your.server.example"
}
```

Server `config.json`:

```json
{
  "server": "0.0.0.0",
  "server_port": 853,
  "password": "secret",
  "method": "chacha20-ietf-poly1305",
  "plugin": "dns-tunnel",
  "plugin_opts": "mode=server;sni=your.server.example;cert=/etc/dns-tunnel/fullchain.pem;key=/etc/dns-tunnel/privkey.pem"
}
```

## Development

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --bins
```

## License

MIT
