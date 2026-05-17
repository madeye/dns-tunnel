---
title: dns-tunnel
layout: default
---

# dns-tunnel

**A [SIP003](https://shadowsocks.org/doc/sip003.html) Shadowsocks plugin written in Rust that obfuscates traffic as standards-conformant DNS-over-QUIC ([RFC 9250](https://www.rfc-editor.org/rfc/rfc9250)).**

```
Shadowsocks TCP  ─►  sslocal  ─►  dns-tunnel (client)
                                       │
                                       ▼  QUIC, ALPN "doq"
                                  DNS messages
                                  (EDNS0-padded queries,
                                   HTTPS-record responses)
                                       │
                                       ▼
                            dns-tunnel (server)  ─►  ssserver  ─►  TCP target
```

## Why

Most plugins that wrap shadowsocks in a "looks like X" envelope settle for
*X-ish*: a TLS record here, an HTTP request there. DPI vendors classify on
*details* — header field counts, message-ID values, record types in the answer
section, presence of EDNS padding. `dns-tunnel` targets those details:

| Detail                              | What dns-tunnel does                          |
| ----------------------------------- | --------------------------------------------- |
| DoQ stream framing                  | one query + one response per QUIC bidi stream |
| DNS message ID                      | `0` on every message (RFC 9250 §4.2.1)        |
| Query QNAME                         | `<short-random>.<popular-cdn-tld>`            |
| Query QTYPE                         | rotated among `A`, `AAAA`, `HTTPS`            |
| Where payload hides (queries)       | EDNS0 OPT, OPTION-CODE 12 (PADDING, RFC 7830) |
| Where payload hides (responses)     | HTTPS resource record's RDATA                 |
| Multi-message streams               | none — strict one-shot per stream             |

## Quick start

```bash
cargo build --release
```

Server-side `shadowsocks-rust` config:

```json
{
  "server": "0.0.0.0",
  "server_port": 853,
  "password": "secret",
  "method": "chacha20-ietf-poly1305",
  "plugin": "/usr/local/bin/dns-tunnel",
  "plugin_opts": "mode=server;sni=your.server.example;cert=/etc/ssl/fullchain.pem;key=/etc/ssl/privkey.pem"
}
```

Client-side:

```json
{
  "server": "your.server.example",
  "server_port": 853,
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "password": "secret",
  "method": "chacha20-ietf-poly1305",
  "plugin": "/usr/local/bin/dns-tunnel",
  "plugin_opts": "mode=client;sni=your.server.example"
}
```

## Docs

- [Configuration]({{ "/configuration.html" | relative_url }}) — every plugin option in `SS_PLUGIN_OPTIONS`.
- [Protocol]({{ "/protocol.html" | relative_url }}) — exact wire format and session layer.
- [Cover traffic]({{ "/cover-traffic.html" | relative_url }}) — the `decoy` mode that maintains real DoQ sessions to public resolvers.

## Source

[madeye/dns-tunnel on GitHub](https://github.com/madeye/dns-tunnel) · MIT licensed.
