# dns-tunnel

A [SIP003](https://shadowsocks.org/doc/sip003.html) Shadowsocks plugin written
in Rust that obfuscates SS traffic as a stream of DNS query / response messages
on top of **DNS-over-QUIC** ([RFC 9250](https://www.rfc-editor.org/rfc/rfc9250)).

```
Shadowsocks (TCP) <-> dns-tunnel client <-- QUIC, ALPN "doq" --> dns-tunnel server <-> Shadowsocks (TCP)
                                            [u16 len][DNS msg]…
                                            (TXT records carrying payload)
```

Each tunneled TCP connection becomes one QUIC bidirectional stream. Bytes are
chunked into DNS messages whose payload sits in a TXT record's RDATA; the
question section uses a synthetic `t.<id>.invalid` QNAME. Each message is
prefixed with a 2-byte length, matching the DoQ stream framing.

No HTTP, no application-layer framing beyond DoQ. On the wire it looks like
a DoQ resolver speaking to a DoQ client.

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
