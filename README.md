# dns-tunnel

A [SIP003](https://shadowsocks.org/doc/sip003.html) Shadowsocks plugin written
in Rust that obfuscates SS traffic as a stream of DNS query / response messages
(DoH-style `application/dns-message`) tunnelled over **HTTP/3** on **QUIC**.

On the wire the traffic looks like a DoH3 client speaking to a DoH3 resolver:

```
Shadowsocks (TCP) <-> dns-tunnel client <-- QUIC/HTTP3 --> dns-tunnel server <-> Shadowsocks (TCP)
                                          DNS-message body
                                          (TXT records carrying payload)
```

Each direction on a tunnel is a single HTTP/3 bidirectional stream
(`POST /dns-query`) whose body is a sequence of length-prefixed DNS messages.
Payload bytes are carried as the RDATA of a TXT record in the answer section;
the question section uses a synthetic `t.<id>.invalid` QNAME.

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
| `sni`     | TLS SNI / `:authority`                               | `SS_REMOTE_HOST` |
| `path`    | request path                                         | `/dns-query`     |
| `insecure`| skip TLS verification (client only, dev/test only)   | off              |
| `cert`    | PEM cert chain (server only; ephemeral if omitted)   | —                |
| `key`     | PEM private key (server only)                        | —                |

### shadowsocks-rust example

Client `config.json`:

```json
{
  "server": "your.server.example",
  "server_port": 443,
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "password": "secret",
  "method": "chacha20-ietf-poly1305",
  "plugin": "dns-tunnel",
  "plugin_opts": "mode=client;sni=your.server.example;path=/dns-query"
}
```

Server `config.json`:

```json
{
  "server": "0.0.0.0",
  "server_port": 443,
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
