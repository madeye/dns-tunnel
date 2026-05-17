---
title: Configuration
layout: default
---

# Configuration

`dns-tunnel` is a [SIP003](https://shadowsocks.org/doc/sip003.html) plugin and
reads its configuration from environment variables set by `sslocal` /
`ssserver`, plus a single `;`-delimited options string:

| Env var                | Meaning                                         |
| ---------------------- | ----------------------------------------------- |
| `SS_REMOTE_HOST`       | Server address (the QUIC peer)                  |
| `SS_REMOTE_PORT`       | Server port (the QUIC peer)                     |
| `SS_LOCAL_HOST`        | Local listen / target address                   |
| `SS_LOCAL_PORT`        | Local listen / target port                      |
| `SS_PLUGIN_OPTIONS`    | `;`-separated `k=v` plugin options (below)      |

## Plugin options

### Common

| Key       | Default          | Meaning                                                        |
| --------- | ---------------- | -------------------------------------------------------------- |
| `mode`    | `client`         | `client` or `server`                                           |
| `sni`     | `SS_REMOTE_HOST` | TLS Server Name Indication used at handshake                   |

### Server-only

| Key   | Default                | Meaning                                                |
| ----- | ---------------------- | ------------------------------------------------------ |
| `cert`| —                      | PEM-encoded certificate chain                          |
| `key` | —                      | PEM-encoded private key                                |

If `cert` / `key` are omitted, the server generates an ephemeral self-signed
certificate for `sni` on startup — useful for local testing, **never for
production**. For production set both, point them at a real cert (e.g. issued
by Let's Encrypt or your own CA), and restart on rotation.

### Client-only

| Key                 | Default                                                | Meaning                                                |
| ------------------- | ------------------------------------------------------ | ------------------------------------------------------ |
| `insecure`          | off                                                    | Skip TLS verification (presence flag; dev/test only)   |
| `decoy`             | off                                                    | Enable cover traffic to public DoQ resolvers           |
| `decoy-resolvers`   | `dns.adguard-dns.com:853,dns.quad9.net:853`            | Comma-separated `host:port` list                       |
| `decoy-interval-ms` | `5000`                                                 | Mean sleep between decoy queries, jittered ±50%        |
| `decoy-domains`     | `example.com,wikipedia.org,github.com,cloudflare.com,apple.com` | Comma-separated A-record query targets        |

See [Cover traffic]({{ "/cover-traffic.html" | relative_url }}) for the design
rationale of `decoy=`.

## Worked example

End-to-end `shadowsocks-rust` deployment on port 443/UDP (real Let's Encrypt
cert assumed):

```bash
# server
SS_REMOTE_HOST=0.0.0.0  SS_REMOTE_PORT=443 \
SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=18388 \
SS_PLUGIN_OPTIONS='mode=server;sni=cdn.example.com;cert=/etc/ssl/cdn.crt;key=/etc/ssl/cdn.key' \
    ssserver -c /etc/shadowsocks/server.json

# client
SS_REMOTE_HOST=cdn.example.com SS_REMOTE_PORT=443 \
SS_LOCAL_HOST=127.0.0.1        SS_LOCAL_PORT=18388 \
SS_PLUGIN_OPTIONS='mode=client;sni=cdn.example.com;decoy' \
    sslocal -c ~/.config/shadowsocks/client.json
```

(In normal use you set `plugin` and `plugin_opts` in the SS JSON config — see
the [main page]({{ "/" | relative_url }}) for that form.)
