---
title: Cover traffic
layout: default
---

# Cover traffic (`decoy` mode)

Even a perfectly DoQ-shaped tunnel has one statistical anomaly: in a network
where almost no host speaks DoQ to your endpoint, the *existence* of long-lived
DoQ flows pointing at a specific server is itself a signal.

`decoy` mode addresses that by making the host *also* speak DoQ to public
recursive resolvers, so the real tunnel hides in a population of legitimate
DoQ flows.

## What it does

When `decoy` is set in `SS_PLUGIN_OPTIONS`, the client spawns one task per
configured resolver. Each task:

1. Resolves the resolver's hostname (A or AAAA).
2. Opens a QUIC connection with ALPN `doq` and full WebPKI certificate
   validation — handshake is byte-identical to what `kdig +quic` would do.
3. Loops: pick a random domain from `decoy-domains`, build an RFC-9250-compliant
   A-record query (`ID = 0`, single QDCOUNT, no answers, no padding), open a
   bidirectional stream, send `[u16 len][DNS message]`, read the response,
   discard it.
4. Sleeps for a uniformly jittered interval (`decoy-interval-ms` ± 50 %).
5. On error: close the QUIC connection, back off 30 s, redial.

The response is discarded — we don't care about the address records, only
about generating an indistinguishable-from-normal DoQ flow on the wire.

## Defaults

| Option              | Default                                                |
| ------------------- | ------------------------------------------------------ |
| `decoy-resolvers`   | `dns.adguard-dns.com:853,dns.quad9.net:853`            |
| `decoy-interval-ms` | `5000`                                                 |
| `decoy-domains`     | `example.com,wikipedia.org,github.com,cloudflare.com,apple.com` |

Both public resolvers above advertise DoQ on port 853 with valid WebPKI
certificates. AdGuard's `dns.adguard-dns.com` accepts arbitrary client
identities; Quad9's `dns.quad9.net` does too. You can substitute any DoQ
endpoint — NextDNS, your ISP, or your own.

## What it doesn't do

* Doesn't change the real tunnel's wire shape.
* Doesn't hide *that you're using a tunnel* if you're the only DoQ source in
  your network — it just dilutes the per-flow signal.
* Doesn't add real throughput; the decoy flows are intentionally low-rate.
