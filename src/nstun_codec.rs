//! DNS message codec for the NS-tunnel transport.
//!
//! Unlike `dns.rs` (which speaks DoQ wire frames to a peer that knows the
//! plugin protocol), this codec produces standard DNS messages that are
//! forwarded by an unsuspecting recursive resolver to our authoritative
//! nameserver and back. The recursive resolver is the visible peer at both
//! endpoints — to a network observer the client just talks UDP/53 to a public
//! resolver, and the server just looks like any authoritative NS.
//!
//! ## Wire format
//!
//! ### Query (`encode_query`)
//! ```text
//! Header     ID = random (16-bit, used for matching responses)
//!            Flags = 0x0100 (RD=1)
//!            QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1 (EDNS0)
//! Question   QNAME  = <b32-label-1>.<b32-label-2>...<b32-label-N>.<zone>
//!            QTYPE  = 16 (TXT)
//!            QCLASS = 1 (IN)
//! Additional OPT pseudo-record advertising UDP payload size 4096
//! ```
//!
//! The base32 payload starts with a 2-byte little-endian cache-buster nonce
//! so otherwise-identical frames produce distinct QNAMEs (recursive resolvers
//! cache aggressively on QNAME+QTYPE).
//!
//! ### Response (`encode_response`)
//! ```text
//! Header     ID = echoes query
//!            Flags = 0x8180 (QR=1, RD=1, RA=1, RCODE=0)
//!            QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
//! Question   echoes the query verbatim (compression-pointer-friendly)
//! Answer     NAME = 0xC00C (pointer to question QNAME)
//!            TYPE = 16 (TXT), CLASS = IN, TTL = 0 (no caching)
//!            RDATA = concatenated printable base64 character-strings
//!                    that together carry the payload
//! ```
//!
//! ## Capacity
//! * QNAME max 255 octets total (RFC 1035). With a 15-octet zone suffix this
//!   leaves room for ~140 raw payload bytes per query — see `query_capacity`.
//! * TXT RDATA is printable base64. Keep responses below typical recursive
//!   UDP limits even when the echoed question name is close to 255 octets.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;

const FLAGS_QUERY: u16 = 0x0100;
const FLAGS_RESPONSE: u16 = 0x8180;
const CLASS_IN: u16 = 1;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_NS: u16 = 2;
const OPT_TYPE: u16 = 41;

const MAX_NAME_OCTETS: usize = 255;
const MAX_LABEL_BYTES: usize = 63;

/// Hard cap on raw payload bytes per response before printable TXT encoding.
///
/// Recursive resolvers commonly advertise/forward UDP payload sizes around
/// 1232 bytes. Since TXT response bodies are base64 encoded and the response
/// echoes the full QNAME, keep the raw frame comfortably below that ceiling.
pub const MAX_RESPONSE_PAYLOAD: usize = 700;

/// Lowercase RFC 4648 base32 alphabet (DNS labels are case-insensitive but
/// many resolvers normalize to lowercase, so emit lowercase to look native).
const B32_ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn b32_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().saturating_mul(8) / 5 + 1);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in input {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32_ALPHA[((bits >> nbits) & 0x1F) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(B32_ALPHA[((bits << (5 - nbits)) & 0x1F) as usize] as char);
    }
    out
}

pub fn b32_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in input {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => 26 + (c - b'2'),
            _ => bail!("invalid base32 byte 0x{c:02x}"),
        };
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

const B64_ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(B64_ALPHA[(b0 >> 2) as usize]);
        out.push(B64_ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        if chunk.len() > 1 {
            out.push(B64_ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHA[(b2 & 0x3f) as usize]);
        } else {
            out.push(b'=');
        }
    }
    out
}

pub fn b64_decode(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if !input.len().is_multiple_of(4) {
        bail!("invalid base64 length {}", input.len());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            vals[i] = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => 26 + c - b'a',
                b'0'..=b'9' => 52 + c - b'0',
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 2 => {
                    pad += 1;
                    0
                }
                _ => bail!("invalid base64 byte 0x{c:02x}"),
            };
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if pad < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if pad < 1 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(out)
}

/// Compute the maximum raw payload bytes (including the 2-byte nonce we
/// prepend internally) that fit in a query QNAME under the given zone.
pub fn query_capacity(zone: &str) -> usize {
    let zone_wire = zone_wire_len(zone);
    // 255 - zone_wire is the total octets we can spend on payload labels
    // including their per-label length bytes.
    let avail_octets = MAX_NAME_OCTETS.saturating_sub(zone_wire);
    let mut chars = 0usize;
    let mut remaining = avail_octets;
    while remaining > 1 {
        let label_data = (remaining - 1).min(MAX_LABEL_BYTES);
        chars += label_data;
        remaining -= label_data + 1;
    }
    // 8 base32 chars decode to 5 raw bytes; round down to whole chunks then
    // subtract the 2-byte nonce we always prepend.
    let raw_bytes = chars / 8 * 5
        + match chars % 8 {
            0 => 0,
            2 => 1,
            4 => 2,
            5 => 3,
            7 => 4,
            _ => 0,
        };
    raw_bytes.saturating_sub(2)
}

fn zone_wire_len(zone: &str) -> usize {
    let mut n = 1; // terminating zero
    for label in zone.split('.').filter(|s| !s.is_empty()) {
        n += 1 + label.len();
    }
    n
}

/// Encode a query message carrying `payload` opaque bytes inside the QNAME.
/// `txid` is the DNS transaction ID (random — used to match responses).
pub fn encode_query(txid: u16, zone: &str, payload: &[u8]) -> Result<Bytes> {
    let cap = query_capacity(zone);
    if payload.len() > cap {
        bail!("payload {} exceeds query capacity {cap}", payload.len());
    }

    // Prepend a 2-byte cache-buster nonce so identical payloads produce
    // distinct QNAMEs (resolvers cache on QNAME+QTYPE).
    let nonce: u16 = rand::thread_rng().gen();
    let mut raw = Vec::with_capacity(2 + payload.len());
    raw.extend_from_slice(&nonce.to_le_bytes());
    raw.extend_from_slice(payload);
    let encoded = b32_encode(&raw);

    let mut buf = BytesMut::with_capacity(64 + encoded.len() + zone.len());
    buf.put_u16(txid);
    buf.put_u16(FLAGS_QUERY);
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(0); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(1); // ARCOUNT (OPT)

    write_qname_with_payload(&mut buf, &encoded, zone)?;
    buf.put_u16(QTYPE_TXT);
    buf.put_u16(CLASS_IN);

    // EDNS0 OPT pseudo-record advertising max UDP size 4096.
    buf.put_u8(0); // NAME = root
    buf.put_u16(OPT_TYPE);
    buf.put_u16(4096); // CLASS = requestor UDP size
    buf.put_u32(0); // TTL
    buf.put_u16(0); // RDLEN

    Ok(buf.freeze())
}

/// Parsed query as seen by the authoritative server.
pub struct ParsedQuery {
    pub txid: u16,
    pub qname_raw: Bytes,
    pub qtype: u16,
    pub payload: Vec<u8>,
}

pub struct ParsedQuestion {
    pub txid: u16,
    pub qname_raw: Bytes,
    pub qtype: u16,
    pub labels: Vec<Vec<u8>>,
}

pub enum ParsedPacket {
    Tunnel(ParsedQuery),
    Question(ParsedQuestion),
}

pub fn decode_packet(msg: Bytes, zone: &str) -> Result<ParsedPacket> {
    let q = decode_question(msg)?;
    if q.qtype == QTYPE_TXT {
        match labels_to_payload(&q.labels, zone) {
            Ok(payload) => {
                return Ok(ParsedPacket::Tunnel(ParsedQuery {
                    txid: q.txid,
                    qname_raw: q.qname_raw,
                    qtype: q.qtype,
                    payload,
                }));
            }
            Err(e) if labels_under_zone(&q.labels, zone) => {
                tracing::debug!(error=%e, "TXT question under zone did not carry tunnel payload");
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ParsedPacket::Question(q))
}

fn decode_question(msg: Bytes) -> Result<ParsedQuestion> {
    let start = msg.clone();
    let mut cur = msg;
    let txid = read_u16(&mut cur)?;
    let flags = read_u16(&mut cur)?;
    if flags & 0x8000 != 0 {
        bail!("not a query (QR=1)");
    }
    let qd = read_u16(&mut cur)?;
    let _an = read_u16(&mut cur)?;
    let _ns = read_u16(&mut cur)?;
    let _ar = read_u16(&mut cur)?;
    if qd != 1 {
        bail!("expected QDCOUNT=1, got {qd}");
    }
    let (labels, end_off) = parse_name(&start, 12)?;
    let consumed = end_off - 12;
    if consumed > cur.remaining() {
        bail!("qname parse beyond buffer");
    }
    cur.advance(consumed);
    let qtype = read_u16(&mut cur)?;
    let _qclass = read_u16(&mut cur)?;

    let qname_raw = start.slice(12..end_off);
    Ok(ParsedQuestion {
        txid,
        qname_raw,
        qtype,
        labels,
    })
}

pub fn question_under_zone(q: &ParsedQuestion, zone: &str) -> bool {
    labels_under_zone(&q.labels, zone)
}

pub fn question_is_zone_apex(q: &ParsedQuestion, zone: &str) -> bool {
    labels_match_zone(&q.labels, zone)
}

fn labels_to_payload(labels: &[Vec<u8>], zone: &str) -> Result<Vec<u8>> {
    let zone_labels: Vec<&str> = zone.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < zone_labels.len() {
        bail!("qname has fewer labels than zone");
    }
    let split = labels.len() - zone_labels.len();
    for (got, want) in labels[split..].iter().zip(zone_labels.iter()) {
        if !got.eq_ignore_ascii_case(want.as_bytes()) {
            bail!("zone suffix mismatch");
        }
    }
    let mut joined = Vec::new();
    for l in &labels[..split] {
        joined.extend_from_slice(l);
    }
    let raw = b32_decode(&joined)?;
    if raw.len() < 2 {
        bail!("decoded payload missing nonce prefix");
    }
    Ok(raw[2..].to_vec())
}

fn labels_under_zone(labels: &[Vec<u8>], zone: &str) -> bool {
    let zone_labels: Vec<&str> = zone.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < zone_labels.len() {
        return false;
    }
    let split = labels.len() - zone_labels.len();
    labels[split..]
        .iter()
        .zip(zone_labels.iter())
        .all(|(got, want)| got.eq_ignore_ascii_case(want.as_bytes()))
}

fn labels_match_zone(labels: &[Vec<u8>], zone: &str) -> bool {
    let zone_labels: Vec<&str> = zone.split('.').filter(|s| !s.is_empty()).collect();
    labels.len() == zone_labels.len()
        && labels
            .iter()
            .zip(zone_labels.iter())
            .all(|(got, want)| got.eq_ignore_ascii_case(want.as_bytes()))
}

/// Encode a TXT response carrying `payload` bytes as printable base64 split
/// into TXT character-strings. `qname_raw` is the wire-format question QNAME
/// to echo.
pub fn encode_response(txid: u16, qname_raw: &[u8], qtype: u16, payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_RESPONSE_PAYLOAD {
        bail!(
            "response payload {} exceeds MAX_RESPONSE_PAYLOAD {}",
            payload.len(),
            MAX_RESPONSE_PAYLOAD
        );
    }
    let encoded = b64_encode(payload);
    let mut buf = BytesMut::with_capacity(64 + encoded.len() + qname_raw.len());
    buf.put_u16(txid);
    buf.put_u16(FLAGS_RESPONSE);
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(1); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(0); // ARCOUNT

    // Question (echo)
    buf.put_slice(qname_raw);
    buf.put_u16(qtype);
    buf.put_u16(CLASS_IN);

    // Answer
    buf.put_u16(0xC00C); // NAME = pointer to question qname at offset 12
    buf.put_u16(QTYPE_TXT);
    buf.put_u16(CLASS_IN);
    buf.put_u32(0); // TTL = 0 (no caching)

    // RDATA = sequence of printable <u8 len><len bytes> strings.
    let chunks = encoded.chunks(255);
    let strings = if encoded.is_empty() {
        1
    } else {
        chunks.clone().count()
    };
    let rdlen = if encoded.is_empty() {
        1 // single empty character-string
    } else {
        encoded.len() + strings
    };
    if rdlen > u16::MAX as usize {
        bail!("response RDATA too large");
    }
    buf.put_u16(rdlen as u16);
    if encoded.is_empty() {
        buf.put_u8(0);
    } else {
        for chunk in chunks {
            buf.put_u8(chunk.len() as u8);
            buf.put_slice(chunk);
        }
    }
    Ok(buf.freeze())
}

pub fn decode_response(msg: Bytes) -> Result<(u16, Vec<u8>)> {
    let start = msg.clone();
    let mut cur = msg;
    let txid = read_u16(&mut cur)?;
    let flags = read_u16(&mut cur)?;
    if flags & 0x8000 == 0 {
        bail!("not a response (QR=0)");
    }
    let qd = read_u16(&mut cur)?;
    let an = read_u16(&mut cur)?;
    let _ns = read_u16(&mut cur)?;
    let _ar = read_u16(&mut cur)?;
    if qd != 1 || an < 1 {
        bail!("response counts qd={qd} an={an}");
    }
    let (_q, q_end) = parse_name(&start, 12)?;
    cur.advance(q_end - 12);
    let _qtype = read_u16(&mut cur)?;
    let _qclass = read_u16(&mut cur)?;
    // Answer
    skip_name_or_pointer(&mut cur)?;
    let _atype = read_u16(&mut cur)?;
    let _aclass = read_u16(&mut cur)?;
    let _ttl = read_u32(&mut cur)?;
    let rdlen = read_u16(&mut cur)? as usize;
    if cur.remaining() < rdlen {
        bail!("RDATA truncated");
    }
    let mut rd = cur.split_to(rdlen);
    let mut out = Vec::with_capacity(rdlen);
    while rd.has_remaining() {
        let l = rd.get_u8() as usize;
        if rd.remaining() < l {
            bail!("TXT character-string truncated");
        }
        out.extend_from_slice(&rd.split_to(l));
    }
    Ok((txid, b64_decode(&out)?))
}

pub fn encode_ns_response(txid: u16, qname_raw: &[u8], zone: &str) -> Result<Bytes> {
    let ns_name = format!("ns.{}", zone.trim_end_matches('.'));
    let mut rdata = BytesMut::new();
    write_plain_qname(&mut rdata, &ns_name)?;
    encode_response_with_answer(txid, qname_raw, QTYPE_NS, QTYPE_NS, 300, &rdata)
}

pub fn encode_empty_noerror(txid: u16, qname_raw: &[u8], qtype: u16) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(32 + qname_raw.len());
    buf.put_u16(txid);
    buf.put_u16(FLAGS_RESPONSE);
    buf.put_u16(1);
    buf.put_u16(0);
    buf.put_u16(0);
    buf.put_u16(0);
    buf.put_slice(qname_raw);
    buf.put_u16(qtype);
    buf.put_u16(CLASS_IN);
    Ok(buf.freeze())
}

fn encode_response_with_answer(
    txid: u16,
    qname_raw: &[u8],
    qtype: u16,
    atype: u16,
    ttl: u32,
    rdata: &[u8],
) -> Result<Bytes> {
    if rdata.len() > u16::MAX as usize {
        bail!("RDATA too large");
    }
    let mut buf = BytesMut::with_capacity(64 + qname_raw.len() + rdata.len());
    buf.put_u16(txid);
    buf.put_u16(FLAGS_RESPONSE);
    buf.put_u16(1);
    buf.put_u16(1);
    buf.put_u16(0);
    buf.put_u16(0);
    buf.put_slice(qname_raw);
    buf.put_u16(qtype);
    buf.put_u16(CLASS_IN);
    buf.put_u16(0xC00C);
    buf.put_u16(atype);
    buf.put_u16(CLASS_IN);
    buf.put_u32(ttl);
    buf.put_u16(rdata.len() as u16);
    buf.put_slice(rdata);
    Ok(buf.freeze())
}

fn write_qname_with_payload(buf: &mut BytesMut, b32: &str, zone: &str) -> Result<()> {
    let bytes = b32.as_bytes();
    let mut written_octets = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let take = (bytes.len() - i).min(MAX_LABEL_BYTES);
        buf.put_u8(take as u8);
        buf.put_slice(&bytes[i..i + take]);
        written_octets += 1 + take;
        i += take;
    }
    for label in zone.split('.').filter(|s| !s.is_empty()) {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > MAX_LABEL_BYTES {
            bail!("invalid zone label {label:?}");
        }
        buf.put_u8(lb.len() as u8);
        buf.put_slice(lb);
        written_octets += 1 + lb.len();
    }
    buf.put_u8(0);
    written_octets += 1;
    if written_octets > MAX_NAME_OCTETS {
        bail!("qname {written_octets} exceeds 255 octets");
    }
    Ok(())
}

fn write_plain_qname(buf: &mut BytesMut, name: &str) -> Result<()> {
    let mut written_octets = 0usize;
    for label in name.split('.').filter(|s| !s.is_empty()) {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > MAX_LABEL_BYTES {
            bail!("invalid name label {label:?}");
        }
        buf.put_u8(lb.len() as u8);
        buf.put_slice(lb);
        written_octets += 1 + lb.len();
    }
    buf.put_u8(0);
    written_octets += 1;
    if written_octets > MAX_NAME_OCTETS {
        bail!("name {written_octets} exceeds 255 octets");
    }
    Ok(())
}

fn parse_name(msg: &Bytes, start: usize) -> Result<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut off = start;
    let mut jumped = false;
    let mut end_off = start;
    let bytes = msg.as_ref();
    let mut steps = 0;
    loop {
        steps += 1;
        if steps > 256 {
            bail!("name parse loop");
        }
        if off >= bytes.len() {
            bail!("name parse out of range");
        }
        let b = bytes[off];
        if b == 0 {
            if !jumped {
                end_off = off + 1;
            }
            break;
        }
        if b & 0xC0 == 0xC0 {
            if off + 1 >= bytes.len() {
                bail!("pointer truncated");
            }
            let ptr = (((b & 0x3F) as usize) << 8) | bytes[off + 1] as usize;
            if !jumped {
                end_off = off + 2;
            }
            jumped = true;
            off = ptr;
            continue;
        }
        if b & 0xC0 != 0 {
            bail!("invalid label length byte 0x{b:02x}");
        }
        let len = b as usize;
        if off + 1 + len > bytes.len() {
            bail!("label truncated");
        }
        labels.push(bytes[off + 1..off + 1 + len].to_vec());
        off += 1 + len;
    }
    Ok((labels, end_off))
}

fn skip_name_or_pointer(msg: &mut Bytes) -> Result<()> {
    loop {
        if !msg.has_remaining() {
            bail!("name truncated");
        }
        let b = msg.get_u8();
        if b == 0 {
            return Ok(());
        }
        if b & 0xC0 == 0xC0 {
            if !msg.has_remaining() {
                bail!("ptr truncated");
            }
            let _ = msg.get_u8();
            return Ok(());
        }
        if b & 0xC0 != 0 {
            bail!("bad label length 0x{b:02x}");
        }
        if msg.remaining() < b as usize {
            bail!("label truncated");
        }
        msg.advance(b as usize);
    }
}

fn read_u16(b: &mut Bytes) -> Result<u16> {
    if b.remaining() < 2 {
        bail!("short read u16");
    }
    Ok(b.get_u16())
}
fn read_u32(b: &mut Bytes) -> Result<u32> {
    if b.remaining() < 4 {
        bail!("short read u32");
    }
    Ok(b.get_u32())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b32_roundtrip() {
        for input in [
            b"".to_vec(),
            b"a".to_vec(),
            b"ab".to_vec(),
            b"abcde".to_vec(),
            (0..200u8).collect::<Vec<_>>(),
        ] {
            let enc = b32_encode(&input);
            let dec = b32_decode(enc.as_bytes()).unwrap();
            // base32 may produce trailing zero bits — but we only care that
            // the decoded prefix matches.
            assert!(dec.starts_with(&input), "len {}", input.len());
        }
    }

    #[test]
    fn b64_roundtrip() {
        for input in [
            b"".to_vec(),
            b"a".to_vec(),
            b"ab".to_vec(),
            b"abc".to_vec(),
            (0..200u8).collect::<Vec<_>>(),
        ] {
            let enc = b64_encode(&input);
            assert!(enc
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')));
            let dec = b64_decode(&enc).unwrap();
            assert_eq!(dec, input);
        }
    }

    #[test]
    fn query_capacity_reasonable() {
        let cap = query_capacity("t.example.com");
        // With a 15-octet zone we expect somewhere between 100 and 160 raw
        // bytes per query.
        assert!(cap >= 100, "cap={cap}");
        assert!(cap <= 160, "cap={cap}");
    }

    #[test]
    fn query_round_trip() {
        let zone = "t.example.com";
        let payload: Vec<u8> = (0..query_capacity(zone) as u32)
            .map(|i| (i & 0xff) as u8)
            .collect();
        let msg = encode_query(0x1234, zone, &payload).unwrap();
        let parsed = match decode_packet(msg, zone).unwrap() {
            ParsedPacket::Tunnel(q) => q,
            ParsedPacket::Question(_) => panic!("expected tunnel query"),
        };
        assert_eq!(parsed.txid, 0x1234);
        assert_eq!(parsed.qtype, QTYPE_TXT);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn query_empty_round_trip() {
        let zone = "t.example.com";
        let msg = encode_query(0xBEEF, zone, &[]).unwrap();
        let parsed = match decode_packet(msg, zone).unwrap() {
            ParsedPacket::Tunnel(q) => q,
            ParsedPacket::Question(_) => panic!("expected tunnel query"),
        };
        assert_eq!(parsed.txid, 0xBEEF);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn response_round_trip() {
        let qname = b"\x04abcd\x07example\x03com\x00";
        let payload: Vec<u8> = (0..MAX_RESPONSE_PAYLOAD as u32)
            .map(|i| (i.wrapping_mul(7) & 0xff) as u8)
            .collect();
        let msg = encode_response(0x4242, qname, QTYPE_TXT, &payload).unwrap();
        assert!(msg
            .windows(1)
            .any(|b| b[0].is_ascii_alphanumeric() || matches!(b[0], b'+' | b'/' | b'=')));
        let (txid, body) = decode_response(msg).unwrap();
        assert_eq!(txid, 0x4242);
        assert_eq!(body, payload);
    }

    #[test]
    fn response_empty_round_trip() {
        let qname = b"\x07example\x03com\x00";
        let msg = encode_response(0x0001, qname, QTYPE_TXT, &[]).unwrap();
        let (txid, body) = decode_response(msg).unwrap();
        assert_eq!(txid, 0x0001);
        assert!(body.is_empty());
    }

    #[test]
    fn payload_over_capacity_rejected() {
        let zone = "t.example.com";
        let too_big = vec![0u8; query_capacity(zone) + 1];
        assert!(encode_query(0, zone, &too_big).is_err());
    }

    #[test]
    fn ns_probe_response_is_valid_question_response() {
        let qname = b"\x01t\x07example\x03com\x00";
        let msg = encode_ns_response(0xCAFE, qname, "t.example.com").unwrap();
        let mut cur = msg;
        assert_eq!(read_u16(&mut cur).unwrap(), 0xCAFE);
        let flags = read_u16(&mut cur).unwrap();
        assert_ne!(flags & 0x8000, 0);
        assert_eq!(read_u16(&mut cur).unwrap(), 1);
        assert_eq!(read_u16(&mut cur).unwrap(), 1);
    }
}
