//! Strict-conformance DoQ (RFC 9250) DNS message codec.
//!
//! ## Wire format
//!
//! ### Query (`encode_query`)
//! ```text
//! Header     ID=0, Flags=0x0100 (RD=1)
//!            QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1
//! Question   QNAME = "<short-prefix>.<popular-domain>." (e.g. "x1k7.googleapis.com.")
//!            QTYPE = 1 (A) | 28 (AAAA) | 65 (HTTPS), rotated per-message
//!            QCLASS = 1 (IN)
//! Additional OPT pseudo-record (RFC 6891):
//!            NAME=root, TYPE=41, CLASS=4096 (UDP size), TTL=0
//!            RDATA = OptionCode=12 (PADDING, RFC 7830) | OptionLen | payload
//! ```
//!
//! Browsers routinely send queries with EDNS0 padding to pad messages to
//! block boundaries; carrying our session frame inside that padding is
//! indistinguishable from normal traffic at the per-message DNS level.
//!
//! ### Response (`encode_response`)
//! ```text
//! Header     ID=0, Flags=0x8180 (QR=1, RD=1, RA=1, RCODE=0)
//!            QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
//! Question   echoes the QNAME / QTYPE / QCLASS from the query
//! Answer     NAME  = compression pointer 0xC00C to the question QNAME
//!            TYPE  = 65 (HTTPS), CLASS = IN, TTL = 300
//!            RDATA = u16 SvcPriority(0) | u8 TargetName(root) | payload bytes
//! ```
//!
//! ## Caps
//! * `MAX_QUERY_PAYLOAD` — bytes of opaque payload per query (OPT RDATA).
//! * `MAX_RESPONSE_PAYLOAD` — soft cap on per-response RDATA.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::seq::SliceRandom;
use rand::Rng;

const FLAGS_QUERY: u16 = 0x0100;
const FLAGS_RESPONSE: u16 = 0x8180;
const CLASS_IN: u16 = 1;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_HTTPS: u16 = 65;

const SUFFIX_POOL: &[&str] = &[
    "googleapis.com",
    "cloudfront.net",
    "akamaiedge.net",
    "fastly.net",
    "azureedge.net",
    "amazonaws.com",
    "github.io",
    "wikipedia.org",
];

const PREFIX_POOL: &[&str] = &[
    "static", "cdn", "assets", "api", "www", "edge", "img", "fonts", "s3", "media",
];

const OPT_TYPE: u16 = 41;
const OPT_CODE_PADDING: u16 = 12;

/// Max raw payload per query (carried inside the EDNS0 OPT padding option).
pub const MAX_QUERY_PAYLOAD: usize = 2048;

/// Soft cap on response RDATA payload (under HTTPS record).
pub const MAX_RESPONSE_PAYLOAD: usize = 3800;

/// Parsed query: bytes pulled from the QNAME labels (minus suffix) and the
/// raw QNAME so the server can echo it verbatim in its response.
pub struct ParsedQuery {
    pub payload: Vec<u8>,
    pub qname_raw: Bytes,
    pub qtype: u16,
}

pub fn encode_query(payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_QUERY_PAYLOAD {
        bail!(
            "query payload {} exceeds MAX_QUERY_PAYLOAD {}",
            payload.len(),
            MAX_QUERY_PAYLOAD
        );
    }
    let mut buf = BytesMut::with_capacity(payload.len() + 64);
    buf.put_u16(0); // ID — RFC 9250 §4.2.1
    buf.put_u16(FLAGS_QUERY);
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(0); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(1); // ARCOUNT (one OPT pseudo-record)

    let mut rng = rand::thread_rng();
    let suffix = SUFFIX_POOL
        .choose(&mut rng)
        .copied()
        .unwrap_or("example.com");
    let prefix = PREFIX_POOL.choose(&mut rng).copied().unwrap_or("www");
    let qtype = *[QTYPE_A, QTYPE_AAAA, QTYPE_HTTPS].choose(&mut rng).unwrap();
    let extra_prefix: String = (0..rng.gen_range(2..=4))
        .map(|_| char::from(b'a' + rng.gen_range(0..26)))
        .collect();
    let host_first = format!("{prefix}{extra_prefix}");

    write_short_qname(&mut buf, &host_first, suffix)?;
    buf.put_u16(qtype);
    buf.put_u16(CLASS_IN);

    // OPT pseudo-record carrying payload as a PADDING option (RFC 7830)
    buf.put_u8(0); // NAME = root
    buf.put_u16(OPT_TYPE); // TYPE = OPT (41)
    buf.put_u16(4096); // CLASS = requestor's UDP payload size
    buf.put_u32(0); // TTL = extended-rcode/flags
    let rdlen = 4 + payload.len();
    if rdlen > u16::MAX as usize {
        bail!("OPT RDATA too large");
    }
    buf.put_u16(rdlen as u16);
    buf.put_u16(OPT_CODE_PADDING);
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);

    Ok(buf.freeze())
}

pub fn decode_query(mut msg: Bytes) -> Result<ParsedQuery> {
    let start = msg.clone();
    let _id = read_u16(&mut msg)?;
    let flags = read_u16(&mut msg)?;
    if flags != FLAGS_QUERY {
        bail!("query flags 0x{flags:04x}");
    }
    let qd = read_u16(&mut msg)?;
    let an = read_u16(&mut msg)?;
    let _ns = read_u16(&mut msg)?;
    let ar = read_u16(&mut msg)?;
    if qd != 1 || an != 0 || ar != 1 {
        bail!("query counts qd={qd} an={an} ar={ar}");
    }
    let qname_start_off = 12;
    let (_labels, qname_end_off) = parse_name(&start, qname_start_off)?;
    msg.advance(qname_end_off - qname_start_off);
    let qtype = read_u16(&mut msg)?;
    let _qclass = read_u16(&mut msg)?;

    // Additional section: OPT pseudo-record with PADDING option carrying payload
    skip_name_or_pointer(&mut msg)?;
    let opt_type = read_u16(&mut msg)?;
    if opt_type != OPT_TYPE {
        bail!("expected OPT in additional section, got TYPE={opt_type}");
    }
    let _opt_class = read_u16(&mut msg)?;
    let _opt_ttl = read_u32(&mut msg)?;
    let rdlen = read_u16(&mut msg)? as usize;
    if msg.remaining() < rdlen {
        bail!("OPT RDATA truncated");
    }
    let mut opt_rd = msg.split_to(rdlen);
    let opt_code = read_u16(&mut opt_rd)?;
    if opt_code != OPT_CODE_PADDING {
        bail!("expected PADDING option, got code={opt_code}");
    }
    let opt_len = read_u16(&mut opt_rd)? as usize;
    if opt_rd.remaining() < opt_len {
        bail!("PADDING option truncated");
    }
    let payload = opt_rd.split_to(opt_len).to_vec();

    let qname_raw = start.slice(qname_start_off..qname_end_off);
    Ok(ParsedQuery {
        payload,
        qname_raw,
        qtype,
    })
}

pub fn encode_response(question_qname: &[u8], qtype: u16, payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_RESPONSE_PAYLOAD {
        bail!(
            "response payload {} exceeds MAX_RESPONSE_PAYLOAD {}",
            payload.len(),
            MAX_RESPONSE_PAYLOAD
        );
    }
    let mut buf = BytesMut::with_capacity(64 + payload.len());
    buf.put_u16(0); // ID
    buf.put_u16(FLAGS_RESPONSE);
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(1); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(0); // ARCOUNT
                    // Question (echoes query)
    buf.put_slice(question_qname);
    buf.put_u16(qtype);
    buf.put_u16(CLASS_IN);
    // Answer
    buf.put_u16(0xC00C); // NAME = compression pointer to QNAME at offset 12
    buf.put_u16(QTYPE_HTTPS); // TYPE = HTTPS
    buf.put_u16(CLASS_IN); // CLASS = IN
    buf.put_u32(300); // TTL
    let rdlen = 2 + 1 + payload.len();
    if rdlen > u16::MAX as usize {
        bail!("response RDATA too large");
    }
    buf.put_u16(rdlen as u16);
    buf.put_u16(0); // SvcPriority
    buf.put_u8(0); // TargetName = root
    buf.put_slice(payload);
    Ok(buf.freeze())
}

pub fn decode_response(mut msg: Bytes) -> Result<Vec<u8>> {
    let start = msg.clone();
    let _id = read_u16(&mut msg)?;
    let flags = read_u16(&mut msg)?;
    if flags != FLAGS_RESPONSE {
        bail!("response flags 0x{flags:04x}");
    }
    let qd = read_u16(&mut msg)?;
    let an = read_u16(&mut msg)?;
    let _ns = read_u16(&mut msg)?;
    let _ar = read_u16(&mut msg)?;
    if qd != 1 || an < 1 {
        bail!("response counts qd={qd} an={an}");
    }
    // Skip question
    let (_q_labels, q_end_off) = parse_name(&start, 12)?;
    msg.advance(q_end_off - 12);
    let _qtype = read_u16(&mut msg)?;
    let _qclass = read_u16(&mut msg)?;
    // Answer: NAME (pointer or labels), TYPE, CLASS, TTL, RDLEN, RDATA
    skip_name_or_pointer(&mut msg)?;
    let _atype = read_u16(&mut msg)?;
    let _aclass = read_u16(&mut msg)?;
    let _ttl = read_u32(&mut msg)?;
    let rdlen = read_u16(&mut msg)? as usize;
    if msg.remaining() < rdlen {
        bail!("response RDATA truncated");
    }
    let rdata = msg.split_to(rdlen);
    if rdata.len() < 3 {
        bail!("response RDATA too short");
    }
    // strip SvcPriority(2) + TargetName(1 byte = root)
    Ok(rdata[3..].to_vec())
}

fn write_short_qname(buf: &mut BytesMut, first_label: &str, suffix: &str) -> Result<()> {
    for label in std::iter::once(first_label).chain(suffix.split('.').filter(|l| !l.is_empty())) {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            bail!("invalid label {label:?}");
        }
        buf.put_u8(bytes.len() as u8);
        buf.put_slice(bytes);
    }
    buf.put_u8(0);
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
            // pointer — 14-bit offset
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

/// Sleep duration that the server should hold an empty downstream poll. Real
/// DNS resolvers take 10–100 ms; we sit at the high end.
pub fn poll_hold_ms() -> u64 {
    rand::thread_rng().gen_range(80..=160)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let payload: Vec<u8> = (0..MAX_QUERY_PAYLOAD as u32)
            .map(|i| (i & 0xff) as u8)
            .collect();
        let msg = encode_query(&payload).unwrap();
        let parsed = decode_query(msg).unwrap();
        assert_eq!(parsed.payload, payload);
        assert!(matches!(parsed.qtype, QTYPE_A | QTYPE_AAAA | QTYPE_HTTPS));
    }

    #[test]
    fn empty_query_round_trip() {
        let msg = encode_query(&[]).unwrap();
        let parsed = decode_query(msg).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn response_round_trip() {
        // Fabricate a question qname (label bytes) for the server to echo.
        let qname = b"\x03foo\x07example\x03com\x00";
        let payload = vec![0xAB; MAX_RESPONSE_PAYLOAD];
        let msg = encode_response(qname, QTYPE_HTTPS, &payload).unwrap();
        let body = decode_response(msg).unwrap();
        assert_eq!(body, payload);
    }

    #[test]
    fn empty_response_round_trip() {
        let qname = b"\x07example\x03com\x00";
        let msg = encode_response(qname, QTYPE_A, &[]).unwrap();
        let body = decode_response(msg).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn query_payload_too_large() {
        let payload = vec![0u8; MAX_QUERY_PAYLOAD + 1];
        assert!(encode_query(&payload).is_err());
    }
}
