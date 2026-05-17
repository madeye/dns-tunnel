//! Minimal DNS message codec used to obfuscate arbitrary bytes as DNS
//! query/response messages. The payload is carried as the RDATA of a single
//! TXT record (type 16) in the answer section.
//!
//! Wire format produced:
//!
//! ```text
//! Header (12 B)
//!   ID            : random per message
//!   Flags         : 0x0100 (query, RD=1) or 0x8180 (response, RA=1)
//!   QDCOUNT=1 ANCOUNT=1 NSCOUNT=0 ARCOUNT=0
//! Question
//!   QNAME         : "t.<8 hex>.invalid."  (well-formed labels, RFC 2606 TLD)
//!   QTYPE=16 (TXT) QCLASS=1 (IN)
//! Answer
//!   NAME          : 0xC00C compression pointer to QNAME
//!   TYPE=16 CLASS=1 TTL=0
//!   RDLENGTH      : payload + ceil(len/255) framing bytes
//!   RDATA         : sequence of <len:u8> <bytes...> chunks
//! ```
//!
//! Max payload per DNS message is bounded by the 16-bit RDLENGTH field; we
//! cap chunks at [`MAX_PAYLOAD`] to keep messages comfortably small.

use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::RngCore;

pub const MAX_PAYLOAD: usize = 16 * 1024;
const FLAGS_QUERY: u16 = 0x0100;
const FLAGS_RESPONSE: u16 = 0x8180;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgKind {
    Query,
    Response,
}

pub fn encode(kind: MsgKind, payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_PAYLOAD {
        bail!(
            "payload {} exceeds MAX_PAYLOAD {}",
            payload.len(),
            MAX_PAYLOAD
        );
    }
    let mut buf = BytesMut::with_capacity(payload.len() + 64);
    let id = rand::thread_rng().next_u32() as u16;
    buf.put_u16(id);
    buf.put_u16(match kind {
        MsgKind::Query => FLAGS_QUERY,
        MsgKind::Response => FLAGS_RESPONSE,
    });
    buf.put_u16(1); // QDCOUNT
    buf.put_u16(1); // ANCOUNT
    buf.put_u16(0); // NSCOUNT
    buf.put_u16(0); // ARCOUNT

    // QNAME: "t.<id>.invalid." — a stable shape that varies per message.
    let label = format!("{:08x}", rand::thread_rng().next_u32());
    write_label(&mut buf, b"t");
    write_label(&mut buf, label.as_bytes());
    write_label(&mut buf, b"invalid");
    buf.put_u8(0); // root
    buf.put_u16(TYPE_TXT);
    buf.put_u16(CLASS_IN);

    // Answer
    buf.put_u16(0xC00C); // pointer to QNAME at offset 12
    buf.put_u16(TYPE_TXT);
    buf.put_u16(CLASS_IN);
    buf.put_u32(0); // TTL
    let rdlen = txt_rdlen(payload.len());
    if rdlen > u16::MAX as usize {
        bail!("encoded RDATA too large");
    }
    buf.put_u16(rdlen as u16);
    write_txt_rdata(&mut buf, payload);
    Ok(buf.freeze())
}

pub fn decode(mut msg: Bytes) -> Result<(MsgKind, Bytes)> {
    if msg.len() < 12 {
        bail!("short DNS header");
    }
    let _id = msg.get_u16();
    let flags = msg.get_u16();
    let kind = match flags {
        FLAGS_QUERY => MsgKind::Query,
        FLAGS_RESPONSE => MsgKind::Response,
        other => bail!("unexpected DNS flags 0x{other:04x}"),
    };
    let qdcount = msg.get_u16();
    let ancount = msg.get_u16();
    let _nscount = msg.get_u16();
    let _arcount = msg.get_u16();
    if qdcount != 1 || ancount != 1 {
        bail!("expected qdcount=1 ancount=1, got {qdcount}/{ancount}");
    }
    // Skip QNAME
    skip_name(&mut msg)?;
    if msg.remaining() < 4 {
        bail!("short question tail");
    }
    let qtype = msg.get_u16();
    let _qclass = msg.get_u16();
    if qtype != TYPE_TXT {
        bail!("expected TXT question, got {qtype}");
    }
    // Answer NAME (pointer or label sequence)
    skip_name(&mut msg)?;
    if msg.remaining() < 10 {
        bail!("short answer header");
    }
    let atype = msg.get_u16();
    let _aclass = msg.get_u16();
    let _ttl = msg.get_u32();
    let rdlen = msg.get_u16() as usize;
    if atype != TYPE_TXT {
        bail!("expected TXT answer, got {atype}");
    }
    if msg.remaining() < rdlen {
        bail!("short RDATA");
    }
    let rdata = msg.split_to(rdlen);
    Ok((kind, parse_txt_rdata(rdata)?))
}

fn write_label(buf: &mut BytesMut, label: &[u8]) {
    assert!(label.len() <= 63);
    buf.put_u8(label.len() as u8);
    buf.put_slice(label);
}

fn skip_name(buf: &mut Bytes) -> Result<()> {
    loop {
        if !buf.has_remaining() {
            bail!("truncated name");
        }
        let len = buf.get_u8();
        if len == 0 {
            return Ok(());
        }
        if len & 0xC0 == 0xC0 {
            // 2-byte pointer
            if !buf.has_remaining() {
                bail!("truncated compression pointer");
            }
            let _ = buf.get_u8();
            return Ok(());
        }
        if (len & 0xC0) != 0 {
            bail!("invalid label length byte 0x{len:02x}");
        }
        if buf.remaining() < len as usize {
            bail!("truncated label");
        }
        buf.advance(len as usize);
    }
}

fn txt_rdlen(payload_len: usize) -> usize {
    if payload_len == 0 {
        return 1; // a single empty <len=0> chunk
    }
    payload_len + payload_len.div_ceil(255)
}

fn write_txt_rdata(buf: &mut BytesMut, payload: &[u8]) {
    if payload.is_empty() {
        buf.put_u8(0);
        return;
    }
    for chunk in payload.chunks(255) {
        buf.put_u8(chunk.len() as u8);
        buf.put_slice(chunk);
    }
}

fn parse_txt_rdata(mut data: Bytes) -> Result<Bytes> {
    let mut out = BytesMut::with_capacity(data.remaining());
    while data.has_remaining() {
        let len = data.get_u8() as usize;
        if data.remaining() < len {
            return Err(anyhow!("truncated TXT chunk"));
        }
        out.put_slice(&data.split_to(len));
    }
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small() {
        let payload = b"hello, shadowsocks";
        let msg = encode(MsgKind::Query, payload).unwrap();
        let (kind, decoded) = decode(msg).unwrap();
        assert_eq!(kind, MsgKind::Query);
        assert_eq!(&decoded[..], payload);
    }

    #[test]
    fn round_trip_response_max() {
        let payload = vec![0xAB; MAX_PAYLOAD];
        let msg = encode(MsgKind::Response, &payload).unwrap();
        let (kind, decoded) = decode(msg).unwrap();
        assert_eq!(kind, MsgKind::Response);
        assert_eq!(decoded.len(), payload.len());
        assert!(decoded.iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn round_trip_multi_segment() {
        // > 255 bytes forces multiple TXT <len><bytes> chunks
        let payload: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let msg = encode(MsgKind::Response, &payload).unwrap();
        let (_, decoded) = decode(msg).unwrap();
        assert_eq!(decoded.as_ref(), payload.as_slice());
    }

    #[test]
    fn empty_payload() {
        let msg = encode(MsgKind::Query, &[]).unwrap();
        let (_, decoded) = decode(msg).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn payload_too_large() {
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        assert!(encode(MsgKind::Query, &payload).is_err());
    }
}
