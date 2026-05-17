//! Session multiplexing protocol carried inside each DNS message.
//!
//! All payload bytes traversing the tunnel are wrapped in this header:
//!
//! ```text
//!   0      8      9     11      …
//!  +------+------+------+--------+
//!  | id   |flags | seq  | body   |
//!  +------+------+------+--------+
//!     u64    u8    u16    bytes
//! ```
//!
//! * `id` — 64-bit session identifier chosen randomly by the client when a
//!   TCP connection is accepted. Lives until either side sets CLOSE.
//! * `flags` — bit 0 (`OPEN`) is set on the very first frame of a session;
//!   bit 1 (`CLOSE`) is set on the final frame from either side.
//! * `seq` — monotonically increasing per direction. Currently advisory
//!   (single-flight queries guarantee in-order delivery), but reserved for
//!   future reordering work.
//! * `body` — opaque payload bytes (may be empty: empty queries act as
//!   downstream polls; empty responses signal "nothing yet").

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, BytesMut};

pub const HEADER_LEN: usize = 8 + 1 + 2;

pub const FLAG_OPEN: u8 = 0b0000_0001;
pub const FLAG_CLOSE: u8 = 0b0000_0010;

#[derive(Debug, Clone)]
pub struct Frame {
    pub session: u64,
    pub flags: u8,
    pub seq: u16,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u64(self.session);
        out.put_u8(self.flags);
        out.put_u16(self.seq);
        out.put_slice(&self.body);
    }

    pub fn encode_vec(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.body.len());
        self.encode(&mut buf);
        buf.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            bail!("frame header truncated ({} bytes)", bytes.len());
        }
        let mut cur = bytes;
        let session = cur.get_u64();
        let flags = cur.get_u8();
        let seq = cur.get_u16();
        Ok(Self {
            session,
            flags,
            seq,
            body: cur.to_vec(),
        })
    }

    pub fn is_open(&self) -> bool {
        self.flags & FLAG_OPEN != 0
    }
    pub fn is_close(&self) -> bool {
        self.flags & FLAG_CLOSE != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let f = Frame {
            session: 0xDEAD_BEEF_CAFE_0123,
            flags: FLAG_OPEN,
            seq: 42,
            body: b"hello".to_vec(),
        };
        let bytes = f.encode_vec();
        let decoded = Frame::decode(&bytes).unwrap();
        assert_eq!(decoded.session, f.session);
        assert_eq!(decoded.flags, f.flags);
        assert_eq!(decoded.seq, f.seq);
        assert_eq!(decoded.body, f.body);
    }
}
