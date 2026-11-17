// SPDX-License-Identifier: GPL-2.0-only
//! AWDL data frames.
//!
//! An AWDL data frame is an ordinary 802.11 data frame (subtype Data, not
//! QoS, in captures) whose body is:
//!
//! ```text
//! aa aa 03 00 17 f2 08 00   LLC/SNAP, Apple OUI, protocol 0x0800 (AWDL)
//! 03 04                     AWDL data header
//! u16 LE                    sequence number
//! 00 00                     (or a "long format" extension, see below)
//! u16 BE                    EtherType (0x86dd)
//! payload
//! ```
//!
//! Wireshark describes a long format, where the two bytes after the sequence
//! number start with 3 and introduce short TLVs. Every captured frame used
//! the short form; the long form is accepted and kept raw.

use alloc::vec::Vec;

use crate::wire::{Put, Reader};
use crate::{APPLE_OUI, Bytes, Error};

/// The LLC/SNAP header of AWDL data: DSAP/SSAP 0xaa, UI, Apple's OUI, and
/// protocol ID 0x0800.
pub const LLC_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, APPLE_OUI[0], APPLE_OUI[1], APPLE_OUI[2], 0x08, 0x00];
/// The two bytes that start the AWDL data header.
pub const MAGIC: [u8; 2] = [0x03, 0x04];
/// The usual header extension: two zero bytes.
pub const SHORT_EXT: [u8; 2] = [0x00, 0x00];

/// EtherType of IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// An AWDL data frame body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataFrame<'a> {
    /// AWDL's own sequence number.
    pub seq: u16,
    /// Bytes between the sequence number and the EtherType: normally
    /// [`SHORT_EXT`].
    pub ext: Bytes<'a>,
    /// EtherType of the payload.
    pub ethertype: u16,
    /// The payload (an IPv6 packet, in practice).
    pub payload: Bytes<'a>,
}

impl<'a> DataFrame<'a> {
    /// A frame with the usual short header.
    pub fn new(seq: u16, ethertype: u16, payload: &'a [u8]) -> Self {
        Self {
            seq,
            ext: Bytes::Borrowed(&SHORT_EXT),
            ethertype,
            payload: Bytes::Borrowed(payload),
        }
    }

    /// Parses an 802.11 data body. `Ok(None)` means it isn't AWDL.
    pub fn parse(body: &'a [u8]) -> Result<Option<Self>, Error> {
        if !body.starts_with(&LLC_SNAP) {
            return Ok(None);
        }
        let mut r = Reader::new(&body[LLC_SNAP.len()..]);
        if r.array::<2>("AWDL data header")? != MAGIC {
            return Err(Error::Invalid("AWDL data header"));
        }
        let seq = r.u16le("AWDL data sequence")?;
        let before = r.clone();
        if r.peek_u8() == Some(3) {
            // Long format: a 3-tagged block, short TLVs, another 3-tagged block.
            let skip_block = |r: &mut Reader<'a>| -> Result<(), Error> {
                r.u8("AWDL data ext tag")?;
                let n = r.u8("AWDL data ext length")? as usize;
                r.bytes(n, "AWDL data ext")?;
                Ok(())
            };
            skip_block(&mut r)?;
            loop {
                match r.peek_u8() {
                    Some(3) => break,
                    Some(_) => skip_block(&mut r)?,
                    None => return Err(Error::Truncated("AWDL data ext TLVs")),
                }
            }
            skip_block(&mut r)?;
        } else {
            r.bytes(2, "AWDL data ext")?;
        }
        let ext_len = before.remaining() - r.remaining();
        let ext = &body[body.len() - before.remaining()..][..ext_len];
        let ethertype = r.u16be("EtherType")?;
        Ok(Some(Self {
            seq,
            ext: Bytes::Borrowed(ext),
            ethertype,
            payload: Bytes::Borrowed(r.rest()),
        }))
    }

    /// Appends the body, from the LLC/SNAP header on.
    pub fn emit(&self, out: &mut Vec<u8>) {
        out.put(&LLC_SNAP);
        out.put(&MAGIC);
        out.put_u16le(self.seq);
        out.put(&self.ext);
        out.put_u16be(self.ethertype);
        out.put(&self.payload);
    }
}
