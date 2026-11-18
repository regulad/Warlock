// SPDX-License-Identifier: GPL-2.0-only
//! Block Ack session setup (802.11 ADDBA): the one non-AWDL action frame an
//! AWDL peer must answer.
//!
//! Captured between iOS 27 and macOS 11 (`docs/awdl-field-observations.md`):
//! - requests carry parameters `0x1003`: TID 0, immediate Block Ack, A-MSDU
//!   allowed, a 64-frame buffer;
//! - responses echo the dialog token and parameters with status 0 and timeout
//!   0;
//! - the iPhone refused a TID 1 session (status 1).
//!
//! The frame body is: category 3 (Block Ack), action (0 request, 1 response),
//! dialog token, then for a request the parameters, timeout and starting
//! sequence control (u16 LE each), and for a response the status, parameters
//! and timeout.

use alloc::vec::Vec;

use crate::ieee80211::{Header, frame_control};
use crate::wire::{Put, Reader};
use crate::{Error, MacAddr};

/// The 802.11 action category for Block Ack.
pub const CATEGORY_BLOCK_ACK: u8 = 3;
/// ADDBA request.
pub const ADDBA_REQUEST: u8 = 0;
/// ADDBA response.
pub const ADDBA_RESPONSE: u8 = 1;

/// An ADDBA request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddbaRequest {
    /// Who asked.
    pub from: MacAddr,
    /// To whom.
    pub to: MacAddr,
    /// Echoed in the response.
    pub dialog_token: u8,
    /// Block Ack parameter set: bit 0 A-MSDU, bit 1 immediate policy, bits
    /// 2–5 TID, bits 6–15 buffer size.
    pub params: u16,
    /// Session timeout, TU (0 = none).
    pub timeout: u16,
    /// Starting sequence control.
    pub ssc: u16,
}

impl AddbaRequest {
    /// The TID the session is for.
    pub fn tid(&self) -> u8 {
        ((self.params >> 2) & 0xf) as u8
    }

    /// The buffer size asked for.
    pub fn buffer_size(&self) -> u16 {
        self.params >> 6
    }

    /// Parses an MPDU. `Ok(None)` for anything that isn't an ADDBA request.
    pub fn parse(mpdu: &[u8]) -> Result<Option<Self>, Error> {
        if mpdu.len() < 2 || u16::from_le_bytes([mpdu[0], mpdu[1]]) & 0x00fc != frame_control::ACTION & 0x00fc {
            return Ok(None);
        }
        let Ok((header, body)) = Header::parse(mpdu) else { return Ok(None) };
        if body.len() < 2 || body[0] != CATEGORY_BLOCK_ACK || body[1] != ADDBA_REQUEST {
            return Ok(None);
        }
        let mut r = Reader::new(&body[2..]);
        Ok(Some(Self {
            from: header.addr2,
            to: header.addr1,
            dialog_token: r.u8("ADDBA dialog token")?,
            params: r.u16le("ADDBA parameters")?,
            timeout: r.u16le("ADDBA timeout")?,
            ssc: r.u16le("ADDBA starting sequence")?,
        }))
    }

    /// The response accepting it as asked, with no timeout, the way macOS
    /// answers an iPhone. `sequence_number` is the response's own 802.11
    /// sequence number.
    pub fn accept(&self, sequence_number: u16) -> Vec<u8> {
        self.respond(0, self.params, sequence_number)
    }

    /// The response refusing it (status 37, "request declined").
    pub fn decline(&self, sequence_number: u16) -> Vec<u8> {
        self.respond(37, self.params, sequence_number)
    }

    fn respond(&self, status: u16, params: u16, sequence_number: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        Header::action(self.to, self.from, sequence_number).emit(&mut out);
        out.put_u8(CATEGORY_BLOCK_ACK);
        out.put_u8(ADDBA_RESPONSE);
        out.put_u8(self.dialog_token);
        out.put_u16le(status);
        out.put_u16le(params);
        out.put_u16le(0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An iPhone's ADDBA request to a Mac, as captured (header, then body).
    const IPHONE_REQUEST: [u8; 33] = [
        0xd0, 0x00, 0x30, 0x00, 0xb6, 0x01, 0x10, 0xf0, 0x98, 0x19, 0x76, 0x56, 0x82, 0x58, 0x57, 0x70, 0x00, 0x25,
        0x00, 0xff, 0x94, 0x73, 0xf0, 0xea, 0x03, 0x00, 0x86, 0x03, 0x10, 0x90, 0xe2, 0x40, 0x84,
    ];

    #[test]
    fn parses_an_iphone_request_and_accepts_it() {
        let req = AddbaRequest::parse(&IPHONE_REQUEST).unwrap().unwrap();
        assert_eq!(req.from, MacAddr([0x76, 0x56, 0x82, 0x58, 0x57, 0x70]));
        assert_eq!((req.dialog_token, req.params, req.timeout), (0x86, 0x1003, 0xe290));
        assert_eq!((req.tid(), req.buffer_size()), (0, 64));
        let resp = req.accept(7);
        let (h, body) = Header::parse(&resp).unwrap();
        assert_eq!((h.addr1, h.addr2, h.sequence_number()), (req.from, req.to, 7));
        // category, action, token, status 0, params 0x1003, timeout 0
        assert_eq!(body, [3, 1, 0x86, 0, 0, 0x03, 0x10, 0, 0]);
    }

    #[test]
    fn ignores_other_frames() {
        let mut psf = IPHONE_REQUEST;
        psf[24] = 127;
        assert_eq!(AddbaRequest::parse(&psf), Ok(None));
        assert_eq!(AddbaRequest::parse(&[0x08, 0x00]), Ok(None));
    }
}
