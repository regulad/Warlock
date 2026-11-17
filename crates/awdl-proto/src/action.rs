// SPDX-License-Identifier: GPL-2.0-only
//! AWDL action frames: Periodic Synchronization Frames (PSF) and Master
//! Indication Frames (MIF).
//!
//! The 802.11 action body is a vendor-specific action: category 127, Apple's
//! OUI, AWDL type 8, then a 12-byte fixed header and the TLVs:
//!
//! ```text
//! u8 category (127)  u8[3] OUI (00:17:f2)  u8 type (8)
//! u8 version (major << 4 | minor)  u8 subtype  u8 reserved
//! u32 LE PHY TX time (µs)  u32 LE target TX time (µs)
//! TLVs …
//! ```
//!
//! Layout: Wireshark `packet-awdl.c`, `dissect_awdl_action`.

use alloc::vec::Vec;
use core::fmt;

use crate::ieee80211::Header;
use crate::tlv::{self, Tlv, TlvBody, TlvIter};
use crate::wire::{Put, Reader};
use crate::{APPLE_OUI, Error};

/// The 802.11 action category for vendor-specific actions.
pub const CATEGORY_VENDOR_SPECIFIC: u8 = 127;
/// The type byte after Apple's OUI that marks AWDL.
pub const AWDL_TYPE: u8 = 8;
/// Bytes from the start of the 802.11 body to the first TLV.
pub const FIXED_LEN: usize = 16;
/// Offset of the PHY TX time within the 802.11 body.
const PHY_TX_TIME_OFFSET: usize = 8;

/// Action frame subtypes.
pub mod subtype {
    /// Periodic Synchronization Frame.
    pub const PSF: u8 = 0;
    /// Master Indication Frame.
    pub const MIF: u8 = 3;
}

/// An AWDL protocol version, `major.minor`, encoded as one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AwdlVersion {
    /// Major version (high nibble).
    pub major: u8,
    /// Minor version (low nibble).
    pub minor: u8,
}

impl AwdlVersion {
    /// Decodes `major << 4 | minor`.
    pub const fn from_byte(b: u8) -> Self {
        Self { major: b >> 4, minor: b & 0xf }
    }

    /// Encodes as `major << 4 | minor` (each truncated to a nibble).
    pub const fn to_byte(self) -> u8 {
        (self.major & 0xf) << 4 | (self.minor & 0xf)
    }
}

impl fmt::Display for AwdlVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The fixed fields between the AWDL type byte and the TLVs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionHeader {
    /// Frame format version. Every capture so far, iOS 27 included, says 1.0.
    pub version: AwdlVersion,
    /// [`subtype::PSF`] or [`subtype::MIF`].
    pub subtype: u8,
    /// Reserved; zero in captures.
    pub reserved: u8,
    /// When the sender handed the frame to its PHY, in µs on its clock.
    pub phy_tx_time: u32,
    /// When the sender meant to transmit, in µs on its clock.
    pub target_tx_time: u32,
}

/// An AWDL action frame body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionFrame<'a> {
    /// The fixed header.
    pub header: ActionHeader,
    tlvs: &'a [u8],
    trailer: &'a [u8],
}

impl<'a> ActionFrame<'a> {
    /// Parses an 802.11 action body (starting at the category byte).
    ///
    /// `Ok(None)` means it's an action frame but not AWDL. The TLV framing is
    /// checked here, so [`ActionFrame::tlvs`] can't fail.
    pub fn parse(body: &'a [u8]) -> Result<Option<Self>, Error> {
        if body.len() < 5
            || body[0] != CATEGORY_VENDOR_SPECIFIC
            || body[1..4] != APPLE_OUI
            || body[4] != AWDL_TYPE
        {
            return Ok(None);
        }
        let mut r = Reader::new(&body[5..]);
        let header = ActionHeader {
            version: AwdlVersion::from_byte(r.u8("AWDL version")?),
            subtype: r.u8("AWDL subtype")?,
            reserved: r.u8("AWDL reserved")?,
            phy_tx_time: r.u32le("PHY TX time")?,
            target_tx_time: r.u32le("target TX time")?,
        };
        let region = r.rest();
        let split = tlv::validate(region)?;
        Ok(Some(Self {
            header,
            tlvs: &region[..split],
            trailer: &region[split..],
        }))
    }

    /// True for a Periodic Synchronization Frame.
    pub fn is_psf(&self) -> bool {
        self.header.subtype == subtype::PSF
    }

    /// True for a Master Indication Frame.
    pub fn is_mif(&self) -> bool {
        self.header.subtype == subtype::MIF
    }

    /// The TLVs, in order.
    pub fn tlvs(&self) -> TlvIter<'a> {
        TlvIter::new(self.tlvs)
    }

    /// The first TLV of the given type.
    pub fn find(&self, kind: u8) -> Option<Tlv<'a>> {
        self.tlvs().find(|t| t.kind == kind)
    }

    /// The encoded TLVs.
    pub fn tlv_bytes(&self) -> &'a [u8] {
        self.tlvs
    }

    /// Bytes after the last whole TLV, too short to be one. Empty in every
    /// capture so far.
    pub fn trailer(&self) -> &'a [u8] {
        self.trailer
    }

    /// Appends the action body, from the category byte on.
    pub fn emit(&self, out: &mut Vec<u8>) {
        emit_fixed(out, &self.header);
        out.put(self.tlvs);
        out.put(self.trailer);
    }
}

fn emit_fixed(out: &mut Vec<u8>, h: &ActionHeader) {
    out.put_u8(CATEGORY_VENDOR_SPECIFIC);
    out.put(&APPLE_OUI);
    out.put_u8(AWDL_TYPE);
    out.put_u8(h.version.to_byte());
    out.put_u8(h.subtype);
    out.put_u8(h.reserved);
    out.put_u32le(h.phy_tx_time);
    out.put_u32le(h.target_tx_time);
}

/// Builds a complete action-frame MPDU (802.11 header included, no FCS).
#[derive(Clone, Debug)]
pub struct ActionFrameBuilder {
    buf: Vec<u8>,
}

impl ActionFrameBuilder {
    /// Starts a frame with the given 802.11 and AWDL headers.
    pub fn new(header: &Header, action: &ActionHeader) -> Self {
        let mut buf = Vec::with_capacity(512);
        header.emit(&mut buf);
        emit_fixed(&mut buf, action);
        Self { buf }
    }

    /// Appends a typed TLV.
    pub fn tlv(&mut self, body: &TlvBody<'_>) -> Result<&mut Self, Error> {
        body.emit(&mut self.buf)?;
        Ok(self)
    }

    /// Appends a TLV from its type and raw value.
    pub fn raw_tlv(&mut self, kind: u8, value: &[u8]) -> Result<&mut Self, Error> {
        Tlv { kind, value }.emit(&mut self.buf)?;
        Ok(self)
    }

    /// The finished MPDU.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Overwrites the PHY and target TX times in a built action-frame MPDU, for
/// stamping them just before the frame goes to the radio.
pub fn set_tx_times(mpdu: &mut [u8], phy_tx_time: u32, target_tx_time: u32) -> Result<(), Error> {
    let body_len = {
        let (_, body) = Header::parse(mpdu)?;
        if ActionFrame::parse(body)?.is_none() {
            return Err(Error::Invalid("not an AWDL action frame"));
        }
        body.len()
    };
    let at = mpdu.len() - body_len + PHY_TX_TIME_OFFSET;
    mpdu[at..at + 4].copy_from_slice(&phy_tx_time.to_le_bytes());
    mpdu[at + 4..at + 8].copy_from_slice(&target_tx_time.to_le_bytes());
    Ok(())
}
