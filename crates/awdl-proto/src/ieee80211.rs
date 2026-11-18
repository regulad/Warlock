// SPDX-License-Identifier: GPL-2.0-only
//! The 802.11 MAC header, as far as AWDL uses it: three-address management
//! (action) and data frames with ToDS = FromDS = 0, where address 1 is the
//! destination, address 2 the source and address 3 [`AWDL_BSSID`].

use alloc::vec::Vec;

use crate::wire::{Put, Reader};
use crate::{AWDL_BSSID, Error, MacAddr};

/// Frame-control values (as the little-endian u16 on the wire) and bits.
pub mod frame_control {
    /// Management frame, subtype Action: AWDL's PSFs and MIFs.
    pub const ACTION: u16 = 0x00d0;
    /// Management frame, subtype Action No Ack.
    pub const ACTION_NO_ACK: u16 = 0x00e0;
    /// Data frame, subtype Data: what Apple devices use for AWDL data.
    pub const DATA: u16 = 0x0008;
    /// Data frame, subtype QoS Data.
    pub const QOS_DATA: u16 = 0x0088;

    /// To DS.
    pub const TO_DS: u16 = 0x0100;
    /// From DS.
    pub const FROM_DS: u16 = 0x0200;
    /// Protected Frame (encrypted body).
    pub const PROTECTED: u16 = 0x4000;
    /// +HTC/Order: an HT Control field follows (management and QoS data).
    pub const ORDER: u16 = 0x8000;
}

/// An 802.11 MAC header for a three-address frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Frame control, as the little-endian u16 on the wire.
    pub frame_control: u16,
    /// Duration/ID.
    pub duration: u16,
    /// Address 1: the destination (and receiver).
    pub addr1: MacAddr,
    /// Address 2: the source (and transmitter).
    pub addr2: MacAddr,
    /// Address 3: the BSSID, [`AWDL_BSSID`] for AWDL.
    pub addr3: MacAddr,
    /// Sequence control: sequence number << 4 | fragment number.
    pub seq_ctrl: u16,
    /// QoS control, present in QoS data frames.
    pub qos_ctrl: Option<u16>,
    /// HT control, present when the Order bit is set.
    pub ht_ctrl: Option<u32>,
}

impl Header {
    /// Header of an AWDL action frame (PSF or MIF).
    pub fn action(source: MacAddr, destination: MacAddr, sequence_number: u16) -> Self {
        Self::new(frame_control::ACTION, source, destination, sequence_number)
    }

    /// Header of an AWDL data frame.
    pub fn data(source: MacAddr, destination: MacAddr, sequence_number: u16) -> Self {
        Self::new(frame_control::DATA, source, destination, sequence_number)
    }

    fn new(frame_control: u16, source: MacAddr, destination: MacAddr, seq: u16) -> Self {
        Self {
            frame_control,
            duration: 0,
            addr1: destination,
            addr2: source,
            addr3: AWDL_BSSID,
            seq_ctrl: (seq & 0x0fff) << 4,
            qos_ctrl: None,
            ht_ctrl: None,
        }
    }

    /// Frame type: 0 management, 1 control, 2 data.
    pub const fn frame_type(&self) -> u8 {
        ((self.frame_control >> 2) & 3) as u8
    }

    /// Frame subtype.
    pub const fn subtype(&self) -> u8 {
        ((self.frame_control >> 4) & 0xf) as u8
    }

    /// The 12-bit sequence number.
    pub const fn sequence_number(&self) -> u16 {
        self.seq_ctrl >> 4
    }

    /// The destination address (address 1).
    pub const fn destination(&self) -> MacAddr {
        self.addr1
    }

    /// The source address (address 2).
    pub const fn source(&self) -> MacAddr {
        self.addr2
    }

    /// Parses a three-address header. Returns it and the frame body.
    ///
    /// Doesn't check ToDS/FromDS: four-address frames would parse wrongly, so
    /// callers check those bits first (as [`crate::parse`] does).
    pub fn parse(mpdu: &[u8]) -> Result<(Self, &[u8]), Error> {
        let mut r = Reader::new(mpdu);
        let frame_control = r.u16le("frame control")?;
        let duration = r.u16le("duration")?;
        let addr1 = r.mac("address 1")?;
        let addr2 = r.mac("address 2")?;
        let addr3 = r.mac("address 3")?;
        let seq_ctrl = r.u16le("sequence control")?;
        let ftype = (frame_control >> 2) & 3;
        let is_qos = ftype == 2 && frame_control & 0x0080 != 0;
        let qos_ctrl = if is_qos { Some(r.u16le("QoS control")?) } else { None };
        let ht_ctrl = if frame_control & frame_control::ORDER != 0 && (ftype == 0 || is_qos) {
            Some(r.u32le("HT control")?)
        } else {
            None
        };
        let h = Self { frame_control, duration, addr1, addr2, addr3, seq_ctrl, qos_ctrl, ht_ctrl };
        Ok((h, r.rest()))
    }

    /// Appends the header.
    pub fn emit(&self, out: &mut Vec<u8>) {
        out.put_u16le(self.frame_control);
        out.put_u16le(self.duration);
        out.put_mac(self.addr1);
        out.put_mac(self.addr2);
        out.put_mac(self.addr3);
        out.put_u16le(self.seq_ctrl);
        if let Some(q) = self.qos_ctrl {
            out.put_u16le(q);
        }
        if let Some(h) = self.ht_ctrl {
            out.put_u32le(h);
        }
    }

    /// Length of the header in bytes.
    pub const fn encoded_len(&self) -> usize {
        24 + if self.qos_ctrl.is_some() { 2 } else { 0 } + if self.ht_ctrl.is_some() { 4 } else { 0 }
    }
}
