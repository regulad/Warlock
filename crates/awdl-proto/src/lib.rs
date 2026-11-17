// SPDX-License-Identifier: GPL-2.0-only
//! Parse and build Apple Wireless Direct Link (AWDL) frames.
//!
//! [`parse`] takes one 802.11 MPDU (no radiotap header, FCS already stripped)
//! and returns the AWDL frame in it, if there is one:
//!
//! - [`Frame::Action`]: a Periodic Synchronization Frame (PSF) or Master
//!   Indication Frame (MIF), whose [`tlv`]s carry AWDL's synchronization,
//!   election, channel-sequence and service-discovery state;
//! - [`Frame::Data`]: an AWDL data frame, which carries an EtherType payload
//!   (IPv6 in practice) behind AWDL's LLC/SNAP encapsulation.
//!
//! Parsing borrows from the input. Variable-length fields are
//! [`Cow`](alloc::borrow::Cow)s, so the same types are used to build frames.
//!
//! **Round-trip guarantee:** every frame and TLV this crate accepts re-emits
//! byte-for-byte. Bytes it doesn't understand are kept, not dropped: see the
//! `trailing` fields, [`tlv::TlvBody::Unknown`] and
//! [`action::ActionFrame::trailer`].
//!
//! Layouts follow our own captures of iOS 27, macOS 11 and Apple TV traffic,
//! with Wireshark's AWDL dissector and the MobiCom '18 paper "One Billion
//! Apples' Secret Sauce" as references. No code was taken from either.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod action;
pub mod data;
pub mod dns;
mod error;
mod frame;
pub mod ieee80211;
mod mac;
pub mod tlv;
mod wire;

pub use error::Error;
pub use frame::{Frame, parse};
pub use mac::MacAddr;

/// Apple's IEEE OUI, which AWDL uses in its action frames and LLC/SNAP header.
pub const APPLE_OUI: [u8; 3] = [0x00, 0x17, 0xf2];

/// The fixed BSSID (802.11 address 3) of every AWDL frame.
pub const AWDL_BSSID: MacAddr = MacAddr([0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);

/// A field's raw bytes: borrowed when parsed, owned when built.
pub type Bytes<'a> = alloc::borrow::Cow<'a, [u8]>;
