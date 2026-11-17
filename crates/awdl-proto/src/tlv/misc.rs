// SPDX-License-Identifier: GPL-2.0-only
//! The small TLVs: version (21), ARPA (16), HT capabilities (7), 802.11
//! container (17) and sync tree (20).
//!
//! Layouts: Wireshark `packet-awdl.c`, `awdl_tag_version`, `awdl_tag_arpa`,
//! `awdl_tag_ht_capabilities` (including how long the MCS bitmask is),
//! `awdl_tag_ieee80211_container` and `awdl_tag_sync_tree`. One departure:
//! the dissector shows only the container's first element, while we read
//! them all.

use alloc::vec::Vec;

use crate::action::AwdlVersion;
use crate::dns::DnsName;
use crate::wire::{Put, Reader};
use crate::{Bytes, Error, MacAddr};

/// Device classes in the version TLV.
pub mod device_class {
    /// macOS.
    pub const MACOS: u8 = 1;
    /// iOS (and iPadOS).
    pub const IOS: u8 = 2;
    /// watchOS.
    pub const WATCHOS: u8 = 4;
    /// tvOS.
    pub const TVOS: u8 = 8;
}

/// Version (type 21): the sender's AWDL implementation version and device
/// class. iOS 27 sends 10.2, device class iOS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionTlv<'a> {
    /// AWDL version.
    pub version: AwdlVersion,
    /// One of [`device_class`].
    pub device_class: u8,
    /// Bytes after the known fields.
    pub trailing: Bytes<'a>,
}

impl<'a> VersionTlv<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        Ok(Self {
            version: AwdlVersion::from_byte(r.u8("version")?),
            device_class: r.u8("device class")?,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.version.to_byte());
        out.put_u8(self.device_class);
        out.put(&self.trailing);
        Ok(())
    }
}

/// ARPA (type 16): the sender's host name. iOS 27 uses a random UUID, as
/// `<uuid>.local`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arpa<'a> {
    /// Flags.
    pub flags: u8,
    /// The host name; fills the rest of the value.
    pub name: DnsName<'a>,
}

impl<'a> Arpa<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        Ok(Self { flags: r.u8("ARPA flags")?, name: DnsName::parse(r.rest())? })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.flags);
        out.put(self.name.as_bytes());
        Ok(())
    }
}

/// HT capabilities (type 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtCapabilities<'a> {
    /// Unknown u16 before the capability field.
    pub unknown: u16,
    /// 802.11 HT capability information.
    pub cap_info: u16,
    /// A-MPDU parameters.
    pub ampdu_params: u8,
    /// Rx MCS bitmask: one byte per spatial stream, 1 to 4 bytes.
    pub rx_mcs: Bytes<'a>,
    /// Two bytes after the MCS bitmask.
    pub tail: u16,
    /// Bytes after that.
    pub trailing: Bytes<'a>,
}

impl<'a> HtCapabilities<'a> {
    /// Parses the value. The MCS bitmask fills the value up to the last two
    /// bytes, at most 4 bytes.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        if v.len() < 8 {
            return Err(Error::Truncated("HT capabilities"));
        }
        let mcs_len = (v.len() - 7).clamp(1, 4);
        let mut r = Reader::new(v);
        Ok(Self {
            unknown: r.u16le("HT unknown")?,
            cap_info: r.u16le("HT capability info")?,
            ampdu_params: r.u8("A-MPDU parameters")?,
            rx_mcs: Bytes::Borrowed(r.bytes(mcs_len, "Rx MCS bitmask")?),
            tail: r.u16le("HT tail")?,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u16le(self.unknown);
        out.put_u16le(self.cap_info);
        out.put_u8(self.ampdu_params);
        out.put(&self.rx_mcs);
        out.put_u16le(self.tail);
        out.put(&self.trailing);
        Ok(())
    }
}

/// 802.11 container (type 17): ordinary 802.11 information elements, such as
/// VHT capabilities (element 191).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ieee80211Container<'a> {
    elements: Bytes<'a>,
    /// Bytes after the last whole element.
    pub trailing: Bytes<'a>,
}

impl<'a> Ieee80211Container<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut used = 0;
        while v.len() - used >= 2 {
            let n = 2 + v[used + 1] as usize;
            if used + n > v.len() {
                break;
            }
            used += n;
        }
        Ok(Self {
            elements: Bytes::Borrowed(&v[..used]),
            trailing: Bytes::Borrowed(&v[used..]),
        })
    }

    /// Builds a container from `(element ID, contents)` pairs.
    pub fn from_elements(elements: &[(u8, &[u8])]) -> Result<Ieee80211Container<'static>, Error> {
        let mut b = Vec::new();
        for (id, data) in elements {
            b.push(*id);
            b.push(u8::try_from(data.len()).map_err(|_| Error::TooLong("802.11 element"))?);
            b.extend_from_slice(data);
        }
        Ok(Ieee80211Container { elements: Bytes::Owned(b), trailing: Bytes::Borrowed(&[]) })
    }

    /// The elements, as `(element ID, contents)`.
    pub fn elements(&self) -> impl Iterator<Item = (u8, &[u8])> {
        let mut rest: &[u8] = &self.elements;
        core::iter::from_fn(move || {
            if rest.len() < 2 {
                return None;
            }
            let (id, n) = (rest[0], rest[1] as usize);
            let data = &rest[2..2 + n];
            rest = &rest[2 + n..];
            Some((id, data))
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put(&self.elements);
        out.put(&self.trailing);
        Ok(())
    }
}

/// Synchronization tree (type 20): addresses from the master down to the
/// sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTree<'a> {
    addresses: Bytes<'a>,
    /// Bytes after the last whole address.
    pub trailing: Bytes<'a>,
}

impl<'a> SyncTree<'a> {
    /// Parses the value. Never fails.
    pub fn parse(v: &'a [u8]) -> Self {
        let n = v.len() / 6 * 6;
        Self { addresses: Bytes::Borrowed(&v[..n]), trailing: Bytes::Borrowed(&v[n..]) }
    }

    /// Builds a tree from addresses.
    pub fn from_addresses(addrs: &[MacAddr]) -> SyncTree<'static> {
        let b = addrs.iter().flat_map(|a| a.0).collect();
        SyncTree { addresses: Bytes::Owned(b), trailing: Bytes::Borrowed(&[]) }
    }

    /// The addresses, in order.
    pub fn addresses(&self) -> impl Iterator<Item = MacAddr> + '_ {
        self.addresses.chunks_exact(6).map(|c| MacAddr([c[0], c[1], c[2], c[3], c[4], c[5]]))
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put(&self.addresses);
        out.put(&self.trailing);
        Ok(())
    }
}
