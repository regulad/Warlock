// SPDX-License-Identifier: GPL-2.0-only
//! Data path state (type 12): a u16 of flags, then one optional field per
//! flag, in a fixed order.
//!
//! Layout and flag meanings: Wireshark `packet-awdl.c`,
//! `awdl_tag_datapath_state`. Two departures:
//! - the social channels field stays a raw u16. The dissector reads it as a
//!   channel map when bit 0 is set and as a channel number otherwise, a
//!   heuristic its own comment marks unverified;
//! - bytes after the fields it knows, such as fields of extended flags it
//!   has no layout for (iOS 27 sets several of those), are kept in
//!   `trailing`.

use alloc::vec::Vec;

use crate::wire::{Put, Reader, len_u16};
use crate::{Bytes, Error, MacAddr};

/// Data path state flags that introduce a field.
pub mod flags {
    /// Infrastructure BSSID and channel follow.
    pub const INFRA_BSSID_CHANNEL: u16 = 0x0001;
    /// Infrastructure address follows.
    pub const INFRA_ADDRESS: u16 = 0x0002;
    /// AWDL address follows.
    pub const AWDL_ADDRESS: u16 = 0x0004;
    /// UMI follows.
    pub const UMI: u16 = 0x0010;
    /// Country code follows.
    pub const COUNTRY_CODE: u16 = 0x0100;
    /// Social channels follow.
    pub const SOCIAL_CHANNELS: u16 = 0x0200;
    /// Unicast options follow.
    pub const UNICAST_OPTIONS: u16 = 0x1000;
    /// Extended flags (and their fields) follow.
    pub const EXTENDED: u16 = 0x8000;

    pub(super) const WITH_FIELDS: u16 = INFRA_BSSID_CHANNEL
        | INFRA_ADDRESS
        | AWDL_ADDRESS
        | UMI
        | COUNTRY_CODE
        | SOCIAL_CHANNELS
        | UNICAST_OPTIONS
        | EXTENDED;
}

/// Extended flags that introduce a field.
pub mod ext_flags {
    /// Log trigger follows.
    pub const LOG_TRIGGER: u16 = 0x0001;
    /// RLFC follows.
    pub const RLFC: u16 = 0x0004;
    /// Active time, AW sequence counter and update counter follow.
    pub const COUNTERS: u16 = 0x0040;

    pub(super) const WITH_FIELDS: u16 = LOG_TRIGGER | RLFC | COUNTERS;
}

/// Unicast Master Indication (UMI) codes: what a device asks of one peer in
/// the unicast options of a data path state it sends that peer, a u32 in
/// little-endian. Zero asks nothing. From static analysis of iOS 27.2.1
/// (24B156): names from `wifip2pd`'s `UnicastMasterIndicationOptions`,
/// actions from the driver (issues #5, #10). macOS 11's driver
/// (`IO80211AWDLPeer::parseAwdlDataPathTLVAndTakeAction`) acts on options
/// with no bit of `0xa20` set, as all of these are.
pub mod umi {
    /// Start Universal Control.
    pub const UNIVERSAL_CONTROL_START: u32 = 0x0100_0000;
    /// Start a remote camera session.
    pub const REMOTE_CAMERA_START: u32 = 0x0b00_0000;
    /// Start a TV remote camera session.
    pub const TV_REMOTE_CAMERA_START: u32 = 0x0d00_0000;
    /// Start Sidecar.
    pub const SIDECAR_START: u32 = 0x1000_0000;
    /// Start a remote screen.
    pub const REMOTE_SCREEN_START: u32 = 0x1100_0000;
    /// Start spatial streaming.
    pub const SPATIAL_STREAMING_START: u32 = 0x1300_0000;
    /// Start a Mac virtual display.
    pub const MAC_VIRTUAL_DISPLAY_START: u32 = 0x1500_0000;
    /// Start a Continuity Real Time Group with the sender; the receiver then
    /// sets up Low-Latency Wi-Fi with it. Sent with a realtime group TLV (31).
    pub const CONTINUITY_REALTIME_GROUP_START: u32 = 0x1700_0000;
    /// Stop that group.
    pub const CONTINUITY_REALTIME_GROUP_STOP: u32 = 0x1800_0000;
    /// Start an MP remote camera session.
    pub const MP_REMOTE_CAMERA_START: u32 = 0x4000_0000;
}

/// The infrastructure network the sender is associated with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfraInfo {
    /// BSSID.
    pub bssid: MacAddr,
    /// Channel.
    pub channel: u16,
}

/// The extended part of a data path state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DataPathExt {
    /// Extended flags that introduce no field. The bits in [`ext_flags`]
    /// aren't stored: they follow from which fields are present. See
    /// [`DataPathExt::wire_flags`].
    pub other_flags: u16,
    /// Log trigger.
    pub log_trigger: Option<u16>,
    /// RLFC (meaning unknown).
    pub rlfc: Option<u32>,
    /// Active time, AW sequence counter, update counter.
    pub counters: Option<(u32, u32, u32)>,
}

impl DataPathExt {
    /// The extended flags field as emitted: `other_flags` plus a bit per
    /// present field.
    pub fn wire_flags(&self) -> u16 {
        let mut f = self.other_flags & !ext_flags::WITH_FIELDS;
        if self.log_trigger.is_some() {
            f |= ext_flags::LOG_TRIGGER;
        }
        if self.rlfc.is_some() {
            f |= ext_flags::RLFC;
        }
        if self.counters.is_some() {
            f |= ext_flags::COUNTERS;
        }
        f
    }
}

/// Data path state (type 12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPathState<'a> {
    /// Flags that introduce no field (e.g. 0x0020 dual-band, 0x0400 AirPlay
    /// solo mode). The bits in [`flags`] aren't stored: they follow from
    /// which fields are present. See [`DataPathState::wire_flags`].
    pub other_flags: u16,
    /// Country code, e.g. `b"US\0"`.
    pub country_code: Option<[u8; 3]>,
    /// Social channels: a channel number, or, when bit 0 is set, a map
    /// (bit 1 = 6, bit 2 = 44, bit 3 = 149).
    pub social_channels: Option<u16>,
    /// Infrastructure BSSID and channel.
    pub infra: Option<InfraInfo>,
    /// Infrastructure address.
    pub infra_address: Option<MacAddr>,
    /// AWDL address.
    pub awdl_address: Option<MacAddr>,
    /// UMI.
    pub umi: Option<u16>,
    /// Unicast options (u16 length on the wire): a UMI code ([`umi`],
    /// [`DataPathState::umi_code`]) in the frames iOS and macOS send.
    pub unicast_options: Option<Bytes<'a>>,
    /// The extended part.
    pub ext: Option<DataPathExt>,
    /// Bytes after the known fields, e.g. fields of extended flags without a
    /// known layout.
    pub trailing: Bytes<'a>,
}

impl<'a> DataPathState<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        let f = r.u16le("data path flags")?;
        let has = |bit: u16| f & bit != 0;
        let country_code = if has(flags::COUNTRY_CODE) { Some(r.array("country code")?) } else { None };
        let social_channels = if has(flags::SOCIAL_CHANNELS) { Some(r.u16le("social channels")?) } else { None };
        let infra = if has(flags::INFRA_BSSID_CHANNEL) {
            Some(InfraInfo { bssid: r.mac("infra BSSID")?, channel: r.u16le("infra channel")? })
        } else {
            None
        };
        let infra_address = if has(flags::INFRA_ADDRESS) { Some(r.mac("infra address")?) } else { None };
        let awdl_address = if has(flags::AWDL_ADDRESS) { Some(r.mac("AWDL address")?) } else { None };
        let umi = if has(flags::UMI) { Some(r.u16le("UMI")?) } else { None };
        let unicast_options = if has(flags::UNICAST_OPTIONS) {
            let n = r.u16le("unicast options length")? as usize;
            Some(Bytes::Borrowed(r.bytes(n, "unicast options")?))
        } else {
            None
        };
        let ext = if has(flags::EXTENDED) {
            let ef = r.u16le("extended flags")?;
            let ehas = |bit: u16| ef & bit != 0;
            Some(DataPathExt {
                other_flags: ef & !ext_flags::WITH_FIELDS,
                log_trigger: if ehas(ext_flags::LOG_TRIGGER) { Some(r.u16le("log trigger")?) } else { None },
                rlfc: if ehas(ext_flags::RLFC) { Some(r.u32le("RLFC")?) } else { None },
                counters: if ehas(ext_flags::COUNTERS) {
                    Some((r.u32le("active time")?, r.u32le("AW sequence counter")?, r.u32le("update counter")?))
                } else {
                    None
                },
            })
        } else {
            None
        };
        Ok(Self {
            other_flags: f & !flags::WITH_FIELDS,
            country_code,
            social_channels,
            infra,
            infra_address,
            awdl_address,
            umi,
            unicast_options,
            ext,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// The unicast options as a UMI code ([`umi`]), when they're the four
    /// bytes iOS sends.
    pub fn umi_code(&self) -> Option<u32> {
        let o: &[u8] = self.unicast_options.as_deref()?;
        Some(u32::from_le_bytes(o.try_into().ok()?))
    }

    /// Sets the unicast options to a UMI code ([`umi`]); 0 asks nothing.
    pub fn set_umi_code(&mut self, code: u32) {
        self.unicast_options = Some(Bytes::Owned(code.to_le_bytes().to_vec()));
    }

    /// The flags field as emitted: `other_flags` plus a bit per present field.
    pub fn wire_flags(&self) -> u16 {
        let mut f = self.other_flags & !flags::WITH_FIELDS;
        let mut set = |present: bool, bit: u16| {
            if present {
                f |= bit;
            }
        };
        set(self.country_code.is_some(), flags::COUNTRY_CODE);
        set(self.social_channels.is_some(), flags::SOCIAL_CHANNELS);
        set(self.infra.is_some(), flags::INFRA_BSSID_CHANNEL);
        set(self.infra_address.is_some(), flags::INFRA_ADDRESS);
        set(self.awdl_address.is_some(), flags::AWDL_ADDRESS);
        set(self.umi.is_some(), flags::UMI);
        set(self.unicast_options.is_some(), flags::UNICAST_OPTIONS);
        set(self.ext.is_some(), flags::EXTENDED);
        f
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u16le(self.wire_flags());
        if let Some(c) = &self.country_code {
            out.put(c);
        }
        if let Some(s) = self.social_channels {
            out.put_u16le(s);
        }
        if let Some(i) = &self.infra {
            out.put_mac(i.bssid);
            out.put_u16le(i.channel);
        }
        if let Some(a) = self.infra_address {
            out.put_mac(a);
        }
        if let Some(a) = self.awdl_address {
            out.put_mac(a);
        }
        if let Some(u) = self.umi {
            out.put_u16le(u);
        }
        if let Some(o) = &self.unicast_options {
            out.put_u16le(len_u16(o.len(), "unicast options")?);
            out.put(o);
        }
        if let Some(e) = &self.ext {
            out.put_u16le(e.wire_flags());
            if let Some(l) = e.log_trigger {
                out.put_u16le(l);
            }
            if let Some(x) = e.rlfc {
                out.put_u32le(x);
            }
            if let Some((a, b, c)) = e.counters {
                out.put_u32le(a);
                out.put_u32le(b);
                out.put_u32le(c);
            }
        }
        out.put(&self.trailing);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UMI goes where macOS 11's driver reads it: after the country code,
    /// social channels and infrastructure fields, a u16 length 4, then the
    /// code in little-endian.
    #[test]
    fn a_umi_code_sits_after_the_infrastructure_fields() {
        let mut d = DataPathState {
            other_flags: 0x0800,
            country_code: Some(*b"US\0"),
            social_channels: Some(7),
            infra: Some(InfraInfo { bssid: MacAddr::default(), channel: 0 }),
            infra_address: Some(MacAddr([2, 0, 0, 0, 0, 1])),
            awdl_address: None,
            umi: None,
            unicast_options: None,
            ext: None,
            trailing: Bytes::Borrowed(&[]),
        };
        assert_eq!(d.umi_code(), None);
        d.set_umi_code(umi::CONTINUITY_REALTIME_GROUP_START);
        let mut v = Vec::new();
        d.emit(&mut v).unwrap();
        assert_eq!(u16::from_le_bytes([v[0], v[1]]), 0x1b03);
        // flags 2, country 3, social 2, BSSID and channel 8, address 6
        assert_eq!(&v[21..], &[4, 0, 0, 0, 0, 0x17]);
        let back = DataPathState::parse(&v).unwrap();
        assert_eq!(back.umi_code(), Some(umi::CONTINUITY_REALTIME_GROUP_START));
    }
}
