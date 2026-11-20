// SPDX-License-Identifier: GPL-2.0-only
//! Realtime group (type 31): a "Continuity Real Time Group", the group in
//! which Apple devices run realtime Continuity traffic (Continuity Camera,
//! Sidecar) and Low-Latency Wi-Fi (`llw0`).
//!
//! Wireshark has no dissector for it. The layout is from static analysis of
//! iOS 27.2.1 (24B156), whose driver reads it as `apple80211_awdl_realtimegroup_tlv`
//! (Koala's `docs/guest-pairing.md`; issue #10):
//!
//! ```text
//! u8      flags
//! [6]     RTG ID
//! u8      infrastructure channel
//! i8      infrastructure RSSI
//! u8      additional flags (retro 2.4 GHz and others)
//! [7]     service flags, a custom infrastructure channel, reserved
//! ```
//!
//! The meanings of the flags and the last 7 bytes aren't known; they're kept
//! as they are.

use alloc::vec::Vec;

use crate::wire::{Put, Reader};
use crate::{Bytes, Error, MacAddr};

/// The value's length as iOS 27 reads it.
pub const LEN: usize = 17;

/// Realtime group (type 31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeGroup<'a> {
    /// Flags; meanings unknown.
    pub flags: u8,
    /// The group's ID. A host starting a group picks it; the iPhone adopts
    /// the initiator's.
    pub rtg_id: MacAddr,
    /// The sender's infrastructure channel, 0 for none.
    pub infra_channel: u8,
    /// The sender's infrastructure RSSI, dBm.
    pub infra_rssi: i8,
    /// Additional flags; meanings unknown.
    pub additional_flags: u8,
    /// The rest: service flags, a custom infrastructure channel, reserved.
    pub rest: Bytes<'a>,
}

impl<'a> RealtimeGroup<'a> {
    /// A group with ID `rtg_id` and everything else zero: no
    /// infrastructure network, no flags Warlock can't back (AGENTS.md).
    pub fn new(rtg_id: MacAddr) -> Self {
        Self {
            flags: 0,
            rtg_id,
            infra_channel: 0,
            infra_rssi: 0,
            additional_flags: 0,
            rest: Bytes::Borrowed(&[0; LEN - 10]),
        }
    }

    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        Ok(Self {
            flags: r.u8("RTG flags")?,
            rtg_id: r.mac("RTG ID")?,
            infra_channel: r.u8("RTG infra channel")?,
            infra_rssi: r.u8("RTG infra RSSI")? as i8,
            additional_flags: r.u8("RTG additional flags")?,
            rest: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.flags);
        out.put_mac(self.rtg_id);
        out.put_u8(self.infra_channel);
        out.put_u8(self.infra_rssi as u8);
        out.put_u8(self.additional_flags);
        out.put(&self.rest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_group_is_17_bytes_and_round_trips() {
        let id = MacAddr([0x62, 0x5a, 0x37, 0xfb, 0xde, 0x77]);
        let mut v = Vec::new();
        RealtimeGroup::new(id).emit(&mut v).unwrap();
        assert_eq!(v.len(), LEN);
        assert_eq!(&v[1..7], &id.0);
        let back = RealtimeGroup::parse(&v).unwrap();
        assert_eq!(back, RealtimeGroup::new(id));
        assert!(RealtimeGroup::parse(&v[..9]).is_err());
    }
}
