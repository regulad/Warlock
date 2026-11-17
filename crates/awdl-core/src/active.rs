// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's own PSFs and MIFs, as a follower.
//!
//! The TLV set and fixed values are modelled on a macOS 11 Mac following an
//! iOS 27 iPhone in our captures, a peer iOS 27 demonstrably accepts (it
//! completed an AirDrop with it). The differences are deliberate:
//! - our own address;
//! - HT capabilities for 20 MHz only, and no VHT container, because we
//!   receive at 20 MHz;
//! - the sync source's channel sequence, copied verbatim (jedbillyb reports
//!   that copying the peer's sequence works with iOS);
//! - no extended data-path block, whose trailing bytes we can't explain yet.
//! See `docs/awdl-field-observations.md`.

use awdl_proto::action::{ActionFrameBuilder, ActionHeader, AwdlVersion};
use awdl_proto::ieee80211::Header;
use awdl_proto::tlv::{
    ChannelSequence, ChannelSequenceTlv, DataPathState, ElectionParams, ElectionParamsV2, HtCapabilities,
    InfraInfo, ServiceParams, SyncParams, SyncTree, TlvBody, VersionTlv, device_class,
};
use awdl_proto::{Bytes, MacAddr};

use crate::TU_US;

/// What Warlock announces about itself, and how it transmits.
#[derive(Clone, Debug)]
pub struct TxConfig {
    /// Our AWDL address.
    pub addr: MacAddr,
    /// The version TLV: 5.2 / macOS by default, what the accepted Mac sends.
    pub version: AwdlVersion,
    /// See `version`.
    pub device_class: u8,
    /// Our own election metric. Kept below any Apple device's so we never
    /// win; the Mac used 65 and the iPhone 538–541.
    pub self_metric: u32,
    /// Legacy rate for action frames, in 500 kb/s.
    pub rate_500kbps: u8,
    /// PSF period, TU.
    pub psf_interval_tu: u16,
}

impl TxConfig {
    /// Defaults for an address.
    pub fn new(addr: MacAddr) -> Self {
        Self {
            addr,
            version: AwdlVersion { major: 5, minor: 2 },
            device_class: device_class::MACOS,
            self_metric: 60,
            rate_500kbps: 12,
            psf_interval_tu: 110,
        }
    }
}

/// What the frame builder needs to know about the cluster at send time.
pub(crate) struct FollowerView<'a> {
    pub now: u64,
    pub channel: u8,
    pub master: MacAddr,
    pub master_channel: u8,
    pub master_metric: u32,
    pub master_counter: u32,
    /// Hops from the master to us.
    pub distance: u32,
    pub sync_parent: MacAddr,
    pub aw_seq: u16,
    pub next_boundary: u64,
    pub sequence_legacy: &'a ChannelSequence<'static>,
    pub sequence_tlv18: Option<&'a ChannelSequence<'static>>,
    pub country: [u8; 3],
}

/// Our HT capabilities: 20 MHz only, 2 streams (MCS 0–15), short GI at 20
/// MHz, SM power save off, RX STBC 1 stream; A-MPDU parameters as the Mac
/// sends them (64 KiB, 4 µs spacing).
fn ht_capabilities() -> HtCapabilities<'static> {
    HtCapabilities {
        unknown: 0,
        cap_info: 0x000c | 0x0020 | 0x0100,
        ampdu_params: 0x17,
        rx_mcs: Bytes::Owned(vec![0xff, 0xff]),
        tail: 0,
        trailing: Bytes::Borrowed(&[]),
    }
}

/// Builds a PSF or MIF.
pub(crate) fn build(
    cfg: &TxConfig,
    v: &FollowerView<'_>,
    kind: u8,
    self_counter: u32,
    sequence_number: u16,
) -> Vec<u8> {
    let header = Header::action(cfg.addr, MacAddr::BROADCAST, sequence_number);
    let action = ActionHeader {
        version: AwdlVersion { major: 1, minor: 0 },
        subtype: kind,
        reserved: 0,
        phy_tx_time: v.now as u32,
        target_tx_time: v.now as u32,
    };
    let tx_counter = (v.next_boundary.saturating_sub(v.now) as f64 / TU_US as f64).round() as u16;
    let sync = SyncParams {
        tx_channel: v.channel,
        tx_counter,
        master_channel: v.master_channel,
        guard_time: 0,
        aw_period: 16,
        action_frame_period: cfg.psf_interval_tu,
        awdl_flags: 0x1800,
        aw_ext_length: 16,
        aw_common_length: 16,
        aw_remaining: 0,
        ext_min: 3,
        ext_max_multicast: 3,
        ext_max_unicast: 3,
        ext_max_af: 3,
        master: v.master,
        presence_mode: 4,
        unknown: 0,
        aw_seq_counter: v.aw_seq,
        ap_beacon_alignment: 0,
        channel_sequence: v.sequence_legacy.clone(),
        trailing: Bytes::Borrowed(&[0, 0]),
    };
    let election = ElectionParams {
        flags: 0,
        id: 0,
        distance_to_master: v.distance.min(255) as u8,
        unknown: 0,
        master: v.master,
        master_metric: v.master_metric,
        self_metric: cfg.self_metric,
        private: None,
        trailing: Bytes::Borrowed(&[0, 0]),
    };
    let election_v2 = ElectionParamsV2 {
        master: v.master,
        other: v.sync_parent,
        master_counter: v.master_counter,
        distance_to_master: v.distance,
        master_metric: v.master_metric,
        self_metric: cfg.self_metric,
        unknown: 0,
        reserved: 0,
        self_counter,
        trailing: Bytes::Borrowed(&[]),
    };
    let data_path = DataPathState {
        other_flags: 0x0c20,
        country_code: Some(v.country),
        social_channels: Some(7),
        infra: Some(InfraInfo { bssid: MacAddr::default(), channel: v.master_channel as u16 }),
        infra_address: Some(cfg.addr),
        awdl_address: None,
        umi: None,
        unicast_options: Some(Bytes::Borrowed(&[0, 0, 0, 0])),
        ext: None,
        trailing: Bytes::Borrowed(&[]),
    };
    let tlv18 = v.sequence_tlv18.unwrap_or(v.sequence_legacy).clone();
    let bodies = [
        TlvBody::SyncParams(sync),
        TlvBody::ElectionParams(election),
        TlvBody::ChannelSequence(ChannelSequenceTlv { sequence: tlv18, trailing: Bytes::Borrowed(&[0, 0, 0]) }),
        TlvBody::ElectionParamsV2(election_v2),
        TlvBody::ServiceParams(ServiceParams {
            unknown: [0; 3],
            sui: 0,
            bitmask: 0,
            values: Bytes::Borrowed(&[]),
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::DataPathState(data_path),
        TlvBody::HtCapabilities(ht_capabilities()),
        TlvBody::Version(VersionTlv {
            version: cfg.version,
            device_class: cfg.device_class,
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::SyncTree(SyncTree::from_addresses(&[cfg.addr, MacAddr::default()])),
    ];
    let mut b = ActionFrameBuilder::new(&header, &action);
    for t in &bodies {
        b.tlv(t).expect("our own TLVs fit their length fields");
    }
    b.finish()
}
