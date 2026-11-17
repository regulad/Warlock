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
use awdl_proto::dns::DnsName;
use awdl_proto::tlv::{
    Arpa, ChannelSequence, ChannelSequenceTlv, DataPathExt, DataPathState, ElectionParams, ElectionParamsV2,
    HtCapabilities, InfraInfo, ServiceParams, SyncParams, SyncTree, TlvBody, VersionTlv, device_class,
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
    /// The data path state's infrastructure channel. `None` advertises the
    /// master's channel (what a Mac following an iPhone sent); `Some(0)` says
    /// "no infrastructure network", as an iOS 27 iPhone does.
    pub infra_channel: Option<u16>,
    /// Add the data path state's extension block the way an iOS 27 iPhone
    /// does: log trigger, RLFC (the master counter) and the AW and update
    /// counters.
    pub datapath_ext: bool,
    /// Advertise 40 MHz (and SGI40) in the HT capabilities, as the iPhone
    /// does. Only meaningful when the radio receives at 40 MHz.
    pub ht_40mhz: bool,
    /// A host name for an ARPA TLV in MIFs (`<name>.local`), as an iPhone
    /// sends one.
    pub hostname: Option<String>,
    /// Advertise ourselves as a master (of a cluster of one) while keeping
    /// to the sync source's AW grid and channels, the way an iPhone visiting
    /// an Apple TV stays its own master. An experiment; off by default.
    pub as_master: bool,
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
            infra_channel: None,
            datapath_ext: false,
            ht_40mhz: false,
            hostname: None,
            as_master: false,
        }
    }
}

/// What the frame builder needs to know about the cluster at send time.
#[derive(Clone, Copy)]
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

/// Our HT capabilities: 2 streams (MCS 0–15), short GI at 20 MHz, SM power
/// save off, RX STBC 1 stream, and optionally 40 MHz with SGI40; A-MPDU
/// parameters as the Mac sends them (64 KiB, 4 µs spacing).
fn ht_capabilities(forty: bool) -> HtCapabilities<'static> {
    let forty_bits = if forty { 0x0002 | 0x0040 } else { 0 };
    HtCapabilities {
        unknown: 0,
        cap_info: 0x000c | 0x0020 | 0x0100 | forty_bits,
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
    // As a master of our own, we name ourselves where a follower names the
    // cluster's master and its sync parent.
    let master_view;
    let v = if cfg.as_master {
        master_view = FollowerView {
            master: cfg.addr,
            master_channel: v.channel,
            master_metric: cfg.self_metric,
            master_counter: self_counter,
            distance: 0,
            sync_parent: cfg.addr,
            ..*v
        };
        &master_view
    } else {
        v
    };
    let header = Header::action(cfg.addr, MacAddr::BROADCAST, sequence_number);
    let action = ActionHeader {
        version: AwdlVersion { major: 1, minor: 0 },
        subtype: kind,
        reserved: 0,
        phy_tx_time: v.now as u32,
        target_tx_time: v.now as u32,
    };
    // tx_counter counts to the start of the next *slot* (a 4-AW extended
    // AW), not the next AW: in every capture, the AW starting at a claimed
    // boundary has aw_seq ≡ 0 (mod 4) (5,639 of 5,641 frames). Claiming the
    // next AW instead put our slot grid 0–3 AWs off where we really are.
    let aws_after_next = (4 - v.aw_seq.wrapping_add(1) % 4) % 4;
    let next_slot = v.next_boundary + aws_after_next as u64 * crate::AW_US;
    let tx_counter = (next_slot.saturating_sub(v.now) as f64 / TU_US as f64).round() as u16;
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
        infra: Some(InfraInfo {
            bssid: MacAddr::default(),
            channel: cfg.infra_channel.unwrap_or(v.master_channel as u16),
        }),
        infra_address: Some(cfg.addr),
        awdl_address: None,
        umi: None,
        unicast_options: Some(Bytes::Borrowed(&[0, 0, 0, 0])),
        // The iPhone's extension flags are 0x19fd; the field-carrying bits
        // follow from the fields set here.
        ext: cfg.datapath_ext.then_some(DataPathExt {
            other_flags: 0x19b8,
            log_trigger: Some(0),
            rlfc: Some(v.master_counter),
            counters: Some((0, v.aw_seq as u32, self_counter)),
        }),
        trailing: Bytes::Borrowed(&[]),
    };
    let tlv18 = v.sequence_tlv18.unwrap_or(v.sequence_legacy).clone();
    let arpa = match (&cfg.hostname, kind) {
        (Some(h), awdl_proto::action::subtype::MIF) => DnsName::encode(&format!("{h}.local"))
            .ok()
            .map(|name| TlvBody::Arpa(Arpa { flags: 3, name })),
        _ => None,
    };
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
        TlvBody::HtCapabilities(ht_capabilities(cfg.ht_40mhz)),
        TlvBody::Version(VersionTlv {
            version: cfg.version,
            device_class: cfg.device_class,
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::SyncTree(SyncTree::from_addresses(&[cfg.addr, MacAddr::default()])),
    ];
    let mut b = ActionFrameBuilder::new(&header, &action);
    for t in bodies.iter().chain(arpa.iter()) {
        b.tlv(t).expect("our own TLVs fit their length fields");
    }
    b.finish()
}
