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
//!
//! See `docs/awdl-field-observations.md`.

use awdl_proto::action::{ActionFrameBuilder, ActionHeader, AwdlVersion};
use awdl_proto::dns::DnsName;
use awdl_proto::ieee80211::Header;
use awdl_proto::tlv::{
    Arpa, Channel, ChannelSequence, ChannelSequenceTlv, DataPathExt, DataPathState, ElectionParams, ElectionParamsV2,
    HtCapabilities, InfraInfo, ServiceParams, ServiceResponse, SyncParams, SyncTree, TlvBody, VersionTlv, device_class,
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
    /// How long after we build a frame it reaches the air, µs, reported in
    /// its PHY TX time so receivers can place our AWs. About 1 ms on the
    /// T3U through devourer: a Mac saw our claims that late when we
    /// reported none.
    pub tx_latency_us: u32,
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
    /// Our channel sequence while we're master: a primary channel per slot,
    /// 0 for an empty slot, which repeats the one before. Encoded the way
    /// Apple devices encode theirs (see [`master_sequences`]). The default
    /// is an idle iPhone's: 6 in slots 0 and 8, 149 in slots 2 and 10.
    pub master_sequence: [u8; 16],
    /// On becoming master, start a new AW grid rather than carry on the one
    /// we were following. An experiment; off by default.
    pub master_fresh_grid: bool,
    /// Raw TLVs that replace ours of the same kind, in place, or are
    /// appended; `None` drops that kind. For interop experiments, such as
    /// sending another device's TLVs verbatim. Empty by default.
    pub tlv_overrides: Vec<(u8, Option<Vec<u8>>)>,
    /// Added to the AW sequence number we advertise. A multiple of 64 (one
    /// pass of the 16-slot sequence) leaves our channel schedule unchanged
    /// and changes only its label. An experiment; 0 by default.
    pub aw_seq_offset: u16,
    /// The election counter we start from (election parameters v2). Apple
    /// devices' counters run from 2 to past 16,000; a master's advances
    /// about every 3 s. An experiment; 0 by default.
    pub self_counter_start: u32,
    /// Service records we advertise: Service Response TLVs in every MIF, as
    /// iPhones and Macs send theirs. Set through
    /// [`crate::Engine::set_services`], which keeps `services_sui` in step.
    pub services: Vec<ServiceResponse<'static>>,
    /// Our service-update counter (Service Parameters TLV): changes whenever
    /// `services` does, so peers re-read them.
    pub services_sui: u16,
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
            tx_latency_us: 1000,
            psf_interval_tu: 110,
            infra_channel: None,
            datapath_ext: false,
            ht_40mhz: false,
            hostname: None,
            master_sequence: [6, 0, 149, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0],
            master_fresh_grid: false,
            tlv_overrides: Vec::new(),
            aw_seq_offset: 0,
            self_counter_start: 0,
            services: Vec::new(),
            services_sui: 0,
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

/// 5 GHz primaries whose 40 MHz partner is above them (36+40, …, 157+161).
const FORTY_LOWER: [u8; 12] = [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157];

/// One slot in the legacy encoding, as Apple devices write it:
/// - 40 MHz, primary lower: centre channel with flags `0x1d` (an Apple TV
///   on 44 sends 46, an iPhone on 149 sends 151);
/// - 2.4 GHz: flags `0x2b` (an Apple TV on 6);
/// - 40 MHz, primary upper (`0x1e`), and 5 GHz at 20 MHz (`0x17`): not
///   seen from Apple; the bits per Wireshark's `awdl_tag_channel_sequence`.
fn legacy_channel(primary: u8, forty: bool) -> Channel {
    let (flags, number) = match primary {
        0 => (0, 0),
        1..=14 => (0x2b, primary),
        p if forty && FORTY_LOWER.contains(&p) => (0x1d, p + 2),
        p if forty => (0x1e, p - 2),
        p => (0x17, p),
    };
    Channel::Legacy { flags, number }
}

/// One slot in the opclass encoding (TLV 18), with 802.11's global operating
/// classes for the width we use. An iOS 27 iPhone wrote 128 (80 MHz) for
/// both 44 and 149; we don't receive 80 MHz.
fn opclass_channel(primary: u8, forty: bool) -> Channel {
    let opclass = match primary {
        0 => 0,
        1..=13 => 81,
        36..=48 if forty => {
            if FORTY_LOWER.contains(&primary) {
                116
            } else {
                117
            }
        }
        52..=64 if forty => {
            if FORTY_LOWER.contains(&primary) {
                119
            } else {
                120
            }
        }
        100..=144 if forty => {
            if FORTY_LOWER.contains(&primary) {
                122
            } else {
                123
            }
        }
        149..=161 if forty => {
            if FORTY_LOWER.contains(&primary) {
                126
            } else {
                127
            }
        }
        36..=48 => 115,
        52..=64 => 118,
        100..=144 => 121,
        _ => 124,
    };
    Channel::OpClass { number: primary, opclass }
}

/// Our sequence as master, as sent: legacy (embedded in the sync
/// parameters) and opclass (TLV 18), four slots per step, empty slots
/// repeating the channel before them.
pub(crate) fn master_sequences(cfg: &TxConfig) -> (ChannelSequence<'static>, ChannelSequence<'static>) {
    let encode = |f: fn(u8, bool) -> Channel| {
        let slots: Vec<Channel> = cfg.master_sequence.iter().map(|&c| f(c, cfg.ht_40mhz)).collect();
        ChannelSequence::new(0, 3, 0xffff, &slots).expect("16 slots, one encoding")
    };
    (encode(legacy_channel), encode(opclass_channel))
}

/// Builds a PSF or MIF.
pub(crate) fn build(
    cfg: &TxConfig,
    v: &FollowerView<'_>,
    kind: u8,
    self_counter: u32,
    sequence_number: u16,
) -> Vec<u8> {
    // tx_counter counts to the start of the next *slot* (a 4-AW extended
    // AW), not the next AW: in every capture, the AW starting at a claimed
    // boundary has aw_seq ≡ 0 (mod 4) (5,639 of 5,641 frames). Claiming the
    // next AW instead put our slot grid 0–3 AWs off where we really are.
    let aws_after_next = (4 - v.aw_seq.wrapping_add(1) % 4) % 4;
    let next_slot = v.next_boundary + aws_after_next as u64 * crate::AW_US;
    // A receiver puts our boundary at rx − (phy − target) + tx_counter TU.
    // tx_counter is whole TU, so the target time is the instant from which
    // it is exact (rounding up keeps it at or before now), and the PHY time
    // is when the frame should reach the air. Reporting both as "now" put
    // our claims about 1.2 ms late, the radio's TX latency, as a Mac saw.
    let tx_counter = next_slot.saturating_sub(v.now).div_ceil(TU_US) as u16;
    let target = next_slot.saturating_sub(tx_counter as u64 * TU_US);
    let header = Header::action(cfg.addr, MacAddr::BROADCAST, sequence_number);
    let action = ActionHeader {
        version: AwdlVersion { major: 1, minor: 0 },
        subtype: kind,
        reserved: 0,
        phy_tx_time: (v.now + cfg.tx_latency_us as u64) as u32,
        target_tx_time: target as u32,
    };
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
        aw_seq_counter: v.aw_seq.wrapping_add(cfg.aw_seq_offset),
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
    let mif = kind == awdl_proto::action::subtype::MIF;
    let arpa = match &cfg.hostname {
        Some(h) if mif => {
            DnsName::encode(&format!("{h}.local")).ok().map(|name| TlvBody::Arpa(Arpa { flags: 3, name }))
        }
        _ => None,
    };
    let services: Vec<TlvBody<'_>> =
        if mif { cfg.services.iter().cloned().map(TlvBody::ServiceResponse).collect() } else { Vec::new() };
    let extra: Vec<&TlvBody<'_>> = arpa.iter().chain(services.iter()).collect();
    let bodies = [
        TlvBody::SyncParams(sync),
        TlvBody::ElectionParams(election),
        TlvBody::ChannelSequence(ChannelSequenceTlv { sequence: tlv18, trailing: Bytes::Borrowed(&[0, 0, 0]) }),
        TlvBody::ElectionParamsV2(election_v2),
        TlvBody::ServiceParams(ServiceParams::for_records(cfg.services_sui, &cfg.services)),
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
    let overridden = |kind: u8| cfg.tlv_overrides.iter().find(|(k, _)| *k == kind);
    for t in bodies.iter().chain(extra.iter().copied()) {
        match overridden(t.kind()) {
            None => b.tlv(t).expect("our own TLVs fit their length fields"),
            Some((k, Some(v))) => b.raw_tlv(*k, v).expect("an override fits a TLV"),
            Some((_, None)) => continue,
        };
    }
    for (k, v) in &cfg.tlv_overrides {
        if let Some(v) = v
            && !bodies.iter().chain(extra.iter().copied()).any(|t| t.kind() == *k)
        {
            b.raw_tlv(*k, v).expect("an override fits a TLV");
        }
    }
    b.finish()
}
