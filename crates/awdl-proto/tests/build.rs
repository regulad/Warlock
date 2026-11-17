// SPDX-License-Identifier: GPL-2.0-only
//! Frames built from typed values parse back to the same values. Runs
//! without the capture corpus.

use awdl_proto::action::{ActionFrameBuilder, ActionHeader, AwdlVersion, set_tx_times, subtype};
use awdl_proto::data::{DataFrame, ETHERTYPE_IPV6};
use awdl_proto::dns::DnsName;
use awdl_proto::ieee80211::Header;
use awdl_proto::tlv::{
    Channel, ChannelSequence, DataPathState, ElectionParamsV2, InfraInfo, Rdata, ServiceResponse, SyncParams,
    TlvBody, VersionTlv, device_class, kind,
};
use awdl_proto::{AWDL_BSSID, Bytes, Error, Frame, MacAddr, parse};

const ME: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);

fn action_header() -> ActionHeader {
    ActionHeader {
        version: AwdlVersion { major: 1, minor: 0 },
        subtype: subtype::MIF,
        reserved: 0,
        phy_tx_time: 1_000_000,
        target_tx_time: 999_900,
    }
}

fn sync_params() -> SyncParams<'static> {
    let mut slots = [Channel::OpClass { number: 6, opclass: 0x51 }; 16];
    slots[0] = Channel::OpClass { number: 149, opclass: 0x80 };
    SyncParams {
        tx_channel: 149,
        tx_counter: 12,
        master_channel: 6,
        guard_time: 0,
        aw_period: 16,
        action_frame_period: 110,
        awdl_flags: 0x1800,
        aw_ext_length: 16,
        aw_common_length: 16,
        aw_remaining: -3,
        ext_min: 3,
        ext_max_multicast: 3,
        ext_max_unicast: 3,
        ext_max_af: 3,
        master: ME,
        presence_mode: 4,
        unknown: 0,
        aw_seq_counter: 4242,
        ap_beacon_alignment: 0,
        channel_sequence: ChannelSequence::new(0, 3, 0xffff, &slots).unwrap(),
        trailing: Bytes::Borrowed(&[0, 0]),
    }
}

fn tlvs() -> Vec<TlvBody<'static>> {
    vec![
        TlvBody::SyncParams(sync_params()),
        TlvBody::ElectionParamsV2(ElectionParamsV2 {
            master: ME,
            other: ME,
            master_counter: 7,
            distance_to_master: 0,
            master_metric: 60,
            self_metric: 60,
            unknown: 0,
            reserved: 0,
            self_counter: 7,
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::DataPathState(DataPathState {
            other_flags: 0x0020, // a flag bit without a field; must survive
            country_code: Some(*b"US\0"),
            social_channels: Some(0x000f),
            infra: Some(InfraInfo { bssid: MacAddr([0x02, 0, 0, 0, 0, 0x99]), channel: 36 }),
            infra_address: None,
            awdl_address: Some(ME),
            umi: None,
            unicast_options: None,
            ext: None,
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::Version(VersionTlv {
            version: AwdlVersion { major: 3, minor: 4 },
            device_class: device_class::MACOS,
            trailing: Bytes::Borrowed(&[]),
        }),
        TlvBody::ServiceResponse(ServiceResponse::new(
            DnsName::encode("_companion-link._tcp.local").unwrap(),
            Rdata::Ptr(DnsName::encode("Warlock Test._companion-link._tcp.local").unwrap()),
        )),
        TlvBody::ServiceResponse(ServiceResponse::new(
            DnsName::encode("Warlock Test._companion-link._tcp.local").unwrap(),
            Rdata::Srv { priority: 0, weight: 0, port: 49152, target: DnsName::encode("warlock.local").unwrap() },
        )),
        TlvBody::ServiceResponse(ServiceResponse::new(
            DnsName::encode("Warlock Test._companion-link._tcp.local").unwrap(),
            Rdata::txt_from_strings(&["rpVr=715.2", "rpFl=0x20000"]).unwrap(),
        )),
        TlvBody::Unknown { kind: 33, value: Bytes::Borrowed(&[1, 2, 3]) },
    ]
}

#[test]
fn built_action_frame_parses_back() {
    let header = Header::action(ME, MacAddr::BROADCAST, 77);
    let mut b = ActionFrameBuilder::new(&header, &action_header());
    for t in &tlvs() {
        b.tlv(t).unwrap();
    }
    let mpdu = b.finish();

    let Some(Frame::Action { header: h, action }) = parse(&mpdu).unwrap() else {
        panic!("not parsed as an action frame");
    };
    assert_eq!(h, header);
    assert_eq!(h.addr3, AWDL_BSSID);
    assert_eq!(h.sequence_number(), 77);
    assert_eq!(action.header, action_header());
    assert!(action.is_mif());
    let decoded: Vec<_> = action.tlvs().map(|t| t.decode().unwrap()).collect();
    assert_eq!(decoded, tlvs());

    // Spot-check accessors on the decoded values.
    let TlvBody::SyncParams(s) = &decoded[0] else { unreachable!() };
    assert_eq!(s.channel_sequence.len(), 16);
    assert_eq!(s.channel_sequence.get(0).unwrap().number(), 149);
    let TlvBody::ServiceResponse(srv) = &decoded[5] else { unreachable!() };
    assert_eq!(srv.name.to_dotted(), "Warlock Test._companion-link._tcp.local");
    let TlvBody::ServiceResponse(txt) = &decoded[6] else { unreachable!() };
    let strings: Vec<&[u8]> = txt.rdata.txt_strings().collect();
    assert_eq!(strings, [&b"rpVr=715.2"[..], b"rpFl=0x20000"]);
    let TlvBody::DataPathState(d) = &decoded[2] else { unreachable!() };
    assert_eq!(d.wire_flags(), 0x0020 | 0x0100 | 0x0200 | 0x0001 | 0x0004);
    assert_eq!(action.find(kind::VERSION).unwrap().value, [0x34, device_class::MACOS]);
}

#[test]
fn legacy_entries_give_their_primary_channel() {
    let lower = Channel::Legacy { flags: 29, number: 46 }; // 40 MHz, 5 GHz, control lower
    let upper = Channel::Legacy { flags: 30, number: 118 }; // control upper
    let twenty = Channel::Legacy { flags: 43, number: 6 }; // 2.4 GHz, control primary
    assert_eq!((lower.number(), lower.primary()), (46, 44));
    assert_eq!(upper.primary(), 120);
    assert_eq!(twenty.primary(), 6);
    assert_eq!(Channel::OpClass { number: 149, opclass: 128 }.primary(), 149);
    assert!(Channel::Legacy { flags: 0, number: 0 }.is_empty());
    assert_eq!(Channel::Legacy { flags: 0, number: 0 }.primary(), 0);
}

#[test]
fn tx_times_are_stamped_in_place() {
    let header = Header::action(ME, MacAddr::BROADCAST, 1);
    let mut b = ActionFrameBuilder::new(&header, &action_header());
    b.tlv(&TlvBody::SyncParams(sync_params())).unwrap();
    let mut mpdu = b.finish();
    set_tx_times(&mut mpdu, 0xdead_beef, 0x0102_0304).unwrap();
    let Some(Frame::Action { action, .. }) = parse(&mpdu).unwrap() else { panic!() };
    assert_eq!((action.header.phy_tx_time, action.header.target_tx_time), (0xdead_beef, 0x0102_0304));
}

#[test]
fn data_frame_round_trips() {
    let payload = [0x60, 0, 0, 0, 0, 0, 17, 255];
    let header = Header::data(ME, MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]), 5);
    let data = DataFrame::new(306, ETHERTYPE_IPV6, &payload);
    let mut mpdu = Vec::new();
    Frame::Data { header, data: data.clone() }.emit(&mut mpdu);
    // The captured layout: header, LLC/SNAP, 03 04, seq LE, 00 00, EtherType BE.
    assert_eq!(&mpdu[24..40], &[0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0, 3, 4, 0x32, 1, 0, 0, 0x86, 0xdd]);
    let Some(Frame::Data { header: h, data: d }) = parse(&mpdu).unwrap() else { panic!() };
    assert_eq!((h, d), (header, data));
}

#[test]
fn rejects_and_ignores() {
    // Not AWDL: a beacon, an action frame of another vendor, a protected
    // data frame, garbage.
    let mut beacon = Vec::new();
    Header { frame_control: 0x0080, ..Header::action(ME, MacAddr::BROADCAST, 0) }.emit(&mut beacon);
    beacon.extend_from_slice(&[0; 12]);
    assert_eq!(parse(&beacon), Ok(None));

    let mut other = Vec::new();
    Header::action(ME, MacAddr::BROADCAST, 0).emit(&mut other);
    other.extend_from_slice(&[127, 0x00, 0x50, 0xf2, 8, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(parse(&other), Ok(None));

    assert_eq!(parse(&[0x08, 0x40, 0, 0]), Ok(None));
    assert_eq!(parse(&[]), Ok(None));

    // AWDL, but a TLV runs past the end.
    let header = Header::action(ME, MacAddr::BROADCAST, 1);
    let mut b = ActionFrameBuilder::new(&header, &action_header());
    b.raw_tlv(kind::VERSION, &[0x34, 1]).unwrap();
    let mut mpdu = b.finish();
    let n = mpdu.len();
    mpdu[n - 3] = 9; // claim 9 bytes, 2 present
    assert_eq!(parse(&mpdu), Err(Error::Truncated("TLV value")));
}
