// SPDX-License-Identifier: GPL-2.0-only
//! Real frames from iOS 27, macOS 11 and Apple TV, anonymized by
//! `examples/scrub.rs` and committed, so these checks always run.

mod common;

use std::collections::BTreeSet;

use awdl_proto::action::{ActionFrameBuilder, AwdlVersion};
use awdl_proto::tlv::{Rdata, TlvBody, device_class, encoding};
use awdl_proto::{Frame, parse};

#[test]
fn fixture_frames_round_trip_and_decode() {
    let mpdus = common::fixture_mpdus();
    assert!(mpdus.len() >= 15, "fixture has {} frames", mpdus.len());

    let mut kinds = BTreeSet::new();
    let (mut psf, mut mif) = (0, 0);
    let mut bodies = Vec::new();
    for mpdu in &mpdus {
        let Some(Frame::Action { header, action }) = parse(mpdu).unwrap() else {
            panic!("fixture frame isn't an AWDL action frame");
        };
        let mut raw = Vec::new();
        Frame::Action { header, action: action.clone() }.emit(&mut raw);
        assert_eq!(&raw, mpdu);
        psf += action.is_psf() as usize;
        mif += action.is_mif() as usize;

        let mut b = ActionFrameBuilder::new(&header, &action.header);
        for t in action.tlvs() {
            kinds.insert(t.kind);
            let body = t.decode().unwrap_or_else(|e| panic!("TLV {}: {e}", t.kind));
            let mut v = Vec::new();
            body.emit_value(&mut v).unwrap();
            assert_eq!(v, t.value, "TLV {} typed re-emit", t.kind);
            b.tlv(&body).unwrap();
            bodies.push(body.clone());
        }
        assert_eq!(&b.finish(), mpdu);
    }
    assert!(psf > 0 && mif > 0, "need both PSFs ({psf}) and MIFs ({mif})");
    for k in [2, 4, 5, 6, 7, 12, 16, 17, 18, 20, 21, 24, 33] {
        assert!(kinds.contains(&k), "fixture lacks TLV {k}");
    }

    // Facts about real Apple devices that the decoding must reproduce.
    let ios_version = bodies.iter().any(|b| {
        matches!(b, TlvBody::Version(v) if v.version == AwdlVersion { major: 10, minor: 2 } && v.device_class == device_class::IOS)
    });
    assert!(ios_version, "no iOS 27 version TLV (10.2, iOS)");
    for b in &bodies {
        if let TlvBody::SyncParams(s) = b {
            assert_eq!(s.aw_period, 16, "AW period");
        }
    }
    let opclass_16 = bodies.iter().any(|b| {
        matches!(b, TlvBody::ChannelSequence(c) if c.sequence.encoding == encoding::OPCLASS && c.sequence.len() == 16)
    });
    assert!(opclass_16, "no 16-slot opclass channel sequence");
    let srv_port = bodies.iter().any(|b| {
        matches!(b, TlvBody::ServiceResponse(s) if matches!(s.rdata, Rdata::Srv { port, .. } if port != 0))
    });
    assert!(srv_port, "no SRV record with a port");
    let airdrop_txt = bodies.iter().any(|b| match b {
        TlvBody::ServiceResponse(s) => s.rdata.txt_strings().any(|t| t == b"sn=com.apple.sharingd.AirDrop"),
        _ => false,
    });
    assert!(airdrop_txt, "no AirDrop application-service TXT");
    let app_service = bodies.iter().any(|b| {
        matches!(b, TlvBody::ServiceResponse(s) if s.name.to_dotted().ends_with("_applicationservicepairing._tcp.local"))
    });
    assert!(app_service, "no _applicationservicepairing._tcp record");
}
