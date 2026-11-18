// SPDX-License-Identifier: GPL-2.0-only
//! Every AWDL frame in the local capture corpus must parse, decode, and
//! re-emit byte-for-byte, both raw and rebuilt from its typed TLVs.

mod common;

use std::collections::BTreeMap;

use awdl_proto::action::ActionFrameBuilder;
use awdl_proto::tlv;
use awdl_proto::{Frame, parse};

#[test]
fn every_captured_frame_round_trips() {
    let files = common::air_captures();
    if files.is_empty() {
        eprintln!("skipping: no capture corpus (see tests/common/mod.rs)");
        return;
    }
    let mut failures = Vec::new();
    let mut per_kind: BTreeMap<u8, (usize, usize)> = BTreeMap::new(); // kind → (seen, decoded)
    let (mut actions, mut datas) = (0, 0);

    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        for (num, mpdu) in common::mpdus(file) {
            let mut fail = |what: String| failures.push(format!("{name} #{num}: {what}"));
            let frame = match parse(&mpdu) {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(e) => {
                    fail(format!("parse: {e}"));
                    continue;
                }
            };

            let mut raw = Vec::new();
            frame.emit(&mut raw);
            if raw != mpdu {
                fail("raw re-emit differs".into());
            }

            match &frame {
                Frame::Data { .. } => datas += 1,
                Frame::Action { header, action } => {
                    actions += 1;
                    if !action.trailer().is_empty() {
                        fail(format!("{}-byte trailer after the TLVs", action.trailer().len()));
                    }
                    let mut b = ActionFrameBuilder::new(header, &action.header);
                    for t in action.tlvs() {
                        let e = per_kind.entry(t.kind).or_default();
                        e.0 += 1;
                        match t.decode() {
                            Ok(body) => {
                                if !matches!(body, tlv::TlvBody::Unknown { .. }) {
                                    e.1 += 1;
                                }
                                let mut v = Vec::new();
                                body.emit_value(&mut v).unwrap();
                                if v != t.value {
                                    fail(format!("TLV {} typed re-emit differs", t.kind));
                                }
                                b.tlv(&body).unwrap();
                            }
                            Err(err) => {
                                fail(format!("TLV {} decode: {err}", t.kind));
                                b.raw_tlv(t.kind, t.value).unwrap();
                            }
                        }
                    }
                    let mut rebuilt = b.finish();
                    rebuilt.extend_from_slice(action.trailer());
                    if rebuilt != mpdu {
                        fail("rebuilt frame differs".into());
                    }
                }
            }
        }
    }

    eprintln!("{actions} action frames, {datas} data frames across {} captures", files.len());
    for (k, (seen, decoded)) in &per_kind {
        eprintln!("  TLV {k:>2} {:<24} {seen:>6} seen, {decoded:>6} typed", tlv::kind::name(*k).unwrap_or("?"));
    }
    assert!(actions > 0, "the corpus has no AWDL action frames");
    assert!(
        failures.is_empty(),
        "{} failures, first ones:\n{}",
        failures.len(),
        failures[..failures.len().min(25)].join("\n")
    );
}
