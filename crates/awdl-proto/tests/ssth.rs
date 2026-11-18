// SPDX-License-Identifier: GPL-2.0-only
//! The SSTH ([`ssth_member`]) against every frame in the local capture
//! corpus that carries service records: each record's member is in the
//! frame's set, and at most one member isn't a record's (a Mac's or Apple
//! TV's SRV target host). Skips without the corpus.

mod common;

use std::collections::BTreeSet;

use awdl_proto::tlv::{Rdata, TlvBody, ssth_member};
use awdl_proto::{Frame, parse};

#[test]
fn every_record_is_in_its_frames_ssth() {
    let files = common::air_captures();
    if files.is_empty() {
        eprintln!("skipping: no capture corpus");
        return;
    }
    let (mut frames, mut with_host) = (0, 0);
    for file in &files {
        let Ok(captured) = warlock_capture::read(file) else { continue };
        for c in captured {
            let Ok(Some(Frame::Action { action, .. })) = parse(&c.mpdu) else { continue };
            let (mut set, mut owners, mut targets) = (None, BTreeSet::new(), BTreeSet::new());
            for t in action.tlvs() {
                match t.decode() {
                    Ok(TlvBody::ServiceParams(s)) => set = Some(s.set_values().collect::<BTreeSet<u32>>()),
                    Ok(TlvBody::ServiceResponse(r)) => {
                        owners.insert(u32::from(ssth_member(&r.name).unwrap()));
                        if let Rdata::Srv { target, .. } = &r.rdata {
                            targets.insert(u32::from(ssth_member(target).unwrap()));
                        }
                    }
                    _ => {}
                }
            }
            let Some(set) = set else { continue };
            if owners.is_empty() {
                continue;
            }
            frames += 1;
            assert!(owners.is_subset(&set), "{}: owners {owners:?} not all in {set:?}", file.display());
            let extra: BTreeSet<u32> = set.difference(&owners).copied().collect();
            assert!(extra.is_subset(&targets), "{}: {extra:?} unexplained in {set:?}", file.display());
            with_host += !extra.is_empty() as usize;
        }
    }
    eprintln!("{frames} frames with records; {with_host} also set their host's member");
    assert!(frames > 0);
}
