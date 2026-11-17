// SPDX-License-Identifier: GPL-2.0-only
//! W2's exit check, on the local capture corpus: replay each capture through
//! the engine and, before each frame from the peer we sync to is used, compare
//! the AW boundary that frame claims with the one we predicted
//! ([`awdl_core::diag::SyncCheck`]). At least 99 % must be within ±1 TU.
//!
//! Also reported, not gated: followers against the same prediction (Apple's
//! own followers sit up to about 1 TU off their master), whether each frame's
//! master is the one we elected, the AW sequence we predict, and whether the
//! slot model puts the peer we sync to on the channel we heard it on. Skips
//! without the corpus.

use awdl_core::diag::{Errors, SyncCheck};
use awdl_core::{AW_US, ChannelSchedule, Engine, RxMeta, SyncClaim};
use awdl_proto::tlv::{ElectionParamsV2, TlvBody, kind};
use awdl_proto::{Frame, parse};

#[test]
fn aw_boundaries_are_predicted_within_a_tu() {
    let files = warlock_capture::corpus_files();
    if files.is_empty() {
        eprintln!("skipping: no capture corpus");
        return;
    }
    let (mut all_source, mut all_follow) = (Errors::default(), Errors::default());
    for file in &files {
        let mut check = SyncCheck::default();
        let (mut agree, mut named) = (0usize, 0usize);
        let (mut slot_ok, mut slot_n, mut seq_ok, mut seq_n) = (0usize, 0usize, 0usize, 0usize);
        let mut aws_ahead = [0usize; 5];
        let mut boundary_phase = [0usize; 4];
        let mut engine = Engine::new(Default::default());
        for c in warlock_capture::read(file).unwrap() {
            let (Some(tsf), Some(channel)) = (c.tsf, c.channel()) else { continue };
            if check.check(&engine, tsf, &c.mpdu).is_some() {
                // A frame from the peer we sync to, while locked: the extras.
                let src = engine.sync_source().unwrap();
                if let Ok(Some(Frame::Action { action, .. })) = parse(&c.mpdu) {
                    if let Some(Ok(TlvBody::SyncParams(s))) = action.find(kind::SYNC_PARAMS).map(|t| t.decode()) {
                        let claim = SyncClaim::new(tsf, &action.header, &s).unwrap();
                        let ahead = ((claim.boundary() - claim.target_tsf()) / AW_US as f64).ceil() as usize;
                        aws_ahead[ahead.min(4)] += 1;
                        // The AW that starts at the claimed boundary: where
                        // in its 4-AW slot is it?
                        if let Some(at) = src.clock.position(claim.boundary() as u64 + AW_US / 2) {
                            boundary_phase[(at.aw_seq % 4) as usize] += 1;
                        }
                        if let Some(pos) = src.clock.position(claim.target_tsf() as u64) {
                            seq_n += 1;
                            seq_ok += (pos.aw_seq == claim.aw_seq) as usize;
                        }
                        if let Some(sched) = ChannelSchedule::from_sequence(&s.channel_sequence) {
                            slot_n += 1;
                            slot_ok += (sched.channel_at(claim.aw_seq) == Some(channel)) as usize;
                        }
                    }
                }
            }
            if let Ok(Some(Frame::Action { action, .. })) = parse(&c.mpdu) {
                let named_master = action.find(kind::ELECTION_PARAMS_V2).and_then(|t| match t.decode() {
                    Ok(TlvBody::ElectionParamsV2(ElectionParamsV2 { master, .. })) => Some(master),
                    _ => None,
                });
                if let (Some(m), Some(ours)) = (named_master, engine.master()) {
                    named += 1;
                    agree += (m == ours) as usize;
                }
            }
            engine.on_frame(RxMeta { tsf, channel, rssi_dbm: c.rssi_dbm.unwrap_or(0) }, &c.mpdu);
        }
        let name = file.file_name().unwrap().to_string_lossy();
        eprintln!("{name}");
        eprintln!("  sync source: {}", check.source);
        eprintln!("  followers:   {}", check.followers);
        eprintln!("  AW seq agrees {seq_ok}/{seq_n}  slot model matches RX channel {slot_ok}/{slot_n}  frames naming our master {agree}/{named}");
        eprintln!("  claimed boundary is 0/1/2/3/4+ AWs after the target TX time: {aws_ahead:?}");
        eprintln!("  AW starting at the claimed boundary, aw_seq mod 4 = 0/1/2/3: {boundary_phase:?}");
        if let Some(src) = engine.sync_source() {
            eprintln!("  synced to {} ({:+.1} ppm)", src.addr, src.clock.drift_ppm());
        }
        all_source.0.extend(check.source.0);
        all_follow.0.extend(check.followers.0);
    }
    eprintln!("ALL sync source: {all_source}");
    eprintln!("ALL followers:   {all_follow}");
    assert!(all_source.0.len() >= 500, "too few checked frames: {}", all_source.0.len());
    assert!(all_source.ratio_within_tu() >= 0.99, "only {:.2} % within ±1 TU", 100.0 * all_source.ratio_within_tu());
}
