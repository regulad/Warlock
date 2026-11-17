// SPDX-License-Identifier: GPL-2.0-only
//! W2's exit check, on the local capture corpus: replay each capture through
//! the engine and, before each frame from the peer we sync to is used, compare
//! the AW boundary that frame claims with the one we predicted. At least 99 %
//! must be within ±1 TU.
//!
//! Also reported, not gated: the same comparison for followers (Apple's own
//! followers sit up to about 1 TU off their master), whether each frame's
//! master is the one we elected, and whether the slot model puts the peer we
//! sync to on the channel we heard it on. Skips without the corpus.

use awdl_core::{ChannelSchedule, Engine, RxMeta, SyncClaim, TU_US};
use awdl_proto::tlv::{ElectionParamsV2, TlvBody, kind};
use awdl_proto::{Frame, parse};

#[derive(Default)]
struct Errors(Vec<f64>);

impl Errors {
    fn within_tu(&self) -> usize {
        self.0.iter().filter(|e| e.abs() <= TU_US as f64).count()
    }
    fn summary(&self) -> String {
        if self.0.is_empty() {
            return "n=0".into();
        }
        let mut a: Vec<f64> = self.0.iter().map(|e| e.abs()).collect();
        a.sort_by(|x, y| x.partial_cmp(y).unwrap());
        format!(
            "n={:<5} within ±1 TU {:>5.1} %  |err| p50 {:>4.0} p95 {:>4.0} max {:>5.0} µs",
            a.len(),
            100.0 * self.within_tu() as f64 / a.len() as f64,
            a[a.len() / 2],
            a[a.len() * 95 / 100],
            a[a.len() - 1]
        )
    }
}

#[test]
fn aw_boundaries_are_predicted_within_a_tu() {
    let files = warlock_capture::corpus_files();
    if files.is_empty() {
        eprintln!("skipping: no capture corpus");
        return;
    }
    let (mut all_source, mut all_follow) = (Errors::default(), Errors::default());
    for file in &files {
        let (mut source, mut follow) = (Errors::default(), Errors::default());
        let (mut agree, mut named) = (0usize, 0usize);
        let (mut slot_ok, mut slot_n, mut seq_ok) = (0usize, 0usize, 0usize);
        let mut aws_ahead = [0usize; 5];
        let mut engine = Engine::new(Default::default());
        for c in warlock_capture::read(file).unwrap() {
            let (Some(tsf), Some(channel)) = (c.tsf, c.channel()) else { continue };
            if let Ok(Some(Frame::Action { header, action })) = parse(&c.mpdu) {
                let sync = action.find(kind::SYNC_PARAMS).and_then(|t| match t.decode() {
                    Ok(TlvBody::SyncParams(s)) => Some(s),
                    _ => None,
                });
                let named_master = action.find(kind::ELECTION_PARAMS_V2).and_then(|t| match t.decode() {
                    Ok(TlvBody::ElectionParamsV2(ElectionParamsV2 { master, .. })) => Some(master),
                    _ => None,
                });
                if let (Some(m), Some(ours)) = (named_master, engine.master()) {
                    named += 1;
                    agree += (m == ours) as usize;
                }
                let claim = sync.as_ref().and_then(|s| SyncClaim::new(tsf, &action.header, s));
                if let (Some(claim), Some(src)) = (claim, engine.sync_source()) {
                    if src.clock.is_locked() {
                        let err = src.clock.residual(&claim).unwrap();
                        if header.source() == src.addr {
                            source.0.push(err);
                            // The AW we predict for the frame's target TX time
                            // (its claimed boundary can be 1-4 AWs later), and
                            // the channel the slot model gives for it.
                            let ahead = ((claim.boundary() - claim.target_tsf()) / awdl_core::AW_US as f64).ceil() as usize;
                            aws_ahead[ahead.min(4)] += 1;
                            if let Some(pos) = src.clock.position(claim.target_tsf() as u64) {
                                seq_ok += (pos.aw_seq == claim.aw_seq) as usize;
                                if let Some(sched) = sync.as_ref().and_then(|s| ChannelSchedule::from_sequence(&s.channel_sequence)) {
                                    slot_n += 1;
                                    slot_ok += (sched.channel_at(claim.aw_seq) == Some(channel)) as usize;
                                }
                            }
                        } else if named_master == engine.master() {
                            follow.0.push(err);
                        }
                    }
                }
            }
            engine.on_frame(RxMeta { tsf, channel, rssi_dbm: c.rssi_dbm.unwrap_or(0) }, &c.mpdu);
        }
        let name = file.file_name().unwrap().to_string_lossy();
        eprintln!("{name}");
        eprintln!("  sync source: {}  AW seq agrees {seq_ok}/{}", source.summary(), source.0.len());
        eprintln!("  followers:   {}", follow.summary());
        eprintln!("  frames naming our master: {agree}/{named}  slot model matches RX channel: {slot_ok}/{slot_n}");
        eprintln!("  claimed boundary is 0/1/2/3/4+ AWs after the target TX time: {aws_ahead:?}");
        if let Some(src) = engine.sync_source() {
            eprintln!("  synced to {} ({:+.1} ppm)", src.addr, src.clock.drift_ppm());
        }
        all_source.0.extend(source.0);
        all_follow.0.extend(follow.0);
    }
    eprintln!("ALL sync source: {}", all_source.summary());
    eprintln!("ALL followers:   {}", all_follow.summary());
    assert!(all_source.0.len() >= 500, "too few checked frames: {}", all_source.0.len());
    let ratio = all_source.within_tu() as f64 / all_source.0.len() as f64;
    assert!(ratio >= 0.99, "only {:.2} % within ±1 TU", 100.0 * ratio);
}
