// SPDX-License-Identifier: GPL-2.0-only
//! Measuring how well the engine predicts AW boundaries: W2's exit check,
//! shared by the replay test and the live tool.

use std::fmt;

use awdl_proto::tlv::{TlvBody, kind};
use awdl_proto::{Frame, parse};

use crate::{Engine, SyncClaim, TU_US};

/// Prediction errors, µs.
#[derive(Clone, Debug, Default)]
pub struct Errors(pub Vec<f64>);

impl Errors {
    /// How many are within ±1 TU.
    pub fn within_tu(&self) -> usize {
        self.0.iter().filter(|e| e.abs() <= TU_US as f64).count()
    }

    /// The share within ±1 TU, 0–1; 1 when empty.
    pub fn ratio_within_tu(&self) -> f64 {
        if self.0.is_empty() { 1.0 } else { self.within_tu() as f64 / self.0.len() as f64 }
    }
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("n=0");
        }
        let mut a: Vec<f64> = self.0.iter().map(|e| e.abs()).collect();
        a.sort_by(|x, y| x.total_cmp(y));
        write!(
            f,
            "n={:<5} within ±1 TU {:>5.1} %  |err| p50 {:>4.0} p95 {:>4.0} max {:>5.0} µs",
            a.len(),
            100.0 * self.ratio_within_tu(),
            a[a.len() / 2],
            a[a.len() * 95 / 100],
            a[a.len() - 1]
        )
    }
}

/// Compares each frame's claimed AW boundary with the engine's prediction,
/// made before the engine sees the frame.
#[derive(Clone, Debug, Default)]
pub struct SyncCheck {
    /// Frames from the peer we sync to: the gated measure.
    pub source: Errors,
    /// Frames from other peers following the same master, against the same
    /// prediction. Apple's own followers sit up to about 1 TU off their
    /// master, so this is reported, not gated.
    pub followers: Errors,
}

impl SyncCheck {
    /// Call with each received frame before feeding it to `engine`. Returns
    /// the error when the frame came from the peer we sync to.
    pub fn check(&mut self, engine: &Engine, tsf: u64, mpdu: &[u8]) -> Option<f64> {
        let Ok(Some(Frame::Action { header, action })) = parse(mpdu) else { return None };
        let src = engine.sync_source()?;
        if !src.clock.is_locked() {
            return None;
        }
        let claim = action.tlvs().find_map(|t| match (t.kind, t.decode()) {
            (kind::SYNC_PARAMS, Ok(TlvBody::SyncParams(s))) => SyncClaim::new(tsf, &action.header, &s),
            _ => None,
        })?;
        let err = src.clock.residual(&claim)?;
        if header.source() == src.addr {
            self.source.0.push(err);
            return Some(err);
        }
        let follows = action.tlvs().any(|t| match t.decode() {
            Ok(TlvBody::ElectionParamsV2(e)) => Some(e.master) == engine.master(),
            Ok(TlvBody::ElectionParams(e)) => Some(e.master) == engine.master(),
            _ => false,
        });
        if follows {
            self.followers.0.push(err);
        }
        None
    }
}
