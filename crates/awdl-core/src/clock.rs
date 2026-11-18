// SPDX-License-Identifier: GPL-2.0-only
//! A peer's availability-window clock, as seen on our TSF.
//!
//! Each PSF and MIF says when its sender's next AW starts (a [`SyncClaim`]).
//! One claim is only good to about ±½ TU, because the counter is in whole TU,
//! and peers' clocks drift against ours by up to a few hundred ppm. So the
//! clock fits a line through recent claims, AW index against boundary time,
//! which gives both phase and period.

use std::collections::VecDeque;

use awdl_proto::action::ActionHeader;
use awdl_proto::tlv::SyncParams;

use crate::{AW_US, TU_US};

/// Claims kept for the fit. Each is only good to about ±½ TU, so the drift
/// estimate needs a long span: 256 claims at a PSF every ~110 TU is ~29 s,
/// which pins the period to a few ppm.
const WINDOW: usize = 256;
/// Claims older than this, in µs, are dropped from the fit.
const MAX_AGE_US: u64 = 30_000_000;
/// A claim further than this from the prediction is an outlier.
const OUTLIER_US: f64 = 2.0 * TU_US as f64;
/// Consecutive outliers that mean the peer really moved: start over.
const RESET_AFTER: u8 = 3;
/// A TX delay above this, in µs, means the claim is stale; it's ignored.
const MAX_DELAY_US: u32 = 100_000;
/// Claims needed, and the span they must cover, before predictions count.
const LOCK_POINTS: usize = 4;
const LOCK_SPAN_US: u64 = 1_000_000;
/// Fitted periods further than this from 16 TU are rejected, in ppm.
const MAX_DRIFT_PPM: f64 = 2_000.0;

/// What one frame says about when its sender's next AW starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncClaim {
    /// Our TSF when the frame arrived.
    pub rx_tsf: u64,
    /// How long the sender's frame waited between its target TX time and
    /// reaching the air (`phy_tx_time − target_tx_time`), µs.
    pub tx_delay_us: u32,
    /// TU from the target TX time to the sender's next AW.
    pub tx_counter_tu: u16,
    /// The sender's AW sequence counter.
    pub aw_seq: u16,
}

impl SyncClaim {
    /// The claim in a PSF or MIF. `None` if the sender's TX delay is
    /// implausible (negative or over 100 ms), which makes the claim stale.
    pub fn new(rx_tsf: u64, action: &ActionHeader, sync: &SyncParams<'_>) -> Option<Self> {
        let delay = action.phy_tx_time.wrapping_sub(action.target_tx_time);
        (delay <= MAX_DELAY_US).then_some(Self {
            rx_tsf,
            tx_delay_us: delay,
            tx_counter_tu: sync.tx_counter,
            aw_seq: sync.aw_seq_counter,
        })
    }

    /// When the sender meant to transmit, on our TSF.
    pub fn target_tsf(&self) -> f64 {
        self.rx_tsf as f64 - self.tx_delay_us as f64
    }

    /// When the sender's next AW starts, on our TSF.
    pub fn boundary(&self) -> f64 {
        self.target_tsf() + self.tx_counter_tu as f64 * TU_US as f64
    }
}

/// Where in a peer's AW schedule a moment falls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AwPosition {
    /// The AW's sequence number, in the peer's (and its master's) counting.
    pub aw_seq: u16,
    /// When the AW started, on our TSF.
    pub start_tsf: u64,
    /// µs since it started.
    pub offset_us: u32,
}

/// Our own AW grid, while we're master: AWs of exactly 16 TU on our TSF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnClock {
    /// When AW `seq_at_origin` starts, on our TSF.
    pub origin: u64,
    /// The AW sequence number at `origin`.
    pub seq_at_origin: u16,
}

impl OwnClock {
    /// Which of our AWs `tsf` falls in (the first one, before `origin`).
    pub fn position(&self, tsf: u64) -> AwPosition {
        let k = tsf.saturating_sub(self.origin) / AW_US;
        let start = self.origin + k * AW_US;
        AwPosition {
            aw_seq: self.seq_at_origin.wrapping_add(k as u16),
            start_tsf: start,
            offset_us: tsf.saturating_sub(start) as u32,
        }
    }

    /// When the AW after `tsf` starts.
    pub fn next_boundary(&self, tsf: u64) -> u64 {
        self.position(tsf).start_tsf + AW_US
    }
}

/// What [`AwClock::observe`] made of a claim.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Observed {
    /// Used. `residual_us` is how far the claim was from the prediction made
    /// before it, when the clock was already locked.
    Accepted { residual_us: Option<f64> },
    /// Too far from the prediction; ignored.
    Outlier { residual_us: f64 },
    /// Several outliers in a row: the clock started over from this claim.
    Reset,
}

#[derive(Clone, Copy, Debug)]
struct Point {
    k: i64,
    boundary: f64,
    rx_tsf: u64,
    /// aw_seq minus the index of the AW holding the target TX time.
    seq_offset: u16,
}

/// A peer's AW clock on our TSF.
#[derive(Clone, Debug)]
pub struct AwClock {
    points: VecDeque<Point>,
    /// Start of AW index 0, on our TSF.
    origin: f64,
    /// AW length on our TSF, µs.
    period: f64,
    outliers_in_row: u8,
}

impl Default for AwClock {
    fn default() -> Self {
        Self::new()
    }
}

impl AwClock {
    /// A clock with no claims yet.
    pub fn new() -> Self {
        Self { points: VecDeque::new(), origin: 0.0, period: AW_US as f64, outliers_in_row: 0 }
    }

    /// Whether there are enough claims, over a long enough span, for
    /// predictions to be trusted.
    pub fn is_locked(&self) -> bool {
        match (self.points.front(), self.points.back()) {
            (Some(a), Some(b)) => self.points.len() >= LOCK_POINTS && b.rx_tsf - a.rx_tsf >= LOCK_SPAN_US,
            _ => false,
        }
    }

    /// The peer's clock rate against ours, in ppm (negative: its AWs are
    /// shorter on our TSF).
    pub fn drift_ppm(&self) -> f64 {
        (self.period / AW_US as f64 - 1.0) * 1e6
    }

    /// How far a claim is from the current prediction, folded into ±½ AW.
    /// `None` before the clock has any claims.
    pub fn residual(&self, claim: &SyncClaim) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        let b = claim.boundary();
        let k = ((b - self.origin) / self.period).round();
        Some(b - (self.origin + self.period * k))
    }

    /// Feeds one claim.
    pub fn observe(&mut self, claim: &SyncClaim) -> Observed {
        let b = claim.boundary();
        if self.points.is_empty() {
            self.origin = b;
            self.period = AW_US as f64;
            self.push(claim, 0);
            return Observed::Accepted { residual_us: None };
        }
        let locked = self.is_locked();
        let k = ((b - self.origin) / self.period).round() as i64;
        let residual = b - (self.origin + self.period * k as f64);
        if locked && residual.abs() > OUTLIER_US {
            self.outliers_in_row += 1;
            if self.outliers_in_row >= RESET_AFTER {
                *self = Self::new();
                self.observe(claim);
                return Observed::Reset;
            }
            return Observed::Outlier { residual_us: residual };
        }
        self.outliers_in_row = 0;
        self.push(claim, k);
        self.fit();
        Observed::Accepted { residual_us: locked.then_some(residual) }
    }

    fn push(&mut self, claim: &SyncClaim, k: i64) {
        let idx = ((claim.target_tsf() - self.origin) / self.period).floor() as i64;
        self.points.push_back(Point {
            k,
            boundary: claim.boundary(),
            rx_tsf: claim.rx_tsf,
            seq_offset: claim.aw_seq.wrapping_sub(idx as u16),
        });
        while self.points.len() > WINDOW
            || self.points.front().is_some_and(|p| claim.rx_tsf.saturating_sub(p.rx_tsf) > MAX_AGE_US)
        {
            self.points.pop_front();
        }
    }

    /// Least squares through (k, boundary). Too few or too short a span of
    /// claims fit the phase only, at the nominal period.
    fn fit(&mut self) {
        let n = self.points.len() as f64;
        let k0 = self.points[0].k;
        let b0 = self.points[0].boundary;
        let (mut sx, mut sy) = (0.0, 0.0);
        for p in &self.points {
            sx += (p.k - k0) as f64;
            sy += p.boundary - b0;
        }
        let (mx, my) = (sx / n, sy / n);
        let (mut sxx, mut sxy) = (0.0, 0.0);
        for p in &self.points {
            let (x, y) = ((p.k - k0) as f64 - mx, p.boundary - b0 - my);
            sxx += x * x;
            sxy += x * y;
        }
        let nominal = AW_US as f64;
        let mut period = nominal;
        if self.points.len() >= 3 && sxx > 0.0 {
            let slope = sxy / sxx;
            if ((slope / nominal - 1.0) * 1e6).abs() <= MAX_DRIFT_PPM {
                period = slope;
            }
        }
        // Boundary of index k0, then back to index 0.
        let at_k0 = b0 + my - period * mx;
        self.period = period;
        self.origin = at_k0 - period * k0 as f64;
    }

    /// The AW sequence number of index 0: the most common offset among the
    /// claims.
    fn seq_offset(&self) -> Option<u16> {
        let mut counts: Vec<(u16, usize)> = Vec::new();
        for p in &self.points {
            match counts.iter_mut().find(|(o, _)| *o == p.seq_offset) {
                Some(c) => c.1 += 1,
                None => counts.push((p.seq_offset, 1)),
            }
        }
        counts.into_iter().max_by_key(|&(o, n)| (n, std::cmp::Reverse(o))).map(|(o, _)| o)
    }

    /// When the AW after `tsf` starts, on our TSF.
    pub fn next_boundary(&self, tsf: u64) -> Option<u64> {
        if self.points.is_empty() {
            return None;
        }
        Some((self.origin + self.period * (self.index_at(tsf) + 1) as f64).round() as u64)
    }

    fn index_at(&self, tsf: u64) -> i64 {
        ((tsf as f64 - self.origin) / self.period).floor() as i64
    }

    /// Which of the peer's AWs `tsf` falls in. `None` before the first claim.
    pub fn position(&self, tsf: u64) -> Option<AwPosition> {
        let offset = self.seq_offset()?;
        let k = self.index_at(tsf);
        let start = self.origin + self.period * k as f64;
        Some(AwPosition {
            aw_seq: offset.wrapping_add(k as u16),
            start_tsf: start.round().max(0.0) as u64,
            offset_us: (tsf as f64 - start).max(0.0) as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claims from a simulated peer whose AWs are `ppm` off ours, sending one
    /// frame every `every_us` with a TX delay pattern and whole-TU counters,
    /// as real senders do.
    fn claims(ppm: f64, every_us: u64, n: usize) -> Vec<SyncClaim> {
        let period = AW_US as f64 * (1.0 + ppm / 1e6);
        let origin = 5_000_123.0;
        (0..n)
            .map(|i| {
                let target = 6_000_000.0 + (i as u64 * every_us) as f64 + (i * 7919 % 3000) as f64;
                let delay = (i * 104_729 % 2000) as u32;
                let k_next = ((target - origin) / period).floor() + 1.0;
                let to_next = origin + period * k_next - target;
                SyncClaim {
                    rx_tsf: (target + delay as f64) as u64,
                    tx_delay_us: delay,
                    tx_counter_tu: (to_next / TU_US as f64).round() as u16,
                    aw_seq: (1000.0 + k_next - 1.0) as u16,
                }
            })
            .collect()
    }

    #[test]
    fn tracks_a_drifting_peer_within_a_tu() {
        for ppm in [-239.0, 0.0, 120.0] {
            let mut clock = AwClock::new();
            let mut worst = 0.0f64;
            for c in claims(ppm, 102_400, 400) {
                if let Observed::Accepted { residual_us: Some(r) } = clock.observe(&c) {
                    worst = worst.max(r.abs());
                }
            }
            assert!(clock.is_locked());
            assert!((clock.drift_ppm() - ppm).abs() < 20.0, "{ppm} ppm fitted as {}", clock.drift_ppm());
            // Whole-TU counters alone allow ½ TU; a good fit stays inside 1 TU.
            assert!(worst < TU_US as f64, "{ppm} ppm: worst residual {worst} µs");
        }
    }

    #[test]
    fn knows_the_aw_sequence() {
        let mut clock = AwClock::new();
        let cs = claims(-239.0, 102_400, 100);
        for c in &cs {
            clock.observe(c);
        }
        // The last claim was sent in AW aw_seq, which ends at its boundary;
        // probe mid-AW, clear of the ±½ TU edges.
        let last = cs.last().unwrap();
        let half = AW_US / 2;
        let pos = clock.position(last.boundary() as u64 - half).unwrap();
        assert_eq!(pos.aw_seq, last.aw_seq);
        let next = clock.position(last.boundary() as u64 + half).unwrap();
        assert_eq!(next.aw_seq, last.aw_seq.wrapping_add(1));
        assert!(next.offset_us.abs_diff(half as u32) < TU_US as u32);
    }

    #[test]
    fn ignores_outliers_and_restarts_after_a_real_jump() {
        let mut clock = AwClock::new();
        let cs = claims(0.0, 102_400, 60);
        for c in &cs[..50] {
            clock.observe(c);
        }
        let mut odd = cs[50];
        odd.tx_counter_tu += 7; // 7 TU off: an outlier
        assert!(matches!(clock.observe(&odd), Observed::Outlier { .. }));
        assert!(matches!(clock.observe(&cs[51]), Observed::Accepted { residual_us: Some(_) }));
        // The peer jumps 5 TU for good.
        let jumped: Vec<SyncClaim> =
            cs[52..].iter().map(|c| SyncClaim { rx_tsf: c.rx_tsf, tx_counter_tu: c.tx_counter_tu + 5, ..*c }).collect();
        let results: Vec<Observed> = jumped.iter().map(|c| clock.observe(c)).collect();
        assert!(results.contains(&Observed::Reset));
    }
}
