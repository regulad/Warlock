// SPDX-License-Identifier: GPL-2.0-only
//! The radio's clock: "now" on the receive timebase, from the moment the radio
//! opens.
//!
//! AWDL timing is reckoned in the hardware TSF that stamps received frames.
//! On the T3U that is not the TSF `dvr_read_tsf` returns: the two counters
//! tick at the same rate, but a register read came back about 318 ms
//! *behind* the timestamps of frames that had already arrived, stable to
//! 20 µs over 30 s. So "now" is estimated from received frames instead.
//! Each frame's RX TSF is paired with the host instant it reached us. Over
//! the last two seconds, the pairing with the smallest host − TSF difference
//! had the least delivery delay, and now ≈ host now − that difference. The
//! estimate runs late by that least delay, a fraction of a TU.
//!
//! Until the first frame there is no RX TSF to pair with, but a lone engine
//! still needs a clock to lead a cluster of its own. So the clock starts as
//! host time, in µs since the radio opened. The first frame fixes an offset
//! that moves the hardware TSF onto it: that frame's TSF becomes the host
//! time it arrived. From then on frames carry the shifted TSF and the clock
//! follows them as above, so an AW grid started before the first frame runs
//! on without a jump. Peers can't tell: what a frame says about time is
//! relative (`phy_tx_time − target_tx_time`), not our TSF's absolute value.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a pairing stays a candidate for the minimum.
const WINDOW: Duration = Duration::from_secs(2);

/// The radio's clock. See the module docs.
#[derive(Debug)]
pub struct RxClock {
    epoch: Instant,
    /// What moves the hardware TSF onto this clock, µs: set by the first
    /// frame.
    offset: Option<i64>,
    /// (host instant, host µs − shifted TSF), ascending in difference: a
    /// sliding minimum.
    window: VecDeque<(Instant, i64)>,
    /// The latest minimum, kept when no frames arrive; zero, so host time,
    /// before the first frame.
    best: i64,
}

impl RxClock {
    /// A clock that reads zero at `epoch` and has heard nothing yet.
    pub fn new(epoch: Instant) -> Self {
        Self { epoch, offset: None, window: VecDeque::new(), best: 0 }
    }

    fn host_us(&self, at: Instant) -> i64 {
        at.saturating_duration_since(self.epoch).as_micros() as i64
    }

    /// Records a frame received at `host` with hardware RX TSF `tsf`, and
    /// returns its TSF on this clock.
    pub fn observe(&mut self, host: Instant, tsf: u64) -> u64 {
        let host_us = self.host_us(host);
        let offset = *self.offset.get_or_insert(host_us - tsf as i64);
        let shifted = tsf.saturating_add_signed(offset);
        let diff = host_us - shifted as i64;
        while self.window.back().is_some_and(|&(_, d)| d >= diff) {
            self.window.pop_back();
        }
        self.window.push_back((host, diff));
        while self.window.front().is_some_and(|&(t, _)| host.saturating_duration_since(t) > WINDOW) {
            self.window.pop_front();
        }
        self.best = self.window.front().map_or(self.best, |&(_, d)| d);
        shifted
    }

    /// The clock at host instant `at`.
    pub fn tsf_at(&self, at: Instant) -> u64 {
        (self.host_us(at) - self.best).max(0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_least_delayed_frame_sets_the_clock() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        // Frames sent at hardware TSF 1_000_000 + k ms, delivered 3, 0.4, 2
        // ms late; the hardware TSF read 1_000_000 when the radio opened.
        let mut shifted = Vec::new();
        for (k, delay_us) in [(0u64, 3000u64), (1, 400), (2, 2000)] {
            let tsf = 1_000_000 + k * 1000;
            let host = epoch + Duration::from_micros(k * 1000 + delay_us);
            shifted.push(c.observe(host, tsf));
        }
        // The first frame's TSF became the host time it arrived; the rest
        // keep their spacing.
        assert_eq!(shifted, [3000, 4000, 5000]);
        // Now = host 10 ms → TSF ≈ 1_010_000 on the hardware, late by the
        // least delay; on this clock, less the 3 ms the first frame took.
        let est = c.tsf_at(epoch + Duration::from_millis(10));
        assert_eq!(est, 1_010_000 - 400 - 1_000_000 + 3000);
    }

    #[test]
    fn old_minima_age_out() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        c.observe(epoch, 1_000_000); // an implausibly early pairing
        let later = epoch + Duration::from_secs(3);
        let shifted = c.observe(later, 1_000_000 + 3_000_000 - 500);
        // Only the later pairing counts: now is its TSF.
        assert_eq!(c.tsf_at(later), shifted);
        assert_eq!(shifted, 3_000_000 - 500);
    }

    #[test]
    fn before_any_frame_it_keeps_host_time() {
        let epoch = Instant::now();
        let c = RxClock::new(epoch);
        assert_eq!(c.tsf_at(epoch), 0);
        assert_eq!(c.tsf_at(epoch + Duration::from_millis(1500)), 1_500_000);
    }

    #[test]
    fn the_first_frame_continues_the_clock_without_a_jump() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        // A minute alone, then a frame stamped by a hardware TSF that has
        // nothing to do with host time.
        let arrived = epoch + Duration::from_secs(60);
        let before = c.tsf_at(arrived);
        let shifted = c.observe(arrived, 987_654_321);
        assert_eq!(shifted, before);
        assert_eq!(c.tsf_at(arrived), before);
        // It carries on at the hardware's pace: 1 s on, a frame with the same
        // delay lands 1 s later on this clock, and so does now.
        let next = arrived + Duration::from_secs(1);
        assert_eq!(c.observe(next, 987_654_321 + 1_000_000), before + 1_000_000);
        assert_eq!(c.tsf_at(next), before + 1_000_000);
    }

    #[test]
    fn a_frame_older_than_the_first_cannot_go_below_zero() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        c.observe(epoch, 5_000_000);
        assert_eq!(c.observe(epoch, 1_000_000), 0);
    }
}
