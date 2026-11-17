// SPDX-License-Identifier: GPL-2.0-only
//! "Now" on the receive timebase.
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

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a pairing stays a candidate for the minimum.
const WINDOW: Duration = Duration::from_secs(2);

/// The receive-timebase clock. See the module docs.
#[derive(Debug)]
pub struct RxClock {
    epoch: Instant,
    /// (host instant, host µs − TSF), ascending in difference: a sliding
    /// minimum.
    window: VecDeque<(Instant, i64)>,
    /// The latest minimum, kept when no frames arrive.
    best: Option<i64>,
}

impl RxClock {
    /// A clock that knows nothing yet.
    pub fn new(epoch: Instant) -> Self {
        Self { epoch, window: VecDeque::new(), best: None }
    }

    fn host_us(&self, at: Instant) -> i64 {
        at.saturating_duration_since(self.epoch).as_micros() as i64
    }

    /// Records a frame received at `host` with RX TSF `tsf`.
    pub fn observe(&mut self, host: Instant, tsf: u64) {
        let diff = self.host_us(host) - tsf as i64;
        while self.window.back().is_some_and(|&(_, d)| d >= diff) {
            self.window.pop_back();
        }
        self.window.push_back((host, diff));
        while self.window.front().is_some_and(|&(t, _)| host.saturating_duration_since(t) > WINDOW) {
            self.window.pop_front();
        }
        self.best = self.window.front().map(|&(_, d)| d);
    }

    /// The TSF at host instant `at`, once a frame has been seen.
    pub fn tsf_at(&self, at: Instant) -> Option<u64> {
        let d = self.best?;
        u64::try_from(self.host_us(at) - d).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_least_delayed_frame_sets_the_clock() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        assert_eq!(c.tsf_at(epoch), None);
        // Frames sent at TSF 1_000_000 + k ms, delivered 3, 0.4, 2 ms late;
        // the host clock started at TSF 1_000_000.
        for (k, delay_us) in [(0u64, 3000u64), (1, 400), (2, 2000)] {
            let tsf = 1_000_000 + k * 1000;
            let host = epoch + Duration::from_micros(k * 1000 + delay_us);
            c.observe(host, tsf);
        }
        // Now = host 10 ms → TSF ≈ 1_010_000, late by the least delay.
        let est = c.tsf_at(epoch + Duration::from_millis(10)).unwrap();
        assert_eq!(est, 1_010_000 - 400);
    }

    #[test]
    fn old_minima_age_out() {
        let epoch = Instant::now();
        let mut c = RxClock::new(epoch);
        c.observe(epoch, 1_000_000); // an implausibly early pairing
        let later = epoch + Duration::from_secs(3);
        c.observe(later, 1_000_000 + 3_000_000 - 500);
        let est = c.tsf_at(later).unwrap();
        assert_eq!(est, 1_000_000 + 3_000_000 - 500);
    }
}
