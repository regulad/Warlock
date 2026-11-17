// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's radio, behind one trait: the TP-Link Archer T3U through
//! devourer ([`DevourerRadio`]), or a capture replayed ([`ReplayRadio`]), so
//! the same code runs live and from recordings.

mod devourer;
mod replay;
mod rxclock;

use std::fmt;
use std::time::{Duration, Instant};

pub use devourer::{DevourerConfig, DevourerRadio};
pub use replay::ReplayRadio;
pub use rxclock::RxClock;

/// A received frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxFrame {
    /// When the host got it from the radio.
    pub host: Instant,
    /// The receiver's hardware TSF at reception, µs, extended to 64 bits.
    pub tsf: u64,
    /// The channel the radio was on.
    pub channel: u8,
    /// Signal, dBm.
    pub rssi_dbm: i8,
    /// The MPDU, without FCS.
    pub mpdu: Vec<u8>,
}

/// A radio.
pub trait Radio {
    /// The next received frame, waiting up to `timeout`. `Ok(None)` when none
    /// arrived in time; [`Error::Ended`] when no more ever will.
    fn recv(&mut self, timeout: Duration) -> Result<Option<RxFrame>, Error>;

    /// The channel it's on.
    fn channel(&self) -> u8;

    /// Moves to a 20 MHz channel, the slow, thorough way.
    fn set_channel(&mut self, channel: u8) -> Result<(), Error>;

    /// Moves to a 20 MHz channel as fast as the radio can: for AWDL's slot
    /// changes. Defaults to [`Radio::set_channel`].
    fn hop(&mut self, channel: u8) -> Result<(), Error> {
        self.set_channel(channel)
    }

    /// Transmits an MPDU (no FCS) at a legacy rate, in units of 500 kb/s
    /// (12 = 6 Mb/s).
    fn send(&mut self, mpdu: &[u8], rate_500kbps: u8) -> Result<(), Error>;

    /// Has the radio ACK unicast frames to `addr` in hardware.
    fn set_ack_responder(&mut self, addr: [u8; 6]) -> Result<(), Error>;

    /// Our hardware TSF now, µs, on the timebase that stamps received frames
    /// (see [`RxClock`]). `None` before the first frame.
    fn tsf_now(&mut self) -> Option<u64>;
}

/// A radiotap header that sets only the legacy rate. devourer reads the rate
/// from radiotap; without one it falls back to 1 Mb/s CCK, which doesn't
/// exist at 5 GHz.
pub fn tx_radiotap(rate_500kbps: u8) -> [u8; 9] {
    [0, 0, 9, 0, 0b100, 0, 0, 0, rate_500kbps]
}

/// Why a radio call failed.
#[derive(Debug)]
pub enum Error {
    /// A devourer call failed.
    Devourer {
        /// The shim function.
        call: &'static str,
        /// Its `DVR_E_*` code.
        code: i32,
        /// devourer's message.
        message: String,
    },
    /// No more frames: a replay reached its end, or the radio stopped.
    Ended,
    /// Reading a capture failed.
    Capture(warlock_capture::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Devourer { call, code, message } => write!(f, "{call} failed ({code}): {message}"),
            Error::Ended => f.write_str("no more frames"),
            Error::Capture(e) => write!(f, "capture: {e}"),
        }
    }
}

impl std::error::Error for Error {}
