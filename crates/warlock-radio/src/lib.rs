// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's radio, behind one trait: the TP-Link Archer T3U through
//! devourer ([`DevourerRadio`]), or a capture replayed ([`ReplayRadio`]), so
//! the same code runs live and from recordings.

mod devourer;
mod replay;

use std::fmt;
use std::time::Duration;

pub use devourer::{DevourerConfig, DevourerRadio};
pub use replay::ReplayRadio;

/// A received frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxFrame {
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

    /// Moves to a 20 MHz channel.
    fn set_channel(&mut self, channel: u8) -> Result<(), Error>;
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
