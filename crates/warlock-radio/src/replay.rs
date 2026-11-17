// SPDX-License-Identifier: GPL-2.0-only
//! A capture, played back as a radio.

use std::path::Path;
use std::time::Duration;

use warlock_capture::Captured;

use crate::{Error, Radio, RxFrame};

/// Plays a radiotap capture back, frame by frame, as fast as it's read.
/// Frames without a TSF or a 2.4/5 GHz channel are skipped. It can't retune
/// or transmit: channel changes are only recorded, and sent frames are kept
/// in [`ReplayRadio::sent`] for inspection. Its TSF is the latest frame's.
pub struct ReplayRadio {
    frames: std::vec::IntoIter<Captured>,
    channel: u8,
    tsf: Option<u64>,
    /// Frames "sent": (TSF at the time, channel, MPDU).
    pub sent: Vec<(u64, u8, Vec<u8>)>,
}

impl ReplayRadio {
    /// Opens a capture.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let frames = warlock_capture::read(path).map_err(Error::Capture)?;
        let channel = frames.iter().find_map(Captured::channel).unwrap_or(0);
        Ok(Self { frames: frames.into_iter(), channel, tsf: None, sent: Vec::new() })
    }
}

impl Radio for ReplayRadio {
    fn recv(&mut self, _timeout: Duration) -> Result<Option<RxFrame>, Error> {
        for c in self.frames.by_ref() {
            let (Some(tsf), Some(channel)) = (c.tsf, c.channel()) else { continue };
            self.channel = channel;
            self.tsf = Some(tsf);
            let host = std::time::Instant::now();
            return Ok(Some(RxFrame { host, tsf, channel, rssi_dbm: c.rssi_dbm.unwrap_or(0), mpdu: c.mpdu }));
        }
        Err(Error::Ended)
    }

    fn channel(&self) -> u8 {
        self.channel
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), Error> {
        self.channel = channel;
        Ok(())
    }

    fn send(&mut self, mpdu: &[u8], _rate_500kbps: u8) -> Result<(), Error> {
        self.sent.push((self.tsf.unwrap_or(0), self.channel, mpdu.to_vec()));
        Ok(())
    }

    fn set_ack_responder(&mut self, _addr: [u8; 6]) -> Result<(), Error> {
        Ok(())
    }

    fn tsf_now(&mut self) -> Option<u64> {
        self.tsf
    }
}
