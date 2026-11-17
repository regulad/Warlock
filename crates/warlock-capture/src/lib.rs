// SPDX-License-Identifier: GPL-2.0-only
//! Radiotap pcapng captures: reading them for replay and tests, writing them
//! from a live radio.
//!
//! pcapng framing is the `pcap-file` crate's and radiotap parsing is the
//! `radiotap` crate's. This crate adds what Warlock needs on top: the hardware
//! TSF, channel and signal of each frame, tolerance of captures cut off
//! mid-write, the radiotap header Warlock writes, and where the local capture
//! corpus lives.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::{Block, PcapNgReader, PcapNgWriter};

/// Errors from reading or writing a capture.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// One captured 802.11 frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captured {
    /// 1-based position among the file's packets, as Wireshark numbers them.
    pub number: usize,
    /// The receiver's hardware TSF when the frame arrived, in µs (radiotap
    /// TSFT).
    pub tsf: Option<u64>,
    /// Centre frequency, MHz.
    pub freq_mhz: Option<u16>,
    /// Signal, dBm.
    pub rssi_dbm: Option<i8>,
    /// The MPDU, without radiotap or FCS.
    pub mpdu: Vec<u8>,
}

impl Captured {
    /// The 2.4 or 5 GHz channel number of `freq_mhz`.
    pub fn channel(&self) -> Option<u8> {
        self.freq_mhz.and_then(channel_of)
    }
}

/// The 2.4 or 5 GHz channel number for a centre frequency.
pub fn channel_of(freq_mhz: u16) -> Option<u8> {
    match freq_mhz {
        2484 => Some(14),
        2412..=2472 => Some(((freq_mhz - 2407) / 5) as u8),
        5000..=5925 => Some(((freq_mhz - 5000) / 5) as u8),
        _ => None,
    }
}

/// The centre frequency of a 2.4 or 5 GHz channel number.
pub fn freq_of(channel: u8) -> u16 {
    match channel {
        14 => 2484,
        1..=13 => 2407 + 5 * channel as u16,
        _ => 5000 + 5 * channel as u16,
    }
}

/// Reads every 802.11 frame of a pcapng file: radiotap (linktype 127) or
/// bare 802.11 (105). A file that ends in a cut-off block, as a capture
/// killed mid-write does, yields the whole frames before it.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<Captured>, Error> {
    let file = BufReader::new(File::open(path.as_ref())?);
    let mut reader = PcapNgReader::new(file)?;
    let mut out = Vec::new();
    let mut number = 0;
    while let Some(block) = reader.next_block() {
        let (block, state) = match block {
            Ok(b) => b,
            // A truncated final block: keep what came before.
            Err(_) if number > 0 => break,
            Err(e) => return Err(e.into()),
        };
        let (iface, data) = match &block {
            Block::EnhancedPacket(p) => (p.interface_id as usize, &p.data),
            Block::SimplePacket(p) => (0, &p.data),
            _ => continue,
        };
        number += 1;
        let linktype = state.interfaces().get(iface).map(|i| i.linktype);
        let frame = match linktype {
            Some(DataLink::IEEE802_11_RADIOTAP) => from_radiotap(number, data),
            Some(DataLink::IEEE802_11) => Some(Captured {
                number,
                tsf: None,
                freq_mhz: None,
                rssi_dbm: None,
                mpdu: data.to_vec(),
            }),
            _ => None,
        };
        out.extend(frame);
    }
    Ok(out)
}

fn from_radiotap(number: usize, data: &[u8]) -> Option<Captured> {
    let (rt, rest) = radiotap::Radiotap::parse(data).ok()?;
    let fcs = rt.flags.as_ref().is_some_and(|f| f.fcs);
    let mpdu = if fcs { rest.get(..rest.len().checked_sub(4)?)? } else { rest };
    Some(Captured {
        number,
        tsf: rt.tsft.map(|t| t.value),
        freq_mhz: rt.channel.map(|c| c.freq),
        rssi_dbm: rt.antenna_signal.map(|s| s.value),
        mpdu: mpdu.to_vec(),
    })
}

/// Writes a pcapng capture.
pub struct Writer<W: Write> {
    inner: PcapNgWriter<W>,
    radiotap: bool,
}

impl<W: Write> Writer<W> {
    /// Radiotap + 802.11 (linktype 127): each frame carries its TSF, channel
    /// and signal, as Warlock's own captures do.
    pub fn radiotap(w: W) -> Result<Self, Error> {
        Self::new(w, DataLink::IEEE802_11_RADIOTAP, true)
    }

    /// Bare 802.11 (linktype 105), for fixtures with nothing to say about
    /// timing or radio.
    pub fn bare(w: W) -> Result<Self, Error> {
        Self::new(w, DataLink::IEEE802_11, false)
    }

    fn new(w: W, linktype: DataLink, radiotap: bool) -> Result<Self, Error> {
        let mut inner = PcapNgWriter::new(w)?;
        inner.write_pcapng_block(InterfaceDescriptionBlock { linktype, snaplen: 0, options: vec![] })?;
        Ok(Self { inner, radiotap })
    }

    /// Writes one frame. `timestamp` is the packet's wall-clock time (time
    /// since the Unix epoch); the TSF, frequency and signal go in the radiotap
    /// header, if this writer writes one.
    pub fn write(
        &mut self,
        timestamp: Duration,
        tsf: u64,
        freq_mhz: u16,
        rssi_dbm: i8,
        mpdu: &[u8],
    ) -> Result<(), Error> {
        let data: Vec<u8> = if self.radiotap {
            let mut d = radiotap_header(tsf, freq_mhz, rssi_dbm).to_vec();
            d.extend_from_slice(mpdu);
            d
        } else {
            mpdu.to_vec()
        };
        self.inner.write_pcapng_block(EnhancedPacketBlock {
            interface_id: 0,
            timestamp,
            original_len: data.len() as u32,
            data: Cow::Owned(data),
            options: vec![],
        })?;
        Ok(())
    }

    /// Flushes and returns the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner.into_inner()
    }

    /// The underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        self.inner.get_mut()
    }
}

/// The radiotap header Warlock writes: TSFT, flags (no FCS), channel and
/// antenna signal.
pub fn radiotap_header(tsf: u64, freq_mhz: u16, rssi_dbm: i8) -> [u8; 23] {
    let mut h = [0u8; 23];
    h[2..4].copy_from_slice(&23u16.to_le_bytes());
    // Present: TSFT (0), Flags (1), Channel (3), Antenna signal (5).
    h[4..8].copy_from_slice(&0b10_1011u32.to_le_bytes());
    h[8..16].copy_from_slice(&tsf.to_le_bytes());
    h[16] = 0; // flags: no FCS
    // h[17]: padding to align the channel field
    h[18..20].copy_from_slice(&freq_mhz.to_le_bytes());
    let chan_flags: u16 = if freq_mhz < 3000 { 0x0080 | 0x0400 } else { 0x0100 | 0x0040 }; // 2 GHz+dyn CCK-OFDM / 5 GHz+OFDM
    h[20..22].copy_from_slice(&chan_flags.to_le_bytes());
    h[22] = rssi_dbm as u8;
    h
}

/// The local capture corpus: `WARLOCK_CAPTURES`, or `captures/air` at the
/// workspace root. It holds real devices' addresses and names, so it's
/// gitignored; tests that need it skip when it's absent.
pub fn corpus_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("WARLOCK_CAPTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../captures/air"));
    dir.is_dir().then_some(dir)
}

/// The `.pcapng` files of the local corpus, sorted by name. Empty when there's
/// no corpus.
pub fn corpus_files() -> Vec<PathBuf> {
    let Some(dir) = corpus_dir() else { return Vec::new() };
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pcapng"))
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_frames_read_back() {
        let mut w = Writer::radiotap(Vec::new()).unwrap();
        w.write(Duration::from_secs(1), 0x0123_4567_89ab, 5220, -48, b"\xd0\x00frame").unwrap();
        w.write(Duration::from_secs(2), 42, 2437, -70, b"\x08\x00other").unwrap();
        let bytes = w.into_inner();
        let path = std::env::temp_dir().join(format!("warlock-capture-test-{}.pcapng", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let frames = read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].tsf, Some(0x0123_4567_89ab));
        assert_eq!((frames[0].freq_mhz, frames[0].channel()), (Some(5220), Some(44)));
        assert_eq!(frames[0].rssi_dbm, Some(-48));
        assert_eq!(frames[0].mpdu, b"\xd0\x00frame");
        assert_eq!((frames[1].number, frames[1].channel()), (2, Some(6)));
    }

    #[test]
    fn cut_off_files_keep_their_whole_frames() {
        let mut w = Writer::bare(Vec::new()).unwrap();
        for i in 0..3u8 {
            w.write(Duration::ZERO, 0, 0, 0, &[i; 40]).unwrap();
        }
        let mut bytes = w.into_inner();
        bytes.truncate(bytes.len() - 10);
        let path = std::env::temp_dir().join(format!("warlock-capture-cut-{}.pcapng", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let frames = read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].mpdu, [1; 40]);
    }

    #[test]
    fn channels_and_frequencies() {
        for (ch, f) in [(1, 2412), (6, 2437), (13, 2472), (14, 2484), (36, 5180), (44, 5220), (149, 5745), (165, 5825)] {
            assert_eq!(freq_of(ch), f);
            assert_eq!(channel_of(f), Some(ch));
        }
    }
}
