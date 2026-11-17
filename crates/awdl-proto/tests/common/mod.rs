// SPDX-License-Identifier: GPL-2.0-only
//! Test helpers: a minimal pcapng reader, radiotap stripping, and locating
//! the local capture corpus.
//!
//! The corpus lives in `<workspace>/captures/air/*.pcapng` (gitignored: the
//! captures contain real devices' addresses and names) or wherever
//! `WARLOCK_CAPTURES` points. Tests that need it skip when it's absent.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct Packet {
    /// 1-based, counting every packet block, as Wireshark numbers frames.
    pub number: usize,
    pub linktype: u16,
    pub data: Vec<u8>,
}

/// Reads every packet of a little-endian pcapng file.
pub fn read_pcapng(path: &Path) -> Vec<Packet> {
    let buf = std::fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let u32_at = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
    let mut off = 0;
    let mut linktypes = Vec::new();
    let mut snaplens = Vec::new();
    let mut packets = Vec::new();
    while off + 12 <= buf.len() {
        let (btype, blen) = (u32_at(off), u32_at(off + 4) as usize);
        assert!(blen >= 12, "bad pcapng block at {off}");
        if off + blen > buf.len() {
            // A capture killed mid-write ends in a cut-off block.
            break;
        }
        let body = &buf[off + 8..off + blen - 4];
        match btype {
            0x0A0D0D0A => {
                assert_eq!(u32::from_le_bytes(body[0..4].try_into().unwrap()), 0x1A2B3C4D, "big-endian pcapng");
                linktypes.clear();
                snaplens.clear();
            }
            1 => {
                linktypes.push(u16::from_le_bytes([body[0], body[1]]));
                snaplens.push(u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize);
            }
            6 => {
                let iface = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
                let cap = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                packets.push(Packet {
                    number: packets.len() + 1,
                    linktype: linktypes[iface],
                    data: body[20..20 + cap].to_vec(),
                });
            }
            3 => {
                let orig = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
                let snap = snaplens[0];
                let cap = if snap == 0 { orig } else { orig.min(snap) };
                packets.push(Packet { number: packets.len() + 1, linktype: linktypes[0], data: body[4..4 + cap].to_vec() });
            }
            _ => {}
        }
        off += blen;
    }
    packets
}

pub const LINKTYPE_IEEE802_11_RADIOTAP: u16 = 127;

/// Strips a radiotap header and, if its flags say so, the trailing FCS.
pub fn mpdu_from_radiotap(pkt: &[u8]) -> Option<&[u8]> {
    if pkt.len() < 8 {
        return None;
    }
    let len = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
    let present = u32::from_le_bytes(pkt[4..8].try_into().unwrap());
    // Skip any extended presence words.
    let mut off = 8;
    let mut word = present;
    while word & 0x8000_0000 != 0 {
        word = u32::from_le_bytes(pkt.get(off..off + 4)?.try_into().unwrap());
        off += 4;
    }
    let mut fcs = false;
    if present & 0b10 != 0 {
        // Field 0 (TSFT) is 8 bytes, 8-aligned; field 1 is the flags byte.
        if present & 1 != 0 {
            off = off.next_multiple_of(8) + 8;
        }
        fcs = pkt.get(off)? & 0x10 != 0;
    }
    let mpdu = pkt.get(len..)?;
    Some(if fcs { &mpdu[..mpdu.len().checked_sub(4)?] } else { mpdu })
}

/// The radiotap captures in the corpus, sorted by name.
pub fn air_captures() -> Vec<PathBuf> {
    let dir = std::env::var_os("WARLOCK_CAPTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../captures/air"));
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pcapng"))
        .collect();
    v.sort();
    v
}

pub const LINKTYPE_IEEE802_11: u16 = 105;

/// The committed, anonymized fixture (see `examples/scrub.rs`): bare MPDUs.
pub fn fixture_mpdus() -> Vec<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/awdl-scrubbed.pcapng");
    read_pcapng(&path)
        .into_iter()
        .filter(|p| p.linktype == LINKTYPE_IEEE802_11)
        .map(|p| p.data)
        .collect()
}

/// The MPDUs of a capture, with their frame numbers.
pub fn mpdus(path: &Path) -> Vec<(usize, Vec<u8>)> {
    read_pcapng(path)
        .into_iter()
        .filter(|p| p.linktype == LINKTYPE_IEEE802_11_RADIOTAP)
        .filter_map(|p| mpdu_from_radiotap(&p.data).map(|m| (p.number, m.to_vec())))
        .collect()
}
