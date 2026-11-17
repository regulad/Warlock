// SPDX-License-Identifier: GPL-2.0-only
//! Captures everything the T3U receives to a radiotap pcapng file, for
//! Wireshark's AWDL dissector and for replay.
//!
//!     cargo run --release -p warlock-radio --example awdlcap -- <out.pcapng> [channels=44] [seconds=60] [dwell_s=5]
//!
//! `channels` is a comma-separated list; with more than one, the radio cycles
//! through them, `dwell_s` seconds each. Creating `<out.pcapng>.stop` ends
//! the capture early and still flushes the file.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use warlock_capture::{Writer, freq_of};
use warlock_radio::{DevourerConfig, DevourerRadio, Radio};

const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: awdlcap <out.pcapng> [channels] [seconds] [dwell_s]");
    let channels: Vec<u8> = args
        .next()
        .unwrap_or_else(|| "44".into())
        .split(',')
        .map(|c| c.trim().parse().expect("channel"))
        .collect();
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(60);
    let dwell = Duration::from_secs(args.next().map(|a| a.parse().expect("dwell seconds")).unwrap_or(5).max(1));

    let mut radio = DevourerRadio::open(&DevourerConfig { channel: channels[0], ..Default::default() })
        .unwrap_or_else(|e| panic!("opening the radio: {e}"));
    let mut out = Writer::radiotap(BufWriter::new(File::create(&path).expect("creating the capture file")))
        .expect("writing the capture header");
    println!("capturing channels {channels:?} to {path} for {seconds} s");

    let stop_file = PathBuf::from(format!("{path}.stop"));
    let _ = std::fs::remove_file(&stop_file);
    let (started, mut hopped, mut reported) = (Instant::now(), Instant::now(), Instant::now());
    let (mut idx, mut frames, mut awdl) = (0, 0u64, 0u64);
    while started.elapsed() < Duration::from_secs(seconds) && !stop_file.exists() {
        if let Some(f) = radio.recv(Duration::from_millis(100)).expect("receiving") {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            out.write(now, f.tsf, freq_of(f.channel), f.rssi_dbm, &f.mpdu).expect("writing a frame");
            frames += 1;
            awdl += (f.mpdu.get(16..22) == Some(&AWDL_BSSID[..])) as u64;
        }
        if channels.len() > 1 && hopped.elapsed() >= dwell {
            idx = (idx + 1) % channels.len();
            if let Err(e) = radio.set_channel(channels[idx]) {
                eprintln!("{e}");
            }
            hopped = Instant::now();
        }
        if reported.elapsed() >= Duration::from_secs(5) {
            println!("t={:>3} s ch={} frames={frames} awdl={awdl}", started.elapsed().as_secs(), radio.channel());
            reported = Instant::now();
        }
    }
    out.get_mut().flush().expect("flushing the capture");
    println!("done: frames={frames} awdl={awdl} dropped={}", radio.dropped());
}
