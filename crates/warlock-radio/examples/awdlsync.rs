// SPDX-License-Identifier: GPL-2.0-only
//! Watches AWDL, live or from a capture, and runs W2's exit check: how well
//! the engine predicts the AW boundaries of the peer it syncs to.
//!
//!     cargo run --release -p warlock-radio --example awdlsync -- [channel=44] [seconds=60]
//!     cargo run --release -p warlock-radio --example awdlsync -- --replay <capture.pcapng>
//!
//! Live needs the T3U bound to WinUSB (`warlock-usb bind`). Bring-up takes
//! about 20 s.

use std::time::{Duration, Instant};

use awdl_core::diag::SyncCheck;
use awdl_core::{Engine, RxMeta};
use warlock_radio::{DevourerConfig, DevourerRadio, Error, Radio, ReplayRadio};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let passed = if args.first().map(String::as_str) == Some("--replay") {
        let path = args.get(1).expect("usage: awdlsync --replay <capture.pcapng>");
        let mut radio = ReplayRadio::open(path).expect("opening the capture");
        run(&mut radio, None)
    } else {
        let channel: u8 = args.first().map(|a| a.parse().expect("channel")).unwrap_or(44);
        let seconds: u64 = args.get(1).map(|a| a.parse().expect("seconds")).unwrap_or(60);
        println!("opening the T3U on channel {channel}; bring-up takes ~20 s");
        let mut radio = DevourerRadio::open(&DevourerConfig { channel, ..Default::default() }).expect("opening the radio");
        println!("receiving for {seconds} s");
        let passed = run(&mut radio, Some(Duration::from_secs(seconds)));
        println!("frames dropped by the RX queue: {}", radio.dropped());
        passed
    };
    std::process::exit(if passed { 0 } else { 1 });
}

/// Runs until the capture ends or `limit` passes. Returns whether W2's check
/// passed: 99 % of the sync source's frames within ±1 TU of prediction.
fn run(radio: &mut impl Radio, limit: Option<Duration>) -> bool {
    let mut engine = Engine::new(Default::default());
    let mut check = SyncCheck::default();
    let started = Instant::now();
    let mut last_report = Instant::now();
    let (mut frames, mut first_tsf, mut last_tsf) = (0u64, None, 0u64);
    loop {
        if limit.is_some_and(|l| started.elapsed() >= l) {
            break;
        }
        let f = match radio.recv(Duration::from_millis(100)) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(Error::Ended) => break,
            Err(e) => {
                eprintln!("radio: {e}");
                break;
            }
        };
        frames += 1;
        last_tsf = f.tsf;
        let t0 = *first_tsf.get_or_insert(f.tsf);
        check.check(&engine, f.tsf, &f.mpdu);
        for ev in engine.on_frame(RxMeta { tsf: f.tsf, channel: f.channel, rssi_dbm: f.rssi_dbm }, &f.mpdu) {
            if !matches!(ev, awdl_core::Event::Packet { .. }) {
                println!("[{:>8.3} s] {ev:?}", (f.tsf - t0) as f64 / 1e6);
            }
        }
        if limit.is_some() && last_report.elapsed() >= Duration::from_secs(5) {
            report(&engine, &check, frames, last_tsf);
            last_report = Instant::now();
        }
    }
    report(&engine, &check, frames, last_tsf);
    let n = check.source.0.len();
    let passed = n >= 50 && check.source.ratio_within_tu() >= 0.99;
    println!(
        "W2 check ({n} frames from the sync source): {}",
        if n < 50 { "not enough frames" } else if passed { "PASS" } else { "FAIL" }
    );
    passed
}

fn report(engine: &Engine, check: &SyncCheck, frames: u64, tsf: u64) {
    println!("--- {frames} frames; master {:?}; sync source {:?}", engine.master(), engine.sync_source().map(|p| p.addr));
    for p in engine.peers() {
        let e = p.election;
        println!(
            "  {} ch {:<3} {:>4} dBm  psf {:<5} mif {:<5} data {:<4} version {:<9} metric {:<5} master {} (+{} hops){}",
            p.addr,
            p.channel,
            p.rssi_dbm,
            p.psfs,
            p.mifs,
            p.data_frames,
            p.version.map(|(v, c)| format!("{v}/{c}")).unwrap_or_else(|| "-".into()),
            e.map(|e| e.self_metric.to_string()).unwrap_or_else(|| "-".into()),
            e.map(|e| e.master.to_string()).unwrap_or_else(|| "?".into()),
            e.map_or(0, |e| e.distance),
            if p.is_valid() { "  valid" } else { "" },
        );
    }
    if let Some(src) = engine.sync_source() {
        let pos = engine.position(tsf);
        println!(
            "  sync: {} locked={} drift {:+.1} ppm  now in AW {:?} (+{} µs)",
            src.addr,
            src.clock.is_locked(),
            src.clock.drift_ppm(),
            pos.map(|p| p.aw_seq),
            pos.map_or(0, |p| p.offset_us)
        );
    }
    println!("  prediction vs sync source: {}", check.source);
    println!("  prediction vs followers:   {}", check.followers);
}
