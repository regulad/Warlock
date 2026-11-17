// SPDX-License-Identifier: GPL-2.0-only
//! Watches Apple's Bluetooth LE "Continuity" advertisements (manufacturer
//! data, company 0x004C) with Windows' own WinRT API, to find what wakes an
//! Apple device's AWDL.
//!
//!     cargo run --release -p warlock-radio --example blewatch -- <log.tsv> [seconds=120]
//!
//! Every Apple advert goes to the log (Unix time µs, sender, RSSI, payload
//! hex). The console shows each new (sender, message type, payload). A
//! payload is a run of messages: a type byte, a length byte, then that many
//! bytes. Type names follow the published Continuity research (Martin et al.,
//! PETS 2019; Celosia & Cunche, PETS 2020) and are hints, not facts.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher, BluetoothLEScanningMode,
};
use windows::Foundation::TypedEventHandler;
use windows::Storage::Streams::DataReader;

const APPLE: u16 = 0x004c;

fn type_name(t: u8) -> &'static str {
    match t {
        0x05 => "AirDrop",
        0x07 => "proximity pairing",
        0x09 => "AirPlay target",
        0x0a => "AirPlay source",
        0x0b => "Magic Switch",
        0x0c => "Handoff",
        0x0d => "tethering target",
        0x0e => "tethering source",
        0x0f => "Nearby Action",
        0x10 => "Nearby Info",
        0x12 => "Find My",
        _ => "?",
    }
}

/// Splits a Continuity payload into (type, bytes) messages.
fn messages(p: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut rest = p;
    while rest.len() >= 2 {
        let (t, n) = (rest[0], rest[1] as usize);
        let body = &rest[2..(2 + n).min(rest.len())];
        out.push((t, body));
        rest = &rest[(2 + n).min(rest.len())..];
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> windows::core::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: blewatch <log.tsv> [seconds]");
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(120);
    let log = Arc::new(Mutex::new(BufWriter::new(File::create(&path).expect("creating the log"))));
    let seen: Arc<Mutex<BTreeSet<(u64, u8, String)>>> = Arc::default();
    let started = Instant::now();

    let watcher = BluetoothLEAdvertisementWatcher::new()?;
    watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
    let (log2, seen2) = (log.clone(), seen.clone());
    watcher.Received(&TypedEventHandler::new(
        move |_, args: windows::core::Ref<BluetoothLEAdvertisementReceivedEventArgs>| {
            let Some(args) = args.as_ref() else { return Ok(()) };
            let addr = args.BluetoothAddress()?;
            let rssi = args.RawSignalStrengthInDBm()?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
            for md in args.Advertisement()?.ManufacturerData()? {
                if md.CompanyId()? != APPLE {
                    continue;
                }
                let buf = md.Data()?;
                let mut bytes = vec![0u8; buf.Length()? as usize];
                DataReader::FromBuffer(&buf)?.ReadBytes(&mut bytes)?;
                let _ = writeln!(log2.lock().unwrap(), "{now}\t{addr:012x}\t{rssi}\t{}", hex(&bytes));
                for (t, body) in messages(&bytes) {
                    if seen2.lock().unwrap().insert((addr, t, hex(body))) {
                        println!(
                            "[{:>7.2} s] {addr:012x} {rssi:>4} dBm  0x{t:02x} {:<18} {}",
                            started.elapsed().as_secs_f64(),
                            type_name(t),
                            hex(body)
                        );
                    }
                }
            }
            Ok(())
        },
    ))?;
    watcher.Start()?;
    println!("watching Apple BLE adverts for {seconds} s, logging to {path}");
    std::thread::sleep(Duration::from_secs(seconds));
    watcher.Stop()?;
    log.lock().unwrap().flush().ok();
    println!("done: {} distinct (sender, type, payload) messages", seen.lock().unwrap().len());
    Ok(())
}
