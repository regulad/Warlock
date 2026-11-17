// SPDX-License-Identifier: GPL-2.0-only
//! Broadcasts one Apple "Continuity" advertisement (manufacturer data,
//! company 0x004C) from Windows' own Bluetooth radio, to test which advert
//! wakes an Apple device's AWDL. The payload is given in hex, in the form
//! blewatch logs it: type, length and body for each message.
//!
//!     cargo run --release -p warlock-radio --example blepublish -- <payload hex> [seconds=30] [delay_s=0]
//!
//! Windows sends the advert from a random address of its own choosing, and
//! sets the advertising interval itself. The start and stop times go to
//! stdout in Unix µs, so they can be lined up against a capture.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementPublisher, BluetoothLEAdvertisementPublisherStatus, BluetoothLEManufacturerData,
};
use windows::Storage::Streams::DataWriter;

const APPLE: u16 = 0x004c;

fn unix_us() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros()
}

fn main() -> windows::core::Result<()> {
    let mut args = std::env::args().skip(1);
    let hex = args.next().expect("usage: blepublish <payload hex> [seconds] [delay_s]");
    let payload: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("payload hex"))
        .collect();
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(30);
    let delay: u64 = args.next().map(|a| a.parse().expect("delay seconds")).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(delay));

    let writer = DataWriter::new()?;
    writer.WriteBytes(&payload)?;
    let data = BluetoothLEManufacturerData::Create(APPLE, &writer.DetachBuffer()?)?;
    let publisher = BluetoothLEAdvertisementPublisher::new()?;
    publisher.Advertisement()?.ManufacturerData()?.Append(&data)?;
    publisher.Start()?;
    std::thread::sleep(Duration::from_millis(300));
    let status = publisher.Status()?;
    println!("{}\tstart\t{hex}\tstatus {}", unix_us(), status.0);
    if status != BluetoothLEAdvertisementPublisherStatus::Started {
        eprintln!("the publisher did not start (status {}; 1 = waiting, 5 = aborted)", status.0);
    }
    std::thread::sleep(Duration::from_secs(seconds));
    publisher.Stop()?;
    println!("{}\tstop", unix_us());
    Ok(())
}
