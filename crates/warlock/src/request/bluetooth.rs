// SPDX-License-Identifier: GPL-2.0-only
//! Bluetooth LE adverts through Windows' own publisher (WinRT
//! `BluetoothLEAdvertisementPublisher`), from this computer's own
//! Bluetooth: no extra hardware.
//!
//! For each advert Windows creates an extended advertising set with a random
//! address of its own choosing, and never tells the program what it is.
//! [`crate::request::hci`] reads it from Windows' trace of the controller.

use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementPublisher, BluetoothLEAdvertisementPublisherStatus, BluetoothLEManufacturerData,
};
use windows::Storage::Streams::DataWriter;

/// An advert being broadcast; it stops when dropped.
pub struct Advert {
    publisher: BluetoothLEAdvertisementPublisher,
}

impl Advert {
    /// Broadcasts `data` as manufacturer data of `company`.
    pub fn start(company: u16, data: &[u8]) -> windows::core::Result<Self> {
        let manufacturer = BluetoothLEManufacturerData::new()?;
        manufacturer.SetCompanyId(company)?;
        let writer = DataWriter::new()?;
        writer.WriteBytes(data)?;
        manufacturer.SetData(&writer.DetachBuffer()?)?;
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        publisher.Advertisement()?.ManufacturerData()?.Append(&manufacturer)?;
        publisher.Start()?;
        Ok(Self { publisher })
    }

    /// Whether Windows is still sending it (or about to): not aborted, as
    /// when Bluetooth goes off, and not stopped.
    pub fn running(&self) -> bool {
        use BluetoothLEAdvertisementPublisherStatus as S;
        !matches!(self.publisher.Status(), Ok(S::Aborted | S::Stopped | S::Stopping) | Err(_))
    }
}

impl Drop for Advert {
    fn drop(&mut self) {
        let _ = self.publisher.Stop();
    }
}
