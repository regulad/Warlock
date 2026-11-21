// SPDX-License-Identifier: GPL-2.0-only
//! Bluetooth LE adverts through Windows' own publisher (WinRT
//! `BluetoothLEAdvertisementPublisher`), from this computer's own
//! Bluetooth: no extra hardware.
//!
//! For each advert Windows creates an extended advertising set with a random
//! address of its own choosing, and never tells the program what it is.
//! [`crate::request::hci`] reads it from Windows' trace of the controller.

use warlock_api::types::{Bluetooth, BluetoothState};
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementPublisher, BluetoothLEAdvertisementPublisherStatus, BluetoothLEManufacturerData,
};
use windows::Devices::Bluetooth::BluetoothAdapter;
use windows::Devices::Radios::RadioState;
use windows::Storage::Streams::DataWriter;

/// This computer's Bluetooth, as Windows reports it: its default adapter,
/// whether its radio is on, and whether its controller has LE extended
/// advertising (which [`crate::request::hci`] needs to see an advert's
/// address). Blocks for as long as Windows takes to answer, a few
/// milliseconds.
pub fn adapter() -> Bluetooth {
    // No adapter, Windows says so with an error or a null result.
    let Ok(adapter) = BluetoothAdapter::GetDefaultAsync().and_then(|op| op.join()) else {
        return Bluetooth { state: BluetoothState::Absent, extended_advertising: false };
    };
    let extended_advertising =
        adapter.IsLowEnergySupported().unwrap_or(false) && adapter.IsExtendedAdvertisingSupported().unwrap_or(false);
    let state = match adapter.GetRadioAsync().and_then(|op| op.join()).and_then(|radio| radio.State()) {
        Ok(RadioState::On) => BluetoothState::On,
        // Off, or disabled (in Device Manager, or by policy): either way not
        // on, and the user's to switch on.
        Ok(_) => BluetoothState::Off,
        // An adapter whose radio Windows won't report: not known to be on.
        Err(_) => BluetoothState::Off,
    };
    Bluetooth { state, extended_advertising }
}

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
