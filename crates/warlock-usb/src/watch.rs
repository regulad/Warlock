// SPDX-License-Identifier: GPL-2.0-only
//! Waking up when USB devices come and go, rather than polling:
//! `CM_Register_Notification` for the USB device interface class
//! (`GUID_DEVINTERFACE_USB_DEVICE`), which every USB device registers
//! whatever its driver, so an adapter is seen on Windows' driver and on
//! WinUSB alike. The daemon waits on it while no adapter is up, and checks
//! its adapter is still present when a device goes.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_NOTIFY_ACTION, CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL, CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL,
    CM_NOTIFY_EVENT_DATA, CM_NOTIFY_FILTER, CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CM_Register_Notification,
    CM_Unregister_Notification, CR_SUCCESS, HCMNOTIFICATION,
};
use windows_sys::core::GUID;

use crate::{Error, Result};

/// `GUID_DEVINTERFACE_USB_DEVICE`.
const USB_DEVICE: GUID = GUID::from_u128(0xa5dcbf10_6530_11d2_901f_00c04fb951ed);

struct Shared {
    /// Arrivals and removals seen.
    changes: Mutex<u64>,
    changed: Condvar,
}

unsafe extern "system" fn on_change(
    _notify: HCMNOTIFICATION,
    context: *const c_void,
    action: CM_NOTIFY_ACTION,
    _data: *const CM_NOTIFY_EVENT_DATA,
    _size: u32,
) -> u32 {
    if action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL || action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL {
        // SAFETY: the context is the Shared that `DeviceWatch::start` leaked.
        let shared = unsafe { &*(context as *const Shared) };
        *shared.changes.lock().unwrap() += 1;
        shared.changed.notify_all();
    }
    0
}

/// Counts USB devices arriving and leaving.
pub struct DeviceWatch {
    handle: HCMNOTIFICATION,
    shared: &'static Shared,
}

impl DeviceWatch {
    /// Starts watching.
    pub fn start() -> Result<Self> {
        // Leaked: Windows may still be in the callback as we unregister, and
        // one watch lives as long as the service.
        let shared: &'static Shared = Box::leak(Box::new(Shared { changes: Mutex::new(0), changed: Condvar::new() }));
        // SAFETY: plain data, filled in below.
        let mut filter: CM_NOTIFY_FILTER = unsafe { zeroed() };
        filter.cbSize = size_of::<CM_NOTIFY_FILTER>() as u32;
        filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
        filter.u.DeviceInterface.ClassGuid = USB_DEVICE;
        let mut handle: HCMNOTIFICATION = null_mut();
        // SAFETY: a valid filter; the context outlives the registration.
        let cr = unsafe {
            CM_Register_Notification(&filter, (shared as *const Shared).cast(), Some(on_change), &mut handle)
        };
        if cr != CR_SUCCESS {
            return Err(Error { op: "CM_Register_Notification", code: cr });
        }
        Ok(Self { handle, shared })
    }

    /// Arrivals and removals so far.
    pub fn changes(&self) -> u64 {
        *self.shared.changes.lock().unwrap()
    }

    /// Waits until the count is no longer `seen`, or `timeout` passes; the
    /// count then.
    pub fn wait(&self, seen: u64, timeout: Duration) -> u64 {
        let guard = self.shared.changes.lock().unwrap();
        let (guard, _) = self.shared.changed.wait_timeout_while(guard, timeout, |c| *c == seen).unwrap();
        *guard
    }
}

impl Drop for DeviceWatch {
    fn drop(&mut self) {
        // SAFETY: a registration we made.
        unsafe { CM_Unregister_Notification(self.handle) };
    }
}
