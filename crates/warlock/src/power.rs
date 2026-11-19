// SPDX-License-Identifier: GPL-2.0-only
//! Sleep and resume, from Windows' power notifications
//! (`PowerRegisterSuspendResumeNotification`), which reach the service and a
//! foreground run alike, without a window.
//!
//! Hibernating cuts the adapter's power under a running radio: devourer's USB
//! session failed mid-call, and after resume the chip came back cold, its
//! firmware gone, while Windows reported no unplug, so nothing told the daemon
//! (2026-11-19). The radio is therefore closed when the system says it will
//! sleep, while the bus still answers, and opened afresh when it wakes.

use std::ffi::c_void;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, HPOWERNOTIFY, PowerRegisterSuspendResumeNotification,
    PowerUnregisterSuspendResumeNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
};

/// How long the suspend notification is held while the radio closes. Windows
/// waits for the callback, but not indefinitely; closing a radio whose bus
/// still answers takes well under this.
const CLOSE_BEFORE_SLEEP: Duration = Duration::from_secs(2);

#[derive(Default)]
struct State {
    /// Between the suspend notification and the resume.
    asleep: bool,
    /// Resumes so far.
    resumes: u64,
    /// Whether the daemon has a radio open.
    radio_open: bool,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn new_shared() -> &'static Shared {
    Box::leak(Box::new(Shared { state: Mutex::new(State::default()), changed: Condvar::new() }))
}

unsafe extern "system" fn on_power(context: *const c_void, kind: u32, _setting: *const c_void) -> u32 {
    // SAFETY: the context is the Shared that `Power::watch` leaked.
    let shared = unsafe { &*(context as *const Shared) };
    let mut state = shared.lock();
    match kind {
        PBT_APMSUSPEND => {
            state.asleep = true;
            shared.changed.notify_all();
            // Hold the system briefly while the daemon closes its radio.
            let _ = shared.changed.wait_timeout_while(state, CLOSE_BEFORE_SLEEP, |s| s.radio_open);
        }
        // Windows sends the first on every resume, the second too when a
        // person woke the system; one resume is counted. Without a suspend
        // notice first, the first still counts: the radio may be cold.
        PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND if state.asleep || kind == PBT_APMRESUMEAUTOMATIC => {
            state.asleep = false;
            state.resumes += 1;
            shared.changed.notify_all();
        }
        _ => {}
    }
    0
}

/// The system's sleeps and resumes, as the daemon needs them.
pub struct Power {
    shared: &'static Shared,
    handle: Option<HPOWERNOTIFY>,
}

impl Power {
    /// Starts listening. Without the notifications (registration failed), the
    /// daemon still finds a dead radio by its failures, only later.
    pub fn watch() -> Result<Self, u32> {
        let shared = new_shared();
        // Leaked, as the context is: Windows may still be in the callback as
        // we unregister, and one registration lives as long as the daemon.
        let parameters: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
            Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                Callback: Some(on_power),
                Context: (shared as *const Shared).cast_mut().cast(),
            }));
        let mut handle: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid parameters that outlive the registration; with
        // DEVICE_NOTIFY_CALLBACK, the recipient is their address.
        let error = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                (parameters as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS).cast(),
                &mut handle,
            )
        };
        if error != 0 {
            return Err(error);
        }
        Ok(Self { shared, handle: Some(handle as HPOWERNOTIFY) })
    }

    /// A `Power` that never hears anything, for when registering failed.
    pub fn deaf() -> Self {
        Self { shared: new_shared(), handle: None }
    }

    /// Whether the system said it is going to sleep and hasn't woken since.
    pub fn asleep(&self) -> bool {
        self.shared.lock().asleep
    }

    /// Resumes so far: one more than when a radio opened means the system
    /// slept under it.
    pub fn resumes(&self) -> u64 {
        self.shared.lock().resumes
    }

    /// Tells the suspend notification whether a radio is open, so that it
    /// waits for one to close and not otherwise.
    pub fn set_radio_open(&self, open: bool) {
        self.shared.lock().radio_open = open;
        self.shared.changed.notify_all();
    }

    /// Waits until the system is awake, or `timeout` passes; whether it is.
    pub fn wait_awake(&self, timeout: Duration) -> bool {
        let state = self.shared.lock();
        let (state, _) =
            self.shared.changed.wait_timeout_while(state, timeout, |s| s.asleep).unwrap_or_else(|e| e.into_inner());
        !state.asleep
    }
}

impl Drop for Power {
    fn drop(&mut self) {
        if let Some(handle) = self.handle {
            // SAFETY: a registration we made.
            unsafe { PowerUnregisterSuspendResumeNotification(handle) };
        }
    }
}
