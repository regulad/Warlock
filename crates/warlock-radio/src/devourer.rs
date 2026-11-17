// SPDX-License-Identifier: GPL-2.0-only
//! The T3U through devourer.
//!
//! devourer's contract (see `devourer-sys`'s `shim/dvr_shim.h`): open and
//! close on one thread, since its Windows adapter lock is a named mutex owned
//! by the opening thread; run the RX loop on a thread of its own; tear down in
//! order. [`DevourerRadio`] is `!Send`, so the compiler keeps it on the thread
//! that opened it. The RX loop runs on a thread it spawns, which hands frames
//! over through a bounded queue.

use std::ffi::{CStr, c_void};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use devourer_sys::*;

use crate::{Error, Radio, RxClock, RxFrame};

/// Frames buffered between the RX thread and the consumer; beyond this,
/// frames are dropped and counted.
const QUEUE: usize = 4096;

/// How to open the adapter.
#[derive(Clone, Debug)]
pub struct DevourerConfig {
    /// USB vendor and product ID: the TP-Link Archer T3U by default.
    pub vid: u16,
    /// See `vid`.
    pub pid: u16,
    /// The channel to bring the radio up on: the primary channel.
    pub channel: u8,
    /// Bandwidth: `DVR_WIDTH_20` or `DVR_WIDTH_40`. Fast hops keep it.
    pub width: u8,
    /// For 40 MHz: 1 when the primary is the lower half (44 of 44+48), 2
    /// when it's the upper half. See [`DevourerConfig::forty`].
    pub offset: u8,
    /// devourer's hardware retry limit for unicast. 0 sends unicast once.
    pub retry_limit: i32,
    /// Channel hops: 0 software, 1 firmware within a band, 2 firmware across
    /// bands too. W0 measured 2 as fastest: ~3 ms within a band, ~9-10 across.
    pub fastretune_fw: i32,
    /// devourer's log level (`DVR_LOG_*`).
    pub log_level: u8,
}

impl Default for DevourerConfig {
    fn default() -> Self {
        Self {
            vid: 0x2357,
            pid: 0x012d,
            channel: 44,
            width: DVR_WIDTH_20,
            offset: 0,
            retry_limit: 3,
            fastretune_fw: 2,
            log_level: DVR_LOG_WARN,
        }
    }
}

impl DevourerConfig {
    /// 40 MHz on a 5 GHz primary channel, with the secondary on the side
    /// 802.11's channel pairs put it (36+40, 44+48, …, 149+153, 157+161).
    pub fn forty(mut self, primary: u8) -> Self {
        const LOWER: [u8; 12] = [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157];
        self.channel = primary;
        self.width = DVR_WIDTH_40;
        self.offset = if LOWER.contains(&primary) { 1 } else { 2 };
        self
    }
}

/// State the RX callback reads, owned by [`DevourerRadio`] and outliving the
/// RX thread.
struct RxContext {
    tx: SyncSender<RxFrame>,
    channel: Arc<AtomicU8>,
    /// (high bits, last low word) of the TSF, extended across 32-bit wraps.
    tsf: Mutex<(u64, Option<u32>)>,
    dropped: AtomicU64,
}

unsafe extern "C" fn on_frame(user: *mut c_void, f: *const dvr_rx_frame) {
    // SAFETY: `user` is the RxContext that DevourerRadio keeps alive until the
    // RX thread has been joined; devourer passes a valid frame for the call.
    let (ctx, f) = unsafe { (&*(user as *const RxContext), &*f) };
    if f.crc_err != 0 || f.data.is_null() {
        return;
    }
    // SAFETY: devourer guarantees `data` points at `len` bytes for this call.
    let data = unsafe { std::slice::from_raw_parts(f.data, f.len) };
    let tsf = {
        let mut t = ctx.tsf.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = t.1 {
            if f.tsfl < prev && prev - f.tsfl > 0x8000_0000 {
                t.0 += 1 << 32;
            }
        }
        t.1 = Some(f.tsfl);
        t.0 | f.tsfl as u64
    };
    let frame = RxFrame {
        host: Instant::now(),
        tsf,
        channel: ctx.channel.load(Ordering::Relaxed),
        rssi_dbm: (f.rssi[0] as i32 - 110) as i8,
        mpdu: data.to_vec(),
    };
    if let Err(TrySendError::Full(_)) = ctx.tx.try_send(frame) {
        ctx.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

struct RadioPtr(*mut dvr_radio);
// SAFETY: the RX thread only calls dvr_run_rx, which devourer runs on a
// thread of its own by design; DevourerRadio stops and joins it before close.
unsafe impl Send for RadioPtr {}

fn last_error() -> String {
    // SAFETY: dvr_last_error returns a valid NUL-terminated thread-local string.
    unsafe { CStr::from_ptr(dvr_last_error()) }.to_string_lossy().into_owned()
}

fn check(call: &'static str, code: i32) -> Result<(), Error> {
    if code == DVR_OK { Ok(()) } else { Err(Error::Devourer { call, code, message: last_error() }) }
}

/// The T3U, open and receiving. Drop closes it (on the thread that opened
/// it, which `!Send` guarantees).
pub struct DevourerRadio {
    radio: *mut dvr_radio,
    rx_thread: Option<JoinHandle<()>>,
    rx: Receiver<RxFrame>,
    ctx: *const RxContext,
    channel: Arc<AtomicU8>,
    rx_clock: RxClock,
    _not_send: PhantomData<*const ()>,
}

impl DevourerRadio {
    /// Opens the adapter, brings it up and starts receiving. Takes ~20 s:
    /// bring-up is ~22k register writes over USB (see
    /// `docs/windows-bringup.md`).
    pub fn open(config: &DevourerConfig) -> Result<Self, Error> {
        // devourer's waits are sleeps; 1 ms timer resolution shortens them.
        // SAFETY: plain Win32 call; matched by timeEndPeriod in Drop.
        unsafe { windows_sys::Win32::Media::timeBeginPeriod(1) };
        let cfg = dvr_config {
            retry_limit: config.retry_limit,
            fastretune_fw: config.fastretune_fw,
            thermal_track: 1,
            // The default RX mode, as validated in W0.
            rx_spsc: 0,
            usb_reset: 1,
            log_level: config.log_level,
        };
        let mut radio: *mut dvr_radio = std::ptr::null_mut();
        // SAFETY: valid config and out-pointer.
        if let Err(e) = check("dvr_open", unsafe { dvr_open(config.vid, config.pid, &cfg, &mut radio) }) {
            unsafe { windows_sys::Win32::Media::timeEndPeriod(1) };
            return Err(e);
        }
        // SAFETY: `radio` was just opened.
        if let Err(e) = check("dvr_init", unsafe { dvr_init(radio, config.channel, config.width, config.offset) }) {
            unsafe {
                dvr_close(radio);
                windows_sys::Win32::Media::timeEndPeriod(1);
            }
            return Err(e);
        }
        let channel = Arc::new(AtomicU8::new(config.channel));
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let ctx = Box::into_raw(Box::new(RxContext {
            tx,
            channel: channel.clone(),
            tsf: Mutex::new((0, None)),
            dropped: AtomicU64::new(0),
        }));
        let (ptr, user) = (RadioPtr(radio), ctx as usize);
        let rx_thread = thread::Builder::new()
            .name("devourer-rx".into())
            .spawn(move || {
                let r = ptr;
                // SAFETY: the radio and context outlive this thread (see Drop).
                let code = unsafe { dvr_run_rx(r.0, on_frame, user as *mut c_void) };
                if code != DVR_OK {
                    eprintln!("dvr_run_rx failed ({code}): {}", last_error());
                }
            })
            .expect("spawning the RX thread");
        Ok(Self {
            radio,
            rx_thread: Some(rx_thread),
            rx,
            ctx,
            channel,
            rx_clock: RxClock::new(Instant::now()),
            _not_send: PhantomData,
        })
    }

    /// Frames dropped because the consumer fell behind.
    pub fn dropped(&self) -> u64 {
        // SAFETY: ctx lives until Drop.
        unsafe { &*self.ctx }.dropped.load(Ordering::Relaxed)
    }
}

impl Radio for DevourerRadio {
    fn recv(&mut self, timeout: Duration) -> Result<Option<RxFrame>, Error> {
        match self.rx.recv_timeout(timeout) {
            Ok(f) => {
                self.rx_clock.observe(f.host, f.tsf);
                Ok(Some(f))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(Error::Ended),
        }
    }

    fn channel(&self) -> u8 {
        self.channel.load(Ordering::Relaxed)
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), Error> {
        // SAFETY: the radio is open; the shim serialises control calls.
        check("dvr_set_channel", unsafe { dvr_set_channel(self.radio, channel, DVR_WIDTH_20, 0) })?;
        self.channel.store(channel, Ordering::Relaxed);
        Ok(())
    }

    fn hop(&mut self, channel: u8) -> Result<(), Error> {
        if channel == self.channel() {
            return Ok(());
        }
        // SAFETY: as above. With fastretune_fw = 2 the firmware hops, across
        // bands too.
        check("dvr_fast_retune", unsafe { dvr_fast_retune(self.radio, channel) })?;
        self.channel.store(channel, Ordering::Relaxed);
        Ok(())
    }

    fn send(&mut self, mpdu: &[u8], rate_500kbps: u8) -> Result<(), Error> {
        let mut buf = Vec::with_capacity(9 + mpdu.len());
        buf.extend_from_slice(&crate::tx_radiotap(rate_500kbps));
        buf.extend_from_slice(mpdu);
        // SAFETY: the radio is open; `buf` is valid for its length.
        check("dvr_send", unsafe { dvr_send(self.radio, buf.as_ptr(), buf.len()) })
    }

    fn set_ack_responder(&mut self, addr: [u8; 6]) -> Result<(), Error> {
        // SAFETY: the radio is open; `addr` is 6 bytes. dvr_close clears it.
        check("dvr_set_ack_responder", unsafe { dvr_set_ack_responder(self.radio, addr.as_ptr()) })
    }

    fn tsf_now(&mut self) -> Option<u64> {
        // Not dvr_read_tsf: that counter isn't the one stamping RX frames.
        self.rx_clock.tsf_at(Instant::now())
    }
}

impl Drop for DevourerRadio {
    fn drop(&mut self) {
        // devourer's order: stop RX, join its thread, then close (which also
        // clears the ACK responder, stops, releases and closes USB).
        // SAFETY: the radio is open; the context is freed only after the RX
        // thread, its only other user, has finished.
        unsafe { dvr_stop_rx(self.radio) };
        if let Some(t) = self.rx_thread.take() {
            let _ = t.join();
        }
        unsafe {
            dvr_close(self.radio);
            drop(Box::from_raw(self.ctx as *mut RxContext));
            windows_sys::Win32::Media::timeEndPeriod(1);
        }
    }
}
