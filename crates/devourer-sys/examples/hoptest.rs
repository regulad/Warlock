// SPDX-License-Identifier: GPL-2.0-only
//! Channel-hop check: bring the T3U up, then hop through a channel list while
//! receiving, and report per dwell the frames received, how long the retune
//! call took, and the time from the retune returning to the first frame.
//!
//! Usage: hoptest [mode=full|fast] [fastretune_fw=0|1|2] [channels=44,6,44,6,161,6,44] [dwell_ms=3000]
//!   full: dvr_set_channel (SetMonitorChannel)
//!   fast: dvr_fast_retune (FastRetune; cross-band needs fastretune_fw=2 or
//!         falls back to the full path)

use std::ffi::{CStr, c_void};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use devourer_sys::*;

const T3U_VID: u16 = 0x2357;
const T3U_PID: u16 = 0x012d;

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period_ms: u32) -> u32;
}

#[derive(Default)]
struct Window {
    frames: u64,
    first: Option<Instant>,
}

unsafe extern "C" fn on_frame(user: *mut c_void, f: *const dvr_rx_frame) {
    let (w, f) = unsafe { (&*(user as *const Mutex<Window>), &*f) };
    if f.crc_err != 0 {
        return;
    }
    let mut w = w.lock().unwrap();
    w.frames += 1;
    if w.first.is_none() {
        w.first = Some(Instant::now());
    }
}

struct SendPtr(*mut dvr_radio);
unsafe impl Send for SendPtr {}

fn last_error() -> String {
    unsafe { CStr::from_ptr(dvr_last_error()) }.to_string_lossy().into_owned()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "full".into());
    let fw: i32 = args.next().map(|a| a.parse().expect("fastretune_fw")).unwrap_or(0);
    let channels: Vec<u8> = args
        .next()
        .unwrap_or_else(|| "44,6,44,6,161,6,44".into())
        .split(',')
        .map(|c| c.trim().parse().expect("channel"))
        .collect();
    let dwell = Duration::from_millis(args.next().map(|a| a.parse().expect("dwell_ms")).unwrap_or(3000));

    unsafe { timeBeginPeriod(1) };
    let cfg = dvr_config {
        retry_limit: 0,
        fastretune_fw: fw,
        thermal_track: 1,
        rx_spsc: 0,
        usb_reset: 1,
        log_level: DVR_LOG_WARN,
        hop_prof: 0,
    };
    let mut radio: *mut dvr_radio = std::ptr::null_mut();
    if unsafe { dvr_open(T3U_VID, T3U_PID, &cfg, &mut radio) } != DVR_OK {
        eprintln!("dvr_open: {}", last_error());
        std::process::exit(1);
    }
    if unsafe { dvr_init(radio, channels[0], DVR_WIDTH_20, 0) } != DVR_OK {
        eprintln!("dvr_init: {}", last_error());
        unsafe { dvr_close(radio) };
        std::process::exit(1);
    }

    let window: &'static Mutex<Window> = Box::leak(Box::new(Mutex::new(Window::default())));
    let user = window as *const Mutex<Window> as usize;
    let rx_radio = SendPtr(radio);
    let rx = thread::spawn(move || {
        let r = rx_radio;
        if unsafe { dvr_run_rx(r.0, on_frame, user as *mut c_void) } != DVR_OK {
            eprintln!("dvr_run_rx: {}", last_error());
        }
    });

    println!("mode={mode} fastretune_fw={fw} dwell={}ms", dwell.as_millis());
    println!("{:>4} {:>4}  {:>10}  {:>14}  {:>8}", "from", "to", "call", "first frame", "frames");
    thread::sleep(dwell);
    {
        let w = window.lock().unwrap();
        println!("{:>4} {:>4}  {:>10}  {:>14}  {:>8}", "-", channels[0], "(bring-up)", "-", w.frames);
    }
    for pair in channels.windows(2) {
        let (from, to) = (pair[0], pair[1]);
        *window.lock().unwrap() = Window::default();
        let t0 = Instant::now();
        let rc = unsafe {
            if mode == "fast" { dvr_fast_retune(radio, to) } else { dvr_set_channel(radio, to, DVR_WIDTH_20, 0) }
        };
        let t1 = Instant::now();
        if rc != DVR_OK {
            eprintln!("retune {from}->{to} failed: {}", last_error());
        }
        // Frames that arrived during the call were queued before the hop.
        *window.lock().unwrap() = Window::default();
        thread::sleep(dwell);
        let w = window.lock().unwrap();
        let first = w.first.map(|f| format!("{:.1} ms", (f - t1).as_secs_f64() * 1e3)).unwrap_or_else(|| "none".into());
        println!("{from:>4} {to:>4}  {:>7.2} ms  {first:>14}  {:>8}", (t1 - t0).as_secs_f64() * 1e3, w.frames);
    }

    unsafe { dvr_stop_rx(radio) };
    rx.join().expect("rx thread panicked");
    unsafe { dvr_close(radio) };
}
