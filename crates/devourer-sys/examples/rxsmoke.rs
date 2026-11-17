// SPDX-License-Identifier: GPL-2.0-or-later
//! W0 bring-up smoke test: open the TP-Link Archer T3U through devourer, tune
//! to one channel and report what arrives for a few seconds, picking out AWDL
//! frames (vendor action frames with Apple's OUI 00:17:f2 and data frames on
//! the AWDL BSSID 00:25:00:ff:94:73).
//!
//! Usage: rxsmoke [channel=149] [seconds=10]

use std::collections::BTreeMap;
use std::ffi::{CStr, c_void};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use devourer_sys::*;

const T3U_VID: u16 = 0x2357;
const T3U_PID: u16 = 0x012d;
const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];
const APPLE_OUI: [u8; 3] = [0x00, 0x17, 0xf2];
const AWDL_ACTION_TYPE: u8 = 8;

#[derive(Default)]
struct Peer {
    psf: u64,
    mif: u64,
    other_af: u64,
    data: u64,
    last_rssi_dbm: i32,
}

#[derive(Default)]
struct Stats {
    frames: u64,
    crc_err: u64,
    awdl_action: u64,
    awdl_data: u64,
    window_frames: u64,
    window_awdl: u64,
    first_tsf: Option<u32>,
    last_tsf: u32,
    max_tsf_gap: u32,
    peers: BTreeMap<[u8; 6], Peer>,
}

fn mac(b: &[u8]) -> [u8; 6] {
    b[..6].try_into().unwrap()
}

fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn last_error() -> String {
    unsafe { CStr::from_ptr(dvr_last_error()) }
        .to_string_lossy()
        .into_owned()
}

unsafe extern "C" fn on_frame(user: *mut c_void, f: *const dvr_rx_frame) {
    let (stats, f) = unsafe { (&*(user as *const Mutex<Stats>), &*f) };
    let d = unsafe { std::slice::from_raw_parts(f.data, f.len) };
    let mut s = stats.lock().unwrap();
    s.frames += 1;
    s.window_frames += 1;
    if f.crc_err != 0 {
        s.crc_err += 1;
        return;
    }
    if let Some(prev) = s.first_tsf.map(|_| s.last_tsf) {
        s.max_tsf_gap = s.max_tsf_gap.max(f.tsfl.wrapping_sub(prev));
    } else {
        s.first_tsf = Some(f.tsfl);
    }
    s.last_tsf = f.tsfl;

    if d.len() < 24 || d[16..22] != AWDL_BSSID {
        return;
    }
    let src = mac(&d[10..16]);
    let rssi = f.rssi[0] as i32 - 110;
    let fc0 = d[0];
    let is_vendor_action = fc0 == 0xd0
        && d.len() >= 31
        && d[24] == 127
        && d[25..28] == APPLE_OUI
        && d[28] == AWDL_ACTION_TYPE;
    let is_data = fc0 & 0x0c == 0x08;
    if !is_vendor_action && !is_data {
        return;
    }
    s.window_awdl += 1;
    if is_vendor_action {
        s.awdl_action += 1;
    } else {
        s.awdl_data += 1;
    }
    let p = s.peers.entry(src).or_default();
    p.last_rssi_dbm = rssi;
    if is_vendor_action {
        match d[30] {
            0 => p.psf += 1,
            3 => p.mif += 1,
            _ => p.other_af += 1,
        }
    } else {
        p.data += 1;
    }
}

struct SendPtr(*mut dvr_radio);
unsafe impl Send for SendPtr {}

fn main() {
    let mut args = std::env::args().skip(1);
    let channel: u8 = args.next().map(|a| a.parse().expect("channel")).unwrap_or(149);
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(10);

    let cfg = dvr_config {
        retry_limit: 0,
        fastretune_fw: 0,
        thermal_track: 1,
        rx_spsc: 0,
        usb_reset: 1,
        log_level: DVR_LOG_WARN,
    };
    let mut radio: *mut dvr_radio = std::ptr::null_mut();
    let t0 = Instant::now();
    let rc = unsafe { dvr_open(T3U_VID, T3U_PID, &cfg, &mut radio) };
    if rc != DVR_OK {
        eprintln!("dvr_open failed ({rc}): {}", last_error());
        std::process::exit(1);
    }
    let rc = unsafe { dvr_init(radio, channel, DVR_WIDTH_20, 0) };
    if rc != DVR_OK {
        eprintln!("dvr_init(ch {channel}) failed ({rc}): {}", last_error());
        unsafe { dvr_close(radio) };
        std::process::exit(1);
    }
    println!("adapter up on channel {channel} in {:?}", t0.elapsed());

    let mut tsf = 0u64;
    if unsafe { dvr_read_tsf(radio, &mut tsf) } == DVR_OK {
        println!("MAC TSF after bring-up: {tsf} us");
    }

    let stats: &'static Mutex<Stats> = Box::leak(Box::new(Mutex::new(Stats::default())));
    let user = stats as *const Mutex<Stats> as usize;
    let rx_radio = SendPtr(radio);
    let rx = thread::spawn(move || {
        let r = rx_radio;
        let rc = unsafe { dvr_run_rx(r.0, on_frame, user as *mut c_void) };
        if rc != DVR_OK {
            eprintln!("dvr_run_rx failed ({rc}): {}", last_error());
        }
    });

    for sec in 1..=seconds {
        thread::sleep(Duration::from_secs(1));
        let mut s = stats.lock().unwrap();
        println!(
            "t={sec:>3}s  frames/s={:>5}  awdl/s={:>4}  awdl peers={}",
            s.window_frames,
            s.window_awdl,
            s.peers.len()
        );
        s.window_frames = 0;
        s.window_awdl = 0;
    }

    unsafe { dvr_stop_rx(radio) };
    rx.join().expect("rx thread panicked");
    unsafe { dvr_close(radio) };

    let s = stats.lock().unwrap();
    println!(
        "\ntotal frames={} crc_err={} awdl_action={} awdl_data={} max_tsf_gap={}us",
        s.frames, s.crc_err, s.awdl_action, s.awdl_data, s.max_tsf_gap
    );
    for (m, p) in &s.peers {
        println!(
            "  awdl peer {}  psf={} mif={} other_af={} data={} rssi={}dBm",
            fmt_mac(m),
            p.psf,
            p.mif,
            p.other_af,
            p.data,
            p.last_rssi_dbm
        );
    }
}
