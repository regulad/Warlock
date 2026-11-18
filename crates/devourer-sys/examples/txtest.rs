// SPDX-License-Identifier: GPL-2.0-only
//! Transmit-while-receiving check for the T3U.
//!
//! 1. Proof of air: sends broadcast probe requests from a random locally
//!    administered MAC and counts probe responses that nearby access points
//!    address back to that MAC.
//! 2. Sustained rate: injects a short burst of small broadcast data frames
//!    with the RX loop running and reports the send rate.
//!
//! Usage: txtest [channel=44] [burst=300] [rate_500kbps=12]

use std::ffi::{CStr, c_void};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use devourer_sys::*;

const T3U_VID: u16 = 0x2357;
const T3U_PID: u16 = 0x012d;

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period_ms: u32) -> u32;
}

struct Rx {
    me: [u8; 6],
    frames: u64,
    probe_resp_to_me: u64,
    responders: std::collections::BTreeSet<[u8; 6]>,
}

unsafe extern "C" fn on_frame(user: *mut c_void, f: *const dvr_rx_frame) {
    let (rx, f) = unsafe { (&*(user as *const Mutex<Rx>), &*f) };
    if f.crc_err != 0 {
        return;
    }
    let d = unsafe { std::slice::from_raw_parts(f.data, f.len) };
    let mut rx = rx.lock().unwrap();
    rx.frames += 1;
    // Probe response (mgmt subtype 5) addressed to our MAC.
    if d.len() >= 24 && d[0] == 0x50 && d[4..10] == rx.me {
        rx.probe_resp_to_me += 1;
        let ta: [u8; 6] = d[10..16].try_into().unwrap();
        rx.responders.insert(ta);
    }
}

fn radiotap(rate_500kbps: u8) -> [u8; 9] {
    // Version 0, length 9, present = RATE (bit 2), rate.
    [0, 0, 9, 0, 0x04, 0, 0, 0, rate_500kbps]
}

fn probe_request(rate: u8, me: &[u8; 6]) -> Vec<u8> {
    let mut f = radiotap(rate).to_vec();
    f.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // probe request, duration 0
    f.extend_from_slice(&[0xff; 6]); // addr1: broadcast
    f.extend_from_slice(me); // addr2: us
    f.extend_from_slice(&[0xff; 6]); // addr3: wildcard BSSID
    f.extend_from_slice(&[0x00, 0x00]); // sequence (hardware fills it)
    f.extend_from_slice(&[0x00, 0x00]); // SSID IE: wildcard
    // Supported rates: OFDM 6/9/12/18/24/36/48/54, basic 6/12/24.
    f.extend_from_slice(&[0x01, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]);
    f
}

fn data_frame(rate: u8, me: &[u8; 6], bssid: &[u8; 6], seq: u32) -> Vec<u8> {
    let mut f = radiotap(rate).to_vec();
    f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // data, no DS bits
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(me);
    f.extend_from_slice(bssid);
    f.extend_from_slice(&[0x00, 0x00]);
    // LLC/SNAP with a local-experimental EtherType, then a small payload.
    f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0xb5]);
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&[0x5a; 60]);
    f
}

struct SendPtr(*mut dvr_radio);
unsafe impl Send for SendPtr {}

fn last_error() -> String {
    unsafe { CStr::from_ptr(dvr_last_error()) }.to_string_lossy().into_owned()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let channel: u8 = args.next().map(|a| a.parse().expect("channel")).unwrap_or(44);
    let burst: u32 = args.next().map(|a| a.parse().expect("burst")).unwrap_or(300);
    let rate: u8 = args.next().map(|a| a.parse().expect("rate")).unwrap_or(12);

    // Random locally administered unicast MAC.
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut me = [0u8; 6];
    for (i, b) in me.iter_mut().enumerate() {
        *b = (seed >> (i * 8 + 3)) as u8 ^ (seed >> 40) as u8;
    }
    me[0] = (me[0] & 0xfc) | 0x02;
    let mut bssid = me;
    bssid[5] ^= 0x55;

    unsafe { timeBeginPeriod(1) };
    let cfg = dvr_config {
        retry_limit: 0,
        fastretune_fw: 2,
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
    if unsafe { dvr_init(radio, channel, DVR_WIDTH_20, 0) } != DVR_OK {
        eprintln!("dvr_init: {}", last_error());
        unsafe { dvr_close(radio) };
        std::process::exit(1);
    }

    let rx: &'static Mutex<Rx> =
        Box::leak(Box::new(Mutex::new(Rx { me, frames: 0, probe_resp_to_me: 0, responders: Default::default() })));
    let user = rx as *const Mutex<Rx> as usize;
    let rx_radio = SendPtr(radio);
    let rx_thread = thread::spawn(move || {
        let r = rx_radio;
        if unsafe { dvr_run_rx(r.0, on_frame, user as *mut c_void) } != DVR_OK {
            eprintln!("dvr_run_rx: {}", last_error());
        }
    });
    thread::sleep(Duration::from_millis(500));
    let mac = me.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    println!("channel {channel}, TX rate {} Mb/s, our MAC {mac} (random)", rate as f32 / 2.0);

    // 1. Proof of air.
    let probe = probe_request(rate, &me);
    let mut sent = 0;
    for _ in 0..5 {
        if unsafe { dvr_send(radio, probe.as_ptr(), probe.len()) } == DVR_OK {
            sent += 1;
        } else {
            eprintln!("probe send failed: {}", last_error());
        }
        thread::sleep(Duration::from_millis(150));
    }
    thread::sleep(Duration::from_millis(500));
    {
        let r = rx.lock().unwrap();
        println!(
            "probe requests sent: {sent}/5 -> probe responses addressed to us: {} from {} AP(s)",
            r.probe_resp_to_me,
            r.responders.len()
        );
    }

    // 2. Sustained send rate with RX running.
    let rx_before = rx.lock().unwrap().frames;
    let t0 = Instant::now();
    let mut ok = 0u32;
    let mut worst = Duration::ZERO;
    for seq in 0..burst {
        let f = data_frame(rate, &me, &bssid, seq);
        let s = Instant::now();
        if unsafe { dvr_send(radio, f.as_ptr(), f.len()) } == DVR_OK {
            ok += 1;
        }
        worst = worst.max(s.elapsed());
    }
    let el = t0.elapsed();
    let rx_during = rx.lock().unwrap().frames - rx_before;
    println!(
        "burst: {ok}/{burst} frames accepted in {:.1} ms = {:.0} frames/s (worst single send {:.2} ms); RX kept running: {rx_during} frames received meanwhile",
        el.as_secs_f64() * 1e3,
        ok as f64 / el.as_secs_f64(),
        worst.as_secs_f64() * 1e3
    );

    unsafe { dvr_stop_rx(radio) };
    rx_thread.join().expect("rx thread panicked");
    unsafe { dvr_close(radio) };
}
