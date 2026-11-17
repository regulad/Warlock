// SPDX-License-Identifier: GPL-2.0-only
//! Capture everything the T3U receives on one channel to a pcapng file, as
//! radiotap + 802.11 (linktype 127), for Wireshark's AWDL dissector.
//!
//! Usage: awdlcap <out.pcapng> [channels=44] [seconds=60] [dwell_s=5]
//!
//! `channels` is a comma-separated list; with more than one, the radio
//! cycles through them, `dwell_s` seconds each. Creating `<out.pcapng>.stop`
//! ends the capture early and still flushes the file.

use std::ffi::{CStr, c_void};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use devourer_sys::*;

const T3U_VID: u16 = 0x2357;
const T3U_PID: u16 = 0x012d;
const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];
const LINKTYPE_IEEE802_11_RADIOTAP: u16 = 127;

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period_ms: u32) -> u32;
}

/// Minimal pcapng writer: one section, one interface, enhanced packet blocks.
struct Pcapng<W: Write> {
    out: W,
}

impl<W: Write> Pcapng<W> {
    fn new(mut out: W, linktype: u16) -> std::io::Result<Self> {
        // Section Header Block.
        out.write_all(&0x0A0D_0D0Au32.to_le_bytes())?;
        out.write_all(&28u32.to_le_bytes())?;
        out.write_all(&0x1A2B_3C4Du32.to_le_bytes())?;
        out.write_all(&1u16.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&(-1i64).to_le_bytes())?;
        out.write_all(&28u32.to_le_bytes())?;
        // Interface Description Block, default microsecond timestamps.
        out.write_all(&1u32.to_le_bytes())?;
        out.write_all(&20u32.to_le_bytes())?;
        out.write_all(&linktype.to_le_bytes())?;
        out.write_all(&0u16.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;
        out.write_all(&20u32.to_le_bytes())?;
        Ok(Self { out })
    }

    fn packet(&mut self, ts_us: u64, data: &[u8]) -> std::io::Result<()> {
        let pad = (4 - data.len() % 4) % 4;
        let len = (32 + data.len() + pad) as u32;
        self.out.write_all(&6u32.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(&0u32.to_le_bytes())?;
        self.out.write_all(&((ts_us >> 32) as u32).to_le_bytes())?;
        self.out.write_all(&(ts_us as u32).to_le_bytes())?;
        self.out.write_all(&(data.len() as u32).to_le_bytes())?;
        self.out.write_all(&(data.len() as u32).to_le_bytes())?;
        self.out.write_all(data)?;
        self.out.write_all(&[0u8; 3][..pad])?;
        self.out.write_all(&len.to_le_bytes())
    }
}

/// Radiotap header carrying TSFT, flags (no FCS), channel and signal.
fn radiotap(tsf: u64, freq_mhz: u16, rssi_dbm: i8) -> [u8; 23] {
    let present: u32 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5);
    let chan_flags: u16 = 0x0040 | if freq_mhz < 3000 { 0x0080 } else { 0x0100 };
    let mut h = [0u8; 23];
    h[2..4].copy_from_slice(&23u16.to_le_bytes());
    h[4..8].copy_from_slice(&present.to_le_bytes());
    h[8..16].copy_from_slice(&tsf.to_le_bytes());
    h[16] = 0; // flags: FCS not included
    h[18..20].copy_from_slice(&freq_mhz.to_le_bytes());
    h[20..22].copy_from_slice(&chan_flags.to_le_bytes());
    h[22] = rssi_dbm as u8;
    h
}

fn channel_freq(ch: u8) -> u16 {
    match ch {
        14 => 2484,
        1..=13 => 2407 + 5 * ch as u16,
        _ => 5000 + 5 * ch as u16,
    }
}

struct Capture {
    pcap: Pcapng<BufWriter<File>>,
    freq: u16,
    tsf_hi: u64,
    last_tsfl: Option<u32>,
    frames: u64,
    awdl: u64,
    buf: Vec<u8>,
}

unsafe extern "C" fn on_frame(user: *mut c_void, f: *const dvr_rx_frame) {
    let (cap, f) = unsafe { (&*(user as *const Mutex<Capture>), &*f) };
    if f.crc_err != 0 {
        return;
    }
    let d = unsafe { std::slice::from_raw_parts(f.data, f.len) };
    let mut c = cap.lock().unwrap();
    // Extend the 32-bit hardware TSF to 64 bits across wraps.
    if let Some(prev) = c.last_tsfl {
        if f.tsfl < prev && prev - f.tsfl > 0x8000_0000 {
            c.tsf_hi += 1 << 32;
        }
    }
    c.last_tsfl = Some(f.tsfl);
    let tsf = c.tsf_hi | f.tsfl as u64;
    let rt = radiotap(tsf, c.freq, (f.rssi[0] as i32 - 110) as i8);
    let mut buf = std::mem::take(&mut c.buf);
    buf.clear();
    buf.extend_from_slice(&rt);
    buf.extend_from_slice(d);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
    let _ = c.pcap.packet(now, &buf);
    c.buf = buf;
    c.frames += 1;
    if d.len() >= 22 && d[16..22] == AWDL_BSSID {
        c.awdl += 1;
    }
}

struct SendPtr(*mut dvr_radio);
unsafe impl Send for SendPtr {}

fn last_error() -> String {
    unsafe { CStr::from_ptr(dvr_last_error()) }.to_string_lossy().into_owned()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: awdlcap <out.pcapng> [channel] [seconds]");
    let channels: Vec<u8> = args
        .next()
        .unwrap_or_else(|| "44".into())
        .split(',')
        .map(|c| c.trim().parse().expect("channel"))
        .collect();
    let channel = channels[0];
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(60);
    let dwell: u64 = args.next().map(|a| a.parse().expect("dwell seconds")).unwrap_or(5).max(1);

    unsafe { timeBeginPeriod(1) };
    let cfg = dvr_config {
        retry_limit: 0,
        fastretune_fw: 0,
        thermal_track: 1,
        rx_spsc: 0,
        usb_reset: 1,
        log_level: DVR_LOG_WARN,
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

    let file = BufWriter::new(File::create(&path).expect("create capture file"));
    let cap: &'static Mutex<Capture> = Box::leak(Box::new(Mutex::new(Capture {
        pcap: Pcapng::new(file, LINKTYPE_IEEE802_11_RADIOTAP).expect("write pcapng header"),
        freq: channel_freq(channel),
        tsf_hi: 0,
        last_tsfl: None,
        frames: 0,
        awdl: 0,
        buf: Vec::with_capacity(4096),
    })));
    println!("capturing channels {channels:?} to {path} for {seconds}s");

    let user = cap as *const Mutex<Capture> as usize;
    let rx_radio = SendPtr(radio);
    let rx = thread::spawn(move || {
        let r = rx_radio;
        if unsafe { dvr_run_rx(r.0, on_frame, user as *mut c_void) } != DVR_OK {
            eprintln!("dvr_run_rx: {}", last_error());
        }
    });
    // Creating "<out.pcapng>.stop" ends the capture early but cleanly.
    let stop_file = std::path::PathBuf::from(format!("{path}.stop"));
    let _ = std::fs::remove_file(&stop_file);
    let mut idx = 0;
    for sec in 1..=seconds {
        thread::sleep(Duration::from_secs(1));
        if stop_file.exists() {
            println!("stop file found at t={sec}s");
            break;
        }
        if sec % 5 == 0 {
            let c = cap.lock().unwrap();
            println!("t={sec:>3}s ch={} frames={} awdl={}", channels[idx], c.frames, c.awdl);
        }
        if channels.len() > 1 && sec % dwell == 0 && sec < seconds {
            idx = (idx + 1) % channels.len();
            let ch = channels[idx];
            cap.lock().unwrap().freq = channel_freq(ch);
            if unsafe { dvr_set_channel(radio, ch, DVR_WIDTH_20, 0) } != DVR_OK {
                eprintln!("dvr_set_channel({ch}): {}", last_error());
            }
        }
    }
    unsafe { dvr_stop_rx(radio) };
    rx.join().expect("rx thread panicked");
    unsafe { dvr_close(radio) };
    let mut c = cap.lock().unwrap();
    c.pcap.out.flush().expect("flush capture");
    println!("done: frames={} awdl={}", c.frames, c.awdl);
}
