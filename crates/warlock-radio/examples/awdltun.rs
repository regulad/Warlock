// SPDX-License-Identifier: GPL-2.0-only
//! Windows on AWDL: takes part in AWDL as `awdljoin` does, and bridges IPv6
//! between it and a Wintun adapter, so Windows' own tools reach AWDL peers.
//!
//!     cargo run --release -p warlock-radio --example awdltun -- [channel=149] [seconds=120] [width=40] [metric=60]
//!
//! Run it as Administrator: it creates the adapter, and the first run
//! downloads Wintun into `%ProgramData%\Warlock` (see `warlock_tun::dll`).
//! It prints our link-local address and the adapter's index; then, e.g.,
//! `ping -6 fe80::<a peer's EUI-64>%<index>`.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant, SystemTime};

use awdl_core::{Action, Config, Engine, Event, TxConfig, TxKind};
use awdl_proto::MacAddr;
use warlock_radio::{DevourerConfig, DevourerRadio, Radio};
use warlock_tun::{Tun, addr, dll};

const ETHERTYPE_IPV6: u16 = 0x86dd;
/// The adapter's fixed identity (the last group spells "WARLOC").
const ADAPTER_GUID: u128 = 0xe1d4a5c3_0b6f_4f26_9b52_5741524c4f43;
const ADAPTER_NAME: &str = "Warlock AWDL";
/// AWDL data frames carry 1500-byte payloads; PLAN.md leaves headroom.
const MTU: u32 = 1450;

fn random_addr() -> MacAddr {
    let b = RandomState::new().hash_one(SystemTime::now()).to_le_bytes();
    MacAddr([(b[0] & 0xfc) | 0x02, b[1], b[2], b[3], b[4], b[5]])
}

fn main() {
    let mut args = std::env::args().skip(1);
    let channel: u8 = args.next().map(|a| a.parse().expect("channel")).unwrap_or(149);
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(120);
    let width: u32 = args.next().map(|a| a.parse().expect("width 20 or 40")).unwrap_or(40);
    let metric: u32 = args.next().map(|a| a.parse().expect("metric")).unwrap_or(60);

    let dll_path = dll::ensure(&dll::default_root()).expect("getting Wintun (run as Administrator)");
    let wintun = dll::load(&dll_path).expect("loading Wintun");
    let own = random_addr();
    println!("our AWDL address: {own}; opening the T3U on channel {channel} at {width} MHz (~20 s)");
    let config = DevourerConfig { channel, ..Default::default() };
    let config = if width == 40 { config.forty(channel) } else { config };
    let mut radio = DevourerRadio::open(&config).expect("opening the radio");
    radio.set_ack_responder(own.0).expect("arming the ACK responder");
    let tun = Tun::open(&wintun, ADAPTER_NAME, ADAPTER_GUID, own.0, MTU).expect("opening the adapter");
    println!(
        "adapter \"{ADAPTER_NAME}\" #{}: {} (MTU {}); try `ping -6 fe80::<peer EUI-64>%{}`",
        tun.index, tun.address, tun.mtu, tun.index
    );

    let mut tx = TxConfig::new(own);
    tx.self_metric = metric;
    tx.ht_40mhz = width == 40;
    let mut engine = Engine::new(Config {
        band_change_settle_us: radio.band_change_settle().as_micros() as u64,
        ..Config::active(tx)
    });

    let started = Instant::now();
    let (mut last_report, mut last_enforce) = (Instant::now(), Instant::now());
    let mut to_air: BTreeMap<String, u64> = BTreeMap::new();
    let mut to_host: BTreeMap<MacAddr, u64> = BTreeMap::new();
    let (mut chatter, mut unroutable) = (0u64, 0u64);
    let mut buf = vec![0u8; 65536];
    while started.elapsed() < Duration::from_secs(seconds) {
        let now = radio.tsf_now();
        // Short waits: packets from Windows are polled, not signalled, here.
        let wait = match (now, now.and_then(|n| engine.next_wakeup(n))) {
            (Some(n), Some(w)) => Duration::from_micros(w.saturating_sub(n)).min(Duration::from_millis(2)),
            _ => Duration::from_millis(2),
        };
        if let Some(f) = radio.recv(wait).expect("receiving") {
            let meta = awdl_core::RxMeta { tsf: f.tsf, channel: f.channel, rssi_dbm: f.rssi_dbm };
            for ev in engine.on_frame(meta, &f.mpdu) {
                match ev {
                    Event::Packet { from, ethertype: ETHERTYPE_IPV6, payload, .. } => {
                        *to_host.entry(from).or_default() += 1;
                        if let Err(e) = tun.send(&payload) {
                            eprintln!("to Windows: {e}");
                        }
                    }
                    Event::Packet { .. } => {}
                    other => println!("[{:>8.3} s] {other:?}", started.elapsed().as_secs_f64()),
                }
            }
        }
        let Some(now) = radio.tsf_now() else { continue };
        // Windows → AWDL.
        while let Some(n) = tun.try_recv(&mut buf) {
            let packet = &buf[..n];
            let Some(dst) = addr::ipv6_dst(packet) else { continue };
            if addr::is_chatter(packet) {
                chatter += 1;
                continue;
            }
            let Some(mac) = addr::mac_for(&dst) else {
                unroutable += 1;
                continue;
            };
            *to_air.entry(dst.to_string()).or_default() += 1;
            engine.send_packet(now, MacAddr(mac), ETHERTYPE_IPV6, packet.to_vec());
        }
        for a in engine.poll(now) {
            match a {
                Action::Hop(c) => {
                    if let Err(e) = radio.hop(c) {
                        eprintln!("hop to {c}: {e}");
                    }
                }
                Action::Transmit { mpdu, rate_500kbps, kind } => {
                    if let Err(e) = radio.send(&mpdu, rate_500kbps) {
                        eprintln!("send ({kind:?}): {e}");
                    }
                    if kind == TxKind::AddbaResponse {
                        println!("[{:>8.3} s] answered Block Ack setup", started.elapsed().as_secs_f64());
                    }
                }
            }
        }
        if last_enforce.elapsed() >= Duration::from_secs(2) {
            last_enforce = Instant::now();
            if let Err(e) = tun.enforce_address() {
                eprintln!("adapter address: {e}");
            }
        }
        if last_report.elapsed() >= Duration::from_secs(10) {
            last_report = Instant::now();
            println!(
                "--- {:>4} s: master {:?}; to the air {to_air:?}; to Windows {to_host:?}; dropped chatter {chatter}, \
                 unroutable {unroutable}",
                started.elapsed().as_secs(),
                engine.master()
            );
            for p in engine.peers() {
                println!(
                    "      peer {} at {} ch {:<3} metric {:?} follows {:?}",
                    p.addr,
                    addr::link_local(p.addr.0),
                    p.channel,
                    p.election.map(|e| e.self_metric),
                    p.election.map(|e| e.master)
                );
            }
        }
    }
    println!("done");
}
