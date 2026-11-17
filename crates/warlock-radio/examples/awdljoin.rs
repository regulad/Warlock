// SPDX-License-Identifier: GPL-2.0-only
//! Joins the AWDL cluster around us as a follower: transmits PSFs and MIFs,
//! follows the sync source's channel sequence, answers Block Ack setup, ACKs
//! unicast in hardware, and reports everything peers address to us, which is
//! the evidence that they accept us.
//!
//!     cargo run --release -p warlock-radio --example awdljoin -- [start channel=149] [seconds=120] [width=20|40]
//!
//! Needs the T3U bound to WinUSB. Prints our address at start, so a witness
//! (a Mac's or the Apple TV's `tcpdump -i awdl0`) can look for it.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant, SystemTime};

use awdl_core::{Action, Config, Engine, Event, RxMeta, TxConfig, TxKind};
use awdl_proto::MacAddr;
use awdl_proto::ieee80211::Header;
use etherparse::{Icmpv6Type, NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use warlock_radio::{DevourerConfig, DevourerRadio, Radio};

const ETHERTYPE_IPV6: u16 = 0x86dd;

/// The modified EUI-64 link-local address of a MAC: how AWDL peers address
/// each other (the Mac and the Apple TV each listed ours this way).
fn link_local(mac: MacAddr) -> [u8; 16] {
    let m = mac.0;
    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]
}

/// The reply to an ICMPv6 echo request, if `packet` is one.
fn echo_reply(own: &[u8; 16], packet: &[u8]) -> Option<Vec<u8>> {
    let p = SlicedPacket::from_ip(packet).ok()?;
    let Some(NetSlice::Ipv6(ip)) = p.net else { return None };
    let Some(TransportSlice::Icmpv6(icmp)) = p.transport else { return None };
    let Icmpv6Type::EchoRequest(echo) = icmp.icmp_type() else { return None };
    let src = ip.header().source();
    let mut out = Vec::new();
    PacketBuilder::ipv6(*own, src, 64).icmpv6_echo_reply(echo.id, echo.seq).write(&mut out, icmp.payload()).ok()?;
    Some(out)
}

/// A random locally administered unicast address, as Apple devices use for
/// AWDL.
fn random_addr() -> MacAddr {
    let h = RandomState::new().hash_one(SystemTime::now());
    let b = h.to_le_bytes();
    MacAddr([(b[0] & 0xfc) | 0x02, b[1], b[2], b[3], b[4], b[5]])
}

fn frame_kind(mpdu: &[u8]) -> String {
    let fc = u16::from_le_bytes([mpdu[0], mpdu.get(1).copied().unwrap_or(0)]);
    let (t, s) = ((fc >> 2) & 3, (fc >> 4) & 0xf);
    match (t, s) {
        (0, 13) if mpdu.get(24) == Some(&3) => format!("block-ack action {}", mpdu.get(25).copied().unwrap_or(0)),
        (0, 13) => "action".into(),
        (1, 8) => "BlockAckReq".into(),
        (1, 9) => "BlockAck".into(),
        (1, 11) => "RTS".into(),
        (1, 12) => "CTS".into(),
        (1, 13) => "ACK".into(),
        (2, 0) => "data".into(),
        (2, 8) => "QoS data".into(),
        _ => format!("type {t} subtype {s}"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let channel: u8 = args.next().map(|a| a.parse().expect("channel")).unwrap_or(149);
    let seconds: u64 = args.next().map(|a| a.parse().expect("seconds")).unwrap_or(120);
    let width: u32 = args.next().map(|a| a.parse().expect("width 20 or 40")).unwrap_or(20);
    let own = random_addr();
    println!("our AWDL address: {own}; opening the T3U on channel {channel} at {width} MHz (~20 s)");
    let config = DevourerConfig { channel, ..Default::default() };
    let config = if width == 40 { config.forty(channel) } else { config };
    let mut radio = DevourerRadio::open(&config).expect("opening the radio");
    radio.set_ack_responder(own.0).expect("arming the ACK responder");
    let mut engine = Engine::new(Config::active(TxConfig::new(own)));

    let started = Instant::now();
    let mut last_report = Instant::now();
    let mut sent: BTreeMap<String, u64> = BTreeMap::new();
    let mut to_us: BTreeMap<(MacAddr, String), u64> = BTreeMap::new();
    let (mut hops, mut tx_errors, mut frames) = (0u64, 0u64, 0u64);
    let mut rx_lag: Vec<i64> = Vec::new();
    let mut packets: BTreeMap<MacAddr, u64> = BTreeMap::new();
    let mut echoes = 0u64;
    let own_ll = link_local(own);
    println!("our link-local address: {}", std::net::Ipv6Addr::from(own_ll));
    let mut t0 = None;
    while started.elapsed() < Duration::from_secs(seconds) {
        let now = radio.tsf_now();
        let wait = match (now, now.and_then(|n| engine.next_wakeup(n))) {
            (Some(n), Some(w)) => Duration::from_micros(w.saturating_sub(n)).min(Duration::from_millis(100)),
            _ => Duration::from_millis(100),
        };
        if let Some(f) = radio.recv(wait).expect("receiving") {
            frames += 1;
            // Our TSF estimate at hand-over minus the frame's RX TSF: the
            // receive latency, if the estimate is on the RX timebase.
            if let Some(n) = radio.tsf_now() {
                rx_lag.push(n as i64 - f.tsf as i64);
            }
            let t = (f.tsf - *t0.get_or_insert(f.tsf)) as f64 / 1e6;
            if f.mpdu.len() >= 10 && f.mpdu[4..10] == own.0 {
                let from = if f.mpdu.len() >= 16 { MacAddr(f.mpdu[10..16].try_into().unwrap()) } else { MacAddr::default() };
                let kind = frame_kind(&f.mpdu);
                let n = to_us.entry((from, kind.clone())).or_default();
                if *n == 0 {
                    println!("[{t:>8.3} s] first {kind} to us from {from} on ch {}", f.channel);
                }
                *n += 1;
            }
            for ev in engine.on_frame(RxMeta { tsf: f.tsf, channel: f.channel, rssi_dbm: f.rssi_dbm }, &f.mpdu) {
                match ev {
                    Event::Packet { from, to, ethertype, payload } => {
                        *packets.entry(from).or_default() += 1;
                        if ethertype == ETHERTYPE_IPV6 {
                            if let Some(reply) = echo_reply(&own_ll, &payload) {
                                if echoes == 0 {
                                    println!("[{t:>8.3} s] echo request from {from} (to {to}); replying");
                                }
                                echoes += 1;
                                engine.send_packet(f.tsf, from, ETHERTYPE_IPV6, reply);
                            }
                        }
                    }
                    other => println!("[{t:>8.3} s] {other:?}"),
                }
            }
        }
        let Some(now) = radio.tsf_now() else { continue };
        for a in engine.poll(now) {
            match a {
                Action::Hop(c) => match radio.hop(c) {
                    Ok(()) => hops += 1,
                    Err(e) => eprintln!("hop to {c}: {e}"),
                },
                Action::Transmit { mpdu, rate_500kbps, kind } => match radio.send(&mpdu, rate_500kbps) {
                    Ok(()) => {
                        *sent.entry(format!("{kind:?}")).or_default() += 1;
                        if kind == TxKind::AddbaResponse {
                            let to = Header::parse(&mpdu).map(|(h, _)| h.addr1).unwrap_or_default();
                            println!("answered Block Ack setup from {to}");
                        }
                    }
                    Err(e) => {
                        tx_errors += 1;
                        if tx_errors <= 5 {
                            eprintln!("send {kind:?}: {e}");
                        }
                    }
                },
            }
        }
        if last_report.elapsed() >= Duration::from_secs(10) {
            last_report = Instant::now();
            println!(
                "--- {:>4} s: rx {frames}, sent {sent:?}, hops {hops}, tx errors {tx_errors}; master {:?}, sync {:?} on ch {}",
                started.elapsed().as_secs(),
                engine.master(),
                engine.sync_source().map(|p| (p.addr, p.clock.is_locked())),
                radio.channel()
            );
            if !rx_lag.is_empty() {
                let mut v = std::mem::take(&mut rx_lag);
                v.sort();
                println!(
                    "      tsf_now − rx_tsf at hand-over: min {} p50 {} p95 {} max {} µs",
                    v[0],
                    v[v.len() / 2],
                    v[v.len() * 95 / 100],
                    v[v.len() - 1]
                );
            }
            for p in engine.peers() {
                println!(
                    "      peer {} ch {:<3} psf {:<5} mif {:<5} data {:<5} metric {:?}",
                    p.addr,
                    p.channel,
                    p.psfs,
                    p.mifs,
                    p.data_frames,
                    p.election.map(|e| e.self_metric)
                );
            }
            for ((from, kind), n) in &to_us {
                println!("      to us: {n:>5} × {kind} from {from}");
            }
            println!("      packets delivered per sender: {packets:?}; echo requests answered: {echoes}");
        }
    }
    println!("done: sent {sent:?}, hops {hops}, tx errors {tx_errors}, rx {frames} (dropped {})", radio.dropped());
    for ((from, kind), n) in &to_us {
        println!("  to us: {n:>5} × {kind} from {from}");
    }
    if to_us.is_empty() {
        println!("  nothing was addressed to us");
    }
}
