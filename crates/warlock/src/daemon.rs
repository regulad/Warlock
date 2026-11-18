// SPDX-License-Identifier: GPL-2.0-only
//! The daemon: the radio, the AWDL engine and the network adapter, run on
//! one thread until told to stop.
//!
//! One thread, because the radio is opened and closed on the thread that
//! owns it (`DevourerRadio` is `!Send`). It waits on the radio in short
//! slices and polls the adapter between them: packets from Windows wait at
//! most ~2 ms, against AWDL's own waits of tens to hundreds of ms for a
//! peer's slot. An event-driven engine thread is PLAN.md's later step.

use std::error::Error;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use awdl_core::{Action, Config, Engine, Event, Peer, RxMeta, TxConfig, TxKind};
use awdl_proto::MacAddr;
use awdl_proto::tlv::Rdata;
use tracing::{info, warn};
use warlock_radio::{DevourerConfig, DevourerRadio, Radio};
use warlock_tun::{Tun, addr, dll};

use crate::advertise::Advertiser;
use crate::discovery::Discovery;

const ETHERTYPE_IPV6: u16 = 0x86dd;
/// The adapter's fixed identity (the last group spells "WARLOC").
const ADAPTER_GUID: u128 = 0xe1d4a5c3_0b6f_4f26_9b52_5741524c4f43;
const ADAPTER_NAME: &str = "Warlock AWDL";
/// PLAN.md's choice, leaving headroom under AWDL's 1500-byte payloads.
const MTU: u32 = 1450;
/// How long the loop waits on the radio at most: the adapter's latency.
const SLICE: Duration = Duration::from_millis(2);

/// What a run is told.
#[derive(Clone, Debug)]
pub struct Options {
    /// The channel to bring the radio up on.
    pub channel: u8,
    /// 20 or 40 MHz.
    pub width: u32,
    /// Our election metric. Apple devices use ~65 idle and ~510–540 active;
    /// at 60 we follow any of them and lead only when alone.
    pub metric: u32,
    /// Stop after this long (`--seconds`): for a foreground run nothing can
    /// send Ctrl+C to, such as an elevated one started from a script.
    pub seconds: Option<u64>,
    /// Log every packet crossing the adapter (`--log-packets`), either way.
    pub log_packets: bool,
    /// Service types whose Windows registrations on the adapter we advertise
    /// on AWDL (`--advertise _x._tcp`, repeatable); the control API's job
    /// later (`docs/service-discovery.md`).
    pub advertise: Vec<String>,
    /// Don't carry Windows' own mDNS to AWDL (`--no-mdns-to-air`), so peers
    /// learn about our services only from our frames. For testing that path
    /// (`docs/service-discovery.md`): Windows still answers its own queries,
    /// which it loops back to itself, so `--advertise` keeps working.
    pub no_mdns_to_air: bool,
}

/// Whether an IPv6 packet is mDNS: UDP to or from port 5353, with no
/// extension headers (Windows sends none on mDNS).
fn is_mdns(packet: &[u8]) -> bool {
    packet.len() >= 48
        && packet[0] >> 4 == 6
        && packet[6] == 17
        && (packet[40..42] == 5353u16.to_be_bytes() || packet[42..44] == 5353u16.to_be_bytes())
}

/// One line about an IPv6 packet: addresses, protocol, UDP ports, length.
fn describe(packet: &[u8]) -> String {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return format!("non-IPv6, {} bytes", packet.len());
    }
    let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let what = match packet[6] {
        17 if packet.len() >= 48 => format!(
            "UDP {}→{}",
            u16::from_be_bytes([packet[40], packet[41]]),
            u16::from_be_bytes([packet[42], packet[43]])
        ),
        58 if packet.len() > 40 => format!("ICMPv6 type {}", packet[40]),
        6 if packet.len() >= 54 => format!(
            "TCP {}→{} flags {:#04x}",
            u16::from_be_bytes([packet[40], packet[41]]),
            u16::from_be_bytes([packet[42], packet[43]]),
            packet[53]
        ),
        n => format!("next header {n}"),
    };
    format!("{src} → {dst} {what}, {} bytes", packet.len())
}

impl Options {
    /// Parses `--channel N`, `--width 20|40` and `--metric N`.
    pub fn parse(args: &[String]) -> Result<Self, Box<dyn Error>> {
        let mut o = Self {
            channel: 149,
            width: 40,
            metric: 60,
            seconds: None,
            log_packets: false,
            advertise: Vec::new(),
            no_mdns_to_air: false,
        };
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            if flag == "--log-packets" {
                o.log_packets = true;
                continue;
            }
            if flag == "--no-mdns-to-air" {
                o.no_mdns_to_air = true;
                continue;
            }
            let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--channel" => o.channel = value.parse()?,
                "--width" => o.width = value.parse()?,
                "--metric" => o.metric = value.parse()?,
                "--seconds" => o.seconds = Some(value.parse()?),
                "--advertise" => o.advertise.push(value.clone()),
                _ => return Err(format!("unknown option {flag}").into()),
            }
        }
        if o.width != 20 && o.width != 40 {
            return Err("--width is 20 or 40".into());
        }
        Ok(o)
    }
}

/// Writes packets onto the adapter, towards Windows; how many went.
fn write_to_windows(tun: &Tun, packets: Vec<Vec<u8>>, log_packets: bool) -> u64 {
    let mut sent = 0;
    for p in packets {
        if log_packets {
            info!("to Windows from Warlock: {}", describe(&p));
        }
        match tun.send(&p) {
            Ok(()) => sent += 1,
            Err(e) => warn!("to Windows: {e}"),
        }
    }
    sent
}

/// The service instances a peer advertises, for logs.
fn instances(p: &Peer) -> Vec<String> {
    p.services.iter().filter(|s| matches!(s.rdata, Rdata::Srv { .. })).map(|s| s.name.to_dotted()).collect()
}

/// A random locally administered unicast address, as Apple devices use for
/// AWDL; a new one each start.
fn random_addr() -> MacAddr {
    let b = RandomState::new().hash_one(SystemTime::now()).to_le_bytes();
    MacAddr([(b[0] & 0xfc) | 0x02, b[1], b[2], b[3], b[4], b[5]])
}

/// Puts the T3U on WinUSB if Windows has its own driver on it.
fn claim_dongle() -> Result<(), Box<dyn Error>> {
    let dev = warlock_usb::find(warlock_usb::T3U_VID, warlock_usb::T3U_PID)?
        .ok_or("no TP-Link Archer T3U (2357:012d) is plugged in")?;
    if !dev.is_winusb() {
        info!(device = %dev.instance_id, driver = ?dev.service, "binding the adapter to WinUSB");
        if warlock_usb::bind_winusb(&dev.instance_id)?.reboot_required {
            warn!("Windows asks for a reboot to finish binding the adapter");
        }
    }
    Ok(())
}

/// Runs until `stop` is set or something fails.
pub fn run(o: &Options, stop: &AtomicBool) -> Result<(), Box<dyn Error>> {
    claim_dongle()?;
    let wintun = dll::load(&dll::ensure(&dll::default_root())?)?;
    let own = random_addr();
    info!(address = %own, channel = o.channel, width = o.width, metric = o.metric, "opening the radio (~8 s)");
    let config = DevourerConfig { channel: o.channel, ..Default::default() };
    let config = if o.width == 40 { config.forty(o.channel) } else { config };
    let mut radio = DevourerRadio::open(&config)?;
    radio.set_ack_responder(own.0)?;
    let tun = Tun::open(&wintun, ADAPTER_NAME, ADAPTER_GUID, own.0, MTU)?;
    info!(adapter = ADAPTER_NAME, index = tun.index, address = %tun.address, mtu = tun.mtu, "up");

    let mut tx = TxConfig::new(own);
    tx.self_metric = o.metric;
    tx.ht_40mhz = o.width == 40;
    let mut engine = Engine::new(Config {
        band_change_settle_us: radio.band_change_settle().as_micros() as u64,
        ..Config::active(tx)
    });

    let mut discovery = Discovery::new(MTU as usize);
    let mut advertiser = Advertiser::new(tun.index, tun.address, &o.advertise);
    let (mut last_report, mut last_enforce) = (Instant::now(), Instant::now());
    let (mut to_air, mut to_windows, mut unroutable, mut announced, mut mdns_held) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut buf = vec![0u8; 65536];
    let until = o.seconds.map(|s| Instant::now() + Duration::from_secs(s));
    while !stop.load(Ordering::Relaxed) && until.is_none_or(|u| Instant::now() < u) {
        let now = radio.tsf_now();
        let wait = match (now, now.and_then(|n| engine.next_wakeup(n))) {
            (Some(n), Some(w)) => Duration::from_micros(w.saturating_sub(n)).min(SLICE),
            _ => SLICE,
        };
        // AWDL → Windows.
        if let Some(f) = radio.recv(wait)? {
            for ev in engine.on_frame(RxMeta { tsf: f.tsf, channel: f.channel, rssi_dbm: f.rssi_dbm }, &f.mpdu) {
                match ev {
                    Event::Packet { from, to, ethertype: ETHERTYPE_IPV6, payload } => {
                        if o.log_packets {
                            info!("to Windows from {from} (to {to}): {}", describe(&payload));
                        }
                        match tun.send(&payload) {
                            Ok(()) => to_windows += 1,
                            Err(e) => warn!("to Windows: {e}"),
                        }
                    }
                    Event::Packet { .. } => {}
                    Event::ServicesChanged(a) => {
                        let Some(p) = engine.peer(a) else { continue };
                        info!(peer = %a, sui = ?p.services_sui, host = ?p.hostname, instances = ?instances(p), "services");
                        announced += write_to_windows(&tun, discovery.update(p), o.log_packets);
                    }
                    Event::PeerLost(a) => {
                        info!("PeerLost({a})");
                        announced += write_to_windows(&tun, discovery.lost(a), o.log_packets);
                    }
                    other => info!("{other:?}"),
                }
            }
        }
        let Some(now) = radio.tsf_now() else { continue };
        // Windows → AWDL: every IPv6 packet with an AWDL address to go to
        // (none for IPv4: the adapter has no ARP).
        while let Some(n) = tun.try_recv(&mut buf) {
            let packet = &buf[..n];
            if o.log_packets {
                info!("from Windows: {}", describe(packet));
            }
            if o.no_mdns_to_air && is_mdns(packet) {
                mdns_held += 1;
                continue;
            }
            let Some(mac) = addr::ipv6_dst(packet).and_then(|d| addr::mac_for(&d)) else {
                unroutable += 1;
                continue;
            };
            to_air += 1;
            engine.send_packet(now, MacAddr(mac), ETHERTYPE_IPV6, packet.to_vec());
        }
        for a in engine.poll(now) {
            match a {
                Action::Hop(c) => {
                    if let Err(e) = radio.hop(c) {
                        warn!("hop to {c}: {e}");
                    }
                }
                Action::Transmit { mpdu, rate_500kbps, kind } => {
                    if let Err(e) = radio.send(&mpdu, rate_500kbps) {
                        warn!("sending {kind:?}: {e}");
                    } else if kind == TxKind::AddbaResponse {
                        info!("answered a Block Ack setup");
                    }
                }
            }
        }
        announced += write_to_windows(&tun, discovery.refresh(Instant::now()), o.log_packets);
        if let Some((records, host)) = advertiser.poll(Instant::now()) {
            let instances: Vec<String> =
                records.iter().filter(|r| matches!(r.rdata, Rdata::Srv { .. })).map(|r| r.name.to_dotted()).collect();
            info!(?instances, ?host, "advertising");
            engine.set_services(records, host);
        }
        if last_enforce.elapsed() >= Duration::from_secs(2) {
            last_enforce = Instant::now();
            if let Err(e) = tun.enforce_address() {
                warn!("adapter address: {e}");
            }
        }
        if last_report.elapsed() >= Duration::from_secs(60) {
            last_report = Instant::now();
            let (advertisers, records) = discovery.counts();
            info!(
                master = ?engine.master(),
                peers = engine.peers().count(),
                to_air,
                to_windows,
                unroutable,
                advertisers,
                records,
                announced,
                mdns_held,
                "status"
            );
        }
    }
    info!("stopping");
    write_to_windows(&tun, discovery.stop(), o.log_packets);
    // The adapter goes first, then the radio, which clears the ACK responder
    // as it closes.
    drop(tun);
    drop(radio);
    Ok(())
}
