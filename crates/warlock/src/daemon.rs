// SPDX-License-Identifier: GPL-2.0-only
//! The daemon: the radio, the AWDL engine and the network adapter, run on
//! one thread until told to stop.
//!
//! One thread, because the radio is opened and closed on the thread that
//! owns it (`DevourerRadio` is `!Send`). It waits on the radio in short
//! slices and polls the adapter between them: packets from Windows wait at
//! most ~2 ms, against AWDL's own waits of tens to hundreds of ms for a
//! peer's slot. An event-driven engine thread is PLAN.md's later step.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use awdl_core::{Action, Config, Engine, Event, Peer, RxMeta, TxConfig, TxKind};
use awdl_proto::MacAddr;
use awdl_proto::tlv::{Rdata, TlvBody, kind};
use tracing::{info, warn};
use warlock_api::types::{self as wire, RadioState};
use warlock_api::{Frame as CapturedFrame, FrameKind, Security, Server};
use warlock_radio::{DevourerConfig, DevourerRadio, Radio};
use warlock_tun::{Tun, addr, dll};

use crate::advertise::Advertiser;
use crate::api;
use crate::discovery::Discovery;
use crate::power::Power;
use crate::request;
use crate::service;

const ETHERTYPE_IPV6: u16 = 0x86dd;
/// The adapter's fixed identity (the last group spells "WARLOC").
const ADAPTER_GUID: u128 = 0xe1d4a5c3_0b6f_4f26_9b52_5741524c4f43;
const ADAPTER_NAME: &str = "Warlock AWDL";
/// PLAN.md's choice, leaving headroom under AWDL's 1500-byte payloads.
const MTU: u32 = 1450;
/// How long the loop waits on the radio at most: the adapter's latency.
const SLICE: Duration = Duration::from_millis(2);
/// How often the control API's view of the state is refreshed.
const PUBLISH: Duration = Duration::from_millis(250);

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
    /// Service types whose Windows registrations on the adapter we always
    /// advertise on AWDL (`--advertise _x._tcp`, repeatable), besides those
    /// programs hold locks on through the control API
    /// (`docs/service-discovery.md`).
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

/// Peers' Low-Latency Wi-Fi addresses (issue #11). An iPhone's `llw0` has
/// an address of its own, not its EUI-64 link-local (in Koala's trial 20 a
/// per-session ULA, `fddd:90e5:8ba0::8`), so nothing tells Windows or
/// Warlock it's an AWDL peer's: Warlock learns it from the LLW the peer
/// sends, routes it to the adapter so Windows sends what's for it there, and
/// sends that back as LLW.
#[derive(Default)]
struct Llw {
    peers: BTreeMap<std::net::Ipv6Addr, MacAddr>,
}

impl Llw {
    /// Takes in an LLW packet from `from`.
    fn learn(&mut self, tun: &Tun, from: MacAddr, packet: &[u8]) {
        let Some(src) = addr::ipv6_src(packet) else { return };
        // Its link-local reaches it as AWDL already; nor can a group or ::
        // be a peer's.
        if addr::mac_for(&src).is_some() || src.is_unspecified() || src.is_multicast() {
            return;
        }
        if self.peers.insert(src, from) == Some(from) {
            return;
        }
        match tun.route_host(src) {
            Ok(()) => info!(address = %src, peer = %from, "routing a peer's LLW address to the adapter"),
            Err(e) => warn!("{e}"),
        }
    }

    /// The peer whose LLW address `dst` is.
    fn peer(&self, dst: &std::net::Ipv6Addr) -> Option<MacAddr> {
        self.peers.get(dst).copied()
    }

    /// Forgets a peer that left, and its routes.
    fn forget(&mut self, tun: &Tun, peer: MacAddr) {
        let gone: Vec<_> = self.peers.iter().filter(|(_, m)| **m == peer).map(|(a, _)| *a).collect();
        for a in gone {
            self.peers.remove(&a);
            if let Err(e) = tun.unroute_host(a) {
                warn!("{e}");
            }
        }
    }

    /// Forgets every peer, and their routes.
    fn clear(&mut self, tun: &Tun) {
        for (a, _) in std::mem::take(&mut self.peers) {
            if let Err(e) = tun.unroute_host(a) {
                warn!("{e}");
            }
        }
    }
}

/// A UMI's destination and code, for the log.
fn umi_of(mpdu: &[u8]) -> Option<(MacAddr, u32)> {
    let Ok(Some(awdl_proto::Frame::Action { header, action })) = awdl_proto::parse(mpdu) else { return None };
    let Ok(TlvBody::DataPathState(d)) = action.find(kind::DATA_PATH_STATE)?.decode() else { return None };
    Some((header.addr1, d.umi_code()?))
}

/// What a frame is to captures: AWDL if Warlock reads it, otherwise other
/// (malformed AWDL included).
fn frame_kind(mpdu: &[u8]) -> FrameKind {
    match awdl_proto::parse(mpdu) {
        Ok(Some(_)) => FrameKind::Awdl,
        _ => FrameKind::Other,
    }
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
/// AWDL: a new one each time the service starts, kept for that run and
/// stored nowhere (PLAN.md, W5).
fn random_addr() -> MacAddr {
    let b = RandomState::new().hash_one(SystemTime::now()).to_le_bytes();
    MacAddr([(b[0] & 0xfc) | 0x02, b[1], b[2], b[3], b[4], b[5]])
}

/// Finds a supported adapter, preferring the T3U v1, and puts it on WinUSB if
/// Windows has its own driver on it: its model and device instance, or
/// `None` if none is plugged in.
fn claim_adapter() -> Result<Option<(warlock_usb::Model, String)>, Box<dyn Error>> {
    let Some((dev, model)) = warlock_usb::find_supported()? else { return Ok(None) };
    if model.is_reference() {
        info!(model = model.name, device = %dev.instance_id, "adapter");
    } else {
        warn!(
            model = model.name,
            id = format!("{:04x}:{:04x}", model.vid, model.pid),
            device = %dev.instance_id,
            "not the {} Warlock is tested with; trying it anyway",
            warlock_usb::REFERENCE.name
        );
    }
    if !dev.is_winusb() {
        info!(device = %dev.instance_id, driver = ?dev.service, "binding the adapter to WinUSB");
        if warlock_usb::bind_winusb(&dev.instance_id)?.reboot_required {
            warn!("Windows asks for a reboot to finish binding the adapter");
        }
    }
    Ok(Some((model, dev.instance_id)))
}

/// The radio's part of the control API's info.
fn radio_info(state: RadioState, own: MacAddr, o: &Options) -> wire::Radio {
    let up = state == RadioState::Up;
    wire::Radio {
        state,
        address: up.then(|| own.to_string()),
        channel: up.then_some(o.channel),
        width_mhz: up.then_some(o.width),
    }
}

/// How long to wait before trying an adapter again after its radio failed.
const RETRY: Duration = Duration::from_secs(2);

/// How long closing a radio may take. A clean close takes a fraction of a
/// second, even after an unplug; devourer stuck on a radio that stopped
/// answering never finishes (2026-11-19, after a hibernation).
const CLOSE_LIMIT: Duration = Duration::from_secs(20);

/// A radio that has failed every send and hop for this long, this many times
/// at least, has stopped answering: its bus died under it, as in a
/// hibernation. devourer's occasional failed register read (one or two a
/// minute on a busy channel) never strings this many together; a radio up
/// sends or hops several times a second.
const DEAD_AFTER: Duration = Duration::from_secs(3);
const DEAD_AFTER_FAILURES: u32 = 20;

/// Why a radio's session ended, when it didn't fail.
enum End {
    /// Warlock is stopping.
    Stopping,
    /// The adapter was unplugged.
    Unplugged,
    /// The system is going to sleep: the radio opens again when it wakes.
    Sleep,
    /// The system slept with the radio open, without saying it would: the
    /// chip may have lost power, and with it everything devourer set up.
    Woke,
}

/// A radio's run of failed sends and hops, to tell one that stopped answering
/// from devourer's occasional failed register read.
#[derive(Default)]
struct Failures {
    since: Option<Instant>,
    count: u32,
}

impl Failures {
    fn ok(&mut self) {
        *self = Self::default();
    }

    /// Counts a failure; whether the radio has now failed long enough to be
    /// given up on.
    fn failed(&mut self, now: Instant) -> bool {
        let since = *self.since.get_or_insert(now);
        self.count += 1;
        self.count >= DEAD_AFTER_FAILURES && now.duration_since(since) >= DEAD_AFTER
    }
}

/// Runs `f`, but gives up on the process (`service::give_up`) if it takes
/// longer than `limit`: for what can hang in devourer.
fn within<T>(limit: Duration, what: &'static str, f: impl FnOnce() -> T) -> T {
    let (done, wait) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(RecvTimeoutError::Timeout) = wait.recv_timeout(limit) {
            service::give_up(&format!("{what} took over {} s", limit.as_secs()));
        }
    });
    let out = f();
    let _ = done.send(());
    out
}

/// What lasts the whole run, through any number of adapters coming and going.
struct Run<'a> {
    o: &'a Options,
    stop: &'a AtomicBool,
    until: Option<Instant>,
    control: warlock_api::Daemon,
    info: wire::Info,
    /// Our AWDL address, for the whole run.
    own: MacAddr,
    /// The adapter, for the whole run; connected while a radio is up.
    tun: Tun,
    /// The service types programs hold advertising locks on.
    locked_types: BTreeSet<String>,
    /// The peers programs hold realtime locks on.
    realtime: BTreeSet<MacAddr>,
    traffic: wire::Traffic,
    mdns_held: u64,
    /// The system's sleeps and resumes.
    power: Power,
}

/// Runs until `stop` is set, or `--seconds` pass. The control API and the
/// adapter come up first and stay; a supported adapter is used whenever one
/// is plugged in (PLAN.md, W5).
pub fn run(o: &Options, stop: &AtomicBool) -> Result<(), Box<dyn Error>> {
    let own = random_addr();
    // The control API first: programs can follow the radio from the start,
    // and a second Warlock stops here, its pipe taken.
    let info = wire::Info {
        version: env!("CARGO_PKG_VERSION").into(),
        host_name: api::host_name(),
        adapter: None,
        radio: radio_info(RadioState::Absent, own, o),
        awdl: wire::Awdl { master: None, peers: 0 },
        traffic: None,
        requestable: request::REQUESTABLE.iter().map(|s| s.to_string()).collect(),
        // The requests' thread reports it, and the API adds it.
        bluetooth: None,
    };
    let initial = warlock_api::State {
        info: info.clone(),
        peers: Vec::new(),
        advertised: BTreeMap::new(),
        realtime_asked: BTreeSet::new(),
        realtime_joined: BTreeSet::new(),
    };
    let pipes = warlock_api::Pipes { api: warlock_api::PIPE, admin: warlock_api::ADMIN_PIPE };
    let (_server, control) = Server::start(pipes, Security::Service, initial).map_err(|e| {
        format!("can't serve the control API on {} and {} (is Warlock running already?): {e}", pipes.api, pipes.admin)
    })?;
    info!(pipe = pipes.api, admin = pipes.admin, "control API up");
    // Requests need no radio: they're served from the start, on their own
    // thread, until the run ends.
    let _requests = request::Asker::start(control.requests())?;

    // The adapter, disconnected until a radio is up.
    let wintun = dll::load(&dll::ensure(&dll::default_root())?)?;
    let tun = Tun::open(&wintun, ADAPTER_NAME, ADAPTER_GUID, own.0, MTU)?;
    info!(adapter = ADAPTER_NAME, index = tun.index, address = %tun.address, mtu = tun.mtu, "adapter ready");
    let watch = warlock_usb::DeviceWatch::start()?;
    let power = Power::watch().unwrap_or_else(|e| {
        warn!("can't follow the system's sleeps (error {e}); a radio that dies in one is found by its failures");
        Power::deaf()
    });

    let mut run = Run {
        o,
        stop,
        until: o.seconds.map(|s| Instant::now() + Duration::from_secs(s)),
        control,
        info,
        own,
        tun,
        locked_types: BTreeSet::new(),
        realtime: BTreeSet::new(),
        traffic: wire::Traffic::default(),
        mdns_held: 0,
        power,
    };
    run.info.adapter =
        Some(wire::Adapter { name: ADAPTER_NAME.into(), index: run.tun.index, address: run.tun.address, mtu: MTU });
    run.set_radio(RadioState::Absent);
    while let Some((model, instance)) = run.wait_for_adapter(&watch) {
        run.set_radio(RadioState::Opening);
        let result = run.session(&watch, model, &instance);
        run.set_radio(RadioState::Absent);
        match result {
            _ if run.stopping() => break,
            Ok(End::Unplugged) => info!("the adapter is gone; waiting for one"),
            // Asleep, the wait for the adapter waits for the system to wake
            // first; woken, the radio opens again at once.
            Ok(End::Sleep | End::Woke | End::Stopping) => {}
            Err(e) => {
                warn!("the radio stopped: {e}; trying again");
                watch.wait(watch.changes(), RETRY);
            }
        }
    }
    info!("stopping");
    Ok(())
}

impl Run<'_> {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.until.is_some_and(|u| Instant::now() >= u)
    }

    /// Reports the radio's state, and clears what only a running radio has.
    fn set_radio(&mut self, state: RadioState) {
        self.info.radio = radio_info(state, self.own, self.o);
        if state != RadioState::Up {
            self.info.awdl = wire::Awdl { master: None, peers: 0 };
            self.control.publish(warlock_api::State {
                info: self.info.clone(),
                peers: Vec::new(),
                advertised: BTreeMap::new(),
                realtime_asked: BTreeSet::new(),
                realtime_joined: BTreeSet::new(),
            });
        }
        info!(?state, "radio");
        self.control.event(wire::Event::RadioChanged { radio: self.info.radio.clone() });
    }

    /// Takes in what locks ask for; whether it changed.
    fn take_wants(&mut self) -> bool {
        let Some(wants) = self.control.wants() else { return false };
        self.realtime = wants.realtime.into_iter().map(MacAddr).collect();
        info!(types = ?wants.types, holds = wants.holds, realtime = ?self.realtime, "locks");
        self.locked_types = wants.types;
        true
    }

    /// Ours plus what locks ask for.
    fn types(&self) -> Vec<String> {
        self.o.advertise.iter().cloned().chain(self.locked_types.iter().cloned()).collect()
    }

    /// Waits for a supported adapter and claims it, waking on USB devices
    /// coming and going; `None` when stopping.
    fn wait_for_adapter(&mut self, watch: &warlock_usb::DeviceWatch) -> Option<(warlock_usb::Model, String)> {
        let mut seen = watch.changes();
        let mut last_error = None;
        let mut said = false;
        loop {
            if self.stopping() {
                return None;
            }
            if self.power.asleep() {
                info!("the system is going to sleep; the radio opens again when it wakes");
                while !self.power.wait_awake(Duration::from_secs(1)) {
                    if self.stopping() {
                        return None;
                    }
                }
                info!("the system woke");
            }
            self.take_wants();
            match claim_adapter() {
                Ok(Some(found)) => return Some(found),
                Ok(None) if !said => {
                    info!("waiting for a supported adapter (a TP-Link Archer T3U, or another RTL8812BU/RTL8822BU)");
                    said = true;
                }
                Ok(None) => {}
                Err(e) => {
                    let message = e.to_string();
                    if last_error.as_ref() != Some(&message) {
                        warn!("can't claim the adapter: {message}");
                        last_error = Some(message);
                    }
                }
            }
            // Wakes when a device comes or goes; at least once a second, to
            // notice being stopped.
            seen = watch.wait(seen, Duration::from_secs(1));
        }
    }

    /// Opens the radio and runs AWDL until the adapter goes, the radio fails,
    /// the system sleeps, or Warlock stops. The adapter is connected
    /// meanwhile; the radio closes last, which clears its ACK responder, and
    /// within `CLOSE_LIMIT`.
    fn session(
        &mut self,
        watch: &warlock_usb::DeviceWatch,
        model: warlock_usb::Model,
        instance: &str,
    ) -> Result<End, Box<dyn Error>> {
        let o = self.o;
        info!(address = %self.own, channel = o.channel, width = o.width, metric = o.metric, "opening the radio (~8 s)");
        let config = DevourerConfig { channel: o.channel, vid: model.vid, pid: model.pid, ..Default::default() };
        let config = if o.width == 40 { config.forty(o.channel) } else { config };
        let mut radio = DevourerRadio::open(&config)?;
        self.power.set_radio_open(true);
        let result = self.up(&mut radio, watch, instance);
        within(CLOSE_LIMIT, "closing the radio", move || drop(radio));
        self.power.set_radio_open(false);
        result
    }

    /// Arms the open radio's ACK responder and runs AWDL on it, the adapter
    /// connected meanwhile.
    fn up(
        &mut self,
        radio: &mut DevourerRadio,
        watch: &warlock_usb::DeviceWatch,
        instance: &str,
    ) -> Result<End, Box<dyn Error>> {
        radio.set_ack_responder(self.own.0)?;
        self.tun.connect()?;
        self.set_radio(RadioState::Up);
        let result = self.awdl(radio, watch, instance);
        self.tun.disconnect();
        result
    }

    /// The AWDL engine on an open radio, bridged to the connected adapter.
    fn awdl(
        &mut self,
        radio: &mut DevourerRadio,
        watch: &warlock_usb::DeviceWatch,
        instance: &str,
    ) -> Result<End, Box<dyn Error>> {
        let o = self.o;
        let mut tx = TxConfig::new(self.own);
        tx.self_metric = o.metric;
        tx.ht_40mhz = o.width == 40;
        let mut engine = Engine::new(Config {
            band_change_settle_us: radio.band_change_settle().as_micros() as u64,
            ..Config::active(tx)
        });
        engine.set_realtime_peers(&self.realtime);
        let mut discovery = Discovery::new(MTU as usize);
        let mut advertiser = Advertiser::new(self.tun.index, self.tun.address, &self.types());
        // What the control API reports as advertised, by type.
        let mut advertised: BTreeMap<String, Vec<String>> = BTreeMap::new();
        // Peers' `llw0` addresses, which aren't their link-locals, learned from
        // their Low-Latency Wi-Fi and routed to the adapter (issue #11).
        let mut llw = Llw::default();
        if let Err(e) = self.tun.clear_host_routes() {
            warn!("adapter routes: {e}");
        }
        let mut seen_devices = watch.changes();
        let mut last_publish = Instant::now() - PUBLISH;
        let (mut last_report, mut last_enforce) = (Instant::now(), Instant::now());
        let mut buf = vec![0u8; 65536];
        let mut ended = Ok(End::Stopping);
        // A radio that stays deaf long after opening is worth knowing about.
        let (opened, mut heard) = (Instant::now(), false);
        let resumes = self.power.resumes();
        let mut failures = Failures::default();
        'session: while !self.stopping() {
            // A USB device came or went: is ours still there?
            if watch.changes() != seen_devices {
                seen_devices = watch.changes();
                if !warlock_usb::is_present(instance)? {
                    info!(device = instance, "the adapter was unplugged");
                    ended = Ok(End::Unplugged);
                    break;
                }
            }
            // Close before the system sleeps, while the bus still answers.
            if self.power.asleep() {
                info!("the system is going to sleep: closing the radio");
                ended = Ok(End::Sleep);
                break;
            }
            if self.power.resumes() != resumes {
                warn!("the system slept with the radio open: opening it afresh");
                ended = Ok(End::Woke);
                break;
            }
            let now = radio.tsf_now();
            let wait = match (now, now.and_then(|n| engine.next_wakeup(n))) {
                (Some(n), Some(w)) => Duration::from_micros(w.saturating_sub(n)).min(SLICE),
                _ => SLICE,
            };
            // AWDL → Windows.
            let frame = match radio.recv(wait) {
                Ok(f) => f,
                Err(e) => {
                    ended = Err(e.into());
                    break;
                }
            };
            // A frame or, failing one, the time: silent peers expire and
            // elections report either way. (Without ticks, becoming master
            // alone went unreported until the first frame.)
            let (events, at) = match frame {
                Some(f) => {
                    if !std::mem::replace(&mut heard, true) {
                        info!(after = ?opened.elapsed(), channel = f.channel, master = ?engine.master(), "first frame heard");
                    }
                    if self.control.capturing() {
                        self.control.capture(&CapturedFrame {
                            sent: false,
                            kind: frame_kind(&f.mpdu),
                            tsf: f.tsf,
                            channel: f.channel,
                            rssi_dbm: Some(f.rssi_dbm),
                            mpdu: &f.mpdu,
                        });
                    }
                    let meta = RxMeta { tsf: f.tsf, channel: f.channel, rssi_dbm: f.rssi_dbm };
                    (engine.on_frame(meta, &f.mpdu), Some(f.tsf))
                }
                None => radio.tsf_now().map_or((Vec::new(), None), |now| (engine.on_tick(now), Some(now))),
            };
            for ev in events {
                match ev {
                    Event::Packet { from, to, ethertype: ETHERTYPE_IPV6, payload, llw: over_llw } => {
                        if o.log_packets {
                            info!("to Windows from {from} (to {to}, LLW {over_llw}): {}", describe(&payload));
                        }
                        if over_llw {
                            llw.learn(&self.tun, from, &payload);
                        }
                        match self.tun.send(&payload) {
                            Ok(()) => self.traffic.to_windows += 1,
                            Err(e) => warn!("to Windows: {e}"),
                        }
                    }
                    Event::Packet { .. } => {}
                    Event::ServicesChanged(a) => {
                        let Some(p) = engine.peer(a) else { continue };
                        info!(peer = %a, sui = ?p.services_sui, host = ?p.hostname, instances = ?instances(p), "services");
                        self.traffic.announced += write_to_windows(&self.tun, discovery.update(p), o.log_packets);
                        self.control
                            .event(wire::Event::ServicesChanged { address: a.to_string(), services: api::services(p) });
                    }
                    Event::PeerLost(a) => {
                        info!("PeerLost({a})");
                        llw.forget(&self.tun, a);
                        self.traffic.announced += write_to_windows(&self.tun, discovery.lost(a), o.log_packets);
                        self.control.event(wire::Event::PeerLost { address: a.to_string() });
                    }
                    Event::PeerFound(a) => {
                        info!("PeerFound({a})");
                        if let Some(p) = engine.peer(a) {
                            self.control.event(wire::Event::PeerFound { peer: Box::new(api::peer(p, at)) });
                        }
                    }
                    Event::MasterChanged(m) => {
                        info!("MasterChanged({m:?})");
                        self.control.event(wire::Event::MasterChanged { master: m.map(|a| a.to_string()) });
                    }
                    other => info!("{other:?}"),
                }
            }
            // The engine's clock is the radio's, which runs from the moment
            // it opens, heard anything or not: alone, after listening, we
            // lead a cluster of our own. (A radio without a clock would hold
            // back only the engine; records, locks and the API run anyway.)
            let tsf = radio.tsf_now();
            if let Some(now) = tsf {
                // Windows → AWDL: every IPv6 packet with an AWDL address to go
                // to (none for IPv4: the adapter has no ARP).
                while let Some(n) = self.tun.try_recv(&mut buf) {
                    let packet = &buf[..n];
                    if o.log_packets {
                        info!("from Windows: {}", describe(packet));
                    }
                    if o.no_mdns_to_air && is_mdns(packet) {
                        self.mdns_held += 1;
                        continue;
                    }
                    let dst = addr::ipv6_dst(packet);
                    if let Some(peer) = dst.and_then(|d| llw.peer(&d)) {
                        self.traffic.to_air += 1;
                        engine.send_llw(now, peer, ETHERTYPE_IPV6, packet.to_vec());
                        continue;
                    }
                    let Some(mac) = dst.and_then(|d| addr::mac_for(&d)) else {
                        self.traffic.unroutable += 1;
                        continue;
                    };
                    self.traffic.to_air += 1;
                    engine.send_packet(now, MacAddr(mac), ETHERTYPE_IPV6, packet.to_vec());
                }
                for a in engine.poll(now) {
                    let result = match &a {
                        Action::Hop(c) => radio.hop(*c),
                        Action::Transmit { mpdu, rate_500kbps, .. } => radio.send(mpdu, *rate_500kbps),
                    };
                    match result {
                        Ok(()) => {
                            failures.ok();
                            if matches!(a, Action::Transmit { kind: TxKind::AddbaResponse, .. }) {
                                info!("answered a Block Ack setup");
                            }
                            if let Action::Transmit { kind: TxKind::Umi, mpdu, .. } = &a
                                && let Some((to, code)) = umi_of(mpdu)
                            {
                                info!(%to, code = format_args!("{code:#010x}"), channel = radio.channel(), "sent a UMI");
                            }
                            if let Action::Transmit { mpdu, .. } = &a
                                && self.control.capturing()
                            {
                                self.control.capture(&CapturedFrame {
                                    sent: true,
                                    kind: frame_kind(mpdu),
                                    tsf: now,
                                    channel: radio.channel(),
                                    rssi_dbm: None,
                                    mpdu,
                                });
                            }
                        }
                        Err(e) => {
                            let what = match a {
                                Action::Hop(c) => format!("hop to {c}"),
                                Action::Transmit { kind, .. } => format!("sending {kind:?}"),
                            };
                            warn!("{what}: {e}");
                            if failures.failed(Instant::now()) {
                                ended = Err(format!(
                                    "the radio stopped answering: {} sends and hops failed in a row, over {} s; the \
                                     last, {what}: {e}",
                                    failures.count,
                                    DEAD_AFTER.as_secs()
                                )
                                .into());
                                break 'session;
                            }
                        }
                    }
                }
            }
            self.traffic.announced += write_to_windows(&self.tun, discovery.refresh(Instant::now()), o.log_packets);
            if self.take_wants() {
                advertiser.set_types(&self.types());
                engine.set_realtime_peers(&self.realtime);
            }
            if let Some(a) = advertiser.poll(Instant::now()) {
                info!(instances = ?a.instances, host = ?a.host, "advertising");
                let types: BTreeSet<&String> = advertised.keys().chain(a.instances.keys()).collect();
                for t in types {
                    let (before, after) = (advertised.get(t), a.instances.get(t));
                    if before != after {
                        self.control.event(wire::Event::AdvertisingChanged {
                            service_type: t.clone(),
                            instances: after.cloned().unwrap_or_default(),
                        });
                    }
                }
                advertised = a.instances;
                engine.set_services(a.records, a.host);
            }
            if last_publish.elapsed() >= PUBLISH {
                last_publish = Instant::now();
                self.info.awdl =
                    wire::Awdl { master: engine.master().map(|m| m.to_string()), peers: engine.peers().count() };
                self.info.traffic = Some(self.traffic.clone());
                self.control.publish(warlock_api::State {
                    info: self.info.clone(),
                    peers: engine.peers().map(|p| api::peer(p, tsf)).collect(),
                    advertised: advertised.clone(),
                    realtime_asked: self
                        .realtime
                        .iter()
                        .filter(|&&p| engine.realtime_asked(p))
                        .map(|p| p.to_string())
                        .collect(),
                    realtime_joined: self
                        .realtime
                        .iter()
                        .filter(|&&p| engine.realtime_joined(p))
                        .map(|p| p.to_string())
                        .collect(),
                });
            }
            if last_enforce.elapsed() >= Duration::from_secs(2) {
                last_enforce = Instant::now();
                if let Err(e) = self.tun.enforce_address() {
                    warn!("adapter address: {e}");
                }
            }
            if last_report.elapsed() >= Duration::from_secs(60) {
                last_report = Instant::now();
                let (advertisers, records) = discovery.counts();
                let t = &self.traffic;
                info!(
                    master = ?engine.master(),
                    peers = engine.peers().count(),
                    to_air = t.to_air,
                    to_windows = t.to_windows,
                    unroutable = t.unroutable,
                    advertisers,
                    records,
                    announced = t.announced,
                    mdns_held = self.mdns_held,
                    "status"
                );
            }
        }
        llw.clear(&self.tun);
        // Goodbyes for the records we announced for peers, while the adapter
        // is still connected.
        write_to_windows(&self.tun, discovery.stop(), o.log_packets);
        for t in advertised.keys() {
            self.control.event(wire::Event::AdvertisingChanged { service_type: t.clone(), instances: Vec::new() });
        }
        ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Failures, `every` apart, until the radio is given up on; how many.
    fn failures_until_dead(every: Duration, limit: u32) -> Option<u32> {
        let (start, mut f) = (Instant::now(), Failures::default());
        (1..=limit).find(|&i| f.failed(start + every * (i - 1)))
    }

    #[test]
    fn a_radio_failing_steadily_is_given_up_on_after_a_few_seconds() {
        // The rate seen after the 2026-11-19 hibernation: ~10 a second.
        assert_eq!(failures_until_dead(Duration::from_millis(100), 1000), Some(31));
        // Faster failures still wait out the time.
        assert_eq!(failures_until_dead(Duration::from_millis(10), 1000), Some(301));
        // Slow ones wait for the count.
        assert_eq!(failures_until_dead(Duration::from_secs(1), 1000), Some(DEAD_AFTER_FAILURES));
    }

    #[test]
    fn one_success_forgives_the_failures_before_it() {
        let (start, mut f) = (Instant::now(), Failures::default());
        for i in 0..100 {
            if i % 25 == 24 {
                f.ok();
            } else {
                assert!(!f.failed(start + Duration::from_millis(100) * i), "given up at {i}");
            }
        }
    }
}
