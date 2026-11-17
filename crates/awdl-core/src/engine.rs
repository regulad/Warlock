// SPDX-License-Identifier: GPL-2.0-only
//! The engine: the peer table, the election and sync, fed frame by frame.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use awdl_proto::action::AwdlVersion;
use awdl_proto::tlv::TlvBody;
use awdl_proto::{Frame, MacAddr, parse};

use crate::{AwClock, AwPosition, ChannelSchedule, ElectionInfo, Observed, SyncClaim};

/// What the radio knows about a received frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxMeta {
    /// Our hardware TSF at reception, µs.
    pub tsf: u64,
    /// The channel we received it on.
    pub channel: u8,
    /// Signal, dBm.
    pub rssi_dbm: i8,
}

/// Engine settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Our own AWDL address; frames from it are ignored.
    pub own_addr: Option<MacAddr>,
    /// A peer silent this long, µs, is dropped (data frames count).
    pub peer_timeout_us: u64,
    /// A peer whose last sync claim is older than this, µs, isn't synced to.
    pub source_stale_us: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { own_addr: None, peer_timeout_us: 5_000_000, source_stale_us: 2_000_000 }
    }
}

/// Something that changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A peer's first frame.
    PeerFound(MacAddr),
    /// A peer timed out.
    PeerLost(MacAddr),
    /// The cluster's master changed; `None` with no peers left.
    MasterChanged(Option<MacAddr>),
    /// The peer we sync to changed.
    SyncSourceChanged(Option<MacAddr>),
}

/// What we know about one peer.
#[derive(Clone, Debug)]
pub struct Peer {
    /// Its AWDL address.
    pub addr: MacAddr,
    /// TSF of its first and latest frames.
    pub first_seen: u64,
    /// See `first_seen`.
    pub last_seen: u64,
    /// The channel and signal of its latest frame.
    pub channel: u8,
    /// See `channel`.
    pub rssi_dbm: i8,
    /// Frames received, by kind.
    pub psfs: u32,
    /// See `psfs`.
    pub mifs: u32,
    /// See `psfs`.
    pub data_frames: u32,
    /// Its version TLV: AWDL version and device class.
    pub version: Option<(AwdlVersion, u8)>,
    /// What it says about the election.
    pub election: Option<ElectionInfo>,
    /// Its channel per slot.
    pub schedule: Option<ChannelSchedule>,
    /// Its host name (ARPA TLV).
    pub hostname: Option<String>,
    /// Its AW clock on our TSF.
    pub clock: AwClock,
    /// Its latest sync claim, and what the clock made of it.
    pub last_claim: Option<(SyncClaim, Observed)>,
}

impl Peer {
    fn new(addr: MacAddr, tsf: u64) -> Self {
        Self {
            addr,
            first_seen: tsf,
            last_seen: tsf,
            channel: 0,
            rssi_dbm: 0,
            psfs: 0,
            mifs: 0,
            data_frames: 0,
            version: None,
            election: None,
            schedule: None,
            hostname: None,
            clock: AwClock::new(),
            last_claim: None,
        }
    }

    /// Whether we could open a data path to it: it has sent a MIF and a
    /// nonzero version.
    pub fn is_valid(&self) -> bool {
        self.mifs > 0 && self.version.is_some_and(|(v, _)| v.to_byte() != 0)
    }

    /// Whether it says it's a master.
    pub fn is_master(&self) -> bool {
        self.election.is_some_and(|e| e.master == self.addr)
    }
}

/// The AWDL engine. See the crate docs.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    config: Config,
    peers: BTreeMap<MacAddr, Peer>,
    master: Option<MacAddr>,
    source: Option<MacAddr>,
}

impl Engine {
    /// An engine with no peers.
    pub fn new(config: Config) -> Self {
        Self { config, ..Self::default() }
    }

    /// Feeds one received MPDU (no radiotap, no FCS).
    pub fn on_frame(&mut self, meta: RxMeta, mpdu: &[u8]) -> Vec<Event> {
        let mut events = self.expire(meta.tsf);
        let Ok(Some(frame)) = parse(mpdu) else { return events };
        let src = frame.header().source();
        if Some(src) == self.config.own_addr || src.is_multicast() {
            return events;
        }
        match &frame {
            Frame::Data { .. } => {
                if let Some(p) = self.peers.get_mut(&src) {
                    p.last_seen = meta.tsf;
                    p.data_frames += 1;
                }
            }
            Frame::Action { action, .. } => {
                if !self.peers.contains_key(&src) {
                    events.push(Event::PeerFound(src));
                }
                let p = self.peers.entry(src).or_insert_with(|| Peer::new(src, meta.tsf));
                p.last_seen = meta.tsf;
                p.channel = meta.channel;
                p.rssi_dbm = meta.rssi_dbm;
                if action.is_mif() {
                    p.mifs += 1;
                } else {
                    p.psfs += 1;
                }
                let (mut v1, mut v2, mut from_sync, mut from_tlv18) = (None, None, None, None);
                for t in action.tlvs() {
                    match t.decode() {
                        Ok(TlvBody::SyncParams(s)) => {
                            if let Some(claim) = SyncClaim::new(meta.tsf, &action.header, &s) {
                                let observed = p.clock.observe(&claim);
                                p.last_claim = Some((claim, observed));
                            }
                            from_sync = ChannelSchedule::from_sequence(&s.channel_sequence);
                        }
                        Ok(TlvBody::ChannelSequence(c)) => from_tlv18 = ChannelSchedule::from_sequence(&c.sequence),
                        Ok(TlvBody::ElectionParamsV2(e)) => v2 = Some(ElectionInfo::from_v2(&e)),
                        Ok(TlvBody::ElectionParams(e)) => v1 = Some(ElectionInfo::from_v1(&e)),
                        Ok(TlvBody::Version(v)) => p.version = Some((v.version, v.device_class)),
                        Ok(TlvBody::Arpa(a)) => p.hostname = Some(a.name.to_dotted()),
                        _ => {}
                    }
                }
                p.election = v2.or(v1).or(p.election);
                p.schedule = from_tlv18.or(from_sync).or(p.schedule);
            }
        }
        events.extend(self.elect(meta.tsf));
        events
    }

    /// Advances time without a frame: drops silent peers.
    pub fn on_tick(&mut self, tsf: u64) -> Vec<Event> {
        let mut events = self.expire(tsf);
        events.extend(self.elect(tsf));
        events
    }

    fn expire(&mut self, now: u64) -> Vec<Event> {
        let timeout = self.config.peer_timeout_us;
        let gone: Vec<MacAddr> =
            self.peers.values().filter(|p| now.saturating_sub(p.last_seen) > timeout).map(|p| p.addr).collect();
        let mut events = Vec::new();
        for a in gone {
            self.peers.remove(&a);
            events.push(Event::PeerLost(a));
        }
        if !events.is_empty() {
            events.extend(self.elect(now));
        }
        events
    }

    /// The cluster's master is the best master any peer names. We sync to
    /// that master if we hear it, else to the peer closest to it; the current
    /// choice is kept while nothing strictly better is heard.
    fn elect(&mut self, now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        let master = self.peers.values().filter_map(|p| p.election.map(|e| e.master_rank())).max().map(|r| r.addr);
        if master != self.master {
            self.master = master;
            events.push(Event::MasterChanged(master));
        }
        let stale = self.config.source_stale_us;
        let rank = |p: &Peer| -> Option<(bool, u32)> {
            let m = master?;
            let fresh = p.last_claim.is_some_and(|(c, _)| now.saturating_sub(c.rx_tsf) <= stale);
            let follows = p.addr == m || p.election.is_some_and(|e| e.master == m);
            (fresh && follows).then(|| (p.addr != m, p.election.map_or(u32::MAX, |e| e.distance)))
        };
        let best = self.peers.values().filter_map(|p| rank(p).map(|r| (r, Reverse(p.last_seen), p.addr))).min();
        let current = self.source.and_then(|s| self.peers.get(&s)).and_then(|p| rank(p));
        let source = match (best, current) {
            (Some((r, _, _)), Some(cur)) if cur <= r => self.source,
            (best, _) => best.map(|(_, _, a)| a),
        };
        if source != self.source {
            self.source = source;
            events.push(Event::SyncSourceChanged(source));
        }
        events
    }

    /// The peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    /// One peer.
    pub fn peer(&self, addr: MacAddr) -> Option<&Peer> {
        self.peers.get(&addr)
    }

    /// The cluster's master.
    pub fn master(&self) -> Option<MacAddr> {
        self.master
    }

    /// The peer we sync to.
    pub fn sync_source(&self) -> Option<&Peer> {
        self.source.and_then(|s| self.peers.get(&s))
    }

    /// Where `tsf` falls in the cluster's AW schedule, once the clock of the
    /// peer we sync to is locked.
    pub fn position(&self, tsf: u64) -> Option<AwPosition> {
        let clock = &self.sync_source()?.clock;
        clock.is_locked().then(|| clock.position(tsf)).flatten()
    }
}
