// SPDX-License-Identifier: GPL-2.0-only
//! The engine: the peer table, the election and sync, fed frame by frame.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use awdl_proto::action::{AwdlVersion, subtype};
use awdl_proto::blockack::AddbaRequest;
use awdl_proto::tlv::{ChannelSequence, TlvBody};
use awdl_proto::{Frame, MacAddr, parse};

use crate::active::{self, FollowerView, TxConfig};
use crate::{
    AW_US, AWS_PER_SLOT, AwClock, AwPosition, ChannelSchedule, ElectionInfo, MasterRank, Observed, OwnClock,
    SyncClaim, TU_US,
};

/// Transmit no earlier than this into an AW, µs: time for a hop to settle.
const TX_FROM_US: u32 = TU_US as u32 / 2;
/// Transmit no later than this into an AW, µs: well inside its 16 TU.
const TX_UNTIL_US: u32 = 8 * TU_US as u32;

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
    /// Set to take part: [`Engine::poll`] then returns frames to send and
    /// channels to be on. `None` only listens.
    pub transmit: Option<TxConfig>,
    /// How long, µs, a taking-part engine listens before it may elect
    /// itself master, so it joins a cluster that's already there rather
    /// than start a rival one.
    pub listen_before_master_us: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            own_addr: None,
            peer_timeout_us: 5_000_000,
            source_stale_us: 2_000_000,
            transmit: None,
            listen_before_master_us: 2_000_000,
        }
    }
}

impl Config {
    /// Taking part as `tx.addr`.
    pub fn active(tx: TxConfig) -> Self {
        Self { own_addr: Some(tx.addr), transmit: Some(tx), ..Self::default() }
    }
}

/// Something for the radio to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Be on this channel (a fast hop).
    Hop(u8),
    /// Send this MPDU (no FCS) at a legacy rate, in 500 kb/s.
    Transmit {
        /// The frame.
        mpdu: Vec<u8>,
        /// The rate.
        rate_500kbps: u8,
        /// What it is, for logs.
        kind: TxKind,
    },
}

/// What a transmitted frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxKind {
    /// A Periodic Synchronization Frame.
    Psf,
    /// A Master Indication Frame.
    Mif,
    /// An answer to a peer's Block Ack setup.
    AddbaResponse,
    /// A data frame carrying a host packet.
    Data,
}

/// Packets waiting for their peer to be on our channel are dropped after
/// this, µs.
const PACKET_MAX_WAIT_US: u64 = 2_000_000;

/// A packet waiting to go out as a data frame.
#[derive(Clone, Debug)]
struct Queued {
    to: MacAddr,
    ethertype: u16,
    payload: Vec<u8>,
    since: u64,
}

#[derive(Clone, Debug, Default)]
struct TxState {
    queue: std::collections::VecDeque<Queued>,
    data_seq: u16,
    sequence_number: u16,
    tuned: Option<u8>,
    /// A hop was just handed out; poll again once it's done.
    repoll: bool,
    last_mif_slot: Option<u16>,
    last_psf: Option<u64>,
    self_counter: u32,
}

impl TxState {
    fn next_sequence_number(&mut self) -> u16 {
        self.sequence_number = (self.sequence_number + 1) & 0x0fff;
        self.sequence_number
    }
}

/// Something that changed, or arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A data frame for us (or multicast): its payload, for the host.
    Packet {
        /// The sender.
        from: MacAddr,
        /// Us, or a multicast group.
        to: MacAddr,
        /// The payload's EtherType (0x86dd, IPv6, in practice).
        ethertype: u16,
        /// The payload.
        payload: Vec<u8>,
    },
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
    /// The master's channel, as it reports it.
    pub master_channel: Option<u8>,
    /// Its latest channel sequences as sent: embedded in its sync parameters
    /// (legacy encoding) and in TLV 18.
    pub sequence_legacy: Option<ChannelSequence<'static>>,
    /// See `sequence_legacy`.
    pub sequence_tlv18: Option<ChannelSequence<'static>>,
    /// Its country code (data path state).
    pub country: Option<[u8; 3]>,
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
            master_channel: None,
            sequence_legacy: None,
            sequence_tlv18: None,
            country: None,
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

/// Our channel sequence as master, as sent and as a schedule.
#[derive(Clone, Debug)]
struct OwnSequence {
    legacy: ChannelSequence<'static>,
    tlv18: ChannelSequence<'static>,
    schedule: ChannelSchedule,
}

/// The AWDL engine. See the crate docs.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    config: Config,
    peers: BTreeMap<MacAddr, Peer>,
    master: Option<MacAddr>,
    source: Option<MacAddr>,
    outbox: Vec<Action>,
    tx: TxState,
    /// Our sequence, for when we're master.
    own_sequence: Option<OwnSequence>,
    /// Our AW grid while we're master.
    own_clock: Option<OwnClock>,
    /// The first moment we saw, for the listening period.
    first_tsf: Option<u64>,
    /// Events from elections run by `poll`, handed out with the next
    /// `on_frame` or `on_tick`.
    pending: Vec<Event>,
}

impl Engine {
    /// An engine with no peers.
    pub fn new(config: Config) -> Self {
        let own_sequence = config.transmit.as_ref().map(|tx| {
            let (legacy, tlv18) = active::master_sequences(tx);
            let schedule = ChannelSchedule::from_sequence(&legacy).expect("16 slots");
            OwnSequence { legacy, tlv18, schedule }
        });
        Self { config, own_sequence, ..Self::default() }
    }

    /// Whether we're the cluster's master.
    pub fn is_master(&self) -> bool {
        self.master.is_some() && self.master == self.config.own_addr
    }

    /// Feeds one received MPDU (no radiotap, no FCS).
    pub fn on_frame(&mut self, meta: RxMeta, mpdu: &[u8]) -> Vec<Event> {
        self.first_tsf.get_or_insert(meta.tsf);
        let mut events = std::mem::take(&mut self.pending);
        events.extend(self.expire(meta.tsf));
        if let (Some(tx), Ok(Some(req))) = (&self.config.transmit, AddbaRequest::parse(mpdu)) {
            if req.to == tx.addr {
                let n = self.tx.next_sequence_number();
                let mpdu = if req.tid() == 0 { req.accept(n) } else { req.decline(n) };
                self.outbox.push(Action::Transmit { mpdu, rate_500kbps: tx.rate_500kbps, kind: TxKind::AddbaResponse });
            }
            return events;
        }
        let Ok(Some(frame)) = parse(mpdu) else { return events };
        let src = frame.header().source();
        if Some(src) == self.config.own_addr || src.is_multicast() {
            return events;
        }
        match &frame {
            Frame::Data { header, data } => {
                if let Some(p) = self.peers.get_mut(&src) {
                    p.last_seen = meta.tsf;
                    p.data_frames += 1;
                }
                let to = header.destination();
                if to.is_multicast() || Some(to) == self.config.own_addr {
                    events.push(Event::Packet {
                        from: src,
                        to,
                        ethertype: data.ethertype,
                        payload: data.payload.to_vec(),
                    });
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
                            p.master_channel = Some(s.master_channel);
                            p.sequence_legacy = Some(s.channel_sequence.into_owned());
                        }
                        Ok(TlvBody::ChannelSequence(c)) => {
                            from_tlv18 = ChannelSchedule::from_sequence(&c.sequence);
                            p.sequence_tlv18 = Some(c.sequence.into_owned());
                        }
                        Ok(TlvBody::DataPathState(d)) => p.country = d.country_code.or(p.country),
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
        self.first_tsf.get_or_insert(tsf);
        let mut events = std::mem::take(&mut self.pending);
        events.extend(self.expire(tsf));
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

    /// The cluster's master is the best master named by a peer we can follow
    /// right now: its clock is locked and its last sync claim is fresh. A
    /// master named only by peers we hear now and then is another cluster's,
    /// and chasing it loses sync. Live, an iOS device we heard sporadically
    /// outranked the Mac we were synced to, though the Mac kept itself master.
    /// We sync to the master if we hear it, else to the peer closest to it;
    /// the current choice is kept while nothing strictly better is heard.
    fn elect(&mut self, now: u64) -> Vec<Event> {
        let mut events = Vec::new();
        let stale = self.config.source_stale_us;
        let followable = |p: &Peer| {
            p.clock.is_locked() && p.last_claim.is_some_and(|(c, _)| now.saturating_sub(c.rx_tsf) <= stale)
        };
        let own = self.config.own_addr;
        let theirs = self
            .peers
            .values()
            .filter(|p| followable(p))
            .filter_map(|p| p.election.map(|e| e.master_rank()))
            .filter(|r| Some(r.addr) != own)
            .max();
        // A taking-part engine stands too, once it has listened long enough
        // to have heard a cluster that's already there.
        let listened = self.first_tsf.is_some_and(|t| now.saturating_sub(t) >= self.config.listen_before_master_us);
        let ours = self.config.transmit.as_ref().filter(|_| listened).map(|tx| MasterRank {
            metric: tx.self_metric,
            counter: self.tx.self_counter,
            addr: tx.addr,
        });
        // We stand only if we outrank every master that anyone we hear names,
        // followable yet or not: while we lock on to a better one, we wait
        // rather than start a rival cluster. (Peers drop out after
        // `peer_timeout_us` of silence, so a vanished master stops counting.)
        let heard = self
            .peers
            .values()
            .filter_map(|p| p.election.map(|e| e.master_rank()))
            .filter(|r| Some(r.addr) != own)
            .max();
        let master = match (ours, heard) {
            (Some(o), h) if h.is_none_or(|h| o > h) => Some(o.addr),
            _ => theirs.map(|r| r.addr),
        };
        if master != self.master {
            self.own_clock = if master.is_some() && master == own {
                // Carry on the grid we were following, so its members keep
                // their places; or, with none (or by choice), start one.
                let fresh = self.config.transmit.as_ref().is_some_and(|tx| tx.master_fresh_grid);
                Some(match self.position(now).filter(|_| !fresh) {
                    Some(p) => OwnClock { origin: p.start_tsf, seq_at_origin: p.aw_seq },
                    None => OwnClock { origin: now, seq_at_origin: (now / AW_US) as u16 },
                })
            } else {
                None
            };
            self.master = master;
            events.push(Event::MasterChanged(master));
        }
        // A master syncs to no one.
        if self.is_master() {
            if self.source.is_some() {
                self.source = None;
                events.push(Event::SyncSourceChanged(None));
            }
            return events;
        }
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
        if self.is_master() {
            return self.own_clock.map(|c| c.position(tsf));
        }
        let clock = &self.sync_source()?.clock;
        clock.is_locked().then(|| clock.position(tsf)).flatten()
    }

    /// When the cluster's next AW after `tsf` starts.
    fn next_boundary(&self, tsf: u64) -> Option<u64> {
        if self.is_master() {
            return self.own_clock.map(|c| c.next_boundary(tsf));
        }
        self.sync_source()?.clock.next_boundary(tsf)
    }

    /// What to do now, at TSF `now`: answers owed to peers (ADDBA), the
    /// channel to be on, and our PSFs and MIFs. Only an engine configured to
    /// transmit, and synced to a locked peer, sends anything of its own; until
    /// then we stay silent rather than advertise a guess.
    pub fn poll(&mut self, now: u64) -> Vec<Action> {
        // Elections run here too, so a lone engine becomes master without
        // hearing anything.
        self.first_tsf.get_or_insert(now);
        let events = self.elect(now);
        self.pending.extend(events);
        let mut out = std::mem::take(&mut self.outbox);
        let Some(tx) = self.config.transmit.clone() else { return out };
        if self.follower_view(now).is_none() {
            return out;
        }
        let Some((pos, channel, explicit)) = self.schedule_at(now) else { return out };
        if self.tx.tuned != Some(channel) {
            self.tx.tuned = Some(channel);
            out.push(Action::Hop(channel));
            // Build nothing until the hop is done: a frame's sync claims
            // count from when it is built, and a retune can take as long as
            // an AW. Frames built before one claimed our slots an AW late
            // (seen by a Mac). next_wakeup asks for the next poll at once.
            self.tx.repoll = true;
            return out;
        }
        self.tx.repoll = false;
        if pos.offset_us < TX_FROM_US || pos.offset_us > TX_UNTIL_US {
            return out;
        }
        self.send_queued(now, pos.aw_seq, channel, &tx, &mut out);
        // One MIF per explicit slot; otherwise a PSF when its period is up.
        let slot = pos.aw_seq / AWS_PER_SLOT;
        let kind = if explicit && self.tx.last_mif_slot != Some(slot) {
            self.tx.last_mif_slot = Some(slot);
            TxKind::Mif
        } else if self.tx.last_psf.is_none_or(|t| now.saturating_sub(t) >= tx.psf_interval_tu as u64 * TU_US) {
            self.tx.last_psf = Some(now);
            TxKind::Psf
        } else {
            return out;
        };
        let n = self.tx.next_sequence_number();
        let self_counter = self.tx.self_counter;
        let view = FollowerView { channel, ..self.follower_view(now).expect("checked above") };
        let st = if kind == TxKind::Mif { subtype::MIF } else { subtype::PSF };
        let mpdu = active::build(&tx, &view, st, self_counter, n);
        out.push(Action::Transmit { mpdu, rate_500kbps: tx.rate_500kbps, kind });
        out
    }

    /// Queues a packet for a peer (or a multicast group) as an AWDL data
    /// frame. [`Engine::poll`] sends it in the next transmit window where the
    /// peer's own sequence puts it on our channel; multicast goes in the next
    /// window. Packets that can't go out within 2 s are dropped.
    pub fn send_packet(&mut self, now: u64, to: MacAddr, ethertype: u16, payload: Vec<u8>) {
        self.tx.queue.push_back(Queued { to, ethertype, payload, since: now });
    }

    fn send_queued(&mut self, now: u64, aw_seq: u16, channel: u8, tx: &TxConfig, out: &mut Vec<Action>) {
        let mut keep = std::collections::VecDeque::new();
        while let Some(q) = self.tx.queue.pop_front() {
            if now.saturating_sub(q.since) > PACKET_MAX_WAIT_US {
                continue;
            }
            let reachable = q.to.is_multicast()
                || self.peers.get(&q.to).and_then(|p| p.schedule).and_then(|s| s.channel_at(aw_seq)) == Some(channel);
            if !reachable {
                keep.push_back(q);
                continue;
            }
            let n = self.tx.next_sequence_number();
            self.tx.data_seq = self.tx.data_seq.wrapping_add(1);
            let mut mpdu = Vec::with_capacity(40 + q.payload.len());
            Frame::Data {
                header: awdl_proto::ieee80211::Header::data(tx.addr, q.to, n),
                data: awdl_proto::data::DataFrame::new(self.tx.data_seq, q.ethertype, &q.payload),
            }
            .emit(&mut mpdu);
            out.push(Action::Transmit { mpdu, rate_500kbps: tx.rate_500kbps, kind: TxKind::Data });
        }
        self.tx.queue = keep;
    }

    /// When to call [`Engine::poll`] next, if something is due before the
    /// next frame: the next AW's transmit window, or now if answers are owed.
    pub fn next_wakeup(&self, now: u64) -> Option<u64> {
        if !self.outbox.is_empty() || self.tx.repoll {
            return Some(now);
        }
        self.config.transmit.as_ref()?;
        let Some(pos) = self.position(now) else {
            // No grid to time to yet. Look again in an AW: the election may
            // make us master, or a clock may lock.
            return Some(now + AW_US);
        };
        if pos.offset_us < TX_FROM_US {
            Some(pos.start_tsf + TX_FROM_US as u64)
        } else {
            Some(self.next_boundary(now)? + TX_FROM_US as u64)
        }
    }

    /// Our AW position, the channel our sequence (as master) or the sync
    /// source's puts us on at `now`, and whether that slot names it
    /// explicitly.
    fn schedule_at(&self, now: u64) -> Option<(AwPosition, u8, bool)> {
        let pos = self.position(now)?;
        let sched = if self.is_master() { self.own_sequence.as_ref()?.schedule } else { self.sync_source()?.schedule? };
        Some((pos, sched.channel_at(pos.aw_seq)?, sched.is_explicit(pos.aw_seq)))
    }

    /// The cluster as our frames describe it: as master, ourselves and our
    /// own grid and sequence; otherwise we follow the sync source, one hop
    /// further from the master than it is.
    fn follower_view(&self, now: u64) -> Option<FollowerView<'_>> {
        if self.is_master() {
            let tx = self.config.transmit.as_ref()?;
            let seq = self.own_sequence.as_ref()?;
            let clock = self.own_clock?;
            let pos = clock.position(now);
            let channel = seq.schedule.channel_at(pos.aw_seq)?;
            return Some(FollowerView {
                now,
                channel,
                master: tx.addr,
                master_channel: channel,
                master_metric: tx.self_metric,
                master_counter: self.tx.self_counter,
                distance: 0,
                sync_parent: tx.addr,
                aw_seq: pos.aw_seq,
                next_boundary: clock.next_boundary(now),
                sequence_legacy: &seq.legacy,
                sequence_tlv18: Some(&seq.tlv18),
                country: self.peers.values().find_map(|p| p.country).unwrap_or(*b"US\0"),
            });
        }
        let master = self.master?;
        let src = self.sync_source()?;
        let e = src.election?;
        let pos = self.position(now)?;
        Some(FollowerView {
            now,
            channel: src.channel,
            master,
            master_channel: src.master_channel.unwrap_or(src.channel),
            master_metric: e.master_metric,
            master_counter: e.master_counter.unwrap_or(0),
            distance: if src.addr == master { 1 } else { e.distance + 1 },
            sync_parent: src.addr,
            aw_seq: pos.aw_seq,
            next_boundary: src.clock.next_boundary(now)?,
            sequence_legacy: src.sequence_legacy.as_ref()?,
            sequence_tlv18: src.sequence_tlv18.as_ref(),
            country: src.country.unwrap_or(*b"US\0"),
        })
    }
}
