// SPDX-License-Identifier: GPL-2.0-only
//! Captures (`GET /v1/capture`): the frames the radio hears, and those it
//! sends if asked, as radiotap pcapng, for as long as the request lasts. Like
//! `GET /v1/events`, a capture holds nothing.
//!
//! The daemon offers every frame to [`Captures::offer`]; while no one
//! captures, that costs one atomic load. Each capture has a bounded queue.
//! When its client reads too slowly, frames are dropped rather than holding
//! up the radio, and the next frame it gets carries the count
//! (`epb_dropcount`, which Wireshark shows).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use tokio::sync::mpsc;
use tracing::info;
use warlock_capture::{Direction, Extra, Writer, freq_of};

use crate::server::percent_decode;

/// Frames queued for one capture before it starts dropping them.
const QUEUE: usize = 4096;

/// What a frame is to Warlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// AWDL: an action frame or AWDL-encapsulated data, which Warlock reads.
    Awdl,
    /// Anything else the radio hears.
    Other,
}

/// A frame offered to captures.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    /// Sent by Warlock, rather than received.
    pub sent: bool,
    pub kind: FrameKind,
    /// The radio's TSF, µs.
    pub tsf: u64,
    pub channel: u8,
    /// The signal of a received frame; 0 for a sent one.
    pub rssi_dbm: i8,
    /// The MPDU, without FCS.
    pub mpdu: &'a [u8],
}

/// What a capture asks for: the query of `GET /v1/capture`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filter {
    /// Frames to or from these addresses; every frame when empty.
    pub peers: Vec<[u8; 6]>,
    pub awdl: bool,
    pub other: bool,
    /// Warlock's own transmissions too.
    pub sent: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self { peers: Vec::new(), awdl: true, other: true, sent: false }
    }
}

impl Filter {
    /// Parses a query: `peer=MAC` (repeatable), `kind=awdl|other|all`,
    /// `tx=true|false`.
    pub fn parse(query: Option<&str>) -> Result<Self, String> {
        let mut f = Filter::default();
        for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key {
                "peer" => f.peers.push(
                    parse_mac(&value)
                        .ok_or_else(|| format!("{value:?} isn't a MAC address such as 76:56:82:58:57:70"))?,
                ),
                "kind" => {
                    (f.awdl, f.other) = match value.as_str() {
                        "awdl" => (true, false),
                        "other" => (false, true),
                        "all" => (true, true),
                        _ => return Err(format!("kind {value:?} isn't awdl, other or all")),
                    }
                }
                "tx" => {
                    f.sent = match value.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(format!("tx {value:?} isn't true or false")),
                    }
                }
                _ => return Err(format!("unknown parameter {key:?}")),
            }
        }
        Ok(f)
    }

    fn matches(&self, frame: &Frame) -> bool {
        let kind = match frame.kind {
            FrameKind::Awdl => self.awdl,
            FrameKind::Other => self.other,
        };
        kind && (!frame.sent || self.sent)
            && (self.peers.is_empty() || addresses(frame.mpdu).any(|a| self.peers.contains(&a)))
    }
}

/// `aa:bb:cc:dd:ee:ff`, either case.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in &mut out {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// An MPDU's addresses: the receiver and, where present, the transmitter;
/// for management and data frames, the third address too.
fn addresses(mpdu: &[u8]) -> impl Iterator<Item = [u8; 6]> + '_ {
    let count = match mpdu.first().map(|fc| (fc >> 2) & 3) {
        None => 0,
        Some(1) => 2, // control: RA, and TA when the frame has one
        Some(_) => 3,
    };
    (0..count).filter_map(move |i| mpdu.get(4 + 6 * i..10 + 6 * i)).filter_map(|a| <[u8; 6]>::try_from(a).ok())
}

/// A frame queued for one capture.
struct Queued {
    at: Duration,
    sent: bool,
    tsf: u64,
    channel: u8,
    rssi_dbm: i8,
    mpdu: Vec<u8>,
    dropped_before: u64,
}

struct Subscriber {
    filter: Filter,
    queue: mpsc::Sender<Queued>,
    /// Dropped since the last frame queued, for that frame to report.
    pending_drops: u64,
    dropped: Arc<AtomicU64>,
}

/// The open captures. The daemon offers frames; the server adds and removes
/// captures as requests come and go.
#[derive(Default)]
pub(crate) struct Captures {
    open: AtomicUsize,
    next_id: AtomicU64,
    subscribers: Mutex<BTreeMap<u64, Subscriber>>,
}

impl Captures {
    pub(crate) fn active(&self) -> bool {
        self.open.load(Ordering::Relaxed) > 0
    }

    /// Queues `frame` for every capture that wants it; never blocks.
    pub(crate) fn offer(&self, frame: &Frame) {
        if !self.active() {
            return;
        }
        let at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut subscribers = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        for s in subscribers.values_mut().filter(|s| s.filter.matches(frame)) {
            let queued = Queued {
                at,
                sent: frame.sent,
                tsf: frame.tsf,
                channel: frame.channel,
                rssi_dbm: frame.rssi_dbm,
                mpdu: frame.mpdu.to_vec(),
                dropped_before: s.pending_drops,
            };
            match s.queue.try_send(queued) {
                Ok(()) => s.pending_drops = 0,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    s.pending_drops += 1;
                    s.dropped.fetch_add(1, Ordering::Relaxed);
                }
                // The capture ended; its guard removes it.
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }

    /// Opens a capture, logged with its owner. It lasts as long as the
    /// returned stream.
    pub(crate) fn open(
        self: &Arc<Self>,
        filter: Filter,
        pid: u32,
        image: String,
    ) -> impl Stream<Item = Bytes> + Send + 'static {
        let (queue, rx) = mpsc::channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let peers: Vec<String> = filter.peers.iter().map(format_mac).collect();
        info!(id, pid, image, ?peers, awdl = filter.awdl, other = filter.other, sent = filter.sent, "capture started");
        let subscriber = Subscriber { filter, queue, pending_drops: 0, dropped: dropped.clone() };
        self.subscribers.lock().unwrap_or_else(|e| e.into_inner()).insert(id, subscriber);
        self.open.fetch_add(1, Ordering::Relaxed);
        let guard = Guard { id, pid, captures: self.clone(), dropped, written: 0 };
        let mut writer = Writer::radiotap(Vec::new()).expect("writing to memory");
        let header = Bytes::from(std::mem::take(writer.get_mut()));
        futures_util::stream::once(async move { header }).chain(futures_util::stream::unfold(
            (guard, rx, writer),
            |(mut guard, mut rx, mut writer)| async move {
                let f = rx.recv().await?;
                let extra = Extra {
                    direction: Some(if f.sent { Direction::Outbound } else { Direction::Inbound }),
                    dropped_before: f.dropped_before,
                };
                writer.write_with(f.at, f.tsf, freq_of(f.channel), f.rssi_dbm, &f.mpdu, extra).ok()?;
                guard.written += 1;
                let chunk = Bytes::from(std::mem::take(writer.get_mut()));
                Some((chunk, (guard, rx, writer)))
            },
        ))
    }
}

fn format_mac(a: &[u8; 6]) -> String {
    a.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Ends its capture when its stream is dropped, as when the client goes.
struct Guard {
    id: u64,
    pid: u32,
    captures: Arc<Captures>,
    dropped: Arc<AtomicU64>,
    written: u64,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let removed = self.captures.subscribers.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id).is_some();
        if removed {
            self.captures.open.fetch_sub(1, Ordering::Relaxed);
        }
        let dropped = self.dropped.load(Ordering::Relaxed);
        info!(id = self.id, pid = self.pid, frames = self.written, dropped, "capture ended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: [u8; 6] = [0x76, 0x56, 0x82, 0x58, 0x57, 0x70];

    /// A data frame from `from` to `to`, BSSID 00:25:00:ff:94:73.
    fn data(to: [u8; 6], from: [u8; 6]) -> Vec<u8> {
        [&[0x08, 0x00, 0, 0][..], &to, &from, &[0x00, 0x25, 0x00, 0xff, 0x94, 0x73], &[0, 0], b"body"].concat()
    }

    fn frame(mpdu: &[u8], kind: FrameKind, sent: bool) -> Frame<'_> {
        Frame { sent, kind, tsf: 1, channel: 149, rssi_dbm: -50, mpdu }
    }

    #[test]
    fn queries_parse() {
        assert_eq!(Filter::parse(None), Ok(Filter::default()));
        let f =
            Filter::parse(Some("peer=76%3A56%3A82%3A58%3A57%3A70&peer=02:00:00:00:00:01&kind=other&tx=true")).unwrap();
        assert_eq!(f.peers, [PEER, [2, 0, 0, 0, 0, 1]]);
        assert_eq!((f.awdl, f.other, f.sent), (false, true, true));
        assert!(Filter::parse(Some("peer=76:56:82")).is_err());
        assert!(Filter::parse(Some("kind=some")).is_err());
        assert!(Filter::parse(Some("tx=yes")).is_err());
        assert!(Filter::parse(Some("channel=6")).is_err());
    }

    #[test]
    fn filters_match_peers_kinds_and_direction() {
        let to_peer = data(PEER, [2, 0, 0, 0, 0, 1]);
        let between_others = data([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 3]);
        let ack = [0xd4, 0x00, 0, 0, 0x76, 0x56, 0x82, 0x58, 0x57, 0x70];
        let only_peer = Filter { peers: vec![PEER], ..Filter::default() };
        assert!(only_peer.matches(&frame(&to_peer, FrameKind::Awdl, false)));
        assert!(only_peer.matches(&frame(&ack, FrameKind::Other, false)));
        assert!(!only_peer.matches(&frame(&between_others, FrameKind::Awdl, false)));
        let other = Filter { awdl: false, ..Filter::default() };
        assert!(!other.matches(&frame(&to_peer, FrameKind::Awdl, false)));
        assert!(other.matches(&frame(&to_peer, FrameKind::Other, false)));
        assert!(!Filter::default().matches(&frame(&to_peer, FrameKind::Awdl, true)));
        assert!(Filter { sent: true, ..Filter::default() }.matches(&frame(&to_peer, FrameKind::Awdl, true)));
    }

    #[tokio::test]
    async fn a_slow_capture_drops_and_says_so() {
        let captures = Arc::new(Captures::default());
        assert!(!captures.active());
        let stream = captures.open(Filter::default(), 1, "test".into());
        assert!(captures.active());
        let mpdu = data(PEER, [2, 0, 0, 0, 0, 1]);
        for _ in 0..QUEUE + 5 {
            captures.offer(&frame(&mpdu, FrameKind::Awdl, false));
        }
        // The frame after the drops reports them.
        let mut stream = Box::pin(stream);
        let header = stream.next().await.unwrap();
        assert_eq!(&header[..4], &0x0A0D_0D0Au32.to_le_bytes(), "a pcapng section header first");
        for _ in 0..QUEUE {
            stream.next().await.unwrap();
        }
        captures.offer(&frame(&mpdu, FrameKind::Awdl, false));
        let last = stream.next().await.unwrap();
        // epb_dropcount: option code 4, length 8, the count.
        let option = [&4u16.to_le_bytes()[..], &8u16.to_le_bytes(), &5u64.to_le_bytes()].concat();
        assert!(last.windows(option.len()).any(|w| w == option), "the drop count rides on the next frame");
        drop(stream);
        assert!(!captures.active(), "a capture ends with its stream");
    }
}
