// SPDX-License-Identifier: GPL-2.0-only
//! The API server: `api/openapi.yaml` over HTTP/1.1 on a named pipe, served
//! by hyper. (Not axum: it depends on `sync_wrapper`, which is Apache-2.0
//! only and so can't go into a GPL-2.0 program; `deny.toml`.)
//!
//! The daemon's engine runs on its own thread; the server runs on a Tokio
//! runtime of its own. They meet in three channels:
//! - [`State`], published by the daemon (`watch`): what the GET endpoints
//!   and lock streams report;
//! - [`Event`]s, sent by the daemon (`broadcast`): `GET /v1/events`;
//! - [`Wants`], published by the server (`watch`): the service types and
//!   holds that open locks ask for, which the daemon acts on.
//!
//! A fourth, captures (`crate::capture`), carries radio frames to
//! `GET /v1/capture` streams, queued per capture so the radio never waits.
//!
//! A lock (`POST /v1/advertising`, `POST /v1/holds`) is registered for as
//! long as its response stream exists. Hyper drops the stream when the
//! connection ends, and the stream's guard then releases the lock. A line
//! goes out at least every [`HEARTBEAT`]; in practice hyper notices a closed
//! pipe at once, and the heartbeat is the backstop.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{broadcast, watch};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tracing::{debug, info, warn};

use crate::capture::{Captures, Filter, Frame as RadioFrame};
use crate::pipe::{Client, PipeListener, Security};
use warlock_client::types::*;

/// The longest a lock stream goes without a line.
pub const HEARTBEAT: Duration = Duration::from_secs(2);

/// The largest request body accepted.
const MAX_BODY: usize = 64 * 1024;

/// What the daemon reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub info: Info,
    pub peers: Vec<Peer>,
    /// The instances in our frames, by service type (`_x._tcp`, lowercase).
    pub advertised: BTreeMap<String, Vec<String>>,
}

/// What open locks ask of the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    /// Service types to advertise (`_x._tcp`, lowercase).
    pub types: BTreeSet<String>,
    /// Open holds.
    pub holds: usize,
}

/// The daemon's end of the channels. Nothing here blocks or needs a runtime.
pub struct Daemon {
    state: watch::Sender<State>,
    events: broadcast::Sender<Event>,
    wants: watch::Receiver<Wants>,
    captures: Arc<Captures>,
}

impl Daemon {
    /// Whether any capture is open: one atomic load, for the radio loop to
    /// skip building [`crate::Frame`]s when no one captures.
    pub fn capturing(&self) -> bool {
        self.captures.active()
    }

    /// Offers a frame to the open captures. Never blocks: a capture that
    /// can't keep up drops frames, and says so in its stream.
    pub fn capture(&self, frame: &RadioFrame) {
        self.captures.offer(frame);
    }

    /// Replaces the state the API reports.
    pub fn publish(&self, state: State) {
        self.state.send_if_modified(|s| {
            let changed = *s != state;
            *s = state;
            changed
        });
    }

    /// The state the API reports now.
    pub fn state(&self) -> State {
        self.state.borrow().clone()
    }

    /// Sends an event to every `GET /v1/events` stream.
    pub fn event(&self, event: Event) {
        // No receivers is fine.
        let _ = self.events.send(event);
    }

    /// What locks ask for, if it changed since the last call.
    pub fn wants(&mut self) -> Option<Wants> {
        self.wants.has_changed().unwrap_or(false).then(|| self.wants.borrow_and_update().clone())
    }

    /// What locks ask for now, changed or not.
    pub fn wants_now(&self) -> Wants {
        self.wants.borrow().clone()
    }
}

/// The running server. Dropping it stops the server, ending every stream.
pub struct Server {
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl Server {
    /// Serves the API on the pipe `name`, reporting `initial` until the
    /// daemon publishes. Fails if the pipe exists already.
    pub fn start(name: &str, security: Security, initial: State) -> io::Result<(Server, Daemon)> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("warlock-api")
            .enable_all()
            .build()?;
        let bound = {
            let _entered = runtime.enter();
            PipeListener::bind(name, security)
        };
        let mut listener = match bound {
            Ok(l) => l,
            Err(e) => {
                // Dropping a runtime blocks, which panics if the caller is async.
                runtime.shutdown_background();
                return Err(e);
            }
        };
        let (state_tx, state_rx) = watch::channel(initial);
        let (events, _) = broadcast::channel(1024);
        let (wants_tx, wants_rx) = watch::channel(Wants::default());
        let captures = Arc::new(Captures::default());
        let app = App {
            state: state_rx,
            events: events.clone(),
            locks: Arc::new(Mutex::new(Locks::default())),
            wants: Arc::new(wants_tx),
            captures: captures.clone(),
        };
        runtime.spawn(async move {
            loop {
                let (pipe, client) = listener.accept().await;
                let app = app.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let app = app.clone();
                        async move { Ok::<_, Infallible>(app.handle(client, request).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(TokioIo::new(pipe), service).await {
                        // A lock's client hanging up ends its connection this way.
                        debug!("connection ended: {e}");
                    }
                });
            }
        });
        Ok((Server { runtime: Some(runtime) }, Daemon { state: state_tx, events, wants: wants_rx, captures }))
    }
}

/// Every operation in `api/openapi.yaml`, as (method, path): the contract
/// test checks this against the document.
pub const OPERATIONS: [(&str, &str); 9] = [
    ("get", "/v1/info"),
    ("get", "/v1/peers"),
    ("get", "/v1/peers/{address}"),
    ("get", "/v1/advertising"),
    ("post", "/v1/advertising"),
    ("get", "/v1/holds"),
    ("post", "/v1/holds"),
    ("get", "/v1/events"),
    ("get", "/v1/capture"),
];

/// A capture's media type: pcapng, as Wireshark names it.
pub const PCAPNG: &str = "application/x-pcapng";

#[derive(Clone)]
struct App {
    state: watch::Receiver<State>,
    events: broadcast::Sender<Event>,
    locks: Arc<Mutex<Locks>>,
    wants: Arc<watch::Sender<Wants>>,
    captures: Arc<Captures>,
}

/// One open lock.
struct Lock {
    /// The service type or the hold's reason.
    what: String,
    owner: Owner,
}

#[derive(Default)]
struct Locks {
    next_id: u64,
    advertising: BTreeMap<u64, Lock>,
    holds: BTreeMap<u64, Lock>,
}

impl Locks {
    fn wants(&self) -> Wants {
        Wants { types: self.advertising.values().map(|l| l.what.clone()).collect(), holds: self.holds.len() }
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Advertising,
    Hold,
}

/// Releases its lock when dropped.
struct Guard {
    id: u64,
    kind: Kind,
    locks: Arc<Mutex<Locks>>,
    wants: Arc<watch::Sender<Wants>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().unwrap();
        let lock = match self.kind {
            Kind::Advertising => locks.advertising.remove(&self.id),
            Kind::Hold => locks.holds.remove(&self.id),
        };
        if let Some(l) = lock {
            info!(kind = ?self.kind, what = l.what, pid = l.owner.pid, "lock released");
        }
        self.wants.send_replace(locks.wants());
    }
}

/// `t` as RFC 3339, in UTC, to the second.
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Days to a civil date: Howard Hinnant, "chrono-Compatible Low-Level Date
    // Algorithms", civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

type Body = UnsyncBoxBody<Bytes, Infallible>;

fn respond(status: StatusCode, content_type: &'static str, body: Body) -> Response<Body> {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    r
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let bytes = serde_json::to_vec(value).expect("our types serialize");
    respond(status, "application/json", Full::new(Bytes::from(bytes)).boxed_unsync())
}

fn ok<T: Serialize>(value: &T) -> Response<Body> {
    json(StatusCode::OK, value)
}

fn error(status: StatusCode, message: String) -> Response<Body> {
    json(status, &Error { message })
}

/// One JSON Lines line.
fn line<T: Serialize>(value: &T) -> Bytes {
    let mut v = serde_json::to_vec(value).expect("our types serialize");
    v.push(b'\n');
    Bytes::from(v)
}

fn jsonl(lines: impl Stream<Item = Bytes> + Send + 'static) -> Response<Body> {
    let body = StreamBody::new(lines.map(|b| Ok::<_, Infallible>(Frame::data(b))));
    respond(StatusCode::OK, "application/jsonl", body.boxed_unsync())
}

/// `%XX` escapes in a path segment or query value, decoded.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(h), Some(l)) = (bytes.get(i + 1).and_then(|&b| hex(b)), bytes.get(i + 2).and_then(|&b| hex(b)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A request body as `T`, or what's wrong with it.
async fn body<T: DeserializeOwned>(request: Request<Incoming>) -> Result<T, String> {
    let bytes = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return Err(format!("can't read the body: {e}")),
    };
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid body: {e}"))
}

impl App {
    async fn handle(self, client: Client, request: Request<Incoming>) -> Response<Body> {
        let path = request.uri().path().to_string();
        let method = request.method().clone();
        if let Some(address) = path.strip_prefix("/v1/peers/").filter(|a| !a.is_empty() && !a.contains('/')) {
            return match method {
                Method::GET => self.peer(&percent_decode(address)),
                _ => not_allowed("GET"),
            };
        }
        match (method, path.as_str()) {
            (Method::GET, "/v1/info") => ok(&self.state.borrow().info),
            (Method::GET, "/v1/peers") => ok(&self.state.borrow().peers),
            (Method::GET, "/v1/advertising") => self.advertising(),
            (Method::POST, "/v1/advertising") => self.advertise(client, request).await,
            (Method::GET, "/v1/holds") => self.holds(),
            (Method::POST, "/v1/holds") => self.hold(client, request).await,
            (Method::GET, "/v1/events") => self.events(),
            (Method::GET, "/v1/capture") => self.capture(client, request.uri().query()),
            (_, "/v1/info" | "/v1/peers" | "/v1/events" | "/v1/capture") => not_allowed("GET"),
            (_, "/v1/advertising" | "/v1/holds") => not_allowed("GET, POST"),
            _ => error(StatusCode::NOT_FOUND, "no such endpoint".into()),
        }
    }

    fn peer(&self, address: &str) -> Response<Body> {
        let wanted = address.to_ascii_lowercase();
        match self.state.borrow().peers.iter().find(|p| p.address == wanted) {
            Some(p) => ok(p),
            None => error(StatusCode::NOT_FOUND, format!("no peer {address}")),
        }
    }

    fn advertising(&self) -> Response<Body> {
        let state = self.state.borrow().clone();
        let mut by_type: BTreeMap<String, Vec<Owner>> = BTreeMap::new();
        for l in self.locks.lock().unwrap().advertising.values() {
            by_type.entry(l.what.clone()).or_default().push(l.owner.clone());
        }
        let list: Vec<AdvertisedType> = by_type
            .into_iter()
            .map(|(t, owners)| AdvertisedType {
                instances: state.advertised.get(&t).cloned().unwrap_or_default(),
                service_type: t,
                owners,
            })
            .collect();
        ok(&list)
    }

    fn holds(&self) -> Response<Body> {
        let locks = self.locks.lock().unwrap();
        let list: Vec<Hold> =
            locks.holds.values().map(|l| Hold { reason: l.what.clone(), owner: l.owner.clone() }).collect();
        ok(&list)
    }

    fn acquire(&self, kind: Kind, what: String, client: Client) -> Guard {
        let owner = Owner { pid: client.pid.unwrap_or(0), image: client.image(), since: rfc3339(SystemTime::now()) };
        info!(?kind, what, pid = owner.pid, image = owner.image, "lock taken");
        let mut locks = self.locks.lock().unwrap();
        let id = locks.next_id;
        locks.next_id += 1;
        let lock = Lock { what, owner };
        match kind {
            Kind::Advertising => locks.advertising.insert(id, lock),
            Kind::Hold => locks.holds.insert(id, lock),
        };
        self.wants.send_replace(locks.wants());
        Guard { id, kind, locks: self.locks.clone(), wants: self.wants.clone() }
    }

    async fn advertise(&self, client: Client, request: Request<Incoming>) -> Response<Body> {
        let request: AdvertiseRequest = match body(request).await {
            Ok(r) => r,
            Err(message) => return error(StatusCode::BAD_REQUEST, message),
        };
        if !is_service_type(&request.service_type) {
            let message = format!("{:?} isn't a service type such as _rdlink._tcp", request.service_type);
            return error(StatusCode::BAD_REQUEST, message);
        }
        let service_type = request.service_type.to_ascii_lowercase();
        let guard = self.acquire(Kind::Advertising, service_type.clone(), client);
        jsonl(lock_stream(guard, self.state.clone(), move |s| AdvertisingState {
            instances: s.advertised.get(&service_type).cloned().unwrap_or_default(),
            service_type: service_type.clone(),
        }))
    }

    async fn hold(&self, client: Client, request: Request<Incoming>) -> Response<Body> {
        let request: HoldRequest = match body(request).await {
            Ok(r) => r,
            Err(message) => return error(StatusCode::BAD_REQUEST, message),
        };
        let guard = self.acquire(Kind::Hold, request.reason, client);
        jsonl(lock_stream(guard, self.state.clone(), |s| HoldState { active: s.info.radio.state == RadioState::Up }))
    }

    fn capture(&self, client: Client, query: Option<&str>) -> Response<Body> {
        let filter = match Filter::parse(query) {
            Ok(f) => f,
            Err(message) => return error(StatusCode::BAD_REQUEST, message),
        };
        let chunks = self.captures.open(filter, client.pid.unwrap_or(0), client.image());
        let body = StreamBody::new(chunks.map(|b| Ok::<_, Infallible>(Frame::data(b))));
        respond(StatusCode::OK, PCAPNG, body.boxed_unsync())
    }

    fn events(&self) -> Response<Body> {
        let rx = self.events.subscribe();
        jsonl(futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(e) => return Some((line(&e), rx)),
                    Err(broadcast::error::RecvError::Lagged(n)) => warn!("an event stream fell behind by {n} events"),
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }))
    }
}

fn not_allowed(allow: &'static str) -> Response<Body> {
    let mut r = error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into());
    r.headers_mut().insert(header::ALLOW, HeaderValue::from_static(allow));
    r
}

/// A lock's stream: `report` turns the state into a line, sent when it
/// changes and at least every [`HEARTBEAT`]. Owns the lock's guard.
fn lock_stream<T: Serialize + PartialEq + Send + 'static>(
    guard: Guard,
    state: watch::Receiver<State>,
    report: impl Fn(&State) -> T + Send + 'static,
) -> impl Stream<Item = Bytes> + Send + 'static {
    let mut tick = interval_at(Instant::now() + HEARTBEAT, HEARTBEAT);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let start = (guard, state, tick, None::<T>, report);
    futures_util::stream::unfold(start, |(guard, mut state, mut tick, mut last, report)| async move {
        loop {
            let now = report(&state.borrow_and_update());
            if last.as_ref() != Some(&now) {
                let out = line(&now);
                last = Some(now);
                tick.reset();
                return Some((out, (guard, state, tick, last, report)));
            }
            tokio::select! {
                changed = state.changed() => {
                    if changed.is_err() {
                        // The daemon is gone: the stream, and the lock, end.
                        return None;
                    }
                }
                _ = tick.tick() => {
                    return Some((line(&now), (guard, state, tick, last, report)));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(1_000_000_000)), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(4_102_444_799)), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn percent_escapes_decode() {
        assert_eq!(percent_decode("02%3A00%3a00:00:00:01"), "02:00:00:00:00:01");
        assert_eq!(percent_decode("100%"), "100%");
    }
}
