// SPDX-License-Identifier: GPL-2.0-only
//! Requests (`POST /v1/request`, `api/openapi.yaml`): asking nearby Apple
//! devices to bring a service up on AWDL. A program says only which service;
//! Warlock builds what it sends (`continuity`), and sends it from this
//! computer's own Bluetooth (`bluetooth`), reading the address Windows sends
//! it from out of the controller's trace (`hci`).
//!
//! It needs nothing of the AWDL radio, so it runs on a thread of its own,
//! talking to the API through [`warlock_api::Requests`].
//!
//! - `_rdlink._tcp`: a Nearby Action "RDLink needs AWDL", with an auth tag
//!   that identifies the program to an iPhone paired with it. Each request
//!   gets an advert and an IRK of its own; the program pairs with the IRK
//!   (Koala, as `altIRK`). If the advert stops (Bluetooth off), it starts
//!   again from a new address, with a new IRK.

mod bluetooth;
mod continuity;
mod hci;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tracing::{info, warn};
use warlock_api::types::Identity;
use warlock_api::{RequestStatus, Requests};

use bluetooth::Advert;
use continuity::{APPLE, nearby_action};
use hci::HciTrace;

/// The service types Warlock can ask for (`GET /v1/info`'s `requestable`).
pub const REQUESTABLE: &[&str] = &["_rdlink._tcp"];

/// How often the open requests and their adverts are looked at.
const POLL: Duration = Duration::from_millis(100);
/// How long an advert that couldn't start, or stopped, waits to try again.
const RETRY: Duration = Duration::from_secs(5);
/// How long Windows has to show an advert's address in the trace.
const ADDRESS_WAIT: Duration = Duration::from_secs(5);

/// What a run is told about requests.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Set the Nearby Action's needs-keyboard bit (`--needs-keyboard`): a
    /// trial's override, never the default (`continuity`'s `NEEDS_KEYBOARD`).
    pub needs_keyboard: bool,
}

/// Serves requests until dropped.
pub struct Asker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Asker {
    pub fn start(requests: Requests, options: Options) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("warlock-request".into())
            .spawn(move || serve(requests, options, &flag))?;
        Ok(Self { stop, thread: Some(thread) })
    }
}

impl Drop for Asker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut requests: Requests, options: Options, stop: &AtomicBool) {
    if options.needs_keyboard {
        warn!("requests set the needs-keyboard bit (--needs-keyboard): a trial's override");
    }
    let mut wanted: BTreeMap<u64, String> = BTreeMap::new();
    let mut asks: BTreeMap<u64, Ask> = BTreeMap::new();
    while !stop.load(Ordering::Relaxed) {
        if let Some(now) = requests.wanted() {
            // Dropping an ask stops its advert.
            asks.retain(|id, _| now.contains_key(id));
            wanted = now;
        }
        for (id, service) in &wanted {
            asks.entry(*id).or_insert_with(|| Ask::new(service)).poll(options);
            if stop.load(Ordering::Relaxed) {
                break;
            }
        }
        requests.publish(asks.iter().map(|(id, a)| (*id, a.status())).collect());
        std::thread::sleep(POLL);
    }
}

/// One request's ask.
struct Ask {
    service: String,
    /// The advert, while it's sent, and the IRK that fits it.
    advert: Option<(Advert, [u8; 16])>,
    message: Option<String>,
    retry: Option<Instant>,
}

impl Ask {
    fn new(service: &str) -> Self {
        Self { service: service.into(), advert: None, message: None, retry: None }
    }

    fn poll(&mut self, options: Options) {
        if let Some((advert, _)) = &self.advert {
            if advert.running() {
                return;
            }
            warn!(service = self.service, "Bluetooth stopped the advert; it starts again with a new identity");
            self.advert = None;
            self.message = Some("Bluetooth stopped the advert: is it off?".into());
            self.retry = Some(Instant::now() + RETRY);
        }
        if self.retry.is_some_and(|at| Instant::now() < at) {
            return;
        }
        match start(&self.service, options) {
            Ok(started) => {
                self.advert = Some(started);
                self.message = None;
                self.retry = None;
            }
            Err(message) => {
                warn!(service = self.service, "can't ask: {message}");
                self.message = Some(message);
                self.retry = Some(Instant::now() + RETRY);
            }
        }
    }

    fn status(&self) -> RequestStatus {
        RequestStatus {
            asking: self.advert.is_some(),
            identity: self.advert.as_ref().map(|(_, irk)| Identity { irk: Some(hex(irk)) }),
            message: self.message.clone(),
        }
    }
}

/// Starts the advert for `service`, and the IRK that identifies its sender.
fn start(service: &str, options: Options) -> Result<(Advert, [u8; 16]), String> {
    match service {
        "_rdlink._tcp" => rdlink(options),
        other => Err(format!("Warlock can't ask for {other}")),
    }
}

/// "RDLink needs AWDL", tagged. Windows picks the advert's address once its
/// data is fixed, so the tag is random and the IRK is chosen to fit it.
fn rdlink(options: Options) -> Result<(Advert, [u8; 16]), String> {
    let mut tag = [0u8; 3];
    getrandom::fill(&mut tag).map_err(|e| format!("no random numbers: {e}"))?;
    let flags = if options.needs_keyboard { nearby_action::flags::NEEDS_KEYBOARD } else { 0 };
    let data = continuity::nearby_action(flags, nearby_action::action::RDLINK_NEEDS_AWDL, &tag);
    // The trace first, so it sees the advert's commands.
    let trace = HciTrace::start()?;
    let advert = Advert::start(APPLE, &data).map_err(|e| format!("Bluetooth won't advertise: {e}"))?;
    // The manufacturer data as the controller gets it: AD type 0xff, then
    // the company ID, little-endian.
    let [lo, hi] = APPLE.to_le_bytes();
    let sent = [&[0xff, lo, hi][..], &data].concat();
    let (set, address) =
        trace.advert_address(&sent, ADDRESS_WAIT).ok_or("Bluetooth didn't show the advert's address in its trace")?;
    drop(trace);
    let mut seed = [0u8; 16];
    getrandom::fill(&mut seed).map_err(|e| format!("no random numbers: {e}"))?;
    let searched = Instant::now();
    let irk = continuity::irk_for(&address, &tag, seed);
    let shown = address.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    info!(
        service = "_rdlink._tcp",
        advert = format_args!("4c00{}", hex(&data)),
        address = shown,
        set,
        search = ?searched.elapsed(),
        "asking: an IRK chosen to fit the advert"
    );
    Ok((advert, irk))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
