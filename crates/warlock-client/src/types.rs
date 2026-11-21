// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! The API's JSON, one type per schema in `api/openapi.yaml`
//! (`components/schemas`), with the same names. The contract is the
//! authority: `tests/contract.rs` checks what the server sends against it.
//!
//! Addresses are kept as the strings the contract specifies, so this crate
//! needs nothing from the AWDL crates.
//!
//! A newer Warlock may add properties, event types and radio states without
//! a break (the contract's "Compatibility"). Properties a type doesn't know
//! are ignored. An event type or radio state it doesn't know arrives as
//! [`Event::Unknown`] or [`RadioState::Unknown`], and both enums are
//! `#[non_exhaustive]`, so a `match` on them already has an arm for what
//! comes later.

use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

/// Every 4xx and 5xx response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    /// What went wrong, for people.
    pub message: String,
}

/// The program holding a lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    /// Its process ID.
    pub pid: u32,
    /// Its executable's path; empty if Windows wouldn't say.
    pub image: String,
    /// When it took the lock (RFC 3339).
    pub since: String,
}

/// `GET /v1/info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    /// Warlock's version.
    pub version: String,
    /// This computer's host name, without `.local`.
    pub host_name: String,
    /// The adapter; `None` until it's up.
    pub adapter: Option<Adapter>,
    pub radio: Radio,
    pub awdl: Awdl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<Traffic>,
    /// The service types `POST /v1/request` can ask nearby devices for.
    /// Empty from a Warlock that predates it.
    #[serde(default)]
    pub requestable: Vec<String>,
}

/// The "Warlock AWDL" network adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adapter {
    pub name: String,
    /// Its interface index.
    pub index: u32,
    /// Its only address.
    pub address: Ipv6Addr,
    pub mtu: u32,
}

/// The radio.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Radio {
    pub state: RadioState,
    /// Warlock's AWDL address while `up`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width_mhz: Option<u32>,
}

/// Where the radio is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RadioState {
    /// No adapter plugged in.
    Absent,
    /// Starting it.
    Opening,
    /// Taking part in AWDL.
    Up,
    /// A state from a newer Warlock than this crate knows: not `Up`.
    /// Warlock never sends it.
    #[serde(other)]
    Unknown,
}

/// The cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Awdl {
    /// The cluster's master; `None` when there's none yet.
    pub master: Option<String>,
    /// How many peers Warlock hears.
    pub peers: usize,
}

/// Packets through the adapter since Warlock started.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Traffic {
    pub to_air: u64,
    pub to_windows: u64,
    pub announced: u64,
    pub unroutable: u64,
}

/// One AWDL device Warlock hears.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub address: String,
    pub ipv6: Ipv6Addr,
    pub host_name: Option<String>,
    /// `major.minor`.
    pub awdl_version: Option<String>,
    pub device_class: Option<u8>,
    /// The master it follows.
    pub master: Option<String>,
    pub channel: u8,
    pub rssi_dbm: i8,
    pub since_last_frame_ms: u64,
    pub frames: Frames,
    /// Its channel in each of the 16 slots; 0 for none.
    pub sequence: Option<Vec<u8>>,
    /// Whether it asks a device AirPlaying to it to follow its channel
    /// sequence (data path state flag `0x0080`). Warlock doesn't act on it.
    #[serde(default)]
    pub follow_channel_sequence: bool,
    pub services: ServiceSet,
}

/// Frames received from a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frames {
    pub psf: u32,
    pub mif: u32,
    pub data: u32,
}

/// The service records a peer carries in its frames.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSet {
    /// Its service-update counter.
    pub update: Option<u16>,
    pub records: Vec<ServiceRecord>,
}

/// One DNS record. The contract's `PtrRecord`, `SrvRecord`, `TxtRecord` and
/// `OtherRecord` share `name` and `type`; the rest is per type, so it's
/// optional here and left out when absent. Build one with the constructors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    /// `PTR`, `SRV`, `TXT`, or `TYPE<n>` (RFC 3597).
    #[serde(rename = "type")]
    pub rtype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<String>>,
    /// Hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl ServiceRecord {
    fn bare(name: String, rtype: String) -> Self {
        Self { name, rtype, target: None, priority: None, weight: None, port: None, strings: None, data: None }
    }

    /// A PTR to `target`.
    pub fn ptr(name: String, target: String) -> Self {
        Self { target: Some(target), ..Self::bare(name, "PTR".into()) }
    }

    /// An SRV.
    pub fn srv(name: String, priority: u16, weight: u16, port: u16, target: String) -> Self {
        Self {
            priority: Some(priority),
            weight: Some(weight),
            port: Some(port),
            target: Some(target),
            ..Self::bare(name, "SRV".into())
        }
    }

    /// A TXT.
    pub fn txt(name: String, strings: Vec<String>) -> Self {
        Self { strings: Some(strings), ..Self::bare(name, "TXT".into()) }
    }

    /// Any other type, its data as given.
    pub fn other(name: String, rtype: u16, data: &[u8]) -> Self {
        let hex = data.iter().map(|b| format!("{b:02x}")).collect();
        Self { data: Some(hex), ..Self::bare(name, format!("TYPE{rtype}")) }
    }
}

/// `POST /v1/advertising`'s body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertiseRequest {
    /// A service type, e.g. `_rdlink._tcp`.
    #[serde(rename = "type")]
    pub service_type: String,
}

/// A line of the advertising stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisingState {
    #[serde(rename = "type")]
    pub service_type: String,
    /// The instances of the type in Warlock's frames now.
    pub instances: Vec<String>,
}

/// An entry of `GET /v1/advertising`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedType {
    #[serde(rename = "type")]
    pub service_type: String,
    pub instances: Vec<String>,
    pub owners: Vec<Owner>,
}

/// `POST /v1/holds`'s body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldRequest {
    /// Why, for logs and `GET /v1/holds`.
    pub reason: String,
}

/// A line of the hold stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldState {
    /// Whether AWDL is up and Warlock is taking part.
    pub active: bool,
}

/// An entry of `GET /v1/holds`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub reason: String,
    pub owner: Owner,
}

/// `POST /v1/realtime`'s body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeRequest {
    /// The peer's AWDL address.
    pub peer: String,
    /// Why, for logs and `GET /v1/realtime`.
    pub reason: String,
}

/// A line of the realtime stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeState {
    pub peer: String,
    /// Whether Warlock hears the peer.
    pub present: bool,
    /// Whether Warlock has asked the peer to start the group since it last
    /// appeared, or the peer is in it.
    pub asked: bool,
    /// Whether the peer says it's in the group (its frames name it).
    #[serde(default)]
    pub joined: bool,
}

/// An entry of `GET /v1/realtime`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeLock {
    pub peer: String,
    pub reason: String,
    pub owner: Owner,
}

/// `POST /v1/request`'s body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRequest {
    /// The service type to ask nearby devices to bring up on AWDL, one of
    /// [`Info::requestable`].
    pub service: String,
    /// Why, for logs and `GET /v1/request`.
    pub reason: String,
}

/// How receivers will recognise the program that asked: what it hands the
/// peer itself, for example in pairing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// A Bluetooth Identity Resolving Key, 16 bytes in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irk: Option<String>,
}

/// A line of a request's stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRequestState {
    pub service: String,
    /// Whether Warlock is asking now.
    pub asking: bool,
    /// How receivers will recognise the program; `None` when they won't. If
    /// it changes, peers given the old one no longer recognise it.
    pub identity: Option<Identity>,
    /// Why Warlock isn't asking, for people; `None` otherwise.
    pub message: Option<String>,
}

/// An entry of `GET /v1/request`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRequestLock {
    pub service: String,
    pub reason: String,
    pub asking: bool,
    pub owner: Owner,
}

/// A line of `GET /v1/events`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Event {
    PeerFound {
        peer: Box<Peer>,
    },
    PeerLost {
        address: String,
    },
    ServicesChanged {
        address: String,
        services: ServiceSet,
    },
    MasterChanged {
        master: Option<String>,
    },
    RadioChanged {
        radio: Radio,
    },
    /// The instances Warlock advertises for a type changed.
    AdvertisingChanged {
        #[serde(rename = "type")]
        service_type: String,
        instances: Vec<String>,
    },
    /// An event type from a newer Warlock than this crate knows, to skip.
    /// Warlock never sends it.
    #[serde(other)]
    Unknown,
}

/// Whether `t` is a service type the contract accepts: `_` and an RFC 6335
/// service name (1–15 letters, digits and inner single hyphens), then
/// `._tcp` or `._udp`, with no domain.
pub fn is_service_type(t: &str) -> bool {
    let Some(rest) = t.strip_prefix('_') else { return false };
    let Some(name) = rest.strip_suffix("._tcp").or_else(|| rest.strip_suffix("._udp")) else { return false };
    (1..=15).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_types() {
        for ok in ["_rdlink._tcp", "_airdrop._tcp", "_a._udp", "_companion-link._tcp", "_abcdefghijklmno._tcp"] {
            assert!(is_service_type(ok), "{ok}");
        }
        for bad in [
            "rdlink._tcp",
            "_rdlink._tcp.local",
            "_rdlink._sctp",
            "_._tcp",
            "_-x._tcp",
            "_x-._tcp",
            "_a--b._tcp",
            "_abcdefghijklmnop._tcp",
            "_x y._tcp",
        ] {
            assert!(!is_service_type(bad), "{bad}");
        }
    }

    /// What a newer Warlock may add without a break, this crate reads.
    #[test]
    fn a_newer_warlocks_additions_still_parse() {
        use serde_json::{from_value, json};
        let info = json!({
            "version": "0.1.9",
            "host_name": "h",
            "adapter": null,
            "radio": { "state": "sleeping", "since": "2026-11-18T00:00:00Z" },
            "awdl": { "master": null, "peers": 0, "clusters": 1 },
            "power": "low"
        });
        let info: Info = from_value(info).unwrap();
        assert_eq!(info.radio.state, RadioState::Unknown);
        let event: Event = from_value(json!({ "event": "peer_moved", "address": "02:00:00:00:00:01" })).unwrap();
        assert_eq!(event, Event::Unknown);
        let event: Event =
            from_value(json!({ "event": "peer_lost", "address": "02:00:00:00:00:01", "why": "gone" })).unwrap();
        assert_eq!(event, Event::PeerLost { address: "02:00:00:00:00:01".into() });
        // Known values still parse as themselves.
        assert_eq!(from_value::<RadioState>(json!("up")).unwrap(), RadioState::Up);
    }

    #[test]
    fn records_serialize_as_the_contract_says() {
        let ptr = ServiceRecord::ptr("_x._tcp.local".into(), "a._x._tcp.local".into());
        assert_eq!(
            serde_json::to_value(&ptr).unwrap(),
            serde_json::json!({"name": "_x._tcp.local", "type": "PTR", "target": "a._x._tcp.local"})
        );
        let other = ServiceRecord::other("h.local".into(), 65, &[0xab, 0x01]);
        assert_eq!(serde_json::to_value(&other).unwrap()["type"], "TYPE65");
        assert_eq!(serde_json::to_value(&other).unwrap()["data"], "ab01");
    }
}
