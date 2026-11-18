// SPDX-License-Identifier: GPL-2.0-only
//! The server against its contract, `api/openapi.yaml`: every response body
//! and every line of every stream it sends is validated against the schema
//! the contract gives for it, and the locks behave as the contract says.
//! Each test serves its own pipe, with this test standing in for the daemon.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use http::{Method, StatusCode};
use jsonschema::{Draft, Registry};
use serde_json::{Value, json};
use warlock_api::{Daemon, HEARTBEAT, OPERATIONS, Security, Server, State};
use warlock_client::types::*;
use warlock_client::{Client, ClientError, Lines};

const CONTRACT: &str = "urn:warlock:openapi";

fn document() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../api/openapi.yaml");
        let text = std::fs::read_to_string(path).expect("api/openapi.yaml");
        serde_norway::from_str(&text).expect("the contract is YAML")
    })
}

fn registry() -> &'static Registry<'static> {
    static REGISTRY: OnceLock<Registry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        Registry::new().draft(Draft::Draft202012).add(CONTRACT, document().clone()).unwrap().prepare().unwrap()
    })
}

/// Validates `value` against `schema`, which may refer to the contract's
/// schemas.
fn check_against(schema: Value, value: &Value, what: &str) {
    let validator = jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_registry(registry())
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("{what}: bad schema: {e}"));
    let errors: Vec<String> = validator.iter_errors(value).map(|e| format!("{e} at {}", e.instance_path())).collect();
    assert!(errors.is_empty(), "{what} breaks the contract: {errors:#?}\n{value:#}");
}

fn schema(name: &str) -> Value {
    json!({ "$ref": format!("{CONTRACT}#/components/schemas/{name}") })
}

fn check(name: &str, value: &Value) {
    check_against(schema(name), value, name);
}

fn check_list(name: &str, value: &Value) {
    check_against(json!({ "type": "array", "items": schema(name) }), value, &format!("[{name}]"));
}

fn mac(n: u8) -> String {
    format!("02:00:00:00:00:{n:02x}")
}

fn info(radio: RadioState) -> Info {
    let up = radio == RadioState::Up;
    Info {
        version: "0.1.0".into(),
        host_name: "testhost".into(),
        adapter: up.then(|| Adapter {
            name: "Warlock AWDL".into(),
            index: 74,
            address: "fe80::1".parse().unwrap(),
            mtu: 1450,
        }),
        radio: Radio {
            state: radio,
            address: up.then(|| mac(1)),
            channel: up.then_some(149),
            width_mhz: up.then_some(40),
        },
        awdl: Awdl { master: up.then(|| mac(2)), peers: 2 },
        traffic: Some(Traffic { to_air: 1, to_windows: 2, announced: 3, unroutable: 4 }),
    }
}

fn peers() -> Vec<Peer> {
    let full = Peer {
        address: mac(2),
        ipv6: "fe80::2".parse().unwrap(),
        host_name: Some("0b5e7c2a-1d3f-4e6a-9c8b-2f4d6a8c0e1f.local".into()),
        awdl_version: Some("3.4".into()),
        device_class: Some(2),
        master: Some(mac(2)),
        channel: 149,
        rssi_dbm: -40,
        since_last_frame_ms: 12,
        frames: Frames { psf: 10, mif: 20, data: 30 },
        sequence: Some(vec![149, 0, 0, 0, 0, 0, 0, 0, 6, 0, 149, 0, 0, 0, 0, 0]),
        services: ServiceSet {
            update: Some(7),
            records: vec![
                ServiceRecord::ptr("_airdrop._tcp.local".into(), "0123456789ab._airdrop._tcp.local".into()),
                ServiceRecord::srv("0123456789ab._airdrop._tcp.local".into(), 0, 0, 8770, "host.local".into()),
                ServiceRecord::txt("0123456789ab._airdrop._tcp.local".into(), vec!["flags=1019".into()]),
                ServiceRecord::other("host.local".into(), 65, &[1, 2, 3]),
            ],
        },
    };
    let bare = Peer {
        address: mac(3),
        ipv6: "fe80::3".parse().unwrap(),
        host_name: None,
        awdl_version: None,
        device_class: None,
        master: None,
        channel: 6,
        rssi_dbm: -80,
        since_last_frame_ms: 4000,
        frames: Frames::default(),
        sequence: None,
        services: ServiceSet::default(),
    };
    vec![full, bare]
}

fn state(radio: RadioState) -> State {
    State { info: info(radio), peers: peers(), advertised: BTreeMap::new() }
}

/// A server on a pipe of its own.
fn serve(radio: RadioState) -> (Server, Daemon, Client, String) {
    static N: AtomicU32 = AtomicU32::new(0);
    let pipe = format!(r"\\.\pipe\warlock-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed));
    let (server, daemon) = Server::start(&pipe, Security::Default, state(radio)).expect("serve");
    (server, daemon, Client::new(&pipe), pipe)
}

/// The next line of a stream within `limit`, checked against `name`.
async fn next_line(lines: &mut Lines, name: &str, limit: Duration) -> Value {
    let v = tokio::time::timeout(limit, lines.next_value())
        .await
        .unwrap_or_else(|_| panic!("no {name} line within {limit:?}"))
        .expect("the stream ended")
        .expect("a JSON line");
    check(name, &v);
    v
}

/// Polls the daemon's end until `done` holds of what locks ask for; how long
/// that took.
async fn until(daemon: &mut Daemon, limit: Duration, mut done: impl FnMut(&warlock_api::Wants) -> bool) -> Duration {
    let start = Instant::now();
    loop {
        let wants = daemon.wants_now();
        if done(&wants) {
            return start.elapsed();
        }
        assert!(start.elapsed() < limit, "not within {limit:?}: {wants:?}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The checks bite: a `$ref` that resolved to nothing would pass everything.
#[test]
#[should_panic(expected = "breaks the contract")]
fn a_body_that_breaks_the_contract_fails_the_check() {
    let mut peer = serde_json::to_value(&peers()[0]).unwrap();
    peer["address"] = json!("02:00:00:00:00:0G");
    check("Peer", &peer);
}

#[test]
fn every_operation_in_the_contract_is_served() {
    let mut documented: Vec<(String, String)> = Vec::new();
    for (path, item) in document()["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            if ["get", "put", "post", "delete", "patch", "head", "options", "query"].contains(&method.as_str()) {
                documented.push((method.clone(), path.clone()));
            }
        }
    }
    let mut served: Vec<(String, String)> = OPERATIONS.iter().map(|(m, p)| (m.to_string(), p.to_string())).collect();
    documented.sort();
    served.sort();
    assert_eq!(served, documented);
}

#[tokio::test]
async fn state_endpoints_match_the_contract() {
    let (_server, _daemon, client, _) = serve(RadioState::Up);
    let (status, v) = client.raw(Method::GET, "/v1/info", None).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    check("Info", &v);
    let (status, v) = client.raw(Method::GET, "/v1/peers", None).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    check_list("Peer", &v);
    assert_eq!(v.as_array().unwrap().len(), 2);
    // Addresses match without case.
    let (status, v) = client.raw(Method::GET, "/v1/peers/02:00:00:00:00:02", None).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    check("Peer", &v);
    assert_eq!(client.peer("02:00:00:00:00:03").await.unwrap(), peers()[1]);
    for (method, path, expected) in [
        (Method::GET, "/v1/peers/02:00:00:00:00:99", StatusCode::NOT_FOUND),
        (Method::GET, "/v1/nothing", StatusCode::NOT_FOUND),
        (Method::DELETE, "/v1/info", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let (status, v) = client.raw(method.clone(), path, None).await.unwrap();
        assert_eq!(status, expected, "{method} {path}");
        check("Error", &v);
    }
    // The typed client reads the same.
    assert_eq!(client.info().await.unwrap(), info(RadioState::Up));
    assert_eq!(client.peers().await.unwrap(), peers());
}

#[tokio::test]
async fn info_before_the_radio_is_up_matches_the_contract() {
    let (_server, _daemon, client, _) = serve(RadioState::Opening);
    let (_, v) = client.raw(Method::GET, "/v1/info", None).await.unwrap();
    check("Info", &v);
    assert_eq!(v["adapter"], Value::Null);
}

#[tokio::test]
async fn an_advertising_lock_lasts_as_long_as_its_connection() {
    let (_server, mut daemon, client, _) = serve(RadioState::Up);
    let mut lines =
        client.raw_stream(Method::POST, "/v1/advertising", Some(br#"{"type": "_Warlock-Test._tcp"}"#)).await.unwrap();
    // Types are kept lowercase.
    let first = next_line(&mut lines, "AdvertisingState", Duration::from_secs(1)).await;
    assert_eq!(first, json!({"type": "_warlock-test._tcp", "instances": []}));
    until(&mut daemon, Duration::from_secs(1), |w| w.types.contains("_warlock-test._tcp")).await;

    // The daemon advertises an instance: the stream says so.
    let mut s = daemon.state();
    s.advertised.insert("_warlock-test._tcp".into(), vec!["Koala._warlock-test._tcp.local".into()]);
    daemon.publish(s);
    let next = next_line(&mut lines, "AdvertisingState", Duration::from_secs(1)).await;
    assert_eq!(next["instances"], json!(["Koala._warlock-test._tcp.local"]));

    // The list names this process as the owner.
    let (_, list) = client.raw(Method::GET, "/v1/advertising", None).await.unwrap();
    check_list("AdvertisedType", &list);
    let typed = client.advertising().await.unwrap();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].owners[0].pid, std::process::id());
    assert!(typed[0].owners[0].image.to_ascii_lowercase().ends_with(".exe"), "{:?}", typed[0].owners[0]);

    // Closing the connection releases the lock.
    drop(lines);
    let took = until(&mut daemon, HEARTBEAT + Duration::from_secs(1), |w| w.types.is_empty()).await;
    eprintln!("advertising lock released {took:?} after its connection closed");
    assert_eq!(client.advertising().await.unwrap(), vec![]);
}

#[tokio::test]
async fn a_hold_lasts_as_long_as_its_connection_and_beats() {
    let (_server, mut daemon, client, _) = serve(RadioState::Up);
    let mut lines = client.hold("call").await.unwrap();
    let first = next_line(&mut lines, "HoldState", Duration::from_secs(1)).await;
    assert_eq!(first, json!({"active": true}));
    until(&mut daemon, Duration::from_secs(1), |w| w.holds == 1).await;

    // Nothing changes: a heartbeat line comes anyway.
    let started = Instant::now();
    let beat = next_line(&mut lines, "HoldState", HEARTBEAT + Duration::from_secs(1)).await;
    assert_eq!(beat, first);
    assert!(started.elapsed() >= HEARTBEAT - Duration::from_millis(200), "{:?}", started.elapsed());

    // The radio goes away: the hold says so at once.
    let mut s = daemon.state();
    s.info.radio = Radio { state: RadioState::Absent, address: None, channel: None, width_mhz: None };
    daemon.publish(s);
    let next = next_line(&mut lines, "HoldState", Duration::from_secs(1)).await;
    assert_eq!(next, json!({"active": false}));

    let (_, list) = client.raw(Method::GET, "/v1/holds", None).await.unwrap();
    check_list("Hold", &list);
    assert_eq!(list[0]["reason"], "call");

    drop(lines);
    let took = until(&mut daemon, HEARTBEAT + Duration::from_secs(1), |w| w.holds == 0).await;
    eprintln!("hold released {took:?} after its connection closed");
    assert_eq!(client.holds().await.unwrap(), vec![]);
}

#[tokio::test]
async fn locks_on_one_type_add_up() {
    let (_server, mut daemon, client, _) = serve(RadioState::Up);
    let a = client.advertise("_x._tcp").await.unwrap();
    let b = client.advertise("_x._tcp").await.unwrap();
    until(&mut daemon, Duration::from_secs(1), |w| w.types.len() == 1).await;
    assert_eq!(client.advertising().await.unwrap()[0].owners.len(), 2);
    drop(a);
    tokio::time::sleep(HEARTBEAT + Duration::from_millis(500)).await;
    // One lock still holds the type.
    assert_eq!(client.advertising().await.unwrap()[0].owners.len(), 1);
    drop(b);
    until(&mut daemon, HEARTBEAT + Duration::from_secs(1), |w| w.types.is_empty()).await;
}

#[tokio::test]
async fn bad_requests_get_400() {
    let (_server, mut daemon, client, _) = serve(RadioState::Up);
    for (path, body) in [
        ("/v1/advertising", &br#"{"type": "rdlink._tcp"}"#[..]),
        ("/v1/advertising", br#"{"type": "_rdlink._tcp.local"}"#),
        ("/v1/advertising", br#"{"kind": "_rdlink._tcp"}"#),
        ("/v1/advertising", b"not json"),
        ("/v1/holds", b"{}"),
    ] {
        let (status, v) = client.raw(Method::POST, path, Some(body)).await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {}", String::from_utf8_lossy(body));
        check("Error", &v);
    }
    let Err(ClientError::Api { status, .. }) = client.advertise("nope").await else { panic!("accepted") };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(daemon.wants(), None, "a rejected request took a lock");
}

#[tokio::test]
async fn events_reach_every_stream() {
    let (_server, daemon, client, _) = serve(RadioState::Up);
    let mut one = client.events().await.unwrap();
    let mut two = client.events().await.unwrap();
    let sent = vec![
        Event::PeerFound { peer: Box::new(peers()[0].clone()) },
        Event::ServicesChanged { address: mac(2), services: peers()[0].services.clone() },
        Event::MasterChanged { master: Some(mac(2)) },
        Event::MasterChanged { master: None },
        Event::RadioChanged { radio: info(RadioState::Up).radio },
        Event::AdvertisingChanged { service_type: "_x._tcp".into(), instances: vec!["a._x._tcp.local".into()] },
        Event::PeerLost { address: mac(2) },
    ];
    for e in &sent {
        daemon.event(e.clone());
    }
    for lines in [&mut one, &mut two] {
        for e in &sent {
            let v = next_line(lines, "Event", Duration::from_secs(1)).await;
            assert_eq!(&serde_json::from_value::<Event>(v).unwrap(), e);
        }
    }
}

#[tokio::test]
async fn streams_end_when_warlock_stops() {
    let (server, _daemon, client, _) = serve(RadioState::Up);
    let mut lines = client.advertise("_x._tcp").await.unwrap();
    next_line(&mut lines, "AdvertisingState", Duration::from_secs(1)).await;
    drop(server);
    let end = tokio::time::timeout(Duration::from_secs(2), lines.next_value()).await.expect("the stream hung");
    assert!(matches!(end, None | Some(Err(_))), "{end:?}");
}

#[tokio::test]
async fn only_one_server_per_pipe() {
    let (_server, _daemon, _client, pipe) = serve(RadioState::Up);
    assert!(Server::start(&pipe, Security::Default, state(RadioState::Up)).is_err());
}

#[tokio::test]
async fn many_clients_at_once() {
    let (_server, _daemon, client, _) = serve(RadioState::Up);
    let calls = (0..32).map(|_| {
        let c = client.clone();
        tokio::spawn(async move { c.info().await })
    });
    for call in calls {
        call.await.unwrap().expect("every client gets through");
    }
}
