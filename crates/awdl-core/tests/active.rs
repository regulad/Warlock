// SPDX-License-Identifier: GPL-2.0-only
//! Active mode on replayed captures: an engine configured to transmit is fed
//! a capture with an iPhone master and polled at the times it asks for. Its
//! hops must follow the master's sequence, it must send one MIF per slot and
//! PSFs at their period, and its frames must parse back and pass Wireshark's
//! dissector cleanly. Needs the local corpus (and tshark for the last check).

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use awdl_core::{Action, Config, Engine, RxMeta, TU_US, TxConfig, TxKind};
use awdl_proto::tlv::{TlvBody, kind};
use awdl_proto::{Frame, MacAddr, parse};

const US: MacAddr = MacAddr([0x02, 0x57, 0x4c, 0x00, 0x00, 0x01]);
const IPHONE: MacAddr = MacAddr([0x76, 0x56, 0x82, 0x58, 0x57, 0x70]);

struct Sent {
    tsf: u64,
    master: Option<MacAddr>,
    source: Option<MacAddr>,
    channel: u8,
    kind: TxKind,
    mpdu: Vec<u8>,
}

fn run(file: &Path) -> (Vec<Sent>, Vec<(u64, u8)>, Engine) {
    let mut engine = Engine::new(Config::active(TxConfig::new(US)));
    let (mut sent, mut hops) = (Vec::new(), Vec::new());
    let mut channel = 0u8;
    let act = |tsf: u64,
               ms: (Option<MacAddr>, Option<MacAddr>),
               actions: Vec<Action>,
               channel: &mut u8,
               sent: &mut Vec<Sent>,
               hops: &mut Vec<(u64, u8)>| {
        for a in actions {
            match a {
                Action::Hop(c) => {
                    *channel = c;
                    hops.push((tsf, c));
                }
                Action::Transmit { mpdu, kind, .. } => {
                    sent.push(Sent { tsf, master: ms.0, source: ms.1, channel: *channel, kind, mpdu })
                }
            }
        }
    };
    let mut now = None;
    for c in warlock_capture::read(file).unwrap() {
        let (Some(tsf), Some(ch)) = (c.tsf, c.channel()) else { continue };
        // Time starts with the first frame, as it does live.
        let now = now.get_or_insert(tsf);
        // Wake-ups that fall before this frame.
        while let Some(w) = engine.next_wakeup(*now).filter(|&w| w < tsf && w >= *now) {
            *now = w.max(*now + 1);
            let a = engine.poll(*now);
            act(*now, (engine.master(), engine.sync_source().map(|p| p.addr)), a, &mut channel, &mut sent, &mut hops);
        }
        *now = tsf;
        engine.on_frame(RxMeta { tsf, channel: ch, rssi_dbm: c.rssi_dbm.unwrap_or(0) }, &c.mpdu);
        let a = engine.poll(*now);
        act(*now, (engine.master(), engine.sync_source().map(|p| p.addr)), a, &mut channel, &mut sent, &mut hops);
    }
    (sent, hops, engine)
}

#[test]
fn follows_an_iphone_master_and_sends_well_formed_frames() {
    let Some(dir) = warlock_capture::corpus_dir() else {
        eprintln!("skipping: no capture corpus");
        return;
    };
    let file = dir.join("mac-iphone149.pcapng");
    if !file.exists() {
        eprintln!("skipping: {} missing", file.display());
        return;
    }
    let (sent, hops, engine) = run(&file);
    let src = engine.sync_source().expect("synced");
    assert_eq!((engine.master(), src.addr), (Some(IPHONE), IPHONE));
    // The capture opens with 3 s of nobody: after listening 2 s we stand as
    // master, and yield to the first better master we hear.
    let as_master: Vec<&Sent> = sent.iter().filter(|s| s.master == Some(US)).collect();
    eprintln!("sent {} of {} frames as master", as_master.len(), sent.len());
    assert!(as_master.iter().all(|s| s.tsf < sent[0].tsf + 2_000_000), "we led after a better master was heard");

    let mifs: Vec<&Sent> = sent.iter().filter(|s| s.kind == TxKind::Mif).collect();
    let psfs: Vec<&Sent> = sent.iter().filter(|s| s.kind == TxKind::Psf).collect();
    let span = (sent.last().unwrap().tsf - sent[0].tsf) as f64;
    let slot_us = 4.0 * 16.0 * TU_US as f64;
    eprintln!(
        "{} MIFs and {} PSFs over {:.1} s; {} hops: {:?}…",
        mifs.len(),
        psfs.len(),
        span / 1e6,
        hops.len(),
        hops[..hops.len().min(6)].iter().map(|h| h.1).collect::<Vec<_>>()
    );
    // One MIF per explicit slot of the master's sequence (which changes over
    // the capture, so allow a wide margin).
    let sched = src.schedule.unwrap();
    let explicit = span / slot_us * sched.explicit_slots() as f64 / 16.0;
    assert!(
        (mifs.len() as f64) > 0.5 * explicit && (mifs.len() as f64) < 2.0 * explicit,
        "{} MIFs for ~{explicit:.0} explicit slots",
        mifs.len()
    );
    // PSFs at about 110 TU (each AW window carries at most one frame).
    let psf_rate = psfs.len() as f64 / (span / (110.0 * TU_US as f64));
    assert!(psf_rate > 0.5 && psf_rate <= 1.05, "PSF rate {psf_rate:.2} of nominal");
    // We hop only between channels in the master's sequence.
    for (_, c) in &hops {
        assert!(sched.visits(*c), "hopped to {c}, which the master never visits");
    }

    // Our frames parse, and say what a follower of the iPhone should.
    for s in sent.iter().filter(|s| s.kind != TxKind::AddbaResponse) {
        let Ok(Some(Frame::Action { header, action })) = parse(&s.mpdu) else { panic!("our frame doesn't parse") };
        assert_eq!((header.addr2, header.addr1), (US, MacAddr::BROADCAST));
        let Some(Ok(TlvBody::SyncParams(sp))) = action.find(kind::SYNC_PARAMS).map(|t| t.decode()) else { panic!() };
        assert_eq!((Some(sp.master), sp.tx_channel), (s.master, s.channel));
        // Counts to the next slot (4 AWs) start, as Apple devices do.
        assert!((1..=64).contains(&sp.tx_counter), "tx_counter {}", sp.tx_counter);
        let boundary_seq = sp.aw_seq_counter.wrapping_add(((sp.tx_counter as u64 * TU_US) / (16 * TU_US)) as u16 + 1);
        assert!(
            boundary_seq % 4 == 0 || sp.tx_counter % 16 == 0,
            "claimed boundary isn't a slot start: seq {} counter {}",
            sp.aw_seq_counter,
            sp.tx_counter
        );
        let Some(Ok(TlvBody::ElectionParamsV2(e))) = action.find(kind::ELECTION_PARAMS_V2).map(|t| t.decode()) else {
            panic!()
        };
        if s.master == Some(US) {
            // Before anyone else was heard, we stood alone.
            assert_eq!((e.master, e.other, e.distance_to_master), (US, US, 0));
        } else {
            assert_eq!((Some(e.master), Some(e.other)), (s.master, s.source));
            assert!(e.self_metric < e.master_metric);
        }
        for t in action.tlvs() {
            t.decode().unwrap_or_else(|err| panic!("TLV {} of our own frame: {err}", t.kind));
        }
    }
    wireshark_accepts(&sent);
}

/// Writes our frames to a capture and has tshark dissect them: every one
/// must be AWDL, and none may raise an error-level expert finding.
fn wireshark_accepts(sent: &[Sent]) {
    let ts = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
    if !ts.exists() {
        eprintln!("tshark not found; skipping the Wireshark check");
        return;
    }
    let mut w = warlock_capture::Writer::radiotap(Vec::new()).unwrap();
    for s in sent {
        w.write(Duration::from_micros(s.tsf), s.tsf, warlock_capture::freq_of(s.channel), -40, &s.mpdu).unwrap();
    }
    // Tests run in parallel in one process: one file per call.
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("warlock-active-{}-{n}.pcapng", std::process::id()));
    std::fs::write(&path, w.into_inner()).unwrap();
    let out = Command::new(ts)
        .arg("-r")
        .arg(&path)
        .args(["-T", "fields", "-e", "awdl.subtype", "-e", "_ws.expert.severity", "-e", "_ws.malformed"])
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), sent.len());
    for (i, l) in lines.iter().enumerate() {
        let cols: Vec<&str> = l.split('\t').collect();
        let is_addba = sent[i].kind == TxKind::AddbaResponse;
        assert!(is_addba || !cols[0].is_empty(), "frame {} isn't AWDL to Wireshark: {l}", i + 1);
        // Expert severities: 8388608 = warning, 0x800000; errors are 0x800000 << 1 and up.
        let worst = cols[1].split(',').filter_map(|s| s.parse::<u64>().ok()).max().unwrap_or(0);
        assert!(worst < 0x0080_0000 * 2 && cols.get(2).is_none_or(|m| m.is_empty()), "frame {}: {l}", i + 1);
    }
}

#[test]
fn a_lone_engine_becomes_master_on_its_own_grid() {
    let mut engine = Engine::new(Config::active(TxConfig::new(US)));
    let (mut sent, mut hops) = (Vec::<Sent>::new(), Vec::<(u64, u8)>::new());
    let (mut now, mut channel) = (1_000_000u64, 0u8);
    while now < 1_000_000 + 12_000_000 {
        for a in engine.poll(now) {
            match a {
                Action::Hop(c) => {
                    channel = c;
                    hops.push((now, c));
                }
                Action::Transmit { mpdu, kind, .. } => {
                    sent.push(Sent { tsf: now, master: engine.master(), source: None, channel, kind, mpdu })
                }
            }
        }
        now = engine.next_wakeup(now).expect("a taking-part engine always has a next wake-up").max(now + 1);
    }
    assert!(engine.is_master() && engine.sync_source().is_none());
    // Silent while listening.
    assert!(sent[0].tsf >= 1_000_000 + 2_000_000, "sent at {} before listening 2 s", sent[0].tsf);
    // Our default sequence: 6 and 149, nothing else.
    assert!(hops.iter().all(|&(_, c)| c == 6 || c == 149), "{hops:?}");
    let span = (sent.last().unwrap().tsf - sent[0].tsf) as f64;
    let slot_us = 4.0 * 16.0 * TU_US as f64;
    let (mifs, psfs) =
        (sent.iter().filter(|s| s.kind == TxKind::Mif).count(), sent.iter().filter(|s| s.kind == TxKind::Psf).count());
    // 4 explicit slots of 16.
    let explicit = span / slot_us * 4.0 / 16.0;
    assert!((mifs as f64 - explicit).abs() <= 2.0, "{mifs} MIFs for {explicit:.1} explicit slots");
    let psf_rate = psfs as f64 / (span / (110.0 * TU_US as f64));
    assert!(psf_rate > 0.8 && psf_rate <= 1.05, "PSF rate {psf_rate:.2} of nominal");

    let mut slot_phase = None;
    for s in &sent {
        let Ok(Some(Frame::Action { action, .. })) = parse(&s.mpdu) else { panic!("our frame doesn't parse") };
        let Some(Ok(TlvBody::SyncParams(sp))) = action.find(kind::SYNC_PARAMS).map(|t| t.decode()) else { panic!() };
        assert_eq!((sp.master, sp.tx_channel), (US, s.channel));
        let Some(Ok(TlvBody::ElectionParamsV2(e))) = action.find(kind::ELECTION_PARAMS_V2).map(|t| t.decode()) else {
            panic!()
        };
        assert_eq!((e.master, e.other, e.distance_to_master), (US, US, 0));
        // Where a receiver puts our next slot: target + tx_counter TU (it
        // receives at the PHY time). One grid, slot-aligned, in every frame.
        let boundary = action.header.target_tx_time as u64 + sp.tx_counter as u64 * TU_US;
        let phase = boundary % (4 * 16 * TU_US);
        assert_eq!(*slot_phase.get_or_insert(phase), phase, "claims disagree on our slot grid");
        let to_boundary_aws = (boundary - s.tsf as u32 as u64).div_ceil(16 * TU_US) as u16;
        assert_eq!(sp.aw_seq_counter.wrapping_add(to_boundary_aws) % 4, 0, "claimed boundary isn't a slot start");
        // It reaches the air after we build it, and the counter is exact
        // from the target time.
        assert!(action.header.phy_tx_time.wrapping_sub(action.header.target_tx_time) < 2 * TU_US as u32);
    }
    wireshark_accepts(&sent);
}

#[test]
fn answers_block_ack_setup_addressed_to_us() {
    // The iPhone's captured ADDBA request, re-addressed to us.
    let mut req: Vec<u8> = vec![
        0xd0, 0x00, 0x30, 0x00, 0xb6, 0x01, 0x10, 0xf0, 0x98, 0x19, 0x76, 0x56, 0x82, 0x58, 0x57, 0x70, 0x00, 0x25,
        0x00, 0xff, 0x94, 0x73, 0xf0, 0xea, 0x03, 0x00, 0x86, 0x03, 0x10, 0x90, 0xe2, 0x40, 0x84,
    ];
    let mut engine = Engine::new(Config::active(TxConfig::new(US)));
    // Not for us: ignored.
    engine.on_frame(RxMeta { tsf: 1, channel: 149, rssi_dbm: -40 }, &req);
    assert!(engine.poll(2).is_empty());
    req[4..10].copy_from_slice(&US.0);
    engine.on_frame(RxMeta { tsf: 3, channel: 149, rssi_dbm: -40 }, &req);
    let actions = engine.poll(4);
    let [Action::Transmit { mpdu, kind: TxKind::AddbaResponse, .. }] = &actions[..] else { panic!("{actions:?}") };
    assert_eq!(&mpdu[4..10], &IPHONE.0);
    assert_eq!(&mpdu[24..], [3, 1, 0x86, 0, 0, 0x03, 0x10, 0, 0]);
}

/// What we advertise reaches a peer's engine as we set it: records in every
/// MIF, none in PSFs, our ARPA name, and a new update counter on a change.
#[test]
fn advertised_services_reach_a_listening_engine() {
    use awdl_proto::tlv::ServiceResponse;

    let records = vec![
        ServiceResponse::ptr("_warlocktest._tcp", "Warlock Test").unwrap(),
        ServiceResponse::srv("_warlocktest._tcp", "Warlock Test", 5555, "winlite.local").unwrap(),
        ServiceResponse::txt("_warlocktest._tcp", "Warlock Test", &["note=test"]).unwrap(),
    ];
    let mut engine = Engine::new(Config::active(TxConfig::new(US)));
    engine.set_services(records.clone(), Some("winlite".into()));
    let mut peer = Engine::new(Config::default());
    let mut sent = Vec::<Sent>::new();
    let (mut now, mut channel) = (1_000_000u64, 0u8);
    let mut changed = 0;
    while now < 1_000_000 + 6_000_000 {
        for a in engine.poll(now) {
            match a {
                Action::Hop(c) => channel = c,
                Action::Transmit { mpdu, kind, .. } => {
                    for ev in peer.on_frame(RxMeta { tsf: now, channel, rssi_dbm: -40 }, &mpdu) {
                        changed += matches!(ev, awdl_core::Event::ServicesChanged(a) if a == US) as usize;
                    }
                    sent.push(Sent { tsf: now, master: engine.master(), source: None, channel, kind, mpdu });
                }
            }
        }
        now = engine.next_wakeup(now).unwrap().max(now + 1);
    }
    let p = peer.peer(US).expect("the peer heard us");
    assert_eq!(p.services, records);
    assert_eq!(p.hostname.as_deref(), Some("winlite.local"));
    assert_eq!(p.services_sui, Some(1));
    assert_eq!(changed, 1, "records changed once, then stayed");
    for s in &sent {
        let Ok(Some(Frame::Action { action, .. })) = parse(&s.mpdu) else { panic!() };
        let n = action.tlvs().filter(|t| t.kind == kind::SERVICE_RESPONSE).count();
        assert_eq!(n, if s.kind == TxKind::Mif { 3 } else { 0 }, "{:?}", s.kind);
        // Every frame's SSTH: one member for the type, one for the instance.
        let Some(Ok(TlvBody::ServiceParams(sp))) = action.find(kind::SERVICE_PARAMS).map(|t| t.decode()) else {
            panic!()
        };
        let want: std::collections::BTreeSet<u32> =
            records.iter().filter_map(|r| awdl_proto::tlv::ssth_member(&r.name)).map(u32::from).collect();
        assert_eq!(sp.set_values().collect::<std::collections::BTreeSet<_>>(), want);
        assert_eq!(want.len(), 2);
    }
    wireshark_accepts(&sent);

    // Withdrawn: the counter moves on and the next MIF has no records.
    engine.set_services(Vec::new(), Some("winlite".into()));
    let mut mif = None;
    while mif.is_none() {
        for a in engine.poll(now) {
            if let Action::Transmit { mpdu, kind: TxKind::Mif, .. } = a {
                mif = Some(mpdu);
            }
        }
        now = engine.next_wakeup(now).unwrap().max(now + 1);
    }
    peer.on_frame(RxMeta { tsf: now, channel, rssi_dbm: -40 }, &mif.unwrap());
    let p = peer.peer(US).unwrap();
    assert!(p.services.is_empty());
    assert_eq!(p.services_sui, Some(2));
}

/// Two taking-part engines on one simulated air, polled at the times they
/// ask for: a frame reaches the other engine when it's on the sender's
/// channel. With no TX latency, so a frame is heard the moment it's built.
/// Our engine's frames go to `ours`; `channels` are the engines' own, kept
/// from call to call.
fn share_air(
    us: &mut Engine,
    them: &mut Engine,
    channels: &mut [u8; 2],
    now: &mut u64,
    until: u64,
    ours: &mut Vec<Sent>,
) {
    while *now < until {
        let actions = [us.poll(*now), them.poll(*now)];
        for (i, actions) in actions.into_iter().enumerate() {
            for a in actions {
                match a {
                    Action::Hop(c) => channels[i] = c,
                    Action::Transmit { mpdu, kind, .. } => {
                        let meta = RxMeta { tsf: *now, channel: channels[i], rssi_dbm: -40 };
                        if channels[1 - i] == channels[i] {
                            if i == 0 {
                                them.on_frame(meta, &mpdu)
                            } else {
                                us.on_frame(meta, &mpdu)
                            };
                        }
                        if i == 0 {
                            let source = us.sync_source().map(|p| p.addr);
                            ours.push(Sent {
                                tsf: *now,
                                master: us.master(),
                                source,
                                channel: channels[0],
                                kind,
                                mpdu,
                            });
                        }
                    }
                }
            }
        }
        *now = [us.next_wakeup(*now), them.next_wakeup(*now)].into_iter().flatten().min().unwrap().max(*now + 1);
    }
}

/// A frame's UMI code and realtime group TLV.
fn umi_and_rtg(mpdu: &[u8]) -> (MacAddr, Option<u32>, Option<MacAddr>) {
    let Ok(Some(Frame::Action { header, action })) = parse(mpdu) else { panic!("our frame doesn't parse") };
    let Some(Ok(TlvBody::DataPathState(d))) = action.find(kind::DATA_PATH_STATE).map(|t| t.decode()) else { panic!() };
    let rtg = action.find(kind::REALTIME_GROUP).map(|t| match t.decode() {
        Ok(TlvBody::RealtimeGroup(g)) => g.rtg_id,
        other => panic!("{other:?}"),
    });
    (header.addr1, d.umi_code(), rtg)
}

/// A realtime group: a few start UMIs to the peer alone, in its slots on our
/// channel, with TLV 31, which our frames then keep while it's wanted; on
/// release, a few stop UMIs and no TLV. The link, and the peer's view of us,
/// stay as they were (issue #10).
#[test]
fn a_realtime_group_starts_and_stops_with_umis() {
    use awdl_proto::tlv::umi;
    use std::collections::BTreeSet;

    const PEER: MacAddr = MacAddr([0x02, 0x57, 0x4c, 0x00, 0x00, 0x02]);
    let quick = |addr, metric| {
        let mut tx = TxConfig::new(addr);
        tx.self_metric = metric;
        tx.tx_latency_us = 0;
        Engine::new(Config::active(tx))
    };
    let (mut us, mut them) = (quick(US, 60), quick(PEER, 600));
    let (mut now, mut channels) = (1_000_000u64, [0u8; 2]);
    let mut sent = Vec::new();
    share_air(&mut us, &mut them, &mut channels, &mut now, 8_000_000, &mut sent);
    assert_eq!((us.master(), us.sync_source().map(|p| p.addr)), (Some(PEER), Some(PEER)), "we follow the peer");
    assert!(sent.iter().all(|s| s.kind != TxKind::Umi));
    let before = sent.len();

    us.set_realtime_peers(&BTreeSet::from([PEER]));
    assert!(!us.realtime_asked(PEER));
    share_air(&mut us, &mut them, &mut channels, &mut now, 12_000_000, &mut sent);
    assert!(us.realtime_asked(PEER));
    let starts: Vec<&Sent> = sent[before..].iter().filter(|s| s.kind == TxKind::Umi).collect();
    assert_eq!(starts.len(), 3, "a few start UMIs, then no more");
    let sched = us.peer(PEER).unwrap().schedule.unwrap();
    for s in &starts {
        assert_eq!(umi_and_rtg(&s.mpdu), (PEER, Some(umi::CONTINUITY_REALTIME_GROUP_START), Some(US)));
        assert!(sched.visits(s.channel));
    }
    for s in sent[before..].iter().filter(|s| s.kind != TxKind::Umi) {
        assert_eq!(umi_and_rtg(&s.mpdu), (MacAddr::BROADCAST, Some(0), Some(US)), "{:?}", s.kind);
    }
    let during = sent.len();

    us.set_realtime_peers(&BTreeSet::new());
    share_air(&mut us, &mut them, &mut channels, &mut now, 16_000_000, &mut sent);
    assert!(!us.realtime_asked(PEER));
    let stops: Vec<&Sent> = sent[during..].iter().filter(|s| s.kind == TxKind::Umi).collect();
    assert_eq!(stops.len(), 3, "a few stop UMIs, then no more");
    for s in &stops {
        assert_eq!(umi_and_rtg(&s.mpdu), (PEER, Some(umi::CONTINUITY_REALTIME_GROUP_STOP), None));
    }
    for s in sent[during..].iter().filter(|s| s.kind != TxKind::Umi) {
        assert_eq!(umi_and_rtg(&s.mpdu), (MacAddr::BROADCAST, Some(0), None));
    }

    // The link held throughout: we still follow the peer, and it still
    // takes us as a valid peer that follows it.
    assert_eq!((us.master(), us.sync_source().map(|p| p.addr)), (Some(PEER), Some(PEER)));
    let seen = them.peer(US).expect("the peer hears us");
    assert!(seen.is_valid() && now.saturating_sub(seen.last_seen) < 1_000_000);
    assert_eq!(seen.election.map(|e| e.master), Some(PEER));
    wireshark_accepts(&sent);
}
