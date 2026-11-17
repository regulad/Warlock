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
    let act = |tsf: u64, ms: (Option<MacAddr>, Option<MacAddr>), actions: Vec<Action>, channel: &mut u8, sent: &mut Vec<Sent>, hops: &mut Vec<(u64, u8)>| {
        for a in actions {
            match a {
                Action::Hop(c) => {
                    *channel = c;
                    hops.push((tsf, c));
                }
                Action::Transmit { mpdu, kind, .. } => sent.push(Sent { tsf, master: ms.0, source: ms.1, channel: *channel, kind, mpdu }),
            }
        }
    };
    let mut now = 0u64;
    for c in warlock_capture::read(file).unwrap() {
        let (Some(tsf), Some(ch)) = (c.tsf, c.channel()) else { continue };
        // Wake-ups that fall before this frame.
        while let Some(w) = engine.next_wakeup(now).filter(|&w| w < tsf && w >= now) {
            now = w.max(now + 1);
            let a = engine.poll(now);
            act(now, (engine.master(), engine.sync_source().map(|p| p.addr)), a, &mut channel, &mut sent, &mut hops);
        }
        now = tsf;
        engine.on_frame(RxMeta { tsf, channel: ch, rssi_dbm: c.rssi_dbm.unwrap_or(0) }, &c.mpdu);
        let a = engine.poll(now);
        act(now, (engine.master(), engine.sync_source().map(|p| p.addr)), a, &mut channel, &mut sent, &mut hops);
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
        &hops[..hops.len().min(6)].iter().map(|h| h.1).collect::<Vec<_>>()
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
        assert!((1..=16).contains(&sp.tx_counter), "tx_counter {}", sp.tx_counter);
        let Some(Ok(TlvBody::ElectionParamsV2(e))) = action.find(kind::ELECTION_PARAMS_V2).map(|t| t.decode()) else { panic!() };
        assert_eq!((Some(e.master), Some(e.other)), (s.master, s.source));
        assert!(e.self_metric < e.master_metric);
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
    let path = std::env::temp_dir().join(format!("warlock-active-{}.pcapng", std::process::id()));
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
fn answers_block_ack_setup_addressed_to_us() {
    // The iPhone's captured ADDBA request, re-addressed to us.
    let mut req: Vec<u8> = vec![
        0xd0, 0x00, 0x30, 0x00, 0xb6, 0x01, 0x10, 0xf0, 0x98, 0x19, 0x76, 0x56, 0x82, 0x58, 0x57, 0x70, 0x00,
        0x25, 0x00, 0xff, 0x94, 0x73, 0xf0, 0xea, 0x03, 0x00, 0x86, 0x03, 0x10, 0x90, 0xe2, 0x40, 0x84,
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
