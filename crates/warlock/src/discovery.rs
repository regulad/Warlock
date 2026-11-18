// SPDX-License-Identifier: GPL-2.0-only
//! Peers that advertise only in their frames, made visible to Windows: each
//! peer's Service Response TLVs, written onto the adapter as mDNS
//! announcements from the peer's own link-local address, so Windows' own
//! DNS-SD browses find them (`docs/service-discovery.md`).
//!
//! The records live as long as the peer advertises them, as Apple's D2D
//! bridge keeps them until the AWDL layer reports them lost. Windows' cache
//! ages records by TTL, so they go out with D2D's own TTL (120 s) and are
//! re-announced well within it; a peer that drops a record, or is lost, gets
//! goodbyes (TTL 0).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use awdl_core::Peer;
use awdl_proto::MacAddr;
use awdl_proto::tlv::Rdata;
use warlock_tun::addr::link_local;
use warlock_tun::mdns::{self, Record, rr_type};

/// The TTL of announced records: what Apple's D2D gives records it puts in
/// mDNSResponder's cache (`mDNSMacOSX/D2D.c`, `xD2DParse`).
const TTL: u32 = 120;
/// How often everything is announced again: half the TTL.
const REFRESH: Duration = Duration::from_secs(TTL as u64 / 2);

/// What has been announced for each peer.
pub struct Discovery {
    announced: BTreeMap<MacAddr, Vec<Record>>,
    last_refresh: Instant,
    mtu: usize,
}

impl Discovery {
    /// Nothing announced yet; packets fit `mtu`.
    pub fn new(mtu: usize) -> Self {
        Self { announced: BTreeMap::new(), last_refresh: Instant::now(), mtu }
    }

    /// The records `peer` advertises, in DNS form, sorted. Its PTR, SRV and
    /// TXT records, and an AAAA giving its ARPA host name its link-local
    /// address: the ARPA TLV is the reverse of that address record.
    ///
    /// Records whose data's encoding we don't know (types other than PTR,
    /// SRV and TXT, none seen so far) can't be converted, and are left out.
    pub fn records(peer: &Peer) -> Vec<Record> {
        let mut out: Vec<Record> = peer
            .services
            .iter()
            .filter(|s| !matches!(s.rdata, Rdata::Other { .. }))
            .filter_map(|s| {
                Some(Record { name: s.name.to_wire()?, rtype: s.rdata.rtype().into(), rdata: s.rdata.to_wire(&s.name)? })
            })
            .collect();
        if let Some(host) = peer.arpa_name.as_ref().and_then(|n| n.to_wire()) {
            out.push(Record { name: host, rtype: rr_type::AAAA, rdata: link_local(peer.addr.0).octets().to_vec() });
        }
        out.sort();
        out.dedup();
        out
    }

    /// `peer`'s records changed: goodbyes for those it dropped, then
    /// everything it advertises now.
    pub fn update(&mut self, peer: &Peer) -> Vec<Vec<u8>> {
        let now = Self::records(peer);
        let before = self.announced.remove(&peer.addr).unwrap_or_default();
        let dropped: Vec<Record> = before.iter().filter(|r| !now.contains(r)).cloned().collect();
        let src = link_local(peer.addr.0);
        let mut packets = mdns::announcements(src, &dropped, 0, self.mtu);
        if now != before {
            packets.extend(mdns::announcements(src, &now, TTL, self.mtu));
        }
        if !now.is_empty() {
            self.announced.insert(peer.addr, now);
        }
        packets
    }

    /// `addr` is gone: goodbyes for everything it advertised.
    pub fn lost(&mut self, addr: MacAddr) -> Vec<Vec<u8>> {
        let records = self.announced.remove(&addr).unwrap_or_default();
        mdns::announcements(link_local(addr.0), &records, 0, self.mtu)
    }

    /// Everything again, when due.
    pub fn refresh(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if now.duration_since(self.last_refresh) < REFRESH {
            return Vec::new();
        }
        self.last_refresh = now;
        self.announced
            .iter()
            .flat_map(|(addr, records)| mdns::announcements(link_local(addr.0), records, TTL, self.mtu))
            .collect()
    }

    /// Stopping: goodbyes for everything.
    pub fn stop(&mut self) -> Vec<Vec<u8>> {
        let peers: Vec<MacAddr> = self.announced.keys().copied().collect();
        peers.into_iter().flat_map(|a| self.lost(a)).collect()
    }

    /// How many peers have records announced, and how many records.
    pub fn counts(&self) -> (usize, usize) {
        (self.announced.len(), self.announced.values().map(Vec::len).sum())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use awdl_core::{Config, Engine, Event, RxMeta};

    use super::*;

    /// Real frames from Apple devices, anonymized (`awdl-proto`'s fixture).
    fn fixture() -> Vec<Vec<u8>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../awdl-proto/tests/fixtures/awdl-scrubbed.pcapng");
        warlock_capture::read(path).unwrap().into_iter().map(|c| c.mpdu).collect()
    }

    /// A classic pcap of raw IP packets (link type 101).
    fn raw_ip_pcap(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut f = Vec::new();
        for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 101u32.to_le_bytes()] {
            f.extend_from_slice(&v);
        }
        for p in packets {
            f.extend_from_slice(&[0; 8]);
            f.extend_from_slice(&(p.len() as u32).to_le_bytes());
            f.extend_from_slice(&(p.len() as u32).to_le_bytes());
            f.extend_from_slice(p);
        }
        f
    }

    #[test]
    fn peers_records_become_mdns_that_wireshark_reads() {
        let mut engine = Engine::new(Config::default());
        let mut d = Discovery::new(1450);
        let mut packets = Vec::new();
        for (i, mpdu) in fixture().iter().enumerate() {
            let meta = RxMeta { tsf: 1_000_000 + i as u64 * 1_000, channel: 149, rssi_dbm: -40 };
            for ev in engine.on_frame(meta, mpdu) {
                if let Event::ServicesChanged(a) = ev {
                    packets.extend(d.update(engine.peer(a).unwrap()));
                }
            }
        }
        let (advertisers, records) = d.counts();
        assert!(advertisers > 0 && records > 0, "no service records in the fixture");
        // Every PTR/SRV/TXT record converts, plus one AAAA per ARPA name.
        for p in engine.peers() {
            let known = p.services.iter().filter(|s| !matches!(s.rdata, Rdata::Other { .. })).count();
            let rs = Discovery::records(p);
            let aaaa = rs.iter().filter(|r| r.rtype == rr_type::AAAA).count();
            assert_eq!(aaaa, p.arpa_name.is_some() as usize);
            assert_eq!(rs.len() - aaaa, known, "peer {}: a record didn't convert", p.addr);
            // A PTR names an instance under its own service type.
            for r in rs.iter().filter(|r| r.rtype == rr_type::PTR) {
                assert!(r.rdata.len() > r.name.len() && r.rdata.ends_with(&r.name), "peer {}: PTR {r:?}", p.addr);
            }
        }
        // Unchanged records aren't announced again outside a refresh.
        for p in engine.peers() {
            assert!(d.update(p).is_empty(), "peer {} re-announced", p.addr);
        }
        let first = engine.peers().find(|p| !p.services.is_empty()).unwrap().addr;
        let goodbyes = d.lost(first);
        assert!(!goodbyes.is_empty());
        packets.extend(goodbyes);

        let ts = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
        if !ts.exists() {
            eprintln!("tshark not found; skipping the Wireshark check");
            return;
        }
        let path = std::env::temp_dir().join(format!("warlock-discovery-{}.pcap", std::process::id()));
        std::fs::write(&path, raw_ip_pcap(&packets)).unwrap();
        let out = Command::new(ts)
            .args(["-o", "udp.check_checksum:TRUE", "-T", "fields", "-E", "separator=|"])
            .args(["-e", "udp.checksum.status", "-e", "_ws.malformed", "-e", "dns.count.answers"])
            .args(["-e", "dns.resp.ttl", "-e", "dns.resp.type", "-e", "dns.resp.name", "-r"])
            .arg(&path)
            .output()
            .unwrap();
        std::fs::remove_file(&path).ok();
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), packets.len(), "tshark read {} of {} packets", lines.len(), packets.len());
        for l in &lines {
            println!("{l}");
            let f: Vec<&str> = l.split('|').collect();
            assert_eq!(f[0], "1", "UDP checksum not good: {l}");
            assert_eq!(f[1], "", "malformed: {l}");
            assert!(f[2].parse::<u32>().unwrap() > 0, "no answers: {l}");
        }
    }
}
