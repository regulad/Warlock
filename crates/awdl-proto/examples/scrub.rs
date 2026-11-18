// SPDX-License-Identifier: GPL-2.0-only
//! Writes a small anonymized fixture from real captures, for tests that
//! must run without the private corpus.
//!
//!     cargo run -p awdl-proto --example scrub -- <out.pcapng> <in.pcapng>...
//!
//! Keeps a sample of AWDL action frames (the first few of each distinct
//! sender / subtype / TLV-set combination) and rebuilds each through the
//! crate's builders with:
//! - every unicast MAC address mapped to `02:00:00:00:00:NN`;
//! - every DNS text label that isn't a service or protocol label (`_…`) or a
//!   common word replaced by `nameN`;
//! - every TXT value whose key isn't on a short allowlist replaced by a hex
//!   counter of the same length.
//!
//! Data frames are left out: their payloads are mDNS and TCP traffic. Output
//! is LINKTYPE_IEEE802_11 (105) with zeroed timestamps.

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::{BTreeMap, BTreeSet};

use awdl_proto::action::ActionFrameBuilder;
use awdl_proto::dns::{DnsName, Label};
use awdl_proto::tlv::{Rdata, TlvBody};
use awdl_proto::{AWDL_BSSID, Frame, MacAddr, parse};

/// TXT keys whose values identify nothing and are worth keeping.
const KEEP_VALUES: &[&str] = &[
    "sn",
    "model",
    "features",
    "flags",
    "srcvers",
    "osvers",
    "vv",
    "pin",
    "protovers",
    "rpFl",
    "rpVr",
    "rpMd",
    "statusFlags",
    "acl",
    "ft",
    "sf",
    "cn",
    "da",
    "et",
    "md",
    "sv",
    "tp",
    "vn",
    "vs",
    "am",
    "ov",
];
/// Text labels that are common words, not names.
const KEEP_LABELS: &[&str] = &["local", "tcp", "udp", "arpa", "ip6", "in-addr"];
/// Frames kept per (sender, subtype, TLV set).
const PER_SHAPE: usize = 2;

#[derive(Default)]
struct Scrubber {
    macs: BTreeMap<MacAddr, MacAddr>,
    labels: BTreeMap<Vec<u8>, Vec<u8>>,
    values: usize,
}

impl Scrubber {
    fn mac(&mut self, m: MacAddr) -> MacAddr {
        if m.is_multicast() || m == AWDL_BSSID || m == MacAddr::default() {
            return m;
        }
        let n = self.macs.len() + 1;
        *self.macs.entry(m).or_insert(MacAddr([0x02, 0, 0, 0, (n >> 8) as u8, n as u8]))
    }

    fn label(&mut self, t: &[u8]) -> Vec<u8> {
        if t.starts_with(b"_") || KEEP_LABELS.iter().any(|k| k.as_bytes() == t) {
            return t.to_vec();
        }
        let n = self.labels.len() + 1;
        self.labels.entry(t.to_vec()).or_insert_with(|| format!("name{n}").into_bytes()).clone()
    }

    fn name(&mut self, n: &DnsName<'_>) -> DnsName<'static> {
        enum Owned {
            Text(Vec<u8>),
            Code(u16),
        }
        let owned: Vec<Owned> = n
            .labels()
            .map(|l| match l {
                Label::Text(t) => Owned::Text(self.label(t)),
                Label::Compressed(c) => Owned::Code(c),
            })
            .collect();
        let labels: Vec<Label<'_>> = owned
            .iter()
            .map(|o| match o {
                Owned::Text(t) => Label::Text(t),
                Owned::Code(c) => Label::Compressed(*c),
            })
            .collect();
        DnsName::from_labels(&labels).unwrap()
    }

    fn txt(&mut self, r: &Rdata<'_>) -> Rdata<'static> {
        let mut out = Vec::new();
        for s in r.txt_strings() {
            let Some(eq) = s.iter().position(|&b| b == b'=') else {
                out.push(s.to_vec());
                continue;
            };
            let (key, value) = (&s[..eq], &s[eq + 1..]);
            if KEEP_VALUES.iter().any(|k| k.as_bytes() == key) || value.is_empty() {
                out.push(s.to_vec());
            } else {
                self.values += 1;
                let mut v = format!("{:0width$x}", self.values, width = value.len()).into_bytes();
                v.truncate(value.len().max(1));
                out.push([key, b"=", &v].concat());
            }
        }
        Rdata::txt_from_strings(&out).unwrap()
    }

    fn tlv<'a>(&mut self, body: TlvBody<'a>) -> TlvBody<'a> {
        match body {
            TlvBody::SyncParams(mut s) => {
                s.master = self.mac(s.master);
                TlvBody::SyncParams(s)
            }
            TlvBody::ElectionParams(mut e) => {
                e.master = self.mac(e.master);
                if let Some(p) = &mut e.private {
                    p.master = self.mac(p.master);
                }
                TlvBody::ElectionParams(e)
            }
            TlvBody::ElectionParamsV2(mut e) => {
                e.master = self.mac(e.master);
                e.other = self.mac(e.other);
                TlvBody::ElectionParamsV2(e)
            }
            TlvBody::DataPathState(mut d) => {
                if let Some(i) = &mut d.infra {
                    i.bssid = self.mac(i.bssid);
                }
                d.infra_address = d.infra_address.map(|a| self.mac(a));
                d.awdl_address = d.awdl_address.map(|a| self.mac(a));
                TlvBody::DataPathState(d)
            }
            TlvBody::SyncTree(t) => {
                let addrs: Vec<MacAddr> = t.addresses().map(|a| self.mac(a)).collect();
                let mut n = awdl_proto::tlv::SyncTree::from_addresses(&addrs);
                n.trailing = t.trailing.clone();
                TlvBody::SyncTree(n)
            }
            TlvBody::Arpa(mut a) => {
                a.name = self.name(&a.name);
                TlvBody::Arpa(a)
            }
            TlvBody::ServiceResponse(mut s) => {
                s.name = self.name(&s.name);
                s.rdata = match &s.rdata {
                    Rdata::Ptr(p) => Rdata::Ptr(self.name(p)),
                    Rdata::Srv { priority, weight, port, target } => {
                        Rdata::Srv { priority: *priority, weight: *weight, port: *port, target: self.name(target) }
                    }
                    t @ Rdata::Txt(_) => self.txt(t),
                    Rdata::Other { rtype, .. } => Rdata::Other { rtype: *rtype, data: Default::default() },
                };
                TlvBody::ServiceResponse(s)
            }
            other => other,
        }
    }
}

fn write_pcapng(path: &str, mpdus: &[Vec<u8>]) {
    let mut w = warlock_capture::Writer::bare(Vec::new()).unwrap();
    for m in mpdus {
        w.write(std::time::Duration::ZERO, 0, 0, 0, m).unwrap();
    }
    std::fs::write(path, w.into_inner()).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out_path, inputs) = args.split_first().expect("usage: scrub <out.pcapng> <in.pcapng>...");
    let mut s = Scrubber::default();
    let mut seen: BTreeMap<(MacAddr, u8, BTreeSet<u8>), usize> = BTreeMap::new();
    let mut kept = Vec::new();
    for input in inputs {
        for (_, mpdu) in common::mpdus(input.as_ref()) {
            let Ok(Some(Frame::Action { header, action })) = parse(&mpdu) else { continue };
            let shape = (header.addr2, action.header.subtype, action.tlvs().map(|t| t.kind).collect());
            let n = seen.entry(shape).or_default();
            if *n >= PER_SHAPE {
                continue;
            }
            *n += 1;
            let mut h = header;
            h.addr1 = s.mac(h.addr1);
            h.addr2 = s.mac(h.addr2);
            let mut b = ActionFrameBuilder::new(&h, &action.header);
            for t in action.tlvs() {
                match t.decode() {
                    Ok(body) => b.tlv(&s.tlv(body)).unwrap(),
                    Err(_) => b.raw_tlv(t.kind, t.value).unwrap(),
                };
            }
            kept.push(b.finish());
        }
    }
    write_pcapng(out_path, &kept);
    eprintln!(
        "kept {} frames; mapped {} addresses, {} labels, {} TXT values",
        kept.len(),
        s.macs.len(),
        s.labels.len(),
        s.values
    );
}
