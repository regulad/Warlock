// SPDX-License-Identifier: GPL-2.0-only
//! Test vectors for the Service Parameters set: for each sender and update
//! counter in the given captures, the set's members next to the records the
//! same frames carry. One line per (sender, counter):
//!
//!     svcbits <capture>...
//!
//! `<mac> sui=<n> head=<flags, dwellTime hex> tlvs=<types in order> set=<a,b,...> | <type> <name hex> <rdata hex> | ...`

use std::collections::BTreeMap;

use awdl_proto::tlv::TlvBody;
use awdl_proto::{Frame, parse};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for path in std::env::args().skip(1) {
        let captured = match warlock_capture::read(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{path}: {e:?}");
                continue;
            }
        };
        for c in captured {
            let Ok(Some(Frame::Action { header, action })) = parse(&c.mpdu) else { continue };
            let (mut set, mut sui, mut head, mut records) = (None, None, String::new(), Vec::new());
            let kinds: Vec<String> = action.tlvs().map(|t| t.kind.to_string()).collect();
            for t in action.tlvs() {
                match t.decode() {
                    Ok(TlvBody::ServiceParams(s)) => {
                        sui = Some(s.sui);
                        head = hex(&s.unknown);
                        set = Some(s.set_values().map(|v| v.to_string()).collect::<Vec<_>>().join(","));
                    }
                    Ok(TlvBody::ServiceResponse(s)) => {
                        let mut data = Vec::new();
                        s.emit(&mut data).unwrap();
                        let name_len = u16::from_le_bytes([data[0], data[1]]) as usize - 1;
                        let rdata = &data[2 + name_len + 1 + 4..];
                        records.push(format!("{} {} {}", s.rdata.rtype(), hex(s.name.as_bytes()), hex(rdata)));
                    }
                    _ => {}
                }
            }
            let (Some(sui), Some(set)) = (sui, set) else { continue };
            if records.is_empty() {
                continue;
            }
            let key = format!("{} sui={sui}", header.source());
            let line = format!("head={head} tlvs={} set={set} | {}", kinds.join(","), records.join(" | "));
            seen.entry(key).or_insert(line);
        }
    }
    for (k, v) in seen {
        println!("{k} {v}");
    }
}
