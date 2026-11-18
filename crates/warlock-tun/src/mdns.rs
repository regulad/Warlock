// SPDX-License-Identifier: GPL-2.0-only
//! mDNS announcements to write onto the adapter: standard DNS responses
//! (RFC 1035; RFC 6762 for mDNS) in IPv6/UDP packets addressed to the mDNS
//! group.
//!
//! Warlock uses them for records it learned from AWDL peers' Service Response
//! TLVs, sent from the peer's own link-local address, so Windows' DNS-SD
//! finds peers that advertise only in their frames
//! (`docs/service-discovery.md`).

use std::net::Ipv6Addr;

/// The mDNS group (RFC 6762 §3).
pub const GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// The mDNS port.
pub const PORT: u16 = 5353;
/// mDNS packets carry hop limit 255, so receivers can tell they're from the
/// link (RFC 6762 §11).
const HOP_LIMIT: u8 = 255;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const DNS_HEADER: usize = 12;
const CLASS_IN: u16 = 1;
/// The class field's top bit in an mDNS answer: this record replaces any
/// cached ones of its name and type (RFC 6762 §10.2).
const CACHE_FLUSH: u16 = 0x8000;

/// DNS record types used here.
pub mod rr_type {
    /// PTR.
    pub const PTR: u16 = 12;
    /// TXT.
    pub const TXT: u16 = 16;
    /// AAAA.
    pub const AAAA: u16 = 28;
    /// SRV.
    pub const SRV: u16 = 33;
}

/// One resource record, its name and data in DNS wire format (uncompressed).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    /// The owner name.
    pub name: Vec<u8>,
    /// The record type.
    pub rtype: u16,
    /// The record data.
    pub rdata: Vec<u8>,
}

impl Record {
    /// Whether this is the only record of its name and type, so it's sent
    /// with the cache-flush bit. A PTR from a service type to an instance
    /// isn't: every advertiser of the type has one, and one's flush mustn't
    /// drop the others' (RFC 6762 §10.2).
    fn unique(&self) -> bool {
        self.rtype != rr_type::PTR
    }

    fn wire_len(&self) -> usize {
        self.name.len() + 10 + self.rdata.len()
    }

    fn emit(&self, ttl: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.name);
        out.extend_from_slice(&self.rtype.to_be_bytes());
        let class = if self.unique() { CLASS_IN | CACHE_FLUSH } else { CLASS_IN };
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(self.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.rdata);
    }
}

/// Unsolicited mDNS responses carrying `records` with `ttl` (0: goodbyes,
/// RFC 6762 §10.1), in as few messages as keep each within `max_message`
/// bytes. A record too big for that gets a message of its own.
pub fn responses(records: &[Record], ttl: u32, max_message: usize) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    let mut batch: Vec<&Record> = Vec::new();
    let mut len = DNS_HEADER;
    for r in records {
        if !batch.is_empty() && len + r.wire_len() > max_message {
            messages.push(message(&batch, ttl));
            batch.clear();
            len = DNS_HEADER;
        }
        len += r.wire_len();
        batch.push(r);
    }
    if !batch.is_empty() {
        messages.push(message(&batch, ttl));
    }
    messages
}

fn message(records: &[&Record], ttl: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(DNS_HEADER + records.iter().map(|r| r.wire_len()).sum::<usize>());
    m.extend_from_slice(&0u16.to_be_bytes()); // ID: 0 in mDNS responses
    m.extend_from_slice(&0x8400u16.to_be_bytes()); // response, authoritative
    m.extend_from_slice(&0u16.to_be_bytes()); // questions
    m.extend_from_slice(&(records.len() as u16).to_be_bytes()); // answers
    m.extend_from_slice(&[0, 0, 0, 0]); // authority, additional
    for r in records {
        r.emit(ttl, &mut m);
    }
    m
}

/// The announcement packets for `records` from `src`: IPv6/UDP to the mDNS
/// group, each within `mtu`.
pub fn announcements(src: Ipv6Addr, records: &[Record], ttl: u32, mtu: usize) -> Vec<Vec<u8>> {
    responses(records, ttl, mtu.saturating_sub(IPV6_HEADER + UDP_HEADER))
        .iter()
        .map(|m| udp(src, GROUP, PORT, PORT, HOP_LIMIT, m))
        .collect()
}

/// An IPv6 packet carrying one UDP datagram, checksum included (mandatory
/// over IPv6).
pub fn udp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let udp_len = (UDP_HEADER + payload.len()) as u16;
    let mut p = Vec::with_capacity(IPV6_HEADER + udp_len as usize);
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.push(17); // next header: UDP
    p.push(hop_limit);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&udp_len.to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let sum = match !checksum(src, dst, &p[IPV6_HEADER..]) {
        0 => 0xffff, // 0 means "no checksum", which IPv6 forbids
        s => s,
    };
    p[IPV6_HEADER + 6..IPV6_HEADER + 8].copy_from_slice(&sum.to_be_bytes());
    p
}

/// The ones'-complement sum over the IPv6 pseudo-header and `datagram`
/// (RFC 8200 §8.1), not yet complemented.
fn checksum(src: Ipv6Addr, dst: Ipv6Addr, datagram: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            sum += u64::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(datagram.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 17]);
    add(datagram);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(dotted: &str) -> Vec<u8> {
        let mut n = Vec::new();
        for l in dotted.split('.') {
            n.push(l.len() as u8);
            n.extend_from_slice(l.as_bytes());
        }
        n.push(0);
        n
    }

    fn records() -> Vec<Record> {
        vec![
            Record { name: name("_airplay._tcp.local"), rtype: rr_type::PTR, rdata: name("TV._airplay._tcp.local") },
            Record { name: name("TV._airplay._tcp.local"), rtype: rr_type::TXT, rdata: b"\x05pin=1".to_vec() },
        ]
    }

    #[test]
    fn a_response_is_an_authoritative_answer_list() {
        let m = &responses(&records(), 120, 1400)[0];
        assert_eq!(&m[..12], &[0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0]);
        // The PTR is shared, the TXT unique.
        let ptr_class = 12 + name("_airplay._tcp.local").len() + 2;
        assert_eq!(&m[ptr_class..ptr_class + 6], &[0, 1, 0, 0, 0, 120]);
        let txt = &m[m.len() - 6 - 10..];
        assert_eq!(&txt[..10], &[0, 16, 0x80, 1, 0, 0, 0, 120, 0, 6]);
        // Goodbyes carry TTL 0.
        let bye = &responses(&records(), 0, 1400)[0];
        assert_eq!(&bye[ptr_class + 2..ptr_class + 6], &[0, 0, 0, 0]);
    }

    #[test]
    fn records_are_split_across_messages_to_fit() {
        let r = records();
        let one = responses(&r, 120, 1400);
        assert_eq!(one.len(), 1);
        let split = responses(&r, 120, one[0].len() - 1);
        assert_eq!(split.len(), 2);
        assert!(split.iter().all(|m| m[7] == 1));
    }

    #[test]
    fn the_udp_checksum_verifies() {
        let src: Ipv6Addr = "fe80::b459:4eff:febd:eda5".parse().unwrap();
        for p in announcements(src, &records(), 120, 1450) {
            assert_eq!(p[0] >> 4, 6);
            assert_eq!((p[6], p[7]), (17, 255));
            assert_eq!(&p[24..40], &GROUP.octets());
            assert_eq!(u16::from_be_bytes([p[4], p[5]]) as usize, p.len() - 40);
            assert_eq!(&p[40..44], &[0x14, 0xe9, 0x14, 0xe9]);
            // Summed with its checksum in place, a datagram sums to 0xffff.
            assert_eq!(checksum(src, GROUP, &p[40..]), 0xffff);
        }
    }
}
