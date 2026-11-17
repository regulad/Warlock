// SPDX-License-Identifier: GPL-2.0-only
//! IPv6 ⇄ AWDL addresses, and what to keep off the air.
//!
//! AWDL peers address each other by the modified EUI-64 link-local address
//! of their AWDL MAC: a Mac and an Apple TV each listed ours that way, and
//! pings to an iPhone's and an Apple TV's worked
//! (`docs/awdl-field-observations.md`).

use std::net::Ipv6Addr;

/// The modified EUI-64 link-local address of `mac`.
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 2, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]])
}

/// The AWDL address to send to for `dst`: the 33:33 group of a multicast
/// address, or the MAC inside an EUI-64 link-local address. `None` for
/// anything else; AWDL has no route beyond its link.
pub fn mac_for(dst: &Ipv6Addr) -> Option<[u8; 6]> {
    let o = dst.octets();
    if o[0] == 0xff {
        return Some([0x33, 0x33, o[12], o[13], o[14], o[15]]);
    }
    if o[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0] && o[11] == 0xff && o[12] == 0xfe {
        return Some([o[8] ^ 2, o[9], o[10], o[13], o[14], o[15]]);
    }
    None
}

/// The destination of an IPv6 packet, `None` if `packet` isn't one.
pub fn ipv6_dst(packet: &[u8]) -> Option<Ipv6Addr> {
    (packet.len() >= 40 && packet[0] >> 4 == 6).then(|| Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()))
}

/// What Windows sends on its own that AWDL peers have no use for: MLD
/// reports and done messages, router solicitations, LLMNR, SSDP and
/// WS-Discovery (UDP 3702 to ff02::c: 21 packets in a 2-minute run).
pub fn is_chatter(packet: &[u8]) -> bool {
    if packet.len() < 40 {
        return false;
    }
    let (mut next, mut at) = (packet[6], 40);
    // MLD carries a hop-by-hop header (Router Alert) first.
    if next == 0 {
        let Some(&len) = packet.get(at + 1) else { return false };
        next = packet[at];
        at += (len as usize + 1) * 8;
    }
    match next {
        58 => packet.get(at).is_some_and(|t| matches!(t, 130..=133 | 143)),
        17 => packet.get(at + 2..at + 4).is_some_and(|p| matches!(u16::from_be_bytes([p[0], p[1]]), 5355 | 1900 | 3702)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_round_trips() {
        let mac = [0x76, 0x56, 0x82, 0x58, 0x57, 0x70];
        let ll = link_local(mac);
        assert_eq!(ll, "fe80::7456:82ff:fe58:5770".parse::<Ipv6Addr>().unwrap());
        assert_eq!(mac_for(&ll), Some(mac));
        assert_eq!(mac_for(&"ff02::fb".parse().unwrap()), Some([0x33, 0x33, 0, 0, 0, 0xfb]));
        assert_eq!(mac_for(&"fe80::1".parse().unwrap()), None);
        assert_eq!(mac_for(&"2001:db8::1".parse().unwrap()), None);
    }

    #[test]
    fn mld_behind_hop_by_hop_is_chatter() {
        let mut p = vec![0x60, 0, 0, 0, 0, 36, 0, 1];
        p.extend_from_slice(&[0; 32]); // addresses
        p.extend_from_slice(&[58, 0, 5, 2, 0, 0, 1, 0]); // hop-by-hop, Router Alert
        p.extend_from_slice(&[143, 0, 0, 0]); // MLDv2 report
        assert!(is_chatter(&p));
        p[48] = 128; // echo request
        assert!(!is_chatter(&p));
    }
}
