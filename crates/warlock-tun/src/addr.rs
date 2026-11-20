// SPDX-License-Identifier: GPL-2.0-only
//! IPv6 ⇄ AWDL addresses.
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

/// The source of an IPv6 packet, `None` if `packet` isn't one.
pub fn ipv6_src(packet: &[u8]) -> Option<Ipv6Addr> {
    (packet.len() >= 40 && packet[0] >> 4 == 6).then(|| Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()))
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
}
