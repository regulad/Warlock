// SPDX-License-Identifier: GPL-2.0-only
//! Apple's Continuity messages over Bluetooth LE, as Warlock builds them to
//! ask for a service: the manufacturer data after Apple's company ID. No OS
//! calls, so a port can keep it.
//!
//! The layouts are from iOS 27.2.1 (24B156): Sharing's builder,
//! `-[SFBLEAdvertiser _preparePayloadNearbyAction:]`, and its parser,
//! `-[SFBLEScanner _nearbyParseManufacturerData:fields:]` and
//! `_nearbyParseNearbyActionPtr`. Koala's `docs/guest-pairing.md` ("Phase B
//! over BLE") has the work and the trials.

use std::hash::Hasher;

use siphasher::sip::SipHasher24;

/// Apple's Bluetooth company identifier.
pub const APPLE: u16 = 0x004c;

/// A Nearby Action: its type, its length, flags, an action type, and a
/// 3-byte auth tag when the flags say one follows.
pub mod nearby_action {
    /// Its Continuity type.
    pub const TYPE: u8 = 0x0f;

    /// Its flags (Sharing's `af1`). Warlock sets a flag only when what it
    /// says is true of the advert, or of what was asked (AGENTS.md).
    pub mod flags {
        /// A 3-byte auth tag follows the action type. Warlock sets it
        /// whenever it sends one.
        pub const AUTH_TAG: u8 = 0x80;
        /// `SFService.needsKeyboard` (`nk`). tvOS's RDLink advert sets it, and
        /// so did Koala's own (`0xa0`, 2026-11-19 to 11-20). What a receiver
        /// does with it is unknown, so it's sent only when a request asks for
        /// it (`needs_keyboard`). An iPhone doesn't need it: in Koala's trial
        /// 25 (2026-11-20, iOS 27.2.1) it identified Warlock's `0x80` advert
        /// and advertised its RDLink 0.1 s later, although its scanner is a
        /// Sharing discovery with the Keyboard flag (`0x20040`).
        pub const NEEDS_KEYBOARD: u8 = 0x20;
    }

    /// Its action types.
    pub mod action {
        /// RDLink needs AWDL: an iPhone that identifies the sender, as a
        /// device paired with it, advertises its `_rdlink._tcp` on AWDL
        /// (rapportd's `_serverBLENeedsAWDLScannerDeviceFound:`, which takes
        /// an identified sender and this action type).
        pub const RDLINK_NEEDS_AWDL: u8 = 0x32;
    }
}

/// A Nearby Action of `action` with `flags`, carrying the auth tag `tag`
/// (which sets [`nearby_action::flags::AUTH_TAG`]).
pub fn nearby_action(flags: u8, action: u8, tag: &[u8; 3]) -> Vec<u8> {
    let flags = flags | nearby_action::flags::AUTH_TAG;
    // The length counts what follows it: flags, action type and tag.
    vec![nearby_action::TYPE, 5, flags, action, tag[0], tag[1], tag[2]]
}

/// The auth tag of an advert sent from `address` (most significant byte
/// first) by a device with Identity Resolving Key `irk`: SipHash-2-4 keyed
/// with the IRK over the address, and of the 64-bit result the 3 bytes
/// below its top two, big-endian. The receiver tries the IRKs of the
/// devices it knows on the tag, over the address the advert came from.
pub fn auth_tag(irk: &[u8; 16], address: &[u8; 6]) -> [u8; 3] {
    let mut hasher = SipHasher24::new_with_key(irk);
    hasher.write(address);
    let h = hasher.finish().to_be_bytes();
    [h[2], h[3], h[4]]
}

/// An IRK whose auth tag for an advert from `address` is `tag`, starting
/// from `seed` (random) and changing only its last 4 bytes: about 2^24
/// tries. For a sender that learns its address only once the advert is
/// fixed, as Windows' publisher does: the advert can't be tagged for a given
/// IRK, so the IRK is chosen for the advert.
pub fn irk_for(address: &[u8; 6], tag: &[u8; 3], seed: [u8; 16]) -> [u8; 16] {
    let mut irk = seed;
    let start = u32::from_le_bytes(seed[12..].try_into().unwrap());
    for counter in 0u32..=u32::MAX {
        irk[12..].copy_from_slice(&start.wrapping_add(counter).to_le_bytes());
        if auth_tag(&irk, address) == *tag {
            return irk;
        }
    }
    unreachable!("a 3-byte tag is matched within 2^32 tries")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    /// SipHash-2-4's reference vectors (Aumasson and Bernstein, key 00..0f,
    /// message 00..n-1): the crate computes what the tag needs.
    #[test]
    fn siphash_is_the_reference() {
        let hash = |m: &[u8]| {
            let mut h = SipHasher24::new_with_key(&KEY);
            h.write(m);
            h.finish()
        };
        assert_eq!(hash(b""), 0x726f_db47_dd0e_0e31);
        assert_eq!(hash(&(0..15).collect::<Vec<u8>>()), 0xa129_ca61_49be_45e5);
    }

    /// The worked example from the reverse engineering (IRK 00..0f,
    /// address c0:11:22:33:44:55), whose reference implementation passed
    /// the vectors above.
    #[test]
    fn the_tag_is_the_reverse_engineerings() {
        assert_eq!(auth_tag(&KEY, &[0xc0, 0x11, 0x22, 0x33, 0x44, 0x55]), [0x37, 0xb4, 0x0c]);
    }

    /// Koala's advert, which worked, with the needs-keyboard bit; and
    /// Warlock's own, without.
    #[test]
    fn the_rdlink_advert_is_laid_out_as_the_iphone_reads_it() {
        use nearby_action::{action, flags};
        let tag = [0x37, 0xb4, 0x0c];
        assert_eq!(
            nearby_action(flags::NEEDS_KEYBOARD, action::RDLINK_NEEDS_AWDL, &tag),
            [0x0f, 0x05, 0xa0, 0x32, 0x37, 0xb4, 0x0c]
        );
        assert_eq!(nearby_action(0, action::RDLINK_NEEDS_AWDL, &tag), [0x0f, 0x05, 0x80, 0x32, 0x37, 0xb4, 0x0c]);
    }

    /// The IRK found tags the advert; here the seed's own counter, a few
    /// tries on, is known to fit, so the search is short.
    #[test]
    fn an_irk_is_found_for_an_advert() {
        let address = [0x6a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
        let mut fits = KEY;
        fits[12..].copy_from_slice(&(u32::from_le_bytes([12, 13, 14, 15]).wrapping_add(5)).to_le_bytes());
        let tag = auth_tag(&fits, &address);
        let irk = irk_for(&address, &tag, KEY);
        assert_eq!(auth_tag(&irk, &address), tag);
        assert_eq!(irk[..12], KEY[..12], "only the counter changes");
    }
}
