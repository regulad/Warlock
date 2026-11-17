// SPDX-License-Identifier: GPL-2.0-only

use core::fmt;

/// A 48-bit IEEE MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// True for group (multicast and broadcast) addresses.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 1 != 0
    }

    /// True for locally administered addresses, such as AWDL's randomized ones.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 2 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(b: [u8; 6]) -> Self {
        MacAddr(b)
    }
}
