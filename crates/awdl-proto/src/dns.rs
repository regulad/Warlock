// SPDX-License-Identifier: GPL-2.0-only
//! AWDL's DNS names, as used by the Service Response and ARPA TLVs.
//!
//! A name is a run of labels that exactly fills a length the enclosing field
//! gives. Each label is either text (a length byte below 0x40, then that many
//! bytes) or a 2-byte big-endian dictionary code `0xC0xx` standing for a
//! common suffix such as `_tcp.local`. There's no terminating zero label.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::{Bytes, Error};

/// AWDL's name dictionary: code → the dotted suffix it stands for. `0xC000`
/// stands for nothing.
pub const DICTIONARY: [(u16, &str); 15] = [
    (0xC000, ""),
    (0xC001, "_airplay._tcp.local"),
    (0xC002, "_airplay._udp.local"),
    (0xC003, "_airplay"),
    (0xC004, "_raop._tcp.local"),
    (0xC005, "_raop._udp.local"),
    (0xC006, "_raop"),
    (0xC007, "_airdrop._tcp.local"),
    (0xC008, "_airdrop._udp.local"),
    (0xC009, "_airdrop"),
    (0xC00A, "_tcp.local"),
    (0xC00B, "_udp.local"),
    (0xC00C, "local"),
    (0xC00D, "ip6.arpa"),
    (0xC00E, "ip4.arpa"),
];

/// The suffix a dictionary code stands for, if the code is known.
pub fn dictionary_entry(code: u16) -> Option<&'static str> {
    DICTIONARY.iter().find(|(c, _)| *c == code).map(|(_, s)| *s)
}

/// One label of a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label<'a> {
    /// A text label (raw bytes, usually UTF-8).
    Text(&'a [u8]),
    /// A dictionary code, `0xC000..=0xFFFF`. See [`dictionary_entry`].
    Compressed(u16),
}

/// An encoded AWDL DNS name.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsName<'a> {
    raw: Bytes<'a>,
}

impl<'a> DnsName<'a> {
    /// Wraps an encoded name, checking that its labels exactly fill it.
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        validate(raw)?;
        Ok(Self { raw: Bytes::Borrowed(raw) })
    }

    /// Encodes the given labels.
    pub fn from_labels(labels: &[Label<'_>]) -> Result<DnsName<'static>, Error> {
        let mut raw = Vec::new();
        for l in labels {
            match *l {
                Label::Text(t) => {
                    if t.len() >= 0x40 {
                        return Err(Error::TooLong("DNS label"));
                    }
                    raw.push(t.len() as u8);
                    raw.extend_from_slice(t);
                }
                Label::Compressed(c) => {
                    if c < 0xC000 {
                        return Err(Error::Invalid("DNS dictionary code"));
                    }
                    raw.extend_from_slice(&c.to_be_bytes());
                }
            }
        }
        Ok(DnsName { raw: Bytes::Owned(raw) })
    }

    /// Encodes a dotted name the way Apple devices do: the longest
    /// label-aligned suffix found in [`DICTIONARY`] becomes its code, and the
    /// labels before it are text. Labels can't contain dots; use
    /// [`DnsName::from_labels`] for instance names that do.
    pub fn encode(name: &str) -> Result<DnsName<'static>, Error> {
        let name = name.strip_suffix('.').unwrap_or(name);
        let parts: Vec<&str> = if name.is_empty() { Vec::new() } else { name.split('.').collect() };
        // The first (longest) suffix with a dictionary code.
        let mut split = parts.len();
        let mut code = None;
        for i in 0..parts.len() {
            let suffix = parts[i..].join(".");
            if let Some((c, _)) = DICTIONARY.iter().find(|(c, s)| *c != 0xC000 && *s == suffix) {
                split = i;
                code = Some(*c);
                break;
            }
        }
        let mut labels: Vec<Label<'_>> = parts[..split].iter().map(|p| Label::Text(p.as_bytes())).collect();
        if let Some(c) = code {
            labels.push(Label::Compressed(c));
        }
        Self::from_labels(&labels)
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The labels, in order.
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.raw }
    }

    /// The dotted name with dictionary codes expanded (`0xC000` and unknown
    /// codes contribute nothing). Text that isn't UTF-8 is replaced lossily.
    pub fn to_dotted(&self) -> String {
        let mut s = String::new();
        for l in self.labels() {
            let part: alloc::borrow::Cow<'_, str> = match l {
                Label::Text(t) => String::from_utf8_lossy(t),
                Label::Compressed(c) => dictionary_entry(c).unwrap_or("").into(),
            };
            if part.is_empty() {
                continue;
            }
            if !s.is_empty() {
                s.push('.');
            }
            s.push_str(&part);
        }
        s
    }

    /// Converts to an owned name.
    pub fn into_owned(self) -> DnsName<'static> {
        DnsName { raw: Bytes::Owned(self.raw.into_owned()) }
    }
}

impl fmt::Display for DnsName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_dotted())
    }
}

impl fmt::Debug for DnsName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({:?})", self.to_dotted())
    }
}

/// Iterator over a validated name's labels.
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = Label<'a>;

    fn next(&mut self) -> Option<Label<'a>> {
        let (&b, tail) = self.rest.split_first()?;
        if b >= 0xC0 {
            let code = u16::from_be_bytes([b, tail[0]]);
            self.rest = &tail[1..];
            Some(Label::Compressed(code))
        } else {
            let (text, tail) = tail.split_at(b as usize);
            self.rest = tail;
            Some(Label::Text(text))
        }
    }
}

fn validate(mut raw: &[u8]) -> Result<(), Error> {
    while let Some((&b, tail)) = raw.split_first() {
        let n = match b {
            0xC0..=0xFF => 1,
            0x40..=0xBF => return Err(Error::Invalid("DNS label type")),
            n => n as usize,
        };
        if tail.len() < n {
            return Err(Error::Truncated("DNS label"));
        }
        raw = &tail[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_longest_dictionary_suffix() {
        let n = DnsName::encode("Test Device._airdrop._tcp.local").unwrap();
        assert_eq!(n.as_bytes(), b"\x0bTest Device\xc0\x07");
        assert_eq!(n.to_dotted(), "Test Device._airdrop._tcp.local");

        let n = DnsName::encode("_companion-link._tcp.local").unwrap();
        assert_eq!(n.as_bytes(), b"\x0f_companion-link\xc0\x0a");

        let n = DnsName::encode("host.local").unwrap();
        assert_eq!(n.as_bytes(), b"\x04host\xc0\x0c");

        let n = DnsName::encode("example.com").unwrap();
        assert_eq!(n.as_bytes(), b"\x07example\x03com");
    }

    #[test]
    fn rejects_overruns_and_reserved_label_types() {
        assert_eq!(DnsName::parse(b"\x05abc"), Err(Error::Truncated("DNS label")));
        assert_eq!(DnsName::parse(b"\xc0"), Err(Error::Truncated("DNS label")));
        assert_eq!(DnsName::parse(b"\x41abc"), Err(Error::Invalid("DNS label type")));
        assert!(DnsName::parse(b"").unwrap().labels().next().is_none());
    }
}
