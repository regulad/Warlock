// SPDX-License-Identifier: GPL-2.0-only
//! A bounds-checked cursor over a byte slice, and the matching writers.

use alloc::vec::Vec;

use crate::{Error, MacAddr};

/// A forward-only reader. Each read names its field, so a truncation error
/// says where the data ran out.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn peek_u8(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    pub(crate) fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        if n > self.buf.len() {
            return Err(Error::Truncated(what));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Error> {
        let b = self.bytes(N, what)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub(crate) fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        Ok(self.array::<1>(what)?[0])
    }

    pub(crate) fn u16le(&mut self, what: &'static str) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array(what)?))
    }

    pub(crate) fn i16le(&mut self, what: &'static str) -> Result<i16, Error> {
        Ok(i16::from_le_bytes(self.array(what)?))
    }

    pub(crate) fn u32le(&mut self, what: &'static str) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array(what)?))
    }

    pub(crate) fn u16be(&mut self, what: &'static str) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    pub(crate) fn mac(&mut self, what: &'static str) -> Result<MacAddr, Error> {
        Ok(MacAddr(self.array(what)?))
    }

    /// Takes everything that's left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }
}

/// Appending big- and little-endian fields to an output buffer.
pub(crate) trait Put {
    fn put(&mut self, b: &[u8]);

    fn put_u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    fn put_u16le(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    fn put_i16le(&mut self, v: i16) {
        self.put(&v.to_le_bytes());
    }
    fn put_u32le(&mut self, v: u32) {
        self.put(&v.to_le_bytes());
    }
    fn put_u16be(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }
    fn put_mac(&mut self, m: MacAddr) {
        self.put(&m.0);
    }
}

impl Put for Vec<u8> {
    fn put(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

/// A length as the u16 that a length field holds.
pub(crate) fn len_u16(n: usize, what: &'static str) -> Result<u16, Error> {
    u16::try_from(n).map_err(|_| Error::TooLong(what))
}

/// A length as the u8 that a length field holds.
pub(crate) fn len_u8(n: usize, what: &'static str) -> Result<u8, Error> {
    u8::try_from(n).map_err(|_| Error::TooLong(what))
}
