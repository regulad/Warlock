// SPDX-License-Identifier: GPL-2.0-only
//! Election parameters, v1 (type 5) and v2 (type 24).

use alloc::vec::Vec;

use crate::wire::{Put, Reader};
use crate::{Bytes, Error, MacAddr};

/// Election parameters v1 (type 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionParams<'a> {
    /// Flags. Nonzero means a [`PrivateElection`] block follows.
    pub flags: u8,
    /// Election ID.
    pub id: u16,
    /// Hops to the master.
    pub distance_to_master: u8,
    /// Unknown.
    pub unknown: u8,
    /// The master's address.
    pub master: MacAddr,
    /// The master's metric.
    pub master_metric: u32,
    /// The sender's own metric.
    pub self_metric: u32,
    /// Present when `flags` is nonzero.
    pub private: Option<PrivateElection>,
    /// Bytes after the known fields.
    pub trailing: Bytes<'a>,
}

/// The private-election block of [`ElectionParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateElection {
    /// Unknown.
    pub unknown: u16,
    /// Private master.
    pub master: MacAddr,
    /// Private master metric.
    pub master_metric: u32,
    /// Private ID.
    pub id: u32,
    /// Private PHC.
    pub phc: u16,
}

impl<'a> ElectionParams<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        let flags = r.u8("election flags")?;
        let id = r.u16le("election ID")?;
        let distance_to_master = r.u8("election distance")?;
        let unknown = r.u8("election unknown")?;
        let master = r.mac("election master")?;
        let master_metric = r.u32le("election master metric")?;
        let self_metric = r.u32le("election self metric")?;
        let private = if flags != 0 {
            Some(PrivateElection {
                unknown: r.u16le("private election unknown")?,
                master: r.mac("private election master")?,
                master_metric: r.u32le("private election master metric")?,
                id: r.u32le("private election ID")?,
                phc: r.u16le("private election PHC")?,
            })
        } else {
            None
        };
        Ok(Self {
            flags,
            id,
            distance_to_master,
            unknown,
            master,
            master_metric,
            self_metric,
            private,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value. The private block is written when present,
    /// whatever `flags` says, so keep the two consistent when building.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.flags);
        out.put_u16le(self.id);
        out.put_u8(self.distance_to_master);
        out.put_u8(self.unknown);
        out.put_mac(self.master);
        out.put_u32le(self.master_metric);
        out.put_u32le(self.self_metric);
        if let Some(p) = &self.private {
            out.put_u16le(p.unknown);
            out.put_mac(p.master);
            out.put_u32le(p.master_metric);
            out.put_u32le(p.id);
            out.put_u16le(p.phc);
        }
        out.put(&self.trailing);
        Ok(())
    }
}

/// Election parameters v2 (type 24). Peers elect by **metric first**, then
/// counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectionParamsV2<'a> {
    /// The master's address.
    pub master: MacAddr,
    /// The other address (the sender's sync parent, per the paper).
    pub other: MacAddr,
    /// The master's counter.
    pub master_counter: u32,
    /// Hops to the master.
    pub distance_to_master: u32,
    /// The master's metric.
    pub master_metric: u32,
    /// The sender's own metric.
    pub self_metric: u32,
    /// Unknown.
    pub unknown: u32,
    /// Reserved.
    pub reserved: u32,
    /// The sender's own counter.
    pub self_counter: u32,
    /// Bytes after the known fields.
    pub trailing: Bytes<'a>,
}

impl<'a> ElectionParamsV2<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        Ok(Self {
            master: r.mac("election v2 master")?,
            other: r.mac("election v2 other")?,
            master_counter: r.u32le("election v2 master counter")?,
            distance_to_master: r.u32le("election v2 distance")?,
            master_metric: r.u32le("election v2 master metric")?,
            self_metric: r.u32le("election v2 self metric")?,
            unknown: r.u32le("election v2 unknown")?,
            reserved: r.u32le("election v2 reserved")?,
            self_counter: r.u32le("election v2 self counter")?,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_mac(self.master);
        out.put_mac(self.other);
        out.put_u32le(self.master_counter);
        out.put_u32le(self.distance_to_master);
        out.put_u32le(self.master_metric);
        out.put_u32le(self.self_metric);
        out.put_u32le(self.unknown);
        out.put_u32le(self.reserved);
        out.put_u32le(self.self_counter);
        out.put(&self.trailing);
        Ok(())
    }
}
