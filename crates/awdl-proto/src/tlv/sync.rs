// SPDX-License-Identifier: GPL-2.0-only
//! Synchronization parameters (type 4) and channel sequences (type 18, and
//! embedded at the end of type 4).
//!
//! Layout: Wireshark `packet-awdl.c`, `awdl_tag_sync_params` and
//! `awdl_tag_channel_sequence`. Unlike the dissector, which shows nothing
//! for an unknown channel encoding, we reject one: its entry size is
//! unknown.

use alloc::vec::Vec;

use crate::wire::{Put, Reader, len_u8};
use crate::{Bytes, Error, MacAddr};

/// Channel-sequence encodings.
pub mod encoding {
    /// One byte per slot: the channel number.
    pub const CHANNEL_NUMBER: u8 = 0;
    /// Two bytes per slot: flags (control channel, bandwidth, band), then the
    /// channel number.
    pub const LEGACY: u8 = 1;
    /// Two bytes per slot: the channel number, then the 802.11 operating
    /// class. What iOS 27 sends.
    pub const OPCLASS: u8 = 3;
}

fn entry_width(enc: u8) -> Option<usize> {
    match enc {
        encoding::CHANNEL_NUMBER => Some(1),
        encoding::LEGACY | encoding::OPCLASS => Some(2),
        _ => None,
    }
}

/// One slot of a channel sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    /// [`encoding::CHANNEL_NUMBER`].
    Number(u8),
    /// [`encoding::LEGACY`].
    Legacy {
        /// Bits 0–1 control channel (1 lower, 2 upper, 3 primary), bits 2–3
        /// bandwidth (1 = 20 MHz, 3 = 40 MHz), bits 4–5 band (1 = 5 GHz,
        /// 2 = 2.4 GHz).
        flags: u8,
        /// Channel number.
        number: u8,
    },
    /// [`encoding::OPCLASS`].
    OpClass {
        /// Channel number.
        number: u8,
        /// 802.11 operating class, which gives the band and width.
        opclass: u8,
    },
}

impl Channel {
    /// The channel number as encoded. For [`Channel::Legacy`] this is the
    /// centre of a 40 MHz pair (46 for 44+48); see [`Channel::primary`].
    pub const fn number(&self) -> u8 {
        match *self {
            Channel::Number(n) | Channel::Legacy { number: n, .. } | Channel::OpClass { number: n, .. } => n,
        }
    }

    /// The primary (control) channel, the one a radio tunes to. Legacy
    /// entries carry the 40 MHz centre channel, with the control-channel bits
    /// saying which side the primary is: lower is 2 below, upper is 2 above.
    /// Captured: an Apple TV on 44 advertises 46 "lower", and an iPhone on 120
    /// advertises 118 "upper". The other encodings carry the primary. Empty
    /// slots (all zero) give 0.
    pub const fn primary(&self) -> u8 {
        match *self {
            Channel::Legacy { flags, number } if number != 0 => match flags & 3 {
                1 => number.wrapping_sub(2),
                2 => number.wrapping_add(2),
                _ => number,
            },
            _ => self.number(),
        }
    }

    /// True for an empty slot: the sender is off AWDL then.
    pub const fn is_empty(&self) -> bool {
        self.number() == 0
    }

    const fn encoding(&self) -> u8 {
        match self {
            Channel::Number(_) => encoding::CHANNEL_NUMBER,
            Channel::Legacy { .. } => encoding::LEGACY,
            Channel::OpClass { .. } => encoding::OPCLASS,
        }
    }
}

/// A channel sequence: which channel the sender is on in each of its
/// availability-window slots (16 in every capture so far).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSequence<'a> {
    /// One of [`encoding`]; fixes the size of each entry.
    pub encoding: u8,
    /// Duplicate count.
    pub duplicate_count: u8,
    /// Step count: slots per channel step, less one (3 → each channel holds
    /// for four slots).
    pub step_count: u8,
    /// Fill channel; `0xffff` means "repeat the current channel".
    pub fill_channel: u16,
    entries: Bytes<'a>,
}

impl<'a> ChannelSequence<'a> {
    /// Builds a sequence. All channels must use the same encoding; there must
    /// be between 1 and 256.
    pub fn new(
        duplicate_count: u8,
        step_count: u8,
        fill_channel: u16,
        channels: &[Channel],
    ) -> Result<ChannelSequence<'static>, Error> {
        let first = channels.first().ok_or(Error::Invalid("empty channel sequence"))?;
        let enc = first.encoding();
        if channels.len() > 256 {
            return Err(Error::TooLong("channel sequence"));
        }
        let mut entries = Vec::with_capacity(channels.len() * 2);
        for c in channels {
            match *c {
                _ if c.encoding() != enc => return Err(Error::Invalid("mixed channel encodings")),
                Channel::Number(n) => entries.push(n),
                Channel::Legacy { flags, number } => entries.extend_from_slice(&[flags, number]),
                Channel::OpClass { number, opclass } => entries.extend_from_slice(&[number, opclass]),
            }
        }
        Ok(ChannelSequence {
            encoding: enc,
            duplicate_count,
            step_count,
            fill_channel,
            entries: Bytes::Owned(entries),
        })
    }

    /// Number of slots.
    pub fn len(&self) -> usize {
        self.entries.len() / self.width()
    }

    /// Always false: a sequence has at least one slot.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn width(&self) -> usize {
        entry_width(self.encoding).unwrap_or(1)
    }

    /// The channel in slot `i`.
    pub fn get(&self, i: usize) -> Option<Channel> {
        let w = self.width();
        let e = self.entries.get(i * w..i * w + w)?;
        Some(match self.encoding {
            encoding::CHANNEL_NUMBER => Channel::Number(e[0]),
            encoding::LEGACY => Channel::Legacy { flags: e[0], number: e[1] },
            _ => Channel::OpClass { number: e[0], opclass: e[1] },
        })
    }

    /// The channels, slot by slot.
    pub fn channels(&self) -> impl Iterator<Item = Channel> + '_ {
        (0..self.len()).filter_map(|i| self.get(i))
    }

    /// Converts to an owned sequence.
    pub fn into_owned(self) -> ChannelSequence<'static> {
        ChannelSequence {
            encoding: self.encoding,
            duplicate_count: self.duplicate_count,
            step_count: self.step_count,
            fill_channel: self.fill_channel,
            entries: Bytes::Owned(self.entries.into_owned()),
        }
    }

    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, Error> {
        let count = r.u8("channel count")? as usize + 1;
        let encoding = r.u8("channel encoding")?;
        let duplicate_count = r.u8("channel duplicate count")?;
        let step_count = r.u8("channel step count")?;
        let fill_channel = r.u16le("fill channel")?;
        let width = entry_width(encoding).ok_or(Error::Invalid("channel sequence encoding"))?;
        let entries = r.bytes(count * width, "channel list")?;
        Ok(Self {
            encoding,
            duplicate_count,
            step_count,
            fill_channel,
            entries: Bytes::Borrowed(entries),
        })
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.entries.is_empty() {
            return Err(Error::Invalid("empty channel sequence"));
        }
        out.put_u8(len_u8(self.len() - 1, "channel sequence")?);
        out.put_u8(self.encoding);
        out.put_u8(self.duplicate_count);
        out.put_u8(self.step_count);
        out.put_u16le(self.fill_channel);
        out.put(&self.entries);
        Ok(())
    }
}

/// The channel sequence TLV (type 18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSequenceTlv<'a> {
    /// The sequence.
    pub sequence: ChannelSequence<'a>,
    /// Bytes after the sequence (zero padding in captures).
    pub trailing: Bytes<'a>,
}

impl<'a> ChannelSequenceTlv<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        let sequence = ChannelSequence::read(&mut r)?;
        Ok(Self { sequence, trailing: Bytes::Borrowed(r.rest()) })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.sequence.write(out)?;
        out.put(&self.trailing);
        Ok(())
    }
}

/// Synchronization parameters (type 4): the sender's timing, its view of
/// the master, and its channel sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncParams<'a> {
    /// Channel this frame was sent on.
    pub tx_channel: u8,
    /// Time until the next availability window, in TU.
    pub tx_counter: u16,
    /// The master's channel.
    pub master_channel: u8,
    /// Guard time, TU.
    pub guard_time: u8,
    /// Availability-window period, TU (16 in captures).
    pub aw_period: u16,
    /// Action frame period, TU.
    pub action_frame_period: u16,
    /// AWDL flags.
    pub awdl_flags: u16,
    /// Extension-window length, TU.
    pub aw_ext_length: u16,
    /// Common extension-window length, TU.
    pub aw_common_length: u16,
    /// Remaining availability-window time, TU (signed).
    pub aw_remaining: i16,
    /// Minimum extension count.
    pub ext_min: u8,
    /// Maximum extension count, multicast.
    pub ext_max_multicast: u8,
    /// Maximum extension count, unicast.
    pub ext_max_unicast: u8,
    /// Maximum extension count, action frames.
    pub ext_max_af: u8,
    /// The master's address.
    pub master: MacAddr,
    /// Presence mode.
    pub presence_mode: u8,
    /// Unknown byte after the presence mode.
    pub unknown: u8,
    /// Availability-window sequence counter.
    pub aw_seq_counter: u16,
    /// AP beacon alignment delta.
    pub ap_beacon_alignment: u16,
    /// The sender's channel sequence.
    pub channel_sequence: ChannelSequence<'a>,
    /// Bytes after the channel sequence.
    pub trailing: Bytes<'a>,
}

impl<'a> SyncParams<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        Ok(Self {
            tx_channel: r.u8("sync tx channel")?,
            tx_counter: r.u16le("sync tx counter")?,
            master_channel: r.u8("sync master channel")?,
            guard_time: r.u8("sync guard time")?,
            aw_period: r.u16le("sync AW period")?,
            action_frame_period: r.u16le("sync AF period")?,
            awdl_flags: r.u16le("sync AWDL flags")?,
            aw_ext_length: r.u16le("sync AW ext length")?,
            aw_common_length: r.u16le("sync AW common length")?,
            aw_remaining: r.i16le("sync AW remaining")?,
            ext_min: r.u8("sync ext min")?,
            ext_max_multicast: r.u8("sync ext max multicast")?,
            ext_max_unicast: r.u8("sync ext max unicast")?,
            ext_max_af: r.u8("sync ext max AF")?,
            master: r.mac("sync master")?,
            presence_mode: r.u8("sync presence mode")?,
            unknown: r.u8("sync unknown")?,
            aw_seq_counter: r.u16le("sync AW sequence counter")?,
            ap_beacon_alignment: r.u16le("sync AP beacon alignment")?,
            channel_sequence: ChannelSequence::read(&mut r)?,
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.tx_channel);
        out.put_u16le(self.tx_counter);
        out.put_u8(self.master_channel);
        out.put_u8(self.guard_time);
        out.put_u16le(self.aw_period);
        out.put_u16le(self.action_frame_period);
        out.put_u16le(self.awdl_flags);
        out.put_u16le(self.aw_ext_length);
        out.put_u16le(self.aw_common_length);
        out.put_i16le(self.aw_remaining);
        out.put_u8(self.ext_min);
        out.put_u8(self.ext_max_multicast);
        out.put_u8(self.ext_max_unicast);
        out.put_u8(self.ext_max_af);
        out.put_mac(self.master);
        out.put_u8(self.presence_mode);
        out.put_u8(self.unknown);
        out.put_u16le(self.aw_seq_counter);
        out.put_u16le(self.ap_beacon_alignment);
        self.channel_sequence.write(out)?;
        out.put(&self.trailing);
        Ok(())
    }
}
