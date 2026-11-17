// SPDX-License-Identifier: GPL-2.0-only
//! Which channel a peer is on, AW by AW, from its channel sequence.
//!
//! Measured on our captures (`docs/awdl-field-observations.md`,
//! "Synchronization"): slot = (AW sequence / 4) mod 16, so each of the 16
//! slots lasts one 64-TU extended AW. An empty slot repeats the last non-empty
//! one when the fill channel is `0xffff` ("repeat current"). With those two
//! rules, 99.5–100 % of the frames from three devices in one capture were
//! received on the channel their sender's own sequence put them on.

use awdl_proto::tlv::ChannelSequence;

use crate::{AWS_PER_SLOT, SLOTS};

/// Fill value meaning "an empty slot repeats the current channel".
const FILL_REPEAT: u16 = 0xffff;

/// The same sequence with every slot the fill repeats written out
/// explicitly, in the same encoding: where its sender is, made available for
/// unicast. A follower advertises this, since it hops the repeats too: a peer
/// sends us unicast only in our explicit slots, and an iPhone held its reply
/// ~420 ms for one when we advertised a master's sparse sequence verbatim.
/// Unchanged when the fill isn't "repeat current" or every slot is empty.
pub fn widen(seq: &ChannelSequence<'_>) -> ChannelSequence<'static> {
    let channels: Vec<_> = seq.channels().collect();
    let Some(last) = channels.iter().rev().find(|c| !c.is_empty()).copied() else {
        return seq.clone().into_owned();
    };
    if seq.fill_channel != FILL_REPEAT {
        return seq.clone().into_owned();
    }
    let mut current = last;
    let widened: Vec<_> = channels
        .iter()
        .map(|c| {
            if !c.is_empty() {
                current = *c;
            }
            current
        })
        .collect();
    ChannelSequence::new(seq.duplicate_count, seq.step_count, seq.fill_channel, &widened)
        .unwrap_or_else(|_| seq.clone().into_owned())
}

/// A peer's channel per slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelSchedule {
    /// Primary channel per slot; 0 for an empty slot.
    pub slots: [u8; SLOTS],
    /// Whether an empty slot repeats the last non-empty one (fill `0xffff`)
    /// rather than meaning "off AWDL".
    pub repeat_on_empty: bool,
}

impl ChannelSchedule {
    /// The schedule a 16-slot sequence describes. `None` for other lengths.
    pub fn from_sequence(seq: &ChannelSequence<'_>) -> Option<Self> {
        if seq.len() != SLOTS {
            return None;
        }
        let mut slots = [0u8; SLOTS];
        for (s, c) in slots.iter_mut().zip(seq.channels()) {
            *s = c.primary();
        }
        Some(Self { slots, repeat_on_empty: seq.fill_channel == FILL_REPEAT })
    }

    /// The slot of an AW.
    pub fn slot_of(aw_seq: u16) -> usize {
        (aw_seq / AWS_PER_SLOT) as usize % SLOTS
    }

    /// The channel the peer is on during AW `aw_seq`, or `None` if it's off
    /// AWDL then.
    pub fn channel_at(&self, aw_seq: u16) -> Option<u8> {
        let slot = Self::slot_of(aw_seq);
        if self.slots[slot] != 0 {
            return Some(self.slots[slot]);
        }
        if !self.repeat_on_empty {
            return None;
        }
        (1..SLOTS).map(|back| self.slots[(slot + SLOTS - back) % SLOTS]).find(|&c| c != 0)
    }

    /// Whether AW `aw_seq` falls in a slot with an explicit channel, rather
    /// than one the fill repeats. Apple devices send a MIF once per explicit
    /// slot: an iPhone whose sequence named 149 in 2 of 16 slots sent 1.9
    /// MIFs a second on 149, while filled slots carried none. And they take
    /// unicast only in explicit slots: an Apple TV received every ping sent
    /// in its explicit 149 slots and none in the filled ones after them,
    /// though its PSFs put it on 149 there too.
    pub fn is_explicit(&self, aw_seq: u16) -> bool {
        self.slots[Self::slot_of(aw_seq)] != 0
    }

    /// How many of the 16 slots name a channel explicitly.
    pub fn explicit_slots(&self) -> usize {
        self.slots.iter().filter(|&&c| c != 0).count()
    }

    /// Whether the peer is on `channel` at any point in its sequence.
    pub fn visits(&self, channel: u8) -> bool {
        (0..SLOTS as u16).any(|s| self.channel_at(s * AWS_PER_SLOT) == Some(channel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awdl_proto::tlv::Channel;

    fn iphone_like(fill: u16) -> ChannelSchedule {
        // The capture's iPhone: infra 120 in slot 0, 149 in slots 2 and 10,
        // 6 in slot 8, empty elsewhere.
        let mut ch = [Channel::OpClass { number: 0, opclass: 0 }; 16];
        ch[0] = Channel::OpClass { number: 120, opclass: 121 };
        ch[2] = Channel::OpClass { number: 149, opclass: 128 };
        ch[10] = Channel::OpClass { number: 149, opclass: 128 };
        ch[8] = Channel::OpClass { number: 6, opclass: 81 };
        ChannelSchedule::from_sequence(&ChannelSequence::new(0, 3, fill, &ch).unwrap()).unwrap()
    }

    #[test]
    fn slots_last_four_aws_and_empty_ones_repeat() {
        let s = iphone_like(0xffff);
        assert_eq!(s.channel_at(0), Some(120));
        assert_eq!(s.channel_at(3), Some(120));
        assert_eq!(s.channel_at(4), Some(120)); // slot 1 empty: repeats 120
        assert_eq!(s.channel_at(8), Some(149)); // slot 2
        assert_eq!(s.channel_at(4 * 9 + 1), Some(6)); // slot 9 empty: repeats slot 8
        assert_eq!(s.channel_at(64), Some(120)); // wraps after 16 slots
        assert!(s.visits(6) && !s.visits(44));
    }

    #[test]
    fn widening_writes_out_the_repeats() {
        let mut ch = [Channel::OpClass { number: 0, opclass: 0 }; 16];
        ch[0] = Channel::OpClass { number: 120, opclass: 121 };
        ch[2] = Channel::OpClass { number: 149, opclass: 128 };
        ch[8] = Channel::OpClass { number: 6, opclass: 81 };
        let seq = ChannelSequence::new(0, 3, 0xffff, &ch).unwrap();
        let wide = ChannelSchedule::from_sequence(&widen(&seq)).unwrap();
        let narrow = ChannelSchedule::from_sequence(&seq).unwrap();
        assert_eq!(wide.explicit_slots(), 16);
        for aw in (0..64).map(|s| s * 4) {
            assert_eq!(wide.channel_at(aw), narrow.channel_at(aw), "slot {}", aw / 4);
        }
        // Not under another fill.
        assert_eq!(widen(&ChannelSequence::new(0, 3, 0, &ch).unwrap()).channels().filter(|c| c.is_empty()).count(), 13);
    }

    #[test]
    fn empty_slots_are_off_without_repeat_fill() {
        let s = iphone_like(0);
        assert_eq!(s.channel_at(4), None);
        assert_eq!(s.channel_at(8), Some(149));
    }
}
