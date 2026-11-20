// SPDX-License-Identifier: GPL-2.0-only
//! AWDL TLVs: a type byte, a little-endian u16 length, then the value.
//!
//! [`Tlv`] is the raw form; [`Tlv::decode`] gives the typed [`TlvBody`]. Each
//! typed TLV keeps any bytes after the fields it knows in a `trailing` field,
//! so `decode` followed by [`TlvBody::emit_value`] reproduces the value
//! exactly.
//!
//! Framing and type numbers: Wireshark `packet-awdl.c`,
//! `awdl_add_tagged_field` and its tag enum. Wireshark calls bytes past a
//! dissected field "padding"; here they're `trailing`.

mod datapath;
mod election;
mod misc;
mod rtg;
mod service;
mod sync;

use alloc::vec::Vec;

pub use datapath::{DataPathExt, DataPathState, InfraInfo, ext_flags, flags as data_path_flags, umi};
pub use election::{ElectionParams, ElectionParamsV2, PrivateElection};
pub use misc::{Arpa, HtCapabilities, Ieee80211Container, SyncTree, VersionTlv, device_class};
pub use rtg::RealtimeGroup;
pub use service::{Rdata, ServiceParams, ServiceResponse, rr_type, ssth_member};
pub use sync::{Channel, ChannelSequence, ChannelSequenceTlv, SyncParams, encoding};

use crate::wire::{Put, Reader, len_u16};
use crate::{Bytes, Error};

/// Bytes of type and length before each value.
pub const HEADER_LEN: usize = 3;

/// TLV type numbers.
pub mod kind {
    /// SSTH request.
    pub const SSTH_REQUEST: u8 = 0;
    /// Service request.
    pub const SERVICE_REQUEST: u8 = 1;
    /// Service response: one DNS-SD record.
    pub const SERVICE_RESPONSE: u8 = 2;
    /// Synchronization parameters.
    pub const SYNC_PARAMS: u8 = 4;
    /// Election parameters (v1).
    pub const ELECTION_PARAMS: u8 = 5;
    /// Service parameters.
    pub const SERVICE_PARAMS: u8 = 6;
    /// HT capabilities ("enhanced data rate capabilities").
    pub const HT_CAPABILITIES: u8 = 7;
    /// HT operation ("enhanced data rate operation").
    pub const HT_OPERATION: u8 = 8;
    /// Infrastructure.
    pub const INFRA: u8 = 9;
    /// Invite.
    pub const INVITE: u8 = 10;
    /// Debug string.
    pub const DEBUG_STRING: u8 = 11;
    /// Data path state.
    pub const DATA_PATH_STATE: u8 = 12;
    /// Encapsulated IP.
    pub const ENCAPSULATED_IP: u8 = 13;
    /// Data path debug: packet live.
    pub const DATAPATH_DEBUG_PACKET_LIVE: u8 = 14;
    /// Data path debug: action frame live.
    pub const DATAPATH_DEBUG_AF_LIVE: u8 = 15;
    /// ARPA: the sender's host name.
    pub const ARPA: u8 = 16;
    /// 802.11 information elements (e.g. VHT capabilities).
    pub const IEEE80211_CONTAINER: u8 = 17;
    /// Channel sequence.
    pub const CHANNEL_SEQUENCE: u8 = 18;
    /// Synchronization tree.
    pub const SYNC_TREE: u8 = 20;
    /// Version.
    pub const VERSION: u8 = 21;
    /// Bloom filter.
    pub const BLOOM_FILTER: u8 = 22;
    /// NAN synchronization.
    pub const NAN_SYNC: u8 = 23;
    /// Election parameters v2.
    pub const ELECTION_PARAMS_V2: u8 = 24;
    /// Realtime group (a Continuity Real Time Group; not in Wireshark).
    pub const REALTIME_GROUP: u8 = 31;

    /// A short name for a type, if it's known.
    pub fn name(kind: u8) -> Option<&'static str> {
        Some(match kind {
            SSTH_REQUEST => "SSTH request",
            SERVICE_REQUEST => "service request",
            SERVICE_RESPONSE => "service response",
            SYNC_PARAMS => "sync params",
            ELECTION_PARAMS => "election params",
            SERVICE_PARAMS => "service params",
            HT_CAPABILITIES => "HT capabilities",
            HT_OPERATION => "HT operation",
            INFRA => "infra",
            INVITE => "invite",
            DEBUG_STRING => "debug string",
            DATA_PATH_STATE => "data path state",
            ENCAPSULATED_IP => "encapsulated IP",
            DATAPATH_DEBUG_PACKET_LIVE => "data path debug packet live",
            DATAPATH_DEBUG_AF_LIVE => "data path debug AF live",
            ARPA => "ARPA",
            IEEE80211_CONTAINER => "802.11 container",
            CHANNEL_SEQUENCE => "channel sequence",
            SYNC_TREE => "sync tree",
            VERSION => "version",
            BLOOM_FILTER => "bloom filter",
            NAN_SYNC => "NAN sync",
            ELECTION_PARAMS_V2 => "election params v2",
            REALTIME_GROUP => "realtime group",
            _ => return None,
        })
    }
}

/// A raw TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Type number; see [`kind`].
    pub kind: u8,
    /// The value.
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Decodes the value by type. Types without a decoder become
    /// [`TlvBody::Unknown`].
    pub fn decode(&self) -> Result<TlvBody<'a>, Error> {
        let v = self.value;
        Ok(match self.kind {
            kind::SERVICE_RESPONSE => TlvBody::ServiceResponse(ServiceResponse::parse(v)?),
            kind::SYNC_PARAMS => TlvBody::SyncParams(SyncParams::parse(v)?),
            kind::ELECTION_PARAMS => TlvBody::ElectionParams(ElectionParams::parse(v)?),
            kind::SERVICE_PARAMS => TlvBody::ServiceParams(ServiceParams::parse(v)?),
            kind::HT_CAPABILITIES => TlvBody::HtCapabilities(HtCapabilities::parse(v)?),
            kind::DATA_PATH_STATE => TlvBody::DataPathState(DataPathState::parse(v)?),
            kind::ARPA => TlvBody::Arpa(Arpa::parse(v)?),
            kind::IEEE80211_CONTAINER => TlvBody::Ieee80211Container(Ieee80211Container::parse(v)?),
            kind::CHANNEL_SEQUENCE => TlvBody::ChannelSequence(ChannelSequenceTlv::parse(v)?),
            kind::SYNC_TREE => TlvBody::SyncTree(SyncTree::parse(v)),
            kind::VERSION => TlvBody::Version(VersionTlv::parse(v)?),
            kind::ELECTION_PARAMS_V2 => TlvBody::ElectionParamsV2(ElectionParamsV2::parse(v)?),
            kind::REALTIME_GROUP => TlvBody::RealtimeGroup(RealtimeGroup::parse(v)?),
            k => TlvBody::Unknown { kind: k, value: Bytes::Borrowed(v) },
        })
    }

    /// Appends type, length and value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u8(self.kind);
        out.put_u16le(len_u16(self.value.len(), "TLV value")?);
        out.put(self.value);
        Ok(())
    }
}

/// A decoded TLV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlvBody<'a> {
    /// Type 2.
    ServiceResponse(ServiceResponse<'a>),
    /// Type 4.
    SyncParams(SyncParams<'a>),
    /// Type 5.
    ElectionParams(ElectionParams<'a>),
    /// Type 6.
    ServiceParams(ServiceParams<'a>),
    /// Type 7.
    HtCapabilities(HtCapabilities<'a>),
    /// Type 12.
    DataPathState(DataPathState<'a>),
    /// Type 16.
    Arpa(Arpa<'a>),
    /// Type 17.
    Ieee80211Container(Ieee80211Container<'a>),
    /// Type 18.
    ChannelSequence(ChannelSequenceTlv<'a>),
    /// Type 20.
    SyncTree(SyncTree<'a>),
    /// Type 21.
    Version(VersionTlv<'a>),
    /// Type 24.
    ElectionParamsV2(ElectionParamsV2<'a>),
    /// Type 31.
    RealtimeGroup(RealtimeGroup<'a>),
    /// Any type without a decoder, kept raw.
    Unknown {
        /// Type number.
        kind: u8,
        /// The value.
        value: Bytes<'a>,
    },
}

impl TlvBody<'_> {
    /// The type number.
    pub fn kind(&self) -> u8 {
        match self {
            TlvBody::ServiceResponse(_) => kind::SERVICE_RESPONSE,
            TlvBody::SyncParams(_) => kind::SYNC_PARAMS,
            TlvBody::ElectionParams(_) => kind::ELECTION_PARAMS,
            TlvBody::ServiceParams(_) => kind::SERVICE_PARAMS,
            TlvBody::HtCapabilities(_) => kind::HT_CAPABILITIES,
            TlvBody::DataPathState(_) => kind::DATA_PATH_STATE,
            TlvBody::Arpa(_) => kind::ARPA,
            TlvBody::Ieee80211Container(_) => kind::IEEE80211_CONTAINER,
            TlvBody::ChannelSequence(_) => kind::CHANNEL_SEQUENCE,
            TlvBody::SyncTree(_) => kind::SYNC_TREE,
            TlvBody::Version(_) => kind::VERSION,
            TlvBody::ElectionParamsV2(_) => kind::ELECTION_PARAMS_V2,
            TlvBody::RealtimeGroup(_) => kind::REALTIME_GROUP,
            TlvBody::Unknown { kind, .. } => *kind,
        }
    }

    /// Appends just the value.
    pub fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            TlvBody::ServiceResponse(t) => t.emit(out),
            TlvBody::SyncParams(t) => t.emit(out),
            TlvBody::ElectionParams(t) => t.emit(out),
            TlvBody::ServiceParams(t) => t.emit(out),
            TlvBody::HtCapabilities(t) => t.emit(out),
            TlvBody::DataPathState(t) => t.emit(out),
            TlvBody::Arpa(t) => t.emit(out),
            TlvBody::Ieee80211Container(t) => t.emit(out),
            TlvBody::ChannelSequence(t) => t.emit(out),
            TlvBody::SyncTree(t) => t.emit(out),
            TlvBody::Version(t) => t.emit(out),
            TlvBody::ElectionParamsV2(t) => t.emit(out),
            TlvBody::RealtimeGroup(t) => t.emit(out),
            TlvBody::Unknown { value, .. } => {
                out.put(value);
                Ok(())
            }
        }
    }

    /// Appends type, length and value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        out.put_u8(self.kind());
        out.put_u16le(0);
        self.emit_value(out)?;
        let len = len_u16(out.len() - start - HEADER_LEN, "TLV value")?;
        out[start + 1..start + 3].copy_from_slice(&len.to_le_bytes());
        Ok(())
    }
}

/// Checks that `region` is a run of whole TLVs followed by fewer than
/// [`HEADER_LEN`] bytes. Returns the length of the TLV run.
pub(crate) fn validate(region: &[u8]) -> Result<usize, Error> {
    let mut r = Reader::new(region);
    let mut used = 0;
    while r.remaining() >= HEADER_LEN {
        r.u8("TLV type")?;
        let len = r.u16le("TLV length")? as usize;
        r.bytes(len, "TLV value")?;
        used += HEADER_LEN + len;
    }
    Ok(used)
}

/// Iterator over the TLVs of a parsed frame, whose framing was checked when
/// the frame was parsed.
#[derive(Clone, Debug)]
pub struct TlvIter<'a> {
    rest: &'a [u8],
}

impl<'a> TlvIter<'a> {
    pub(crate) fn new(validated: &'a [u8]) -> Self {
        Self { rest: validated }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.rest.len() < HEADER_LEN {
            return None;
        }
        let kind = self.rest[0];
        let len = u16::from_le_bytes([self.rest[1], self.rest[2]]) as usize;
        let value = &self.rest[HEADER_LEN..HEADER_LEN + len];
        self.rest = &self.rest[HEADER_LEN + len..];
        Some(Tlv { kind, value })
    }
}
