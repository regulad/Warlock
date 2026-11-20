// SPDX-License-Identifier: GPL-2.0-only

use alloc::vec::Vec;

use crate::action::ActionFrame;
use crate::data::DataFrame;
use crate::ieee80211::{Header, frame_control};
use crate::{Bytes, Error, MacAddr};

/// An AWDL frame: its 802.11 header and AWDL body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A PSF or MIF.
    Action {
        /// The 802.11 header.
        header: Header,
        /// The AWDL action body.
        action: ActionFrame<'a>,
    },
    /// A data frame.
    Data {
        /// The 802.11 header.
        header: Header,
        /// The AWDL data body.
        data: DataFrame<'a>,
    },
    /// A QoS data frame aggregating several AWDL data bodies, an A-MSDU
    /// (802.11-2020, 9.3.2.2.2). The iPhone sends them under a Block Ack
    /// agreement that allows A-MSDUs, as Warlock's responses do
    /// ([`crate::blockack`]): 41 of its frames in Koala's trial 19
    /// (2026-11-19), the Rapport TCP streams.
    Amsdu {
        /// The 802.11 header; its QoS control has the A-MSDU bit.
        header: Header,
        /// The subframes, in order.
        msdus: Vec<Msdu<'a>>,
    },
}

/// One subframe of an A-MSDU: its own destination and source, and an AWDL
/// data body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msdu<'a> {
    /// The subframe's destination address.
    pub da: MacAddr,
    /// The subframe's source address.
    pub sa: MacAddr,
    /// Its AWDL data body.
    pub data: DataFrame<'a>,
    /// The padding after it, to 4 bytes: empty for the last subframe. Kept
    /// as received, so the frame re-emits byte for byte.
    pub padding: Bytes<'a>,
}

/// QoS control's A-MSDU Present bit.
const AMSDU_PRESENT: u16 = 0x80;

impl Frame<'_> {
    /// The 802.11 header.
    pub fn header(&self) -> &Header {
        match self {
            Frame::Action { header, .. } | Frame::Data { header, .. } | Frame::Amsdu { header, .. } => header,
        }
    }

    /// Appends the whole MPDU (no FCS).
    pub fn emit(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Action { header, action } => {
                header.emit(out);
                action.emit(out);
            }
            Frame::Data { header, data } => {
                header.emit(out);
                data.emit(out);
            }
            Frame::Amsdu { header, msdus } => {
                header.emit(out);
                for m in msdus {
                    let mut body = Vec::new();
                    m.data.emit(&mut body);
                    out.extend_from_slice(&m.da.0);
                    out.extend_from_slice(&m.sa.0);
                    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                    out.extend_from_slice(&body);
                    out.extend_from_slice(&m.padding);
                }
            }
        }
    }
}

/// Parses one 802.11 MPDU (no radiotap header, FCS stripped).
///
/// `Ok(None)` means the frame isn't AWDL, including frames too short or
/// otherwise unsuitable to tell. `Err` means it is AWDL but malformed.
pub fn parse(mpdu: &[u8]) -> Result<Option<Frame<'_>>, Error> {
    let Some(fc) = mpdu.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]])) else {
        return Ok(None);
    };
    let excluded = frame_control::TO_DS | frame_control::FROM_DS | frame_control::PROTECTED;
    if fc & 3 != 0 || fc & excluded != 0 {
        return Ok(None);
    }
    let (ftype, subtype) = ((fc >> 2) & 3, (fc >> 4) & 0xf);
    let is_action = ftype == 0 && (subtype == 13 || subtype == 14);
    // Data subtypes with bit 2 set carry no body (Null, QoS Null, ...).
    let is_data = ftype == 2 && subtype & 0x4 == 0;
    if !is_action && !is_data {
        return Ok(None);
    }
    let Ok((header, body)) = Header::parse(mpdu) else {
        return Ok(None);
    };
    if is_action {
        Ok(ActionFrame::parse(body)?.map(|action| Frame::Action { header, action }))
    } else if header.qos_ctrl.is_some_and(|q| q & AMSDU_PRESENT != 0) {
        parse_amsdu(header, body)
    } else {
        Ok(DataFrame::parse(body)?.map(|data| Frame::Data { header, data }))
    }
}

/// An A-MSDU's subframes: each a destination, a source, a big-endian length
/// and that many bytes of body, padded to 4 bytes unless it's the last. It
/// is AWDL if its first subframe is; a later one that isn't is malformed.
fn parse_amsdu(header: Header, body: &[u8]) -> Result<Option<Frame<'_>>, Error> {
    let mut msdus = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let sub = &body[at..];
        let fields = sub.get(..14).map(|h| (&h[0..6], &h[6..12], u16::from_be_bytes([h[12], h[13]]) as usize));
        let Some((da, sa, len)) = fields else {
            return if msdus.is_empty() { Ok(None) } else { Err(Error::Truncated("A-MSDU subframe header")) };
        };
        let Some(msdu) = sub.get(14..14 + len) else {
            return if msdus.is_empty() { Ok(None) } else { Err(Error::Truncated("A-MSDU subframe")) };
        };
        let data = match DataFrame::parse(msdu) {
            Ok(Some(data)) => data,
            Ok(None) | Err(_) if msdus.is_empty() => return Ok(None),
            Ok(None) => return Err(Error::Invalid("A-MSDU subframe that isn't AWDL")),
            Err(e) => return Err(e),
        };
        let end = at + 14 + len;
        // Every subframe but the last is padded to 4 bytes.
        let next = if end < body.len() { ((end + 3) & !3).min(body.len()) } else { end };
        let addr = |a: &[u8]| MacAddr(<[u8; 6]>::try_from(a).expect("six bytes"));
        msdus.push(Msdu { da: addr(da), sa: addr(sa), data, padding: Bytes::Borrowed(&body[end..next]) });
        at = next;
    }
    Ok((!msdus.is_empty()).then_some(Frame::Amsdu { header, msdus }))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::data::ETHERTYPE_IPV6;

    /// A QoS data frame from 76:56:82:58:57:70 to 62:5a:37:fb:de:77 under
    /// the AWDL BSSID, TID 0, with `amsdu` setting the A-MSDU bit.
    fn qos_header(amsdu: bool) -> Vec<u8> {
        let mut h = vec![0x88, 0x00, 0x00, 0x00];
        h.extend_from_slice(&[0x62, 0x5a, 0x37, 0xfb, 0xde, 0x77]);
        h.extend_from_slice(&[0x76, 0x56, 0x82, 0x58, 0x57, 0x70]);
        h.extend_from_slice(&[0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);
        h.extend_from_slice(&[0x10, 0x00]);
        h.extend_from_slice(&[if amsdu { 0x80 } else { 0x00 }, 0x00]);
        h
    }

    /// Two subframes (the first padded), as the iPhone sends its TCP.
    #[test]
    fn amsdus_parse_into_their_subframes_and_back() {
        let (da, sa) = (MacAddr([0x62, 0x5a, 0x37, 0xfb, 0xde, 0x77]), MacAddr([0x76, 0x56, 0x82, 0x58, 0x57, 0x70]));
        let payloads: [&[u8]; 2] = [b"first, odd-sized", b"second"];
        let mut mpdu = qos_header(true);
        let body_start = mpdu.len();
        for (i, p) in payloads.iter().enumerate() {
            let mut body = Vec::new();
            DataFrame::new(i as u16, ETHERTYPE_IPV6, p).emit(&mut body);
            mpdu.extend_from_slice(&da.0);
            mpdu.extend_from_slice(&sa.0);
            mpdu.extend_from_slice(&(body.len() as u16).to_be_bytes());
            mpdu.extend_from_slice(&body);
            if i == 0 {
                while !(mpdu.len() - body_start).is_multiple_of(4) {
                    mpdu.push(0);
                }
            }
        }
        let Some(Frame::Amsdu { header, msdus }) = parse(&mpdu).unwrap() else { panic!("not an A-MSDU") };
        assert_eq!(msdus.len(), 2);
        for (m, p) in msdus.iter().zip(payloads) {
            assert_eq!((m.da, m.sa, m.data.ethertype, &*m.data.payload), (da, sa, ETHERTYPE_IPV6, p));
        }
        let mut again = Vec::new();
        Frame::Amsdu { header, msdus }.emit(&mut again);
        assert_eq!(again, mpdu);
    }

    /// An A-MSDU of something else isn't AWDL; a cut-off AWDL one is
    /// malformed.
    #[test]
    fn other_or_cut_off_amsdus() {
        let mut other = qos_header(true);
        other.extend_from_slice(&[0u8; 12]);
        other.extend_from_slice(&8u16.to_be_bytes());
        other.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
        assert_eq!(parse(&other), Ok(None));
        let mut body = Vec::new();
        DataFrame::new(1, ETHERTYPE_IPV6, b"payload").emit(&mut body);
        let mut cut = qos_header(true);
        cut.extend_from_slice(&[0u8; 12]);
        cut.extend_from_slice(&(body.len() as u16).to_be_bytes());
        cut.extend_from_slice(&body);
        cut.extend_from_slice(&[0, 0]);
        cut.extend_from_slice(&[1, 2, 3]);
        assert!(parse(&cut).is_err());
    }
}
