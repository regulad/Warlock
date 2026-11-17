// SPDX-License-Identifier: GPL-2.0-only

use alloc::vec::Vec;

use crate::Error;
use crate::action::ActionFrame;
use crate::data::DataFrame;
use crate::ieee80211::{Header, frame_control};

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
}

impl Frame<'_> {
    /// The 802.11 header.
    pub fn header(&self) -> &Header {
        match self {
            Frame::Action { header, .. } | Frame::Data { header, .. } => header,
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
    } else {
        // A-MSDU bodies aren't a bare LLC header.
        if header.qos_ctrl.is_some_and(|q| q & 0x80 != 0) {
            return Ok(None);
        }
        Ok(DataFrame::parse(body)?.map(|data| Frame::Data { header, data }))
    }
}
