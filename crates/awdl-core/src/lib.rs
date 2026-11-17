// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's AWDL engine, sans-IO.
//!
//! [`Engine`] takes received frames, each with the receiver's hardware TSF,
//! and keeps the state AWDL needs: the peer table, the election (who the
//! cluster's master is, and which peer to sync to) and an availability-window
//! clock per peer. It does no I/O and reads no clock, so the same code runs
//! live, from captures and in tests. All times are TSF microseconds.
//!
//! # Sources
//!
//! The behaviour here comes from our own captures and from the MobiCom '18
//! paper (Stute et al., "One Billion Apples' Secret Sauce"), with field
//! meanings from Wireshark's AWDL dissector. OWL and owly are not used (see
//! `docs/prior-art.md`). The measured facts the engine relies on, from
//! `docs/awdl-field-observations.md`, "Synchronization":
//! - a frame's sender starts its next AW at `rx_tsf − (phy_tx_time −
//!   target_tx_time) + tx_counter × 1 TU`, to within ±½ TU per frame;
//! - AWs are 16 TU, and a peer's clock drifts against ours (an Apple TV by
//!   −239 ppm), so the clock fits a period as well as a phase;
//! - the AW sequence counter counts AWs, and followers adopt their master's;
//! - channel-sequence slot = (AW sequence / 4) mod 16: one slot per 64-TU
//!   extended AW.

mod clock;
pub mod diag;
mod election;
mod engine;
mod schedule;

pub use clock::{AwClock, AwPosition, Observed, SyncClaim};
pub use election::{ElectionInfo, MasterRank};
pub use engine::{Config, Engine, Event, Peer, RxMeta};
pub use schedule::ChannelSchedule;

/// One time unit, in µs.
pub const TU_US: u64 = 1024;
/// An availability window, in TU.
pub const AW_TU: u64 = 16;
/// An availability window, in µs.
pub const AW_US: u64 = AW_TU * TU_US;
/// AWs per channel-sequence slot: one extended AW.
pub const AWS_PER_SLOT: u16 = 4;
/// Slots in a channel sequence.
pub const SLOTS: usize = 16;
