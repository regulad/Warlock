// SPDX-License-Identifier: GPL-2.0-only
//! What peers say about the election, and how masters rank.
//!
//! Every PSF and MIF names the master its sender follows, with that master's
//! metric and counter (election parameters v2, type 24; v1, type 5, on older
//! senders). A cluster's master is the one with the highest metric, then the
//! highest counter: metric first is what jedbillyb's iOS work reports, and it
//! is checked against our captures by `tests/replay.rs`, where every frame's
//! named master is compared with the one we elect. The paper describes the
//! metric/counter pair. An address tie-break (higher wins) is our assumption,
//! needed only for exact ties.
//!
//! The counter half is unconfirmed, and one capture contradicts it: of two
//! iOS devices at metric 65, the one at counter 16163 joined the one at 130.
//! What is confirmed about counters: Apple devices follow a master only
//! while its counter advances (see `docs/awdl-field-observations.md`).

use awdl_proto::MacAddr;
use awdl_proto::tlv::{ElectionParams, ElectionParamsV2};

/// A peer's election state, as it advertises it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElectionInfo {
    /// The master it follows; itself when it's a master.
    pub master: MacAddr,
    /// The peer it syncs to, one hop towards the master (v2 only).
    pub sync_parent: Option<MacAddr>,
    /// Hops to the master.
    pub distance: u32,
    /// The master's metric.
    pub master_metric: u32,
    /// The master's counter (v2 only).
    pub master_counter: Option<u32>,
    /// Its own metric.
    pub self_metric: u32,
}

impl ElectionInfo {
    /// From election parameters v2.
    pub fn from_v2(e: &ElectionParamsV2<'_>) -> Self {
        Self {
            master: e.master,
            sync_parent: Some(e.other),
            distance: e.distance_to_master,
            master_metric: e.master_metric,
            master_counter: Some(e.master_counter),
            self_metric: e.self_metric,
        }
    }

    /// From election parameters v1.
    pub fn from_v1(e: &ElectionParams<'_>) -> Self {
        Self {
            master: e.master,
            sync_parent: None,
            distance: e.distance_to_master as u32,
            master_metric: e.master_metric,
            master_counter: None,
            self_metric: e.self_metric,
        }
    }

    /// How the master this peer follows ranks.
    pub fn master_rank(&self) -> MasterRank {
        MasterRank {
            metric: self.master_metric,
            counter: self.master_counter.unwrap_or(0),
            addr: self.master,
        }
    }
}

/// A master's standing: compare with `>`; greater wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MasterRank {
    /// Compared first.
    pub metric: u32,
    /// Then this.
    pub counter: u32,
    /// Then the address, higher winning (an assumption; see the module docs).
    pub addr: MacAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_outranks_counter() {
        let a = MasterRank { metric: 522, counter: 393, addr: MacAddr([2, 0, 0, 0, 0, 1]) };
        let b = MasterRank { metric: 510, counter: 3214, addr: MacAddr([2, 0, 0, 0, 0, 9]) };
        assert!(a > b);
        let c = MasterRank { counter: 394, ..a };
        assert!(c > a);
    }
}
