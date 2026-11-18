// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's control API server (`api/openapi.yaml`): HTTP/1.1 on the named
//! pipe [`PIPE`], served by [`Server`] on its own Tokio runtime. The daemon
//! talks to it through [`Daemon`]: it publishes [`State`] and events, and
//! reads the [`Wants`] of the locks programs hold.
//!
//! The wire types, and the client, are `warlock-client`'s, which is
//! dual-licensed like the contract so AGPL programs can use it too.
//! `tests/contract.rs` checks every response and stream line the server
//! sends against the contract's schemas.

mod pipe;
mod server;

pub use pipe::{Security, USERS_GROUP};
pub use server::{Daemon, HEARTBEAT, OPERATIONS, Server, State, Wants};
pub use warlock_client::{PIPE, types};
