// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's control API (`api/openapi.yaml`): HTTP/1.1 on the named pipe
//! [`PIPE`], served by [`Server`], spoken by [`client::Client`].
//!
//! - [`types`]: the JSON, one type per schema in the contract.
//! - [`Server`]: the server, on its own Tokio runtime. The daemon talks to it
//!   through [`Daemon`]: it publishes [`State`] and events, and reads the
//!   [`Wants`] of the locks programs hold.
//! - [`client`]: a client, for `warlockctl` and the tests.
//!
//! `tests/contract.rs` checks every response and stream line the server
//! sends against the contract's schemas.

pub mod client;
mod pipe;
mod server;
pub mod types;

pub use pipe::{Security, USERS_GROUP};
pub use server::{Daemon, HEARTBEAT, OPERATIONS, Server, State, Wants};

/// The API's pipe.
pub const PIPE: &str = r"\\.\pipe\warlock";
