// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's control API server: HTTP/1.1 on two named pipes, served by
//! [`Server`] on its own Tokio runtime.
//!
//! - [`PIPE`] serves `api/openapi.yaml`, for [`USERS_GROUP`] and
//!   [`ADMIN_GROUP`].
//! - [`ADMIN_PIPE`] serves `api/admin.yaml`, captures, for [`ADMIN_GROUP`]
//!   only.
//!
//! The daemon talks to it through [`Daemon`]: it publishes [`State`] and
//! events, reads the [`Wants`] of the locks programs hold, and offers each
//! radio [`Frame`] to the captures open.
//!
//! The wire types, and the client, are `warlock-client`'s, which is
//! dual-licensed like the contracts so AGPL programs can use it too.
//! `tests/contract.rs` checks every response and stream line the server
//! sends against the contracts' schemas.

mod capture;
mod pipe;
mod server;

pub use capture::{Filter, Frame, FrameKind};
pub use pipe::{ADMIN_GROUP, Security, USERS_GROUP};
pub use server::{
    ADMIN_OPERATIONS, Daemon, HEARTBEAT, OPERATIONS, Pipes, RequestStatus, RequestWant, Requests, Server, State, Wants,
};
pub use warlock_client::{ADMIN_PIPE, PIPE, types};
