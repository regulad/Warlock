// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! A client of Warlock's control API: HTTP/1.1 on two named pipes.
//!
//! - [`PIPE`] (`api/openapi.yaml`): Warlock, its peers, advertising, holds
//!   and events. Administrators and the `warlock-users` and `warlock-admin`
//!   groups may open it.
//! - [`ADMIN_PIPE`] (`api/admin.yaml`): the radio's frames
//!   ([`Client::capture`]). Only Administrators and `warlock-admin` may open
//!   it.
//!
//! Windows decides who may open each pipe, by the pipe's access list; the
//! client doesn't care. Make a [`Client`] for the pipe the call is on.
//!
//! - [`types`]: the JSON, one type per schema in the contracts.
//! - [`client`]: the HTTP client, holding a lock for as long as its stream
//!   is kept.
//!
//! Dual-licensed like the contract, `GPL-2.0-only OR AGPL-3.0-or-later`:
//! Warlock's server (GPL-2.0-only) shares these types, and AGPL programs such
//! as `warlockctl` use the client.

pub mod client;
pub mod types;

pub use client::{CaptureFilter, CaptureKind, Chunks, Client, ClientError, Lines};

/// The API's pipe.
pub const PIPE: &str = r"\\.\pipe\warlock";

/// The admin API's pipe: captures.
pub const ADMIN_PIPE: &str = r"\\.\pipe\warlock-admin";
