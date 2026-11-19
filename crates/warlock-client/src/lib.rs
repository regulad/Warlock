// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! A client of Warlock's control API (`api/openapi.yaml`): HTTP/1.1 on the
//! named pipe [`PIPE`].
//!
//! - [`types`]: the JSON, one type per schema in the contract.
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
