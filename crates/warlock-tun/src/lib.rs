// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's virtual network adapter: a Wintun layer-3 adapter carrying IPv6
//! between Windows and AWDL.
//!
//! - [`dll`] gets `wintun.dll` onto the machine. Wintun's signed DLL is
//!   under WireGuard LLC's prebuilt-binaries license, not the GPL, so
//!   Warlock never ships it. It downloads the pinned release from wintun.net
//!   at runtime and checks it (PLAN.md, "`wintun.dll`").
//! - [`Tun`] is the adapter, set up the way PLAN.md describes (one EUI-64
//!   link-local address, no router discovery, no DAD).
//! - [`addr`] maps IPv6 destinations to AWDL addresses.

mod adapter;
pub mod addr;
pub mod dll;
pub mod mdns;

pub use adapter::Tun;
