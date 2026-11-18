// SPDX-License-Identifier: GPL-2.0-only
//! What Warlock's MSI asks of `warlock.exe` as it installs and uninstalls,
//! beyond what Windows Installer does itself (the files, the service and its
//! configuration): `warlock setup` and `warlock teardown`, run as SYSTEM.

use std::error::Error;
use std::ptr::null;

use tracing::info;
use warlock_api::USERS_GROUP;
use windows_sys::Win32::NetworkManagement::NetManagement::{LOCALGROUP_INFO_1, NetLocalGroupAdd, NetLocalGroupDel};

/// `ERROR_ALIAS_EXISTS` and `NERR_GroupExists`.
const GROUP_EXISTS: [u32; 2] = [1379, 2223];
/// `ERROR_NO_SUCH_ALIAS` and `NERR_GroupNotFound`.
const NO_GROUP: [u32; 2] = [1376, 2220];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// After the files are installed: creates the local group allowed to use
/// the control API ([`USERS_GROUP`]), if it isn't there.
pub fn setup() -> Result<(), Box<dyn Error>> {
    let mut name = wide(USERS_GROUP);
    let mut comment = wide("Members may use Warlock's control API (warlockctl), like docker-users");
    let group = LOCALGROUP_INFO_1 { lgrpi1_name: name.as_mut_ptr(), lgrpi1_comment: comment.as_mut_ptr() };
    let mut bad_field = 0;
    // SAFETY: a valid level-1 structure whose strings outlive the call.
    let rc = unsafe { NetLocalGroupAdd(null(), 1, (&raw const group).cast(), &mut bad_field) };
    match rc {
        0 => info!(group = USERS_GROUP, "created"),
        rc if GROUP_EXISTS.contains(&rc) => info!(group = USERS_GROUP, "already there"),
        rc => return Err(format!("creating the {USERS_GROUP} group: error {rc}").into()),
    }
    Ok(())
}

/// Before the files go, on an uninstall that isn't an upgrade: gives the
/// adapter back to Windows' own driver, if Warlock had it, and removes the
/// group. Either may fail without stopping the uninstall.
pub fn teardown() -> Result<(), Box<dyn Error>> {
    let mut problems = Vec::new();
    match warlock_usb::find_supported() {
        Ok(Some((dev, _))) if dev.is_winusb() => match warlock_usb::release(&dev.instance_id) {
            Ok(_) => info!(device = %dev.instance_id, "given back to Windows"),
            Err(e) => problems.push(format!("giving the adapter back to Windows: {e}")),
        },
        Ok(_) => {}
        Err(e) => problems.push(format!("looking for the adapter: {e}")),
    }
    // SAFETY: a NUL-terminated name.
    let rc = unsafe { NetLocalGroupDel(null(), wide(USERS_GROUP).as_ptr()) };
    match rc {
        0 => info!(group = USERS_GROUP, "removed"),
        rc if NO_GROUP.contains(&rc) => {}
        rc => problems.push(format!("removing the {USERS_GROUP} group: error {rc}")),
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("; ").into()) }
}
