// SPDX-License-Identifier: GPL-2.0-only
//! What Warlock's MSI asks of `warlock.exe` as it installs and uninstalls,
//! beyond what Windows Installer does itself (the files, the service and most
//! of its configuration): `warlock setup` and `warlock teardown`, run as
//! SYSTEM.

use std::error::Error;
use std::ptr::null;
use std::time::Duration;

use tracing::info;
use warlock_api::USERS_GROUP;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::NetworkManagement::NetManagement::{LOCALGROUP_INFO_1, NetLocalGroupAdd, NetLocalGroupDel};

use crate::service;

/// `ERROR_ALIAS_EXISTS` and `NERR_GroupExists`.
const GROUP_EXISTS: [u32; 2] = [1379, 2223];
/// `ERROR_NO_SUCH_ALIAS` and `NERR_GroupNotFound`.
const NO_GROUP: [u32; 2] = [1376, 2220];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// After the service is installed and before it starts: creates the local
/// group allowed to use the control API ([`USERS_GROUP`]), if it isn't there,
/// and sets the service's failure actions. With `--undo` (the MSI's rollback
/// of a fresh install), removes the group instead.
pub fn setup(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [] => {
            create_group()?;
            failure_actions()
        }
        [undo] if undo == "--undo" => remove_group(),
        _ => Err("usage: warlock setup [--undo]".into()),
    }
}

/// Restart after 5 s, 10 s, then 60 s; failures forgiven after a day. The
/// MSI's own `MsiServiceConfigFailureActions` can't: restart actions need the
/// service opened with start access too, and Windows Installer fails with
/// "access denied" (error 1939, seen 2026-11-18).
fn failure_actions() -> Result<(), Box<dyn Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = manager.open_service(service::NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(10), restart(60)]),
    })?;
    info!(service = service::NAME, "failure actions set");
    Ok(())
}

fn create_group() -> Result<(), Box<dyn Error>> {
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
    if let Err(e) = remove_group() {
        problems.push(e.to_string());
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("; ").into()) }
}

fn remove_group() -> Result<(), Box<dyn Error>> {
    // SAFETY: a NUL-terminated name.
    let rc = unsafe { NetLocalGroupDel(null(), wide(USERS_GROUP).as_ptr()) };
    match rc {
        0 => info!(group = USERS_GROUP, "removed"),
        rc if NO_GROUP.contains(&rc) => {}
        rc => return Err(format!("removing the {USERS_GROUP} group: error {rc}").into()),
    }
    Ok(())
}
