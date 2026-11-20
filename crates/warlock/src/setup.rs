// SPDX-License-Identifier: GPL-2.0-only
//! What Warlock's MSI asks of `warlock.exe` as it installs and uninstalls,
//! beyond what Windows Installer does itself (the files, the service and most
//! of its configuration): `warlock setup` and `warlock teardown`, run as
//! SYSTEM.

use std::error::Error;
use std::ptr::{null, null_mut};
use std::time::Duration;

use tracing::info;
use warlock_api::{ADMIN_GROUP, USERS_GROUP};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::PSID;

use crate::{events, service};

/// `ERROR_ALIAS_EXISTS` and `NERR_GroupExists`.
const GROUP_EXISTS: [u32; 2] = [1379, 2223];
/// `ERROR_NO_SUCH_ALIAS` and `NERR_GroupNotFound`.
const NO_GROUP: [u32; 2] = [1376, 2220];
/// `ERROR_MEMBER_IN_ALIAS`.
const ALREADY_MEMBER: u32 = 1378;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Warlock's local groups, with their comments: who may open which of the
/// API's pipes (`warlock_api`'s `pipe` module).
const GROUPS: [(&str, &str); 2] = [
    (USERS_GROUP, "Members may use Warlock's control API (warlockctl), like docker-users"),
    (ADMIN_GROUP, "Members may also capture Warlock's radio (warlockctl capture, the Wireshark plugin)"),
];

/// After the service is installed and before it starts: registers Warlock's
/// events, so the service's land in the Event Log, creates Warlock's local
/// groups ([`GROUPS`]) that aren't there, and sets the service's failure
/// actions. With `--undo` (the MSI's rollback of a fresh install), removes
/// the groups and the events' registration instead. With `--member GROUP
/// SID`, after that, adds the account with that SID to one of the groups:
/// the installer's "add me" checkboxes, with the SID of the account that
/// ran it.
pub fn setup(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [] => {
            events::install()?;
            info!("events registered");
            for (group, comment) in GROUPS {
                create_group(group, comment)?;
            }
            failure_actions()
        }
        [undo] if undo == "--undo" => {
            let groups = remove_groups();
            let _ = events::uninstall();
            groups
        }
        [member, group, sid] if member == "--member" && GROUPS.iter().any(|(g, _)| g == group) => {
            add_member(group, sid)
        }
        _ => Err(format!("usage: warlock setup [--undo | --member {USERS_GROUP}|{ADMIN_GROUP} SID]").into()),
    }
}

/// Adds the account `sid` (`S-1-5-21-…`) to `group`; already being in it is
/// fine. It counts from that account's next sign-in, when Windows builds its
/// token afresh.
fn add_member(group: &str, sid: &str) -> Result<(), Box<dyn Error>> {
    let mut psid: PSID = null_mut();
    // SAFETY: a NUL-terminated string, and an out pointer.
    if unsafe { ConvertStringSidToSidW(wide(sid).as_ptr(), &mut psid) } == 0 {
        return Err(format!("adding {sid:?} to the {group} group: that isn't a SID").into());
    }
    let member = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: psid };
    // SAFETY: a valid level-0 entry whose SID outlives the call.
    let rc = unsafe { NetLocalGroupAddMembers(null(), wide(group).as_ptr(), 0, (&raw const member).cast(), 1) };
    // SAFETY: allocated by ConvertStringSidToSidW.
    unsafe { LocalFree(psid) };
    match rc {
        0 => info!(group, sid, "member added"),
        ALREADY_MEMBER => info!(group, sid, "already a member"),
        rc => return Err(format!("adding {sid} to the {group} group: error {rc}").into()),
    }
    Ok(())
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

fn create_group(group: &str, comment: &str) -> Result<(), Box<dyn Error>> {
    let mut name = wide(group);
    let mut comment = wide(comment);
    let info = LOCALGROUP_INFO_1 { lgrpi1_name: name.as_mut_ptr(), lgrpi1_comment: comment.as_mut_ptr() };
    let mut bad_field = 0;
    // SAFETY: a valid level-1 structure whose strings outlive the call.
    let rc = unsafe { NetLocalGroupAdd(null(), 1, (&raw const info).cast(), &mut bad_field) };
    match rc {
        0 => info!(group, "created"),
        rc if GROUP_EXISTS.contains(&rc) => info!(group, "already there"),
        rc => return Err(format!("creating the {group} group: error {rc}").into()),
    }
    Ok(())
}

/// Before the files go, on an uninstall that isn't an upgrade: gives the
/// adapter back to Windows' own driver, if Warlock had it, removes the
/// groups, and last, unregisters the events. Any may fail without stopping
/// the uninstall.
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
    if let Err(e) = remove_groups() {
        problems.push(e.to_string());
    }
    for p in &problems {
        tracing::warn!("{p}");
    }
    if let Err(e) = events::uninstall() {
        problems.push(format!("unregistering the events: {e}"));
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("; ").into()) }
}

/// Removes every group of [`GROUPS`] that's there, trying each.
fn remove_groups() -> Result<(), Box<dyn Error>> {
    let mut problems = Vec::new();
    for (group, _) in GROUPS {
        // SAFETY: a NUL-terminated name.
        let rc = unsafe { NetLocalGroupDel(null(), wide(group).as_ptr()) };
        match rc {
            0 => info!(group, "removed"),
            rc if NO_GROUP.contains(&rc) => {}
            rc => problems.push(format!("removing the {group} group: error {rc}")),
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("; ").into()) }
}
