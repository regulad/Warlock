// SPDX-License-Identifier: GPL-2.0-only
//! warlock-msi-ca: the one custom action Warlock's MSI runs from a DLL, and
//! the only thing it can't do with its own tables (PLAN.md, W6).
//!
//! The install page's "Add me to warlock-users" checkbox should show, ticked
//! and greyed out, when the account installing is already in the group
//! (Parker, 2026-11-19). Windows Installer's searches see files, folders,
//! registry values and components, not group membership, and the group's
//! members are in the SAM, which only SYSTEM can read. So before the pages,
//! [`FindMembership`] lists the group's members and compares them with
//! `UserSID`, the account running the install.
//!
//! An account the install added only gets the group's rights from its next
//! sign-in, so the Done page then asks it to sign out (Parker, 2026-11-19):
//! its Finish runs [`FindJoined`], which looks again, and the page's modal
//! "Sign out now" runs [`SignOut`].
//!
//! [`FindMembership`] runs in the UI sequence after `LaunchConditions`, and
//! the others after the install, so the Visual C++ runtime the DLL links to
//! is there. None fails the install: what one can't find out leaves things
//! as they were, and says why in the log.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, GetLastError, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetLocalGroupGetMembers,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{EqualSid, PSID};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    INSTALLMESSAGE_INFO, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiGetPropertyW, MsiProcessMessage,
    MsiRecordSetStringW, MsiSetPropertyW,
};
use windows_sys::Win32::System::Shutdown::{
    EWX_LOGOFF, ExitWindowsEx, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_APPLICATION,
    SHTDN_REASON_MINOR_INSTALLATION,
};

/// `warlock_api::USERS_GROUP`, which this DLL doesn't link.
const GROUP: &str = "warlock-users";
/// Set to 1 when the account installing is already a member.
const MEMBER_PROPERTY: &str = "WARLOCKUSERSMEMBER";
/// Set to 1 after the install when that account wasn't a member before it
/// and is now.
const JOINED_PROPERTY: &str = "WARLOCKUSERSJOINED";
/// The checkbox's property, which a member gets ticked.
const JOIN_PROPERTY: &str = "JOINWARLOCKUSERS";
/// `ERROR_NO_SUCH_ALIAS` and `NERR_GroupNotFound`: no group, as before
/// Warlock is first installed.
const NO_GROUP: [u32; 2] = [1376, 2220];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The custom action: sets [`MEMBER_PROPERTY`] and [`JOIN_PROPERTY`] to 1
/// when `UserSID` is a member of [`GROUP`]. Always succeeds.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FindMembership(install: MSIHANDLE) -> u32 {
    let sid = property(install, "UserSID").unwrap_or_default();
    let said = match is_member(&sid) {
        Ok(true) => {
            set(install, MEMBER_PROPERTY, "1");
            set(install, JOIN_PROPERTY, "1");
            format!("{sid} is already in {GROUP}")
        }
        Ok(false) => format!("{sid} isn't in {GROUP}"),
        Err(e) => format!("couldn't tell whether {sid:?} is in {GROUP}: {e}"),
    };
    log(install, &format!("FindMembership: {said}"));
    0
}

/// The custom action the Done page's Finish runs: sets [`JOINED_PROPERTY`]
/// to 1 when `UserSID` is in [`GROUP`] now and [`MEMBER_PROPERTY`] said it
/// wasn't before. It asks the group itself, so an install that failed to
/// add the account doesn't ask it to sign out. Always succeeds.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FindJoined(install: MSIHANDLE) -> u32 {
    let sid = property(install, "UserSID").unwrap_or_default();
    let before = property(install, MEMBER_PROPERTY).is_some_and(|v| !v.is_empty());
    let said = match is_member(&sid) {
        Ok(true) if !before => {
            set(install, JOINED_PROPERTY, "1");
            format!("{sid} joined {GROUP}")
        }
        Ok(true) => format!("{sid} was already in {GROUP}"),
        Ok(false) => format!("{sid} isn't in {GROUP}"),
        Err(e) => format!("couldn't tell whether {sid:?} is in {GROUP}: {e}"),
    };
    log(install, &format!("FindJoined: {said}"));
    0
}

/// The custom action of the sign-out modal's "Sign out now": signs the
/// user out as the Start menu does, so programs with unsaved work may still
/// hold it up. Always succeeds.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SignOut(install: MSIHANDLE) -> u32 {
    let reason = SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_INSTALLATION | SHTDN_REASON_FLAG_PLANNED;
    // SAFETY: no pointers; it signs out this process's session.
    let said = if unsafe { ExitWindowsEx(EWX_LOGOFF, reason) } != 0 {
        "signing out".to_string()
    } else {
        // SAFETY: no preconditions.
        format!("couldn't sign out: error {}", unsafe { GetLastError() })
    };
    log(install, &format!("SignOut: {said}"));
    0
}

/// Whether the account `sid` (`S-1-5-21-…`) is a direct member of [`GROUP`].
/// No group means no.
fn is_member(sid: &str) -> Result<bool, String> {
    let mut psid: PSID = null_mut();
    // SAFETY: a NUL-terminated string and an out pointer.
    if unsafe { ConvertStringSidToSidW(wide(sid).as_ptr(), &mut psid) } == 0 {
        // SAFETY: no preconditions.
        return Err(format!("not a SID (error {})", unsafe { GetLastError() }));
    }
    let mut buf: *mut u8 = null_mut();
    let (mut read, mut total, mut resume) = (0u32, 0u32, 0usize);
    // SAFETY: valid strings and out pointers; level 0 fills `buf` with
    // LOCALGROUP_MEMBERS_INFO_0 entries, all of them at the preferred length.
    let rc = unsafe {
        NetLocalGroupGetMembers(
            null(),
            wide(GROUP).as_ptr(),
            0,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            &mut resume,
        )
    };
    let found = match rc {
        0 => {
            // SAFETY: `read` entries of level 0, as the call returned.
            let members = unsafe { std::slice::from_raw_parts(buf.cast::<LOCALGROUP_MEMBERS_INFO_0>(), read as usize) };
            // SAFETY: both SIDs valid while compared.
            Ok(members.iter().any(|m| unsafe { EqualSid(m.lgrmi0_sid, psid) } != 0))
        }
        rc if NO_GROUP.contains(&rc) => Ok(false),
        rc => Err(format!("listing {GROUP}: error {rc}")),
    };
    // SAFETY: allocated by the calls that filled them (a null buffer is fine).
    unsafe {
        NetApiBufferFree(buf.cast());
        LocalFree(psid);
    }
    found
}

/// A property's value; `None` if Windows Installer won't give it.
fn property(install: MSIHANDLE, name: &str) -> Option<String> {
    let name = wide(name);
    let mut buf = vec![0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: a buffer of `len` characters, then of the length asked for
    // (which excludes the NUL).
    unsafe {
        let mut rc = MsiGetPropertyW(install, name.as_ptr(), buf.as_mut_ptr(), &mut len);
        if rc == ERROR_MORE_DATA {
            len += 1;
            buf.resize(len as usize, 0);
            rc = MsiGetPropertyW(install, name.as_ptr(), buf.as_mut_ptr(), &mut len);
        }
        (rc == 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn set(install: MSIHANDLE, name: &str, value: &str) {
    // SAFETY: NUL-terminated strings.
    unsafe { MsiSetPropertyW(install, wide(name).as_ptr(), wide(value).as_ptr()) };
}

/// A line in the install's log (`msiexec /l*v`).
fn log(install: MSIHANDLE, text: &str) {
    // SAFETY: a record of our own, closed after use; a NUL-terminated string.
    unsafe {
        let record = MsiCreateRecord(0);
        MsiRecordSetStringW(record, 0, wide(text).as_ptr());
        MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
        MsiCloseHandle(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_is_not_a_member() {
        // Whether or not this PC has the group, LocalSystem isn't in it.
        assert_eq!(is_member("S-1-5-18"), Ok(false));
    }

    #[test]
    fn a_bad_sid_is_an_error() {
        assert!(is_member("").is_err());
        assert!(is_member("regulad").is_err());
    }
}
