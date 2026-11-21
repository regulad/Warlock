// SPDX-License-Identifier: AGPL-3.0-only
//! warlock-msi-ca: the custom actions Warlock's MSI runs from a DLL: what it
//! can't do with its own tables (PLAN.md, W6), and its diagnostics.
//!
//! The installer's "Add me to warlock-users" and "Add me to warlock-admin"
//! checkboxes should show, ticked and greyed out, when the account installing
//! is already in that group (Parker, 2026-11-19). Windows Installer's searches
//! see files, folders, registry values and components, not group membership,
//! and the groups' members are in the SAM, which only SYSTEM can read. So
//! before the pages, [`FindMembership`] lists each group's members and
//! compares them with `UserSID`, the account running the install.
//!
//! An account the install added only gets a group's rights from its next
//! sign-in, so setup then asks it to sign out (Parker, 2026-11-19): once the
//! install is done, [`FindJoined`] looks again, the Done page's Finish goes
//! on to the sign-out prompt if it found the account added, and the
//! prompt's "Sign out now" runs [`SignOut`].
//!
//! [`FindMembership`] runs in the UI sequence after `LaunchConditions`, and
//! the others after the install, so the Visual C++ runtime the DLL links to
//! is there. None fails the install: what one can't find out leaves things
//! as they were, and says why in the log.
//!
//! **Diagnostics** (PRIVACY.md; Parker, 2026-11-21): every action reports to
//! Sentry's `warlock-installer` project (`warlock-sentry`), as fully as it
//! can without identifying anyone, unless `DO_NOT_TRACK` is set in its own
//! environment (it looks no further):
//! - each action as a transaction, with how it went;
//! - its errors, and its panics, which it catches, so none reaches msiexec;
//! - the install's kind (fresh, upgrade, repair, uninstall), its UI, and
//!   the options chosen ([`facts`]);
//! - how the install ended: [`Finished`] after `InstallFinalize`, [`Failed`]
//!   and [`Cancelled`] from the Failed and Cancelled pages' Finish, or, with
//!   no full UI, as the execute sequence's ending actions.
//!
//! The account's SID, which the log names, never goes: what's sent is
//! written apart from the log, and `redact` takes SIDs out besides.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};

use warlock_sentry::{Fact, Outcome, Timed};

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

/// One of Warlock's groups (`warlock_api`'s, which this DLL doesn't link),
/// and the installer's properties for it.
struct Group {
    name: &'static str,
    /// Set to 1 when the account installing is already a member.
    member: &'static str,
    /// Its checkbox's property, which a member gets ticked.
    join: &'static str,
}

const GROUPS: [Group; 2] = [
    Group { name: "warlock-users", member: "WARLOCKUSERSMEMBER", join: "JOINWARLOCKUSERS" },
    Group { name: "warlock-admin", member: "WARLOCKADMINMEMBER", join: "JOINWARLOCKADMIN" },
];
/// The diagnostics' names, group by group, for whether it was asked for and
/// whether the account was already in it ([`facts`]).
const GROUP_FACTS: [(&str, &str); 2] =
    [("join_warlock_users", "in_warlock_users"), ("join_warlock_admin", "in_warlock_admin")];
/// Set to 1 after the install when the account is now in a group it wasn't
/// in before.
const JOINED_PROPERTY: &str = "WARLOCKJOINED";
/// Those groups, for the sign-out modal: "warlock-users and warlock-admin".
const JOINED_GROUPS_PROPERTY: &str = "WARLOCKJOINEDGROUPS";
/// `ERROR_NO_SUCH_ALIAS` and `NERR_GroupNotFound`: no group, as before
/// Warlock is first installed.
const NO_GROUP: [u32; 2] = [1376, 2220];

/// The installer's Sentry project (`regulad/warlock-installer`, platform
/// `rust`, made by the homelab's `tofu/sentry`, 2026-11-21). A DSN only lets
/// a client send events, so it isn't a secret.
const PROJECT: &str = "https://9170239ec5263c1a87ee70264e7db513@o4506961510596608.ingest.us.sentry.io/4512468747943938";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Runs the action `name` as a step of the install, for the diagnostics:
/// timed, with the install's [`facts`], its panics caught and reported. The
/// action itself always succeeds, as before.
fn step(install: MSIHANDLE, name: &str, body: impl FnOnce(&mut Timed)) -> u32 {
    let _diagnostics = warlock_sentry::start("warlock-installer", warlock_sentry::dsn(PROJECT));
    warlock_sentry::set_context("install", &facts(install));
    let mut timed = Timed::start(name, "msi.custom_action");
    if catch_unwind(AssertUnwindSafe(|| body(&mut timed))).is_err() {
        // The SDK's panic hook has reported it.
        timed.fail("panic");
        log(install, &format!("{name}: panicked"));
    }
    0
}

/// What kind of install this is, for the diagnostics, from its properties:
/// none of them identifying.
fn facts(install: MSIHANDLE) -> Vec<(&'static str, Fact)> {
    let has = |name: &str| property(install, name).is_some_and(|v| !v.is_empty());
    let kind = if property(install, "REMOVE").is_some_and(|v| v.eq_ignore_ascii_case("ALL")) {
        "uninstall"
    } else if has("Installed") {
        "repair"
    } else if has("OLDERFOUND") {
        "upgrade"
    } else {
        "install"
    };
    let ui = match property(install, "UILevel").as_deref() {
        Some("2") => "none",
        Some("3") => "basic",
        Some("4") => "reduced",
        Some("5") => "full",
        _ => "unknown",
    };
    let mut facts = vec![("kind", kind.into()), ("ui", ui.into())];
    for (group, (join, member)) in GROUPS.iter().zip(GROUP_FACTS) {
        facts.push((join, has(group.join).into()));
        facts.push((member, has(group.member).into()));
    }
    facts.push(("wireshark_found", has("WIRESHARKDIR").into()));
    facts.push(("wireshark_plugin", has("WIRESHARKPLUGIN").into()));
    facts
}

/// The custom action: for each group `UserSID` is a member of, sets its
/// `member` and `join` properties to 1. Always succeeds.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FindMembership(install: MSIHANDLE) -> u32 {
    step(install, "FindMembership", |timed| {
        let sid = property(install, "UserSID").unwrap_or_default();
        for group in &GROUPS {
            let said = match is_member(group.name, &sid) {
                Ok(true) => {
                    set(install, group.member, "1");
                    set(install, group.join, "1");
                    timed.set(group.name, "member");
                    format!("{sid} is already in {}", group.name)
                }
                Ok(false) => {
                    timed.set(group.name, "not-member");
                    format!("{sid} isn't in {}", group.name)
                }
                Err(e) => {
                    timed.fail("membership-unknown");
                    warlock_sentry::error(&format!(
                        "FindMembership: couldn't tell whether the account is in {}: {e}",
                        group.name
                    ));
                    format!("couldn't tell whether {sid:?} is in {}: {e}", group.name)
                }
            };
            log(install, &format!("FindMembership: {said}"));
        }
    })
}

/// The custom action run once the install is done, before the Done page
/// (the UI sequence, after `ExecuteAction`): when `UserSID` is now in
/// groups whose `member` property said it wasn't before, sets
/// [`JOINED_PROPERTY`] to 1 and [`JOINED_GROUPS_PROPERTY`] to their names.
/// It asks the groups themselves, so an install that failed to add the
/// account doesn't ask it to sign out. Always succeeds.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FindJoined(install: MSIHANDLE) -> u32 {
    step(install, "FindJoined", |timed| {
        let sid = property(install, "UserSID").unwrap_or_default();
        let mut joined = Vec::new();
        for group in &GROUPS {
            let before = property(install, group.member).is_some_and(|v| !v.is_empty());
            let asked = property(install, group.join).is_some_and(|v| !v.is_empty());
            let said = match is_member(group.name, &sid) {
                Ok(true) if !before => {
                    joined.push(group.name);
                    timed.set(group.name, "joined");
                    format!("{sid} joined {}", group.name)
                }
                Ok(true) => {
                    timed.set(group.name, "member");
                    format!("{sid} was already in {}", group.name)
                }
                Ok(false) => {
                    // Asked to join, and the install didn't add it.
                    if asked {
                        timed.fail("not-joined");
                        warlock_sentry::error(&format!(
                            "FindJoined: the install didn't add the account to {}",
                            group.name
                        ));
                    }
                    timed.set(group.name, "not-member");
                    format!("{sid} isn't in {}", group.name)
                }
                Err(e) => {
                    timed.fail("membership-unknown");
                    warlock_sentry::error(&format!(
                        "FindJoined: couldn't tell whether the account is in {}: {e}",
                        group.name
                    ));
                    format!("couldn't tell whether {sid:?} is in {}: {e}", group.name)
                }
            };
            log(install, &format!("FindJoined: {said}"));
        }
        if !joined.is_empty() {
            set(install, JOINED_PROPERTY, "1");
            set(install, JOINED_GROUPS_PROPERTY, &joined.join(" and "));
        }
    })
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
    step(install, "SignOut", |timed| {
        let reason = SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_MINOR_INSTALLATION | SHTDN_REASON_FLAG_PLANNED;
        // SAFETY: no pointers; it signs out this process's session.
        let said = if unsafe { ExitWindowsEx(EWX_LOGOFF, reason) } != 0 {
            "signing out".to_string()
        } else {
            // SAFETY: no preconditions.
            let said = format!("couldn't sign out: error {}", unsafe { GetLastError() });
            timed.fail("not-signed-out");
            warlock_sentry::error(&format!("SignOut: {said}"));
            said
        };
        log(install, &format!("SignOut: {said}"));
    })
}

/// How the install ended, for the diagnostics: as a transaction named by
/// its kind (`install`, `upgrade`, `repair`, `uninstall`), with its facts; a
/// failure as an error too. Always succeeds.
fn ended(install: MSIHANDLE, outcome: Outcome) -> u32 {
    let _diagnostics = warlock_sentry::start("warlock-installer", warlock_sentry::dsn(PROJECT));
    let facts = facts(install);
    let kind = match facts.first() {
        Some((_, Fact::Text(kind))) => kind.clone(),
        _ => "install".into(),
    };
    warlock_sentry::set_context("install", &facts);
    // Nothing in it panics, but nothing may reach msiexec either.
    let _ = catch_unwind(AssertUnwindSafe(|| warlock_sentry::ended(&kind, "msi.install", outcome, &facts)));
    log(install, &format!("the {kind} {outcome:?}"));
    0
}

/// The custom action run once the install has finished: after
/// `InstallFinalize`, in the execute sequence, whatever the UI.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Finished(install: MSIHANDLE) -> u32 {
    ended(install, Outcome::Finished)
}

/// The custom action run when the install failed: the Failed page's
/// Finish, or with no full UI the execute sequence's ending action.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Failed(install: MSIHANDLE) -> u32 {
    ended(install, Outcome::Failed)
}

/// The custom action run when the install was cancelled: the Cancelled
/// page's Finish, or with no full UI the execute sequence's ending action.
///
/// # Safety
///
/// Windows Installer calls it with a valid install handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Cancelled(install: MSIHANDLE) -> u32 {
    ended(install, Outcome::Cancelled)
}

/// Whether the account `sid` (`S-1-5-21-…`) is a direct member of `group`.
/// No group means no.
fn is_member(group: &str, sid: &str) -> Result<bool, String> {
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
            wide(group).as_ptr(),
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
        rc => Err(format!("listing {group}: error {rc}")),
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
        for group in &GROUPS {
            assert_eq!(is_member(group.name, "S-1-5-18"), Ok(false), "{}", group.name);
        }
    }

    #[test]
    fn a_bad_sid_is_an_error() {
        assert!(is_member("warlock-users", "").is_err());
        assert!(is_member("warlock-users", "regulad").is_err());
    }
}
