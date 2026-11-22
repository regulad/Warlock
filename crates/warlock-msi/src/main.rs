// SPDX-License-Identifier: GPL-2.0-only
//! warlock-msi: builds Warlock's Windows Installer package, for winget as
//! `Regulad.Warlock`, with Windows' own tools only: the Windows Installer
//! API (`msi.dll`) writes the database and `makecab` packs the files. No
//! WiX, no installer toolchain (Parker, 2026-11-18).
//!
//! ```text
//! cargo run -p warlock-msi [-- --out PATH] [--no-build]
//! cargo run -p warlock-msi -- winget MSI --installer-url URL [--out DIR]
//! ```
//!
//! Builds `warlock`, `warlockctl` and the custom action DLL
//! (`warlock-msi-ca`) in release (unless `--no-build`) and
//! writes `target/msi/Warlock-<version>-x64.msi`. It installs only where
//! the Visual C++ runtime the binaries link to is there, at least as new as
//! the toolset that linked them (read from their headers): a fresh Windows
//! has none (PLAN.md, W5). It then installs:
//! - `warlock.exe`, `warlockctl.exe`, both licence texts and the Wintun
//!   exception into
//!   `C:\Program Files\Warlock`, which joins the system `PATH`;
//! - the Warlock service: LocalSystem, automatic (delayed) start, its own
//!   service SID;
//! - `warlock setup` once the service exists and before it starts (the
//!   `warlock-users` and `warlock-admin` groups, the service's
//!   restart-on-failure actions; undone if a fresh install rolls back), and
//!   on an uninstall that isn't an upgrade, `warlock teardown` (the adapter
//!   back to Windows' own driver, the groups removed);
//! - optionally, the account installing in `warlock-users` or
//!   `warlock-admin` ([`GROUPS`]), when its checkbox on the Options page (off
//!   by default) or `JOINWARLOCKUSERS=1` / `JOINWARLOCKADMIN=1` asks. A
//!   checkbox shows ticked and greyed out when that account is already a
//!   member, which `warlock-msi-ca`'s DLL finds out before the pages;
//! - optionally, `warlock-extcap.exe` in Wireshark's `extcap` folder, which
//!   makes Warlock's radio a Wireshark capture interface. It goes in when
//!   the Options page's checkbox (off by default) or `WIRESHARKPLUGIN=1`
//!   asks for it and the registry shows where Wireshark is; it stays in on
//!   an upgrade that finds it installed.
//!
//! A newer version replaces an older one (and a rebuild of the same version
//! replaces itself); an older one won't install over a newer one.
//!
//! Started by hand, it shows its own pages ([`ui`]): the licences
//! ([`licence`], from the repository's licence files), the install folder,
//! progress and the end; opened again, repair or remove. Silent installs,
//! winget's among them, show none.
//!
//! `winget` writes winget's three manifests for a finished package, from what
//! the package itself records (version, product and upgrade codes, the least
//! runtime version) and its SHA-256, so it runs on the package as published:
//! after signing, which changes the hash. They make the runtime's winget
//! package, `Microsoft.VCRedist.2015+.x64`, a dependency, so winget installs
//! it first. A release builds and signs the binaries, packages them with
//! `--no-build`, signs the package, then runs `winget` with the URL it will
//! be downloaded from.
//!
//! The machinery is `warlock-msi-kit`'s, which Koala's builder shares: the
//! tables and their column definitions, the database, the cabinet, the
//! searches, the standard pages and the manifests. What's here is Warlock's
//! own: its files, components and service, what it looks for, its custom
//! actions, its Options page and its words. Sequence numbers are Windows
//! Installer's suggested ones.

mod licence;
mod notices;
mod ui;

use std::path::{Path, PathBuf};
use std::process::Command;

use warlock_msi_kit::winget::{self, Manifest};
use warlock_msi_kit::{
    CA_CONTINUE, CA_DEFERRED, CA_DLL, CA_EXE_FILE, CA_NO_IMPERSONATE, CA_ROLLBACK, COMPONENT_64BIT, Database, HKLM,
    LOCATOR_64BIT, LOCATOR_DIRECTORY, LOCATOR_FILE, Payload, Result, SERVICE_AUTO_START,
    SERVICE_CONFIG_DELAYED_AUTO_START, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_INSTALL,
    SERVICE_CONFIG_REINSTALL, SERVICE_CONFIG_REQUIRED_PRIVILEGES, SERVICE_CONFIG_SERVICE_SID, SERVICE_DELETE_UNINSTALL,
    SERVICE_ERROR_NORMAL, SERVICE_OWN_PROCESS, SERVICE_START_INSTALL, SERVICE_STOP_INSTALL, SERVICE_STOP_UNINSTALL,
    Search, Summary, Table, UPGRADE_MAX_INCLUSIVE, UPGRADE_MIGRATE_FEATURES, UPGRADE_ONLY_DETECT, VcRuntime,
    file_table, media_table, n, new_guid, package_properties, product_version, runtime_min, s, schema, sequence,
    with_sizes,
};

// GUIDs that never change. Generated once with PowerShell's
// `[guid]::NewGuid()` on 2026-11-18, while writing this builder.
// - The upgrade code ties every version of Warlock together: Windows
//   Installer finds an installed Warlock to replace by it.
// - A component's GUID is how Windows Installer counts that component
//   across versions and products, so each stays with its key file for good.
//   A new file that isn't one of these goes in a new component with a new
//   GUID, generated the same way and noted here.
// The product code and package code are new for every build (`new_guid`).
const UPGRADE_CODE: &str = "{13F9A3A8-EA0D-4025-8C66-70946C436AE5}";
/// Key file `warlock.exe`; the service hangs off it.
const COMPONENT_WARLOCK: &str = "{10DE44B3-190C-48DD-AF42-3E24BA15F241}";
/// Key file `warlockctl.exe`; the `PATH` entry hangs off it.
const COMPONENT_WARLOCKCTL: &str = "{34A10DA0-A780-4C21-8E81-FE0E0DDED176}";
/// Key file `LICENSE.md`; with `LICENSE-AGPL-3.0.md` and
/// `LICENSE-WINTUN-EXCEPTION.md` (added before the first release, so no
/// installed version had the component without it).
const COMPONENT_LICENSES: &str = "{017BEEEC-3CC4-4536-BC22-1F8363621EB7}";
/// Key file `warlock-extcap.exe`, in Wireshark's `extcap` folder. Generated
/// 2026-11-19 (0.1.2).
const COMPONENT_WIRESHARK_PLUGIN: &str = "{5BB193A0-3D81-4220-97CA-7FC16F300AC6}";
/// Key file `PRIVACY.md`, the privacy policy. Generated 2026-11-21 (0.2.5).
const COMPONENT_DIAGNOSTICS: &str = "{E3E20141-999A-41F6-9A64-D6972807FA22}";
/// Key file `THIRD-PARTY-NOTICES.txt`: the licences of the third-party
/// software built into the programs (`notices`). Generated 2026-11-21
/// (0.2.5).
const COMPONENT_NOTICES: &str = "{2158E17D-8824-46F1-8417-DC476B9B59F3}";

/// The optional Wireshark plugin (PLAN.md, W6): installed when the
/// installer's checkbox sets this property and Wireshark was found, which
/// sets `WIRESHARKDIR`. Off by default, so silent installs (winget's) leave
/// it out unless given `WIRESHARKPLUGIN=1`.
const WIRESHARK_PLUGIN_PROPERTY: &str = "WIRESHARKPLUGIN";
/// Set by the same search when the plugin is already installed, and left
/// alone by the checkbox: unticking it on an upgrade says the previous
/// version's plugin will be removed (Parker, 2026-11-19).
const WIRESHARK_PLUGIN_FOUND_PROPERTY: &str = "WIRESHARKPLUGINFOUND";

/// One of Warlock's groups that the installer can add the account running it
/// (`UserSID`) to, from that account's next sign-in: a checkbox each (off by
/// default), or the `join` property on a silent install (Parker,
/// 2026-11-19). Nothing takes the account out again but an uninstall, which
/// removes the groups.
pub(crate) struct Group {
    pub name: &'static str,
    /// The checkbox's property: `JOINWARLOCKUSERS=1` joins `warlock-users`.
    pub join: &'static str,
    /// Set by `warlock-msi-ca`'s `FindMembership`, before the pages, when the
    /// account is already a member: the checkbox shows ticked and greyed out.
    pub member: &'static str,
    /// The custom action that adds the account, as SYSTEM.
    pub action: &'static str,
    /// The checkbox's control, and the start of its notes' names.
    pub control: &'static str,
    /// The checkbox's label, with its keyboard shortcut.
    pub label: &'static str,
    /// What membership is for, under the checkbox.
    pub purpose: &'static str,
}

/// `warlock-users`, then `warlock-admin` below it (Parker, 2026-11-19).
/// The names and properties are `warlock-msi-ca`'s too.
pub(crate) const GROUPS: [Group; 2] = [
    Group {
        name: "warlock-users",
        join: "JOINWARLOCKUSERS",
        member: "WARLOCKUSERSMEMBER",
        action: "WarlockJoinUsers",
        control: "JoinUsers",
        label: "Add &me ([LogonUser]) to warlock-users",
        purpose: "To use Warlock without elevation, from your next sign-in.",
    },
    Group {
        name: "warlock-admin",
        join: "JOINWARLOCKADMIN",
        member: "WARLOCKADMINMEMBER",
        action: "WarlockJoinAdmin",
        control: "JoinAdmin",
        label: "Add me ([LogonUser]) to warlock-&admin",
        purpose: "To capture the radio (warlockctl capture, the Wireshark plugin), from your next sign-in.",
    },
];
/// Set by `FindJoined`, when the Done page's Finish is pressed, when the
/// install added that account to a group: a modal asks it to sign out, since
/// groups count from the next sign-in (Parker, 2026-11-19).
const JOINED_PROPERTY: &str = "WARLOCKJOINED";
/// Those groups, as the modal names them ("warlock-users and warlock-admin").
const JOINED_GROUPS_PROPERTY: &str = "WARLOCKJOINEDGROUPS";
/// The Binary table's name for `warlock_msi_ca.dll`.
const CA_BINARY: &str = "WarlockCa";

/// As the winget package's publisher.
const MANUFACTURER: &str = "Regulad";
/// The winget package.
const PACKAGE: &str = "Regulad.Warlock";
/// Warlock's repository, where its privacy policy is published.
const REPOSITORY: &str = "https://github.com/regulad/Warlock";
const DESCRIPTION: &str = "Apple Wireless Direct Link (AWDL) for Windows, on a USB Wi-Fi adapter";
/// The service's name, as `warlock install` and `sc` know it.
const SERVICE: &str = "Warlock";
const CABINET: &str = "warlock.cab";

/// The Visual C++ runtime DLLs `warlock.exe` imports (`warlockctl.exe` only
/// the first), each with the property the package's search for it sets and
/// its `short|long` name.
const RUNTIME_DLLS: [(&str, &str); 3] = [
    ("VCRUNTIME140", "VCRT140.DLL|vcruntime140.dll"),
    ("VCRUNTIME140_1", "VCRT1401.DLL|vcruntime140_1.dll"),
    ("MSVCP140", "msvcp140.dll"),
];
/// The property recording the least runtime version, for `winget`.
const RUNTIME_MIN_PROPERTY: &str = "WarlockVcRuntimeMin";

/// Custom action type 18 (run an EXE installed with the product), deferred,
/// not impersonating, so as SYSTEM.
const CA_EXE_AS_SYSTEM: i32 = CA_EXE_FILE | CA_DEFERRED | CA_NO_IMPERSONATE;
/// An install without the full UI (`UILevel` 5), whose own pages report how
/// it ended: silent (2), basic (3) or reduced (4).
const NO_FULL_UI: &str = "UILevel < 5";
/// ServiceControl events: start on install, stop on install and uninstall,
/// delete on uninstall.
const CONTROL_EVENTS: i32 =
    SERVICE_START_INSTALL | SERVICE_STOP_INSTALL | SERVICE_STOP_UNINSTALL | SERVICE_DELETE_UNINSTALL;
/// MsiServiceConfig events: install and reinstall.
const CONFIG_EVENTS: i32 = SERVICE_CONFIG_INSTALL | SERVICE_CONFIG_REINSTALL;

/// Every table, filled in. `runtime_min` is the least Visual C++ runtime
/// version (`14.50`) the binaries need.
fn tables(
    version: &str,
    product_code: &str,
    runtime_min: &str,
    (licence, privacy): (&str, &str),
    files: &[(Payload, u64)],
) -> Vec<Table> {
    let ui = ui::build(licence, privacy);
    let ui_properties = ui.properties();
    let mut all = ui.into_tables();
    let runtime = VcRuntime { dlls: &RUNTIME_DLLS, min: runtime_min.to_string() };

    let mut property = schema::property();
    for (k, v) in [
        (RUNTIME_MIN_PROPERTY, runtime_min),
        ("ProductCode", product_code),
        ("UpgradeCode", UPGRADE_CODE),
        ("ProductName", "Warlock"),
        ("ProductVersion", version),
        ("Manufacturer", MANUFACTURER),
        ("ProductLanguage", "1033"),
        ("ALLUSERS", "1"),
        ("ARPNOMODIFY", "1"),
        ("ARPCOMMENTS", "Apple Wireless Direct Link (AWDL) for Windows"),
        // Set in the UI (FindRelatedProducts, AppSearch, the checkbox), used
        // by the elevated part.
        (
            "SecureCustomProperties",
            "OLDERFOUND;NEWERFOUND;WIRESHARKDIR;WIRESHARKPLUGIN;JOINWARLOCKUSERS;JOINWARLOCKADMIN",
        ),
    ] {
        property.row(vec![s(k), s(v)]);
    }
    for (k, v) in &ui_properties {
        property.row(vec![s(k), s(v)]);
    }
    all.push(property);

    let mut directory = schema::directory();
    directory
        .row(vec![s("TARGETDIR"), None, s("SourceDir")])
        .row(vec![s("ProgramFiles64Folder"), s("TARGETDIR"), s(".")])
        .row(vec![s("INSTALLDIR"), s("ProgramFiles64Folder"), s("Warlock")])
        // Wireshark's folder, as AppSearch finds it (a directory takes the
        // path of the property named after it), and its extcap folder.
        .row(vec![s("WIRESHARKDIR"), s("TARGETDIR"), s(".")])
        .row(vec![s("WIRESHARKEXTCAP"), s("WIRESHARKDIR"), s("extcap")]);
    all.push(directory);

    let mut component = schema::component();
    for (name, guid, key) in [
        ("Warlock", COMPONENT_WARLOCK, "warlock.exe"),
        ("Warlockctl", COMPONENT_WARLOCKCTL, "warlockctl.exe"),
        ("Licenses", COMPONENT_LICENSES, "LICENSE.md"),
        ("Diagnostics", COMPONENT_DIAGNOSTICS, "PRIVACY.md"),
        ("Notices", COMPONENT_NOTICES, "THIRD-PARTY-NOTICES.txt"),
    ] {
        component.row(vec![s(name), s(guid), s("INSTALLDIR"), n(COMPONENT_64BIT), None, s(key)]);
    }
    component.row(vec![
        s("WiresharkPlugin"),
        s(COMPONENT_WIRESHARK_PLUGIN),
        s("WIRESHARKEXTCAP"),
        n(COMPONENT_64BIT),
        None,
        s("warlock_extcap.exe"),
    ]);
    all.push(component);

    let mut feature = schema::feature();
    feature.row(vec![s("Warlock"), None, s("Warlock"), s("Warlock and warlockctl"), n(1), n(1), s("INSTALLDIR"), n(0)]);
    // Level 1000, above the default INSTALLLEVEL of 1: off unless the
    // Condition table raises it. Not displayed: the checkbox is its UI.
    feature.row(vec![
        s("WiresharkPlugin"),
        s("Warlock"),
        s("Wireshark plugin"),
        s("Warlock's radio as a capture interface in Wireshark"),
        n(0),
        n(1000),
        None,
        n(0),
    ]);
    all.push(feature);

    let mut condition = schema::condition();
    condition.row(vec![s("WiresharkPlugin"), n(1), s(&format!("{WIRESHARK_PLUGIN_PROPERTY} AND WIRESHARKDIR"))]);
    all.push(condition);

    let mut feature_components = schema::feature_components();
    for c in ["Warlock", "Warlockctl", "Licenses", "Diagnostics", "Notices"] {
        feature_components.row(vec![s("Warlock"), s(c)]);
    }
    feature_components.row(vec![s("WiresharkPlugin"), s("WiresharkPlugin")]);
    all.push(feature_components);

    all.push(file_table(files));
    all.push(media_table(CABINET, files.len()));

    let mut upgrade = schema::upgrade();
    upgrade
        // Up to and including this version: replaced.
        .row(vec![
            s(UPGRADE_CODE),
            None,
            s(version),
            None,
            n(UPGRADE_MIGRATE_FEATURES | UPGRADE_MAX_INCLUSIVE),
            None,
            s("OLDERFOUND"),
        ])
        // Newer: only noticed, to refuse the install.
        .row(vec![s(UPGRADE_CODE), s(version), None, None, n(UPGRADE_ONLY_DETECT), None, s("NEWERFOUND")]);
    all.push(upgrade);

    // The Visual C++ runtime, found by its DLLs in System32: each search sets
    // its property when the file is there at `runtime_min` or later.
    let mut search = Search::new();
    runtime.search(&mut search);
    // Wireshark's folder, from either place its installer records it: the
    // App Paths entry (64-bit registry) or its own key (32-bit). A directory
    // search sets the property only if the folder exists.
    search
        .registry(
            "SigWiresharkAppPath",
            HKLM,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe",
            "Path",
            LOCATOR_DIRECTORY | LOCATOR_64BIT,
            &["WIRESHARKDIR"],
        )
        .registry(
            "SigWiresharkInstallDir",
            HKLM,
            r"SOFTWARE\Wireshark",
            "InstallDir",
            LOCATOR_DIRECTORY,
            &["WIRESHARKDIR"],
        )
        // The plugin already installed (an upgrade or repair): the checkbox
        // starts ticked, so a silent upgrade keeps it.
        .component(
            "SigWiresharkPlugin",
            COMPONENT_WIRESHARK_PLUGIN,
            LOCATOR_FILE,
            &[WIRESHARK_PLUGIN_PROPERTY, WIRESHARK_PLUGIN_FOUND_PROPERTY],
        );
    all.extend(search.into_tables());

    let (runtime_found, runtime_missing) = runtime.launch_condition("Warlock");
    let mut launch = schema::launch_condition();
    launch
        .row(vec![s("VersionNT64"), s("Warlock needs 64-bit Windows.")])
        .row(vec![s("NOT NEWERFOUND"), s("A newer version of Warlock is already installed.")])
        // Not needed to uninstall.
        .row(vec![s(&runtime_found), s(&runtime_missing)]);
    all.push(launch);

    let mut service_install = schema::service_install();
    // No StartName: LocalSystem, the account that may rebind drivers and
    // create adapters. Its privileges are trimmed in MsiServiceConfig.
    service_install.row(vec![
        s("WarlockService"),
        s(SERVICE),
        s("Warlock"),
        n(SERVICE_OWN_PROCESS),
        n(SERVICE_AUTO_START),
        n(SERVICE_ERROR_NORMAL),
        None,
        None,
        None,
        None,
        s("service"),
        s("Warlock"),
        s(DESCRIPTION),
    ]);
    all.push(service_install);

    let mut service_control = schema::service_control();
    service_control.row(vec![s("WarlockServiceControl"), s(SERVICE), n(CONTROL_EVENTS), None, n(1), s("Warlock")]);
    all.push(service_control);

    let mut service_config = schema::msi_service_config();
    let config = |name: &str, kind: i32, argument: &str| {
        vec![s(name), s(SERVICE), n(CONFIG_EVENTS), n(kind), s(argument), s("Warlock")]
    };
    service_config
        // Started after the rest of boot.
        .row(config("WarlockDelayedStart", SERVICE_CONFIG_DELAYED_AUTO_START, "1"))
        // SERVICE_SID_TYPE_UNRESTRICTED: NT SERVICE\Warlock, for ACLs.
        .row(config("WarlockServiceSid", SERVICE_CONFIG_SERVICE_SID, "1"))
        // Restarted when it stops with an error too, not only on a crash.
        .row(config("WarlockFailureFlag", SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, "1"))
        // The service manager removes every other privilege from its token,
        // 27 of LocalSystem's 28. Rebinding the stick to WinUSB, fetching
        // Wintun, installing its driver on a fresh Windows and creating the
        // adapter all worked without them (PLAN.md, W5, tried 2026-11-18).
        // More entries would be separated by `[~]`.
        .row(config("WarlockPrivileges", SERVICE_CONFIG_REQUIRED_PRIVILEGES, "SeChangeNotifyPrivilege"));
    all.push(service_config);

    // No MsiServiceConfigFailureActions: Windows Installer fails to set
    // restart actions ("access denied", error 1939, seen 2026-11-18), as they
    // need the service opened with start access too. `warlock setup` sets them.

    let mut custom = schema::custom_action();
    custom
        .row(vec![s("WarlockSetup"), n(CA_EXE_AS_SYSTEM), s("warlock.exe"), s("setup"), None])
        // If the install fails after WarlockSetup ran: its group goes again.
        .row(vec![
            s("WarlockSetupRollback"),
            n(CA_EXE_AS_SYSTEM | CA_ROLLBACK | CA_CONTINUE),
            s("warlock.exe"),
            s("setup --undo"),
            None,
        ])
        .row(vec![s("WarlockTeardown"), n(CA_EXE_AS_SYSTEM | CA_CONTINUE), s("warlock.exe"), s("teardown"), None])
        // Before the pages: is the account installing already in the groups?
        .row(vec![s("WarlockFindMembership"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("FindMembership"), None])
        // After the install (the UI sequence), and by the sign-out prompt.
        .row(vec![s("WarlockFindJoined"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("FindJoined"), None])
        .row(vec![s("WarlockSignOut"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("SignOut"), None])
        // How the install ended, for the diagnostics (warlock-msi-ca).
        .row(vec![s("WarlockFinished"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("Finished"), None])
        .row(vec![s("WarlockFailed"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("Failed"), None])
        .row(vec![s("WarlockCancelled"), n(CA_DLL | CA_CONTINUE), s(CA_BINARY), s("Cancelled"), None]);
    // Joining a group. The target is formatted as the action is scheduled, so
    // it carries the SID of the account installing. A failure only goes in
    // the log: that account can still join the group by hand.
    for g in &GROUPS {
        let target = format!("setup --member {} [UserSID]", g.name);
        custom.row(vec![s(g.action), n(CA_EXE_AS_SYSTEM | CA_CONTINUE), s("warlock.exe"), s(&target), None]);
    }
    all.push(custom);

    // The custom action DLL's row is added by `build`, as a stream.
    all.push(schema::binary());

    let mut environment = schema::environment();
    // `=`: set on install; `-`: removed on uninstall; `*`: the system's.
    // `[~];` appends to what's there.
    environment.row(vec![s("WarlockPath"), s("=-*PATH"), s("[~];[INSTALLDIR]"), s("Warlockctl")]);
    all.push(environment);

    let install = Some("NOT REMOVE~=\"ALL\"");
    // Only a fresh install takes its group back: an upgrade's group was
    // there before, with its members.
    let fresh_install = Some("NOT REMOVE~=\"ALL\" AND NOT OLDERFOUND");
    let real_uninstall = Some("REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE");
    // Joining each group asked for, once the groups exist and before the
    // service starts.
    let joins: Vec<(&str, String, i32)> = GROUPS
        .iter()
        .zip(5880..)
        .map(|(g, at)| (g.action, format!("{} AND UserSID AND NOT REMOVE~=\"ALL\"", g.join), at))
        .collect();
    // Asked to join a group it wasn't in before.
    let asked = GROUPS.iter().map(|g| format!("({} AND NOT {})", g.join, g.member)).collect::<Vec<_>>().join(" OR ");
    // With the dialogs (`ui`) between costing and executing.
    let ui_sequence: Vec<(&str, Option<&str>, i32)> = [
        ("FindRelatedProducts", None, 25),
        ("AppSearch", None, 50),
        ("LaunchConditions", None, 100),
        // After LaunchConditions, which makes sure of the Visual C++
        // runtime the DLL links to.
        ("WarlockFindMembership", Some("NOT Installed"), 110),
        ("CostInitialize", None, 800),
        ("FileCost", None, 900),
        ("CostFinalize", None, 1000),
        ("MigrateFeatureStates", None, 1200),
        ("ExecuteAction", None, 1300),
        // Once the install is done, before the Done page: did it add the
        // account to a group it asked for? The page's Finish then goes on to
        // the sign-out prompt. (Run from Finish itself, in 0.2.0, the prompt
        // never came: `ui`.)
        ("WarlockFindJoined", Some(asked.as_str()), 1310),
    ]
    .into_iter()
    .chain(warlock_msi_kit::ui::sequence(ui::FIRST))
    .collect();
    all.push(sequence("InstallUISequence", &ui_sequence));
    let execute: Vec<(&str, Option<&str>, i32)> = [
        ("FindRelatedProducts", None, 25),
        ("AppSearch", None, 50),
        ("LaunchConditions", None, 100),
        ("ValidateProductID", None, 700),
        ("CostInitialize", None, 800),
        ("FileCost", None, 900),
        ("CostFinalize", None, 1000),
        ("MigrateFeatureStates", None, 1200),
        ("InstallValidate", None, 1400),
        // The old version goes first, whole.
        ("RemoveExistingProducts", None, 1401),
        ("InstallInitialize", None, 1500),
        ("ProcessComponents", None, 1600),
        ("UnpublishFeatures", None, 1800),
        ("StopServices", Some("VersionNT"), 1900),
        ("WarlockTeardown", real_uninstall, 1950),
        ("DeleteServices", Some("VersionNT"), 2000),
        ("RemoveEnvironmentStrings", None, 3300),
        ("RemoveFiles", None, 3500),
        ("RemoveFolders", None, 3600),
        ("CreateFolders", None, 3700),
        ("InstallFiles", None, 4000),
        ("WriteEnvironmentStrings", None, 5200),
        ("InstallServices", Some("VersionNT"), 5800),
        ("MsiConfigureServices", Some("VersionNT"), 5850),
        // Once the service exists (for its failure actions), before it
        // starts; a rollback action goes before the action it undoes.
        ("WarlockSetupRollback", fresh_install, 5870),
        ("WarlockSetup", install, 5875),
        ("StartServices", Some("VersionNT"), 5900),
        ("RegisterUser", None, 6000),
        ("RegisterProduct", None, 6100),
        ("PublishFeatures", None, 6300),
        ("PublishProduct", None, 6400),
        ("InstallFinalize", None, 6600),
        // How it ended, for the diagnostics: finished, whatever the UI; with
        // no full UI, failed or cancelled as the ending actions (with one,
        // the Failed and Cancelled pages report it, `ui`).
        ("WarlockFinished", None, 6650),
        ("WarlockCancelled", Some(NO_FULL_UI), -2),
        ("WarlockFailed", Some(NO_FULL_UI), -3),
    ]
    .into_iter()
    .chain(joins.iter().map(|(action, condition, at)| (*action, Some(condition.as_str()), *at)))
    .collect();
    all.push(sequence("InstallExecuteSequence", &execute));
    all.push(sequence(
        "AdminUISequence",
        &[
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("ExecuteAction", None, 1300),
        ],
    ));
    all.push(sequence(
        "AdminExecuteSequence",
        &[
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("InstallValidate", None, 1400),
            ("InstallInitialize", None, 1500),
            ("InstallAdminPackage", None, 3900),
            ("InstallFiles", None, 4000),
            ("InstallFinalize", None, 6600),
        ],
    ));
    all.push(sequence(
        "AdvtExecuteSequence",
        &[
            ("CostInitialize", None, 800),
            ("CostFinalize", None, 1000),
            ("InstallValidate", None, 1400),
            ("InstallInitialize", None, 1500),
            ("PublishFeatures", None, 6300),
            ("PublishProduct", None, 6400),
            ("InstallFinalize", None, 6600),
        ],
    ));
    all
}

/// Warlock's version: the workspace's, which this builder shares with
/// `warlock` and every other crate.
fn warlock_version() -> Result<String> {
    Ok(product_version(env!("CARGO_PKG_VERSION"))?.to_string())
}

fn build(root: &Path, out: &Path, version: &str) -> Result<()> {
    let release = root.join("target").join("release");
    // The File key, the component, the `short|long` name, the source, and
    // whether it's vital.
    let payload = [
        ("warlock.exe", "Warlock", "warlock.exe", release.join("warlock.exe"), true),
        ("warlockctl.exe", "Warlockctl", "WLCTL.EXE|warlockctl.exe", release.join("warlockctl.exe"), true),
        (
            "warlock_extcap.exe",
            "WiresharkPlugin",
            "WLEXTCAP.EXE|warlock-extcap.exe",
            release.join("warlock-extcap.exe"),
            true,
        ),
        ("LICENSE.md", "Licenses", "LICENSE.MD|LICENSE.md", root.join("LICENSE.md"), false),
        ("LICENSE_AGPL.md", "Licenses", "AGPL3.MD|LICENSE-AGPL-3.0.md", root.join("LICENSE-AGPL-3.0.md"), false),
        (
            "LICENSE_WINTUN.md",
            "Licenses",
            "WINTUNEX.MD|LICENSE-WINTUN-EXCEPTION.md",
            root.join("LICENSE-WINTUN-EXCEPTION.md"),
            false,
        ),
        ("PRIVACY.md", "Diagnostics", "PRIVACY.MD|PRIVACY.md", root.join("PRIVACY.md"), false),
        ("THIRD-PARTY-NOTICES.txt", "Notices", "NOTICES.TXT|THIRD-PARTY-NOTICES.txt", root.join(notices::FILE), false),
    ];
    let files = with_sizes(payload.into_iter().map(|(key, component, name, source, vital)| Payload {
        key: key.into(),
        component: component.into(),
        name: name.into(),
        source,
        vital,
    }))?;

    let exes: Vec<&Path> =
        files.iter().filter(|(p, _)| p.key.ends_with(".exe")).map(|(p, _)| p.source.as_path()).collect();
    let runtime_min = runtime_min(&exes)?;
    let licence = licence::rtf(root)?;
    let privacy = licence::privacy(root)?;

    let product_code = new_guid()?;
    let package_code = new_guid()?;
    let db = Database::create(out)?;
    for t in tables(version, &product_code, &runtime_min, (&licence, &privacy), &files) {
        db.import(&t)?;
    }
    // The cabinet goes in as a stream of the package, and the custom
    // action DLL as the Binary table's one row.
    db.cabinet(CABINET, &files)?;
    db.binary(CA_BINARY, &release.join("warlock_msi_ca.dll"))?;
    db.summary(&Summary {
        subject: "Warlock",
        author: MANUFACTURER,
        keywords: "Installer, AWDL",
        comments: "This installer database contains the logic and data required to install Warlock.",
        // x64, English.
        template: "x64;1033",
        package_code: &package_code,
        application: "warlock-msi (Windows Installer API)",
    })?;
    db.commit()?;
    println!(
        "{} (Warlock {version}, product code {product_code}, Visual C++ runtime {runtime_min} or later)",
        out.display()
    );
    Ok(())
}

/// Writes winget's three manifests (version, installer, default locale) for
/// the package at `msi`, to be downloaded from `url`, into `out` (by default
/// `target/msi/winget/<version>`).
fn winget(root: &Path, msi: &Path, url: &str, out: Option<PathBuf>) -> Result<()> {
    let p = package_properties(msi)?;
    let get = |k: &str| p.get(k).map(String::as_str).ok_or_else(|| format!("{}: no {k} property", msi.display()));
    let version = get("ProductVersion")?;
    let runtime = VcRuntime { dlls: &RUNTIME_DLLS, min: get(RUNTIME_MIN_PROPERTY)?.to_string() };
    let manifest = Manifest {
        package: PACKAGE,
        name: "Warlock",
        generator: "warlock-msi",
        // warlock.exe, and warlockctl.exe.
        license: "GPL-2.0-only AND AGPL-3.0-only",
        short_description: DESCRIPTION,
        // The privacy policy as of this version's tag (the release workflow
        // tags v<version>).
        privacy_url: Some(format!("{REPOSITORY}/blob/v{version}/PRIVACY.md")),
        dependencies_note: Some("The Visual C++ runtime warlock.exe links to, which a fresh Windows lacks."),
        dependencies: &[runtime.dependency()],
        // Warlock's version is its ProductVersion.
        package_version: None,
    };
    let manifests = winget::manifests(&manifest, msi, &p, url)?;
    let dir = out.unwrap_or_else(|| root.join("target").join("msi").join("winget").join(version));
    std::fs::create_dir_all(&dir)?;
    for (name, text) in manifests {
        std::fs::write(dir.join(&name), text)?;
        println!("{}", dir.join(name).display());
    }
    Ok(())
}

const USAGE: &str = "usage: warlock-msi [--out PATH] [--no-build]\n       \
                     warlock-msi winget MSI --installer-url URL [--out DIR]\n       \
                     warlock-msi notices";

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    // Without the `\\?\` prefix canonicalize adds, which makecab can't read.
    let root = PathBuf::from(root.to_string_lossy().trim_start_matches(r"\\?\"));
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|a| a == "notices") {
        return notices::write(&root);
    }
    if args.peek().is_some_and(|a| a == "winget") {
        args.next();
        let (mut msi, mut url, mut out) = (None, None, None);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--installer-url" => url = Some(args.next().ok_or("--installer-url needs a URL")?),
                "--out" => out = Some(PathBuf::from(args.next().ok_or("--out needs a folder")?)),
                _ if msi.is_none() && !a.starts_with("--") => msi = Some(PathBuf::from(a)),
                _ => return Err(format!("unknown argument {a}\n{USAGE}").into()),
            }
        }
        let msi = msi.ok_or(USAGE)?;
        let url = url.ok_or("--installer-url is needed: where winget will download the package from")?;
        return winget(&root, &msi, &url, out);
    }
    let (mut out, mut no_build) = (None, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(args.next().ok_or("--out needs a path")?)),
            "--no-build" => no_build = true,
            _ => return Err(format!("unknown argument {a}\n{USAGE}").into()),
        }
    }
    let version = warlock_version()?;
    if !no_build {
        let status = Command::new("cargo")
            // warlockctl's package also builds warlock-extcap.
            .args(["build", "--release", "-p", "warlock", "-p", "warlockctl", "-p", "warlock-msi-ca"])
            .current_dir(&root)
            .status()?;
        if !status.success() {
            return Err("cargo build failed".into());
        }
    }
    let out = out.unwrap_or_else(|| root.join("target").join("msi").join(format!("Warlock-{version}-x64.msi")));
    std::fs::create_dir_all(out.parent().ok_or("no folder for --out")?)?;
    build(&root, &out, &version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The groups and properties here are written out again in the custom
    /// action DLL and in `warlock-api`, which this builder doesn't link: they
    /// must say the same.
    #[test]
    fn the_groups_agree_with_the_dll_and_the_server() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let dll = std::fs::read_to_string(root.join("warlock-msi-ca/src/lib.rs")).unwrap();
        let server = std::fs::read_to_string(root.join("warlock-api/src/pipe.rs")).unwrap();
        for g in &GROUPS {
            let entry = format!("Group {{ name: \"{}\", member: \"{}\", join: \"{}\" }}", g.name, g.member, g.join);
            assert!(dll.contains(&entry), "warlock-msi-ca has no {entry}");
            assert!(server.contains(&format!("= \"{}\";", g.name)), "warlock-api has no group {}", g.name);
        }
        for property in [JOINED_PROPERTY, JOINED_GROUPS_PROPERTY] {
            assert!(dll.contains(&format!("= \"{property}\";")), "warlock-msi-ca doesn't set {property}");
        }
    }

    /// `FindJoined` runs in the UI sequence once the install is done
    /// (after ExecuteAction), so the Done page knows before Finish whether
    /// to go on to the sign-out prompt.
    #[test]
    fn joining_is_known_before_the_done_page() {
        let all = tables("0.0.0", "{00000000-0000-0000-0000-000000000000}", "14.50", ("{\\rtf1 x}", "{\\rtf1 y}"), &[]);
        let ui = &all.iter().find(|t| t.name == "InstallUISequence").unwrap().rows;
        let at = |action: &str| -> i32 {
            let row = ui.iter().find(|r| r[0].as_deref() == Some(action)).unwrap_or_else(|| panic!("no {action}"));
            row[2].as_deref().unwrap().parse().unwrap()
        };
        assert!(at("WarlockFindJoined") > at("ExecuteAction"));
        assert_eq!(at("ExitDlg"), -1, "the Done page comes at the end, after it");
    }
}
