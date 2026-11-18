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
//! Builds `warlock` and `warlockctl` in release (unless `--no-build`) and
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
//!   `warlock-users` group, the service's restart-on-failure actions; undone
//!   if a fresh install rolls back), and on an uninstall that isn't an
//!   upgrade, `warlock teardown` (the adapter back to Windows' own driver,
//!   the group removed).
//!
//! A newer version replaces an older one (and a rebuild of the same version
//! replaces itself); an older one won't install over a newer one.
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
//! Tables are written as Windows Installer's own `.idt` text and imported
//! (`MsiDatabaseImportW`). Their column definitions are copied from MSIs
//! Windows itself installed, exported from `C:\Windows\Installer` on
//! 2026-11-18. Sequence numbers are Windows Installer's suggested ones.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIDBOPEN_CREATE, MSIDBOPEN_READONLY, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiDatabaseCommit,
    MsiDatabaseImportW, MsiDatabaseOpenViewW, MsiGetSummaryInformationW, MsiOpenDatabaseW, MsiRecordGetStringW,
    MsiRecordSetStreamW, MsiRecordSetStringW, MsiSummaryInfoPersist, MsiSummaryInfoSetPropertyW, MsiViewClose,
    MsiViewExecute, MsiViewFetch,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::core::GUID;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

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

/// As the winget package's publisher.
const MANUFACTURER: &str = "Regulad";
/// The winget package.
const PACKAGE: &str = "Regulad.Warlock";
const DESCRIPTION: &str = "Apple Wireless Direct Link (AWDL) for Windows, on a USB Wi-Fi adapter";
/// The service's name, as `warlock install` and `sc` know it.
const SERVICE: &str = "Warlock";
const CABINET: &str = "warlock.cab";

/// The Visual C++ runtime DLLs `warlock.exe` imports (`warlockctl.exe` only
/// the first), each with the property the package's search for it sets and
/// its `short|long` name. The short name only counts where long names don't.
const RUNTIME_DLLS: [(&str, &str); 3] = [
    ("VCRUNTIME140", "VCRT140.DLL|vcruntime140.dll"),
    ("VCRUNTIME140_1", "VCRT1401.DLL|vcruntime140_1.dll"),
    ("MSVCP140", "msvcp140.dll"),
];
/// The runtime's winget package: a dependency of ours.
const RUNTIME_PACKAGE: &str = "Microsoft.VCRedist.2015+.x64";
/// The property recording the least runtime version, for `winget`.
const RUNTIME_MIN_PROPERTY: &str = "WarlockVcRuntimeMin";

/// `msidbComponentAttributes64bit`.
const COMPONENT_64BIT: i32 = 256;
/// `msidbFileAttributesVital`.
const FILE_VITAL: i32 = 512;
/// Custom action type 18 (run an EXE installed with the product), deferred
/// (1024), not impersonating, so as SYSTEM (2048).
const CA_EXE_AS_SYSTEM: i32 = 18 + 1024 + 2048;
/// `msidbCustomActionTypeContinue`: the exit code doesn't fail the install.
const CA_CONTINUE: i32 = 64;
/// `msidbCustomActionTypeRollback`: runs only if the install rolls back.
const CA_ROLLBACK: i32 = 256;
/// `SERVICE_WIN32_OWN_PROCESS`.
const OWN_PROCESS: i32 = 0x10;
/// `SERVICE_AUTO_START`.
const AUTO_START: i32 = 2;
/// `SERVICE_ERROR_NORMAL`.
const ERROR_NORMAL: i32 = 1;
/// ServiceControl events: start on install (1), stop on install (2) and
/// uninstall (32), delete on uninstall (128).
const CONTROL_EVENTS: i32 = 1 | 2 | 32 | 128;
/// MsiServiceConfig events: install (1) and reinstall (4).
const CONFIG_EVENTS: i32 = 1 | 4;
/// `ChangeServiceConfig2` info level `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
const DELAYED_AUTO_START: i32 = 3;
/// … `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
const FAILURE_ACTIONS_FLAG: i32 = 4;
/// … `SERVICE_CONFIG_SERVICE_SID_INFO`.
const SERVICE_SID: i32 = 5;
/// … `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`.
const REQUIRED_PRIVILEGES: i32 = 6;
/// `msidbUpgradeAttributesMigrateFeatures`.
const MIGRATE_FEATURES: i32 = 1;
/// `msidbUpgradeAttributesOnlyDetect`.
const ONLY_DETECT: i32 = 2;
/// `msidbUpgradeAttributesVersionMaxInclusive`.
const MAX_INCLUSIVE: i32 = 0x200;

/// A cell: `None` is null.
type Cell = Option<String>;

fn s(v: &str) -> Cell {
    Some(v.to_string())
}

fn n(v: i32) -> Cell {
    Some(v.to_string())
}

/// One table: its columns as (name, `.idt` type), its primary key, its rows.
struct Table {
    name: &'static str,
    columns: &'static [(&'static str, &'static str)],
    keys: &'static [&'static str],
    rows: Vec<Vec<Cell>>,
}

impl Table {
    fn new(
        name: &'static str,
        columns: &'static [(&'static str, &'static str)],
        keys: &'static [&'static str],
    ) -> Self {
        Self { name, columns, keys, rows: Vec::new() }
    }

    fn row(&mut self, cells: Vec<Cell>) -> &mut Self {
        assert_eq!(cells.len(), self.columns.len(), "a {} row", self.name);
        self.rows.push(cells);
        self
    }

    /// The table as `.idt` text: column names, types, the table and its
    /// keys, then a line per row, tab-separated, a null being empty.
    fn idt(&self) -> Result<String> {
        let mut out = String::new();
        let line = |cells: Vec<&str>| cells.join("\t") + "\r\n";
        out += &line(self.columns.iter().map(|c| c.0).collect());
        out += &line(self.columns.iter().map(|c| c.1).collect());
        out += &line(std::iter::once(self.name).chain(self.keys.iter().copied()).collect());
        for row in &self.rows {
            for cell in row.iter().flatten() {
                if !cell.is_ascii() || cell.contains(['\t', '\r', '\n']) {
                    return Err(format!("{}: {cell:?} needs escaping this builder doesn't do", self.name).into());
                }
            }
            out += &line(row.iter().map(|c| c.as_deref().unwrap_or("")).collect());
        }
        Ok(out)
    }
}

const SEQUENCE: &[(&str, &str)] = &[("Action", "s72"), ("Condition", "S255"), ("Sequence", "I2")];

fn sequence(name: &'static str, actions: &[(&str, Option<&str>, i32)]) -> Table {
    let mut t = Table::new(name, SEQUENCE, &["Action"]);
    for (action, condition, number) in actions {
        t.row(vec![s(action), condition.map(str::to_string), n(*number)]);
    }
    t
}

/// A file going into the package.
struct Payload {
    /// The File table key, and its name in the cabinet.
    key: &'static str,
    component: &'static str,
    /// `short|long` when the long name isn't a valid 8.3 one.
    name: &'static str,
    source: PathBuf,
    vital: bool,
}

/// Every table, filled in. `runtime_min` is the least Visual C++ runtime
/// version (`14.50`) the binaries need.
fn tables(version: &str, product_code: &str, runtime_min: &str, files: &[(Payload, u64)]) -> Vec<Table> {
    let mut all = Vec::new();

    let mut property = Table::new("Property", &[("Property", "s72"), ("Value", "l0")], &["Property"]);
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
        // Found by FindRelatedProducts in the UI, used by the elevated part.
        ("SecureCustomProperties", "OLDERFOUND;NEWERFOUND"),
    ] {
        property.row(vec![s(k), s(v)]);
    }
    all.push(property);

    let mut directory = Table::new(
        "Directory",
        &[("Directory", "s72"), ("Directory_Parent", "S72"), ("DefaultDir", "l255")],
        &["Directory"],
    );
    directory
        .row(vec![s("TARGETDIR"), None, s("SourceDir")])
        .row(vec![s("ProgramFiles64Folder"), s("TARGETDIR"), s(".")])
        .row(vec![s("INSTALLDIR"), s("ProgramFiles64Folder"), s("Warlock")]);
    all.push(directory);

    let mut component = Table::new(
        "Component",
        &[
            ("Component", "s72"),
            ("ComponentId", "S38"),
            ("Directory_", "s72"),
            ("Attributes", "i2"),
            ("Condition", "S255"),
            ("KeyPath", "S72"),
        ],
        &["Component"],
    );
    for (name, guid, key) in [
        ("Warlock", COMPONENT_WARLOCK, "warlock.exe"),
        ("Warlockctl", COMPONENT_WARLOCKCTL, "warlockctl.exe"),
        ("Licenses", COMPONENT_LICENSES, "LICENSE.md"),
    ] {
        component.row(vec![s(name), s(guid), s("INSTALLDIR"), n(COMPONENT_64BIT), None, s(key)]);
    }
    all.push(component);

    let mut feature = Table::new(
        "Feature",
        &[
            ("Feature", "s38"),
            ("Feature_Parent", "S38"),
            ("Title", "L64"),
            ("Description", "L255"),
            ("Display", "I2"),
            ("Level", "i2"),
            ("Directory_", "S72"),
            ("Attributes", "i2"),
        ],
        &["Feature"],
    );
    feature.row(vec![s("Warlock"), None, s("Warlock"), s("Warlock and warlockctl"), n(1), n(1), s("INSTALLDIR"), n(0)]);
    all.push(feature);

    let mut feature_components =
        Table::new("FeatureComponents", &[("Feature_", "s38"), ("Component_", "s72")], &["Feature_", "Component_"]);
    for c in ["Warlock", "Warlockctl", "Licenses"] {
        feature_components.row(vec![s("Warlock"), s(c)]);
    }
    all.push(feature_components);

    let mut file = Table::new(
        "File",
        &[
            ("File", "s72"),
            ("Component_", "s72"),
            ("FileName", "l255"),
            ("FileSize", "i4"),
            ("Version", "S72"),
            ("Language", "S20"),
            ("Attributes", "I2"),
            ("Sequence", "i4"),
        ],
        &["File"],
    );
    for (i, (p, size)) in files.iter().enumerate() {
        let size = i32::try_from(*size).expect("files under 2 GiB");
        let attributes = p.vital.then_some(FILE_VITAL).map(|a| a.to_string());
        file.row(vec![s(p.key), s(p.component), s(p.name), n(size), None, None, attributes, n(i as i32 + 1)]);
    }
    all.push(file);

    let mut media = Table::new(
        "Media",
        &[
            ("DiskId", "i2"),
            ("LastSequence", "i4"),
            ("DiskPrompt", "L64"),
            ("Cabinet", "S255"),
            ("VolumeLabel", "S32"),
            ("Source", "S72"),
        ],
        &["DiskId"],
    );
    // `#` means the cabinet is a stream inside the package.
    media.row(vec![n(1), n(files.len() as i32), None, s(&format!("#{CABINET}")), None, None]);
    all.push(media);

    let mut upgrade = Table::new(
        "Upgrade",
        &[
            ("UpgradeCode", "s38"),
            ("VersionMin", "S20"),
            ("VersionMax", "S20"),
            ("Language", "S255"),
            ("Attributes", "i4"),
            ("Remove", "S255"),
            ("ActionProperty", "s72"),
        ],
        &["UpgradeCode", "VersionMin", "VersionMax", "Language", "Attributes"],
    );
    upgrade
        // Up to and including this version: replaced.
        .row(vec![s(UPGRADE_CODE), None, s(version), None, n(MIGRATE_FEATURES | MAX_INCLUSIVE), None, s("OLDERFOUND")])
        // Newer: only noticed, to refuse the install.
        .row(vec![s(UPGRADE_CODE), s(version), None, None, n(ONLY_DETECT), None, s("NEWERFOUND")]);
    all.push(upgrade);

    // The Visual C++ runtime, found by its DLLs in System32: each search sets
    // its property when the file is there at `runtime_min` or later.
    let mut app_search =
        Table::new("AppSearch", &[("Property", "s72"), ("Signature_", "s72")], &["Property", "Signature_"]);
    let mut signature = Table::new(
        "Signature",
        &[
            ("Signature", "s72"),
            ("FileName", "s255"),
            ("MinVersion", "S20"),
            ("MaxVersion", "S20"),
            ("MinSize", "I4"),
            ("MaxSize", "I4"),
            ("MinDate", "I4"),
            ("MaxDate", "I4"),
            ("Languages", "S255"),
        ],
        &["Signature"],
    );
    let mut dr_locator = Table::new(
        "DrLocator",
        &[("Signature_", "s72"), ("Parent", "S72"), ("Path", "S255"), ("Depth", "I2")],
        &["Signature_", "Parent", "Path"],
    );
    // Any build of that minor version or later. (The version is compared
    // with the language only when equal, which a real build number isn't.)
    let floor = format!("{runtime_min}.0.0");
    for (property, file_name) in RUNTIME_DLLS {
        let sig = format!("Sig{property}");
        app_search.row(vec![s(property), s(&sig)]);
        signature.row(vec![s(&sig), s(file_name), s(&floor), None, None, None, None, None, None]);
        dr_locator.row(vec![s(&sig), None, s("[System64Folder]"), n(0)]);
    }
    all.push(app_search);
    all.push(signature);
    all.push(dr_locator);

    let runtime_found = RUNTIME_DLLS.map(|(p, _)| p).join(" AND ");
    let mut launch = Table::new("LaunchCondition", &[("Condition", "s255"), ("Description", "l255")], &["Condition"]);
    launch
        .row(vec![s("VersionNT64"), s("Warlock needs 64-bit Windows.")])
        .row(vec![s("NOT NEWERFOUND"), s("A newer version of Warlock is already installed.")])
        // Not needed to uninstall.
        .row(vec![
            s(&format!("Installed OR ({runtime_found})")),
            s(&format!(
                "Warlock needs the Microsoft Visual C++ v14 Redistributable (x64), version {runtime_min} or later: \
                 winget install {RUNTIME_PACKAGE}"
            )),
        ]);
    all.push(launch);

    let mut service_install = Table::new(
        "ServiceInstall",
        &[
            ("ServiceInstall", "s72"),
            ("Name", "s255"),
            ("DisplayName", "L255"),
            ("ServiceType", "i4"),
            ("StartType", "i4"),
            ("ErrorControl", "i4"),
            ("LoadOrderGroup", "S255"),
            ("Dependencies", "S255"),
            ("StartName", "S255"),
            ("Password", "S255"),
            ("Arguments", "S255"),
            ("Component_", "s72"),
            ("Description", "L255"),
        ],
        &["ServiceInstall"],
    );
    // No StartName: LocalSystem, the account that may rebind drivers and
    // create adapters. Its privileges are trimmed in MsiServiceConfig.
    service_install.row(vec![
        s("WarlockService"),
        s(SERVICE),
        s("Warlock"),
        n(OWN_PROCESS),
        n(AUTO_START),
        n(ERROR_NORMAL),
        None,
        None,
        None,
        None,
        s("service"),
        s("Warlock"),
        s(DESCRIPTION),
    ]);
    all.push(service_install);

    let mut service_control = Table::new(
        "ServiceControl",
        &[
            ("ServiceControl", "s72"),
            ("Name", "l255"),
            ("Event", "i2"),
            ("Arguments", "L255"),
            ("Wait", "I2"),
            ("Component_", "s72"),
        ],
        &["ServiceControl"],
    );
    service_control.row(vec![s("WarlockServiceControl"), s(SERVICE), n(CONTROL_EVENTS), None, n(1), s("Warlock")]);
    all.push(service_control);

    let mut service_config = Table::new(
        "MsiServiceConfig",
        &[
            ("MsiServiceConfig", "s72"),
            ("Name", "l255"),
            ("Event", "i2"),
            ("ConfigType", "i4"),
            ("Argument", "S0"),
            ("Component_", "s72"),
        ],
        &["MsiServiceConfig"],
    );
    service_config
        // Started after the rest of boot.
        .row(vec![s("WarlockDelayedStart"), s(SERVICE), n(CONFIG_EVENTS), n(DELAYED_AUTO_START), s("1"), s("Warlock")])
        // SERVICE_SID_TYPE_UNRESTRICTED: NT SERVICE\Warlock, for ACLs.
        .row(vec![s("WarlockServiceSid"), s(SERVICE), n(CONFIG_EVENTS), n(SERVICE_SID), s("1"), s("Warlock")])
        // Restarted when it stops with an error too, not only on a crash.
        .row(vec![s("WarlockFailureFlag"), s(SERVICE), n(CONFIG_EVENTS), n(FAILURE_ACTIONS_FLAG), s("1"), s("Warlock")])
        // The service manager removes every other privilege from its token,
        // 27 of LocalSystem's 28. Rebinding the stick to WinUSB, fetching
        // Wintun, installing its driver on a fresh Windows and creating the
        // adapter all worked without them (PLAN.md, W5, tried 2026-11-18).
        // More entries would be separated by `[~]`.
        .row(vec![
            s("WarlockPrivileges"),
            s(SERVICE),
            n(CONFIG_EVENTS),
            n(REQUIRED_PRIVILEGES),
            s("SeChangeNotifyPrivilege"),
            s("Warlock"),
        ]);
    all.push(service_config);

    // No MsiServiceConfigFailureActions: Windows Installer fails to set
    // restart actions ("access denied", error 1939, seen 2026-11-18), as they
    // need the service opened with start access too. `warlock setup` sets them.

    let mut custom = Table::new(
        "CustomAction",
        &[("Action", "s72"), ("Type", "i2"), ("Source", "S72"), ("Target", "S255"), ("ExtendedType", "I4")],
        &["Action"],
    );
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
        .row(vec![s("WarlockTeardown"), n(CA_EXE_AS_SYSTEM | CA_CONTINUE), s("warlock.exe"), s("teardown"), None]);
    all.push(custom);

    let mut environment = Table::new(
        "Environment",
        &[("Environment", "s72"), ("Name", "l255"), ("Value", "L255"), ("Component_", "s72")],
        &["Environment"],
    );
    // `=`: set on install; `-`: removed on uninstall; `*`: the system's.
    // `[~];` appends to what's there.
    environment.row(vec![s("WarlockPath"), s("=-*PATH"), s("[~];[INSTALLDIR]"), s("Warlockctl")]);
    all.push(environment);

    let install = Some("NOT REMOVE~=\"ALL\"");
    // Only a fresh install takes its group back: an upgrade's group was
    // there before, with its members.
    let fresh_install = Some("NOT REMOVE~=\"ALL\" AND NOT OLDERFOUND");
    let real_uninstall = Some("REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE");
    all.push(sequence(
        "InstallUISequence",
        &[
            ("FindRelatedProducts", None, 25),
            ("AppSearch", None, 50),
            ("LaunchConditions", None, 100),
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("MigrateFeatureStates", None, 1200),
            ("ExecuteAction", None, 1300),
        ],
    ));
    all.push(sequence(
        "InstallExecuteSequence",
        &[
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
        ],
    ));
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

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    wide(&p.to_string_lossy())
}

/// A new GUID, braced and upper-case as Windows Installer writes them.
fn new_guid() -> Result<String> {
    let mut g = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
    // SAFETY: an out-parameter.
    if unsafe { CoCreateGuid(&mut g) } != 0 {
        return Err("CoCreateGuid failed".into());
    }
    let d = g.data4;
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    ))
}

/// A Windows Installer handle, closed on drop.
struct Handle(MSIHANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle Windows Installer gave us.
        unsafe { MsiCloseHandle(self.0) };
    }
}

fn check(what: &str, rc: u32) -> Result<()> {
    if rc == 0 { Ok(()) } else { Err(format!("{what}: Windows Installer error {rc}").into()) }
}

/// Warlock's version: the workspace's, which this builder shares with
/// `warlock` and every other crate.
fn warlock_version() -> Result<String> {
    let version = env!("CARGO_PKG_VERSION");
    // ProductVersion is major.minor.build, numbers only, at most
    // 255.255.65535: no pre-release or build suffixes.
    let parts: Vec<&str> = version.split('.').collect();
    let fits = parts.len() == 3
        && parts[0].parse::<u8>().is_ok()
        && parts[1].parse::<u8>().is_ok()
        && parts[2].parse::<u16>().is_ok();
    if !fits {
        return Err(format!("{version} isn't a version Windows Installer takes (major.minor.build)").into());
    }
    Ok(version.to_string())
}

/// The least Visual C++ runtime version the binaries need, as `14.50`: a
/// runtime at least as new as the newest toolset that linked any of them
/// ("C++ binary compatibility between Visual Studio versions", Microsoft
/// Learn). The toolset is read from each one's PE header.
fn runtime_min(exes: &[&Path]) -> Result<String> {
    let mut newest = None;
    for exe in exes {
        let (major, minor) = linker_version(exe)?;
        if major != 14 {
            return Err(format!("{}: linker {major}.{minor} isn't an MSVC v14 toolset", exe.display()).into());
        }
        newest = newest.max(Some(minor));
    }
    Ok(format!("14.{}", newest.ok_or("no binaries to package")?))
}

/// A PE file's linker version (14.50 for Visual Studio 18's).
fn linker_version(path: &Path) -> Result<(u8, u8)> {
    let b = std::fs::read(path)?;
    let bad = || format!("{} isn't a PE file", path.display());
    let pe = b.get(0x3c..0x40).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize).ok_or_else(bad)?;
    if b.get(pe..pe + 4) != Some(&b"PE\0\0"[..]) {
        return Err(bad().into());
    }
    // The optional header follows the 20-byte file header: its magic, then
    // the linker's major and minor version.
    let optional = pe + 4 + 20;
    match b.get(optional + 2..optional + 4) {
        Some(&[major, minor]) => Ok((major, minor)),
        _ => Err(bad().into()),
    }
}

/// Packs the files into one cabinet with `makecab`, each named by its File
/// key, in File table order.
fn cabinet(work: &Path, files: &[(Payload, u64)]) -> Result<PathBuf> {
    let mut ddf = String::new();
    writeln!(ddf, ".OPTION EXPLICIT")?;
    for (k, v) in [
        ("CabinetNameTemplate", CABINET),
        ("DiskDirectoryTemplate", &work.display().to_string()),
        ("InfFileName", &work.join("cab.inf").display().to_string()),
        ("RptFileName", &work.join("cab.rpt").display().to_string()),
        ("Cabinet", "on"),
        ("Compress", "on"),
        ("CompressionType", "LZX"),
        ("CompressionMemory", "21"),
        ("MaxDiskSize", "0"),
        ("UniqueFiles", "on"),
    ] {
        writeln!(ddf, ".Set {k}=\"{v}\"")?;
    }
    for (p, _) in files {
        writeln!(ddf, "\"{}\" \"{}\"", p.source.display(), p.key)?;
    }
    let ddf_path = work.join("cab.ddf");
    std::fs::write(&ddf_path, ddf)?;
    let out = Command::new("makecab.exe").arg("/F").arg(&ddf_path).current_dir(work).output()?;
    if !out.status.success() {
        return Err(format!("makecab failed: {}", String::from_utf8_lossy(&out.stdout)).into());
    }
    Ok(work.join(CABINET))
}

fn build(root: &Path, out: &Path, version: &str) -> Result<()> {
    let release = root.join("target").join("release");
    let payload = [
        Payload {
            key: "warlock.exe",
            component: "Warlock",
            name: "warlock.exe",
            source: release.join("warlock.exe"),
            vital: true,
        },
        Payload {
            key: "warlockctl.exe",
            component: "Warlockctl",
            name: "WLCTL.EXE|warlockctl.exe",
            source: release.join("warlockctl.exe"),
            vital: true,
        },
        Payload {
            key: "LICENSE.md",
            component: "Licenses",
            name: "LICENSE.MD|LICENSE.md",
            source: root.join("LICENSE.md"),
            vital: false,
        },
        Payload {
            key: "LICENSE_AGPL.md",
            component: "Licenses",
            name: "AGPL3.MD|LICENSE-AGPL-3.0.md",
            source: root.join("LICENSE-AGPL-3.0.md"),
            vital: false,
        },
        Payload {
            key: "LICENSE_WINTUN.md",
            component: "Licenses",
            name: "WINTUNEX.MD|LICENSE-WINTUN-EXCEPTION.md",
            source: root.join("LICENSE-WINTUN-EXCEPTION.md"),
            vital: false,
        },
    ];
    let mut files = Vec::new();
    for p in payload {
        let size = std::fs::metadata(&p.source).map_err(|e| format!("{}: {e}", p.source.display()))?.len();
        files.push((p, size));
    }

    let exes: Vec<&Path> =
        files.iter().filter(|(p, _)| p.key.ends_with(".exe")).map(|(p, _)| p.source.as_path()).collect();
    let runtime_min = runtime_min(&exes)?;

    let work = out.with_extension("work");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(work.join("idt"))?;
    let cab = cabinet(&work, &files)?;

    let product_code = new_guid()?;
    let package_code = new_guid()?;
    let _ = std::fs::remove_file(out);
    let mut db: MSIHANDLE = 0;
    // SAFETY: valid paths and out-parameter.
    check("creating the database", unsafe { MsiOpenDatabaseW(wide_path(out).as_ptr(), MSIDBOPEN_CREATE, &mut db) })?;
    let db = Handle(db);
    for t in tables(version, &product_code, &runtime_min, &files) {
        let file = format!("{}.idt", t.name);
        std::fs::write(work.join("idt").join(&file), t.idt()?)?;
        // SAFETY: valid handle and paths.
        let rc = unsafe { MsiDatabaseImportW(db.0, wide_path(&work.join("idt")).as_ptr(), wide(&file).as_ptr()) };
        check(&format!("importing {}", t.name), rc)?;
    }

    // The cabinet goes in as a stream of the package.
    let mut view: MSIHANDLE = 0;
    let query = wide("INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)");
    // SAFETY: valid handles, strings and paths throughout.
    unsafe {
        check("opening _Streams", MsiDatabaseOpenViewW(db.0, query.as_ptr(), &mut view))?;
        let view = Handle(view);
        let record = Handle(MsiCreateRecord(2));
        check("naming the cabinet", MsiRecordSetStringW(record.0, 1, wide(CABINET).as_ptr()))?;
        check("reading the cabinet", MsiRecordSetStreamW(record.0, 2, wide_path(&cab).as_ptr()))?;
        check("adding the cabinet", MsiViewExecute(view.0, record.0))?;
        check("closing _Streams", MsiViewClose(view.0))?;
    }

    // Summary information: what kind of package this is.
    let mut summary: MSIHANDLE = 0;
    // SAFETY: valid handle; strings outlive each call.
    unsafe {
        check("summary information", MsiGetSummaryInformationW(db.0, std::ptr::null(), 20, &mut summary))?;
        let summary = Handle(summary);
        const VT_I4: u32 = 3;
        const VT_LPSTR: u32 = 30;
        for (pid, text) in [
            (2, "Installation Database"),
            (3, "Warlock"),
            (4, MANUFACTURER),
            (5, "Installer, AWDL"),
            (6, "This installer database contains the logic and data required to install Warlock."),
            // x64, English.
            (7, "x64;1033"),
            (9, package_code.as_str()),
            (18, "warlock-msi (Windows Installer API)"),
        ] {
            let text = wide(text);
            let rc = MsiSummaryInfoSetPropertyW(summary.0, pid, VT_LPSTR, 0, std::ptr::null_mut(), text.as_ptr());
            check(&format!("summary property {pid}"), rc)?;
        }
        // Windows Installer 5.0; long names, compressed; read-only recommended.
        for (pid, value) in [(14, 500), (15, 2), (19, 2)] {
            let rc = MsiSummaryInfoSetPropertyW(summary.0, pid, VT_I4, value, std::ptr::null_mut(), std::ptr::null());
            check(&format!("summary property {pid}"), rc)?;
        }
        check("saving the summary information", MsiSummaryInfoPersist(summary.0))?;
    }
    // SAFETY: a valid handle.
    check("committing the database", unsafe { MsiDatabaseCommit(db.0) })?;
    drop(db);
    std::fs::remove_dir_all(&work)?;
    println!(
        "{} (Warlock {version}, product code {product_code}, Visual C++ runtime {runtime_min} or later)",
        out.display()
    );
    Ok(())
}

/// A record's string field.
fn record_string(record: MSIHANDLE, field: u32) -> Result<String> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    let mut len = 0u32;
    let mut buf = vec![0u16; 1];
    // SAFETY: a buffer of the length passed; first for the length needed
    // (without the NUL), then for the string.
    unsafe {
        let rc = MsiRecordGetStringW(record, field, buf.as_mut_ptr(), &mut len);
        if rc != 0 && rc != ERROR_MORE_DATA {
            return Err(format!("reading a field: Windows Installer error {rc}").into());
        }
        len += 1;
        buf.resize(len as usize, 0);
        check("reading a field", MsiRecordGetStringW(record, field, buf.as_mut_ptr(), &mut len))?;
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// A package's Property table.
fn package_properties(msi: &Path) -> Result<BTreeMap<String, String>> {
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    let mut db: MSIHANDLE = 0;
    // SAFETY: a valid path and out-parameter.
    let rc = unsafe { MsiOpenDatabaseW(wide_path(msi).as_ptr(), MSIDBOPEN_READONLY, &mut db) };
    check(&format!("opening {}", msi.display()), rc)?;
    let db = Handle(db);
    let query = wide("SELECT `Property`, `Value` FROM `Property`");
    let mut properties = BTreeMap::new();
    let mut view: MSIHANDLE = 0;
    // SAFETY: valid handles and query; records are closed as they go.
    unsafe {
        check("reading Property", MsiDatabaseOpenViewW(db.0, query.as_ptr(), &mut view))?;
        let view = Handle(view);
        check("reading Property", MsiViewExecute(view.0, 0))?;
        loop {
            let mut record: MSIHANDLE = 0;
            match MsiViewFetch(view.0, &mut record) {
                0 => {}
                ERROR_NO_MORE_ITEMS => break,
                rc => return Err(format!("reading Property: Windows Installer error {rc}").into()),
            }
            let record = Handle(record);
            properties.insert(record_string(record.0, 1)?, record_string(record.0, 2)?);
        }
    }
    Ok(properties)
}

/// winget's manifest schema the manifests are written to.
const MANIFEST_VERSION: &str = "1.10.0";

/// Writes winget's three manifests (version, installer, default locale) for
/// the package at `msi`, to be downloaded from `url`, into `out` (by default
/// `target/msi/winget/<version>`).
fn winget(root: &Path, msi: &Path, url: &str, out: Option<PathBuf>) -> Result<()> {
    if !url.starts_with("https://") {
        return Err(format!("{url}: winget downloads installers over https").into());
    }
    let p = package_properties(msi)?;
    let get = |k: &str| p.get(k).map(String::as_str).ok_or_else(|| format!("{}: no {k} property", msi.display()));
    let version = get("ProductVersion")?;
    let product_code = get("ProductCode")?;
    let upgrade_code = get("UpgradeCode")?;
    let publisher = get("Manufacturer")?;
    let runtime_min = get(RUNTIME_MIN_PROPERTY)?;
    let sha256: String = Sha256::digest(std::fs::read(msi)?).iter().map(|b| format!("{b:02X}")).collect();
    let file = msi.file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned());
    // Single-quoted YAML scalars: only `'` needs escaping, as `''`.
    let q = |v: &str| format!("'{}'", v.replace('\'', "''"));
    let header = |kind: &str| {
        format!(
            "# Written by warlock-msi for {file}.\n\
             # yaml-language-server: $schema=https://aka.ms/winget-manifest.{kind}.{MANIFEST_VERSION}.schema.json\n\n\
             PackageIdentifier: {PACKAGE}\nPackageVersion: {}\n",
            q(version)
        )
    };
    let footer = |kind: &str| format!("ManifestType: {kind}\nManifestVersion: {MANIFEST_VERSION}\n");
    let manifests = [
        (format!("{PACKAGE}.yaml"), format!("{}DefaultLocale: en-US\n{}", header("version"), footer("version"))),
        (
            format!("{PACKAGE}.installer.yaml"),
            format!(
                "{}InstallerType: msi\nScope: machine\nInstallModes:\n- interactive\n- silent\n- silentWithProgress\n\
                 UpgradeBehavior: install\n\
                 # The Visual C++ runtime warlock.exe links to, which a fresh Windows lacks.\n\
                 Dependencies:\n  PackageDependencies:\n  - PackageIdentifier: {RUNTIME_PACKAGE}\n    MinimumVersion: {}\n\
                 ProductCode: {}\nAppsAndFeaturesEntries:\n- Publisher: {}\n  ProductCode: {}\n  UpgradeCode: {}\n\
                 Installers:\n- Architecture: x64\n  InstallerUrl: {}\n  InstallerSha256: {sha256}\n{}",
                header("installer"),
                q(&format!("{runtime_min}.0.0")),
                q(product_code),
                q(publisher),
                q(product_code),
                q(upgrade_code),
                q(url),
                footer("installer")
            ),
        ),
        (
            format!("{PACKAGE}.locale.en-US.yaml"),
            format!(
                "{}PackageLocale: en-US\nPublisher: {}\nPackageName: Warlock\n\
                 License: {}\nShortDescription: {}\n{}",
                header("defaultLocale"),
                q(publisher),
                // warlock.exe, and warlockctl.exe.
                q("GPL-2.0-only AND AGPL-3.0-only"),
                q(DESCRIPTION),
                footer("defaultLocale")
            ),
        ),
    ];
    let dir = out.unwrap_or_else(|| root.join("target").join("msi").join("winget").join(version));
    std::fs::create_dir_all(&dir)?;
    for (name, text) in manifests {
        std::fs::write(dir.join(&name), text)?;
        println!("{}", dir.join(name).display());
    }
    Ok(())
}

const USAGE: &str = "usage: warlock-msi [--out PATH] [--no-build]\n       \
                     warlock-msi winget MSI --installer-url URL [--out DIR]";

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    // Without the `\\?\` prefix canonicalize adds, which makecab can't read.
    let root = PathBuf::from(root.to_string_lossy().trim_start_matches(r"\\?\"));
    let mut args = std::env::args().skip(1).peekable();
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
            .args(["build", "--release", "-p", "warlock", "-p", "warlockctl"])
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
