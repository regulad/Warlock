// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! warlock-msi-kit: what it takes to write a Windows Installer package with
//! Windows' own tools only: the Windows Installer API (`msi.dll`) writes the
//! database and `makecab` packs the files. No WiX, no installer toolchain
//! (Parker, 2026-11-18). Warlock's builder, `warlock-msi`, uses it, and so
//! does Koala's (Parker, 2026-11-21).
//!
//! A builder fills in [`Table`]s, most of them begun by [`schema`]; its files
//! ([`Payload`], [`file_table`], [`media_table`]); its searches ([`Search`]),
//! the Visual C++ runtime's among them ([`VcRuntime`]); and its pages
//! ([`ui`]), whose licence and privacy text comes from Markdown ([`rtf`]). A
//! [`Database`] then takes the tables, the files as one cabinet, any binaries
//! and the summary information. [`winget`] writes winget's manifests for a
//! finished package, from what the package records
//! ([`package_properties`]).
//!
//! Tables are written as Windows Installer's own `.idt` text and imported
//! (`MsiDatabaseImportW`).

mod files;
mod msi;
pub mod rtf;
pub mod schema;
mod search;
pub mod ui;
pub mod winget;

use std::error::Error;

pub use files::{Payload, file_table, media_table, with_sizes};
pub use msi::{Database, Handle, Summary, check, new_guid, package_properties, record_string, wide, wide_path};
pub use search::{Search, VC_RUNTIME_PACKAGE, VcRuntime, linker_version, runtime_min};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

// The values of the tables' attribute and type columns, by the names
// Windows Installer's documentation gives them.

/// `msidbComponentAttributes64bit`.
pub const COMPONENT_64BIT: i32 = 256;
/// `msidbFileAttributesVital`.
pub const FILE_VITAL: i32 = 512;
/// Custom action type 1: a function of a DLL in the Binary table.
pub const CA_DLL: i32 = 1;
/// Custom action type 18: an EXE installed with the product, its Source a
/// File key.
pub const CA_EXE_FILE: i32 = 18;
/// `msidbCustomActionTypeContinue`: the exit code doesn't fail the install.
pub const CA_CONTINUE: i32 = 64;
/// `msidbCustomActionTypeRollback`: runs only if the install rolls back.
pub const CA_ROLLBACK: i32 = 256;
/// `msidbCustomActionTypeInScript`: deferred, run from the install script.
pub const CA_DEFERRED: i32 = 1024;
/// `msidbCustomActionTypeNoImpersonate`: a deferred action runs as SYSTEM,
/// not as the user.
pub const CA_NO_IMPERSONATE: i32 = 2048;
/// `msidbUpgradeAttributesMigrateFeatures`.
pub const UPGRADE_MIGRATE_FEATURES: i32 = 1;
/// `msidbUpgradeAttributesOnlyDetect`.
pub const UPGRADE_ONLY_DETECT: i32 = 2;
/// `msidbUpgradeAttributesVersionMinInclusive`.
pub const UPGRADE_MIN_INCLUSIVE: i32 = 0x100;
/// `msidbUpgradeAttributesVersionMaxInclusive`.
pub const UPGRADE_MAX_INCLUSIVE: i32 = 0x200;
/// `msidbRegistryRootLocalMachine`, in the Registry and RegLocator tables.
pub const HKLM: i32 = 2;
/// `msidbLocatorTypeDirectory`: the value is a folder, which must exist.
pub const LOCATOR_DIRECTORY: i32 = 0;
/// `msidbLocatorTypeFileName`: a component's key path is a file.
pub const LOCATOR_FILE: i32 = 1;
/// `msidbLocatorType64bit`: the 64-bit registry, not the 32-bit view.
pub const LOCATOR_64BIT: i32 = 16;
/// `SERVICE_WIN32_OWN_PROCESS`.
pub const SERVICE_OWN_PROCESS: i32 = 0x10;
/// `SERVICE_AUTO_START`.
pub const SERVICE_AUTO_START: i32 = 2;
/// `SERVICE_ERROR_NORMAL`.
pub const SERVICE_ERROR_NORMAL: i32 = 1;
/// ServiceControl event `msidbServiceControlEventStart`: start on install.
pub const SERVICE_START_INSTALL: i32 = 1;
/// … `msidbServiceControlEventStop`: stop on install.
pub const SERVICE_STOP_INSTALL: i32 = 2;
/// … `msidbServiceControlEventUninstallStop`: stop on uninstall.
pub const SERVICE_STOP_UNINSTALL: i32 = 32;
/// … `msidbServiceControlEventUninstallDelete`: delete on uninstall.
pub const SERVICE_DELETE_UNINSTALL: i32 = 128;
/// MsiServiceConfig event `msidbServiceConfigEventInstall`.
pub const SERVICE_CONFIG_INSTALL: i32 = 1;
/// … `msidbServiceConfigEventReinstall`.
pub const SERVICE_CONFIG_REINSTALL: i32 = 4;
/// MsiServiceConfig type: `ChangeServiceConfig2`'s info level
/// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
pub const SERVICE_CONFIG_DELAYED_AUTO_START: i32 = 3;
/// … `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
pub const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: i32 = 4;
/// … `SERVICE_CONFIG_SERVICE_SID_INFO`.
pub const SERVICE_CONFIG_SERVICE_SID: i32 = 5;
/// … `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`.
pub const SERVICE_CONFIG_REQUIRED_PRIVILEGES: i32 = 6;

/// A cell: `None` is null.
pub type Cell = Option<String>;

/// A text cell.
pub fn s(v: &str) -> Cell {
    Some(v.to_string())
}

/// A number cell.
pub fn n(v: i32) -> Cell {
    Some(v.to_string())
}

/// One table: its columns as (name, `.idt` type), its primary key, its rows.
pub struct Table {
    pub name: &'static str,
    pub columns: &'static [(&'static str, &'static str)],
    pub keys: &'static [&'static str],
    pub rows: Vec<Vec<Cell>>,
}

impl Table {
    pub fn new(
        name: &'static str,
        columns: &'static [(&'static str, &'static str)],
        keys: &'static [&'static str],
    ) -> Self {
        Self { name, columns, keys, rows: Vec::new() }
    }

    /// Adds a row, a cell for each column.
    pub fn row(&mut self, cells: Vec<Cell>) -> &mut Self {
        assert_eq!(cells.len(), self.columns.len(), "a {} row", self.name);
        self.rows.push(cells);
        self
    }

    /// The table as `.idt` text: column names, types, the table and its
    /// keys, then a line per row, tab-separated, a null being empty.
    pub fn idt(&self) -> Result<String> {
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

/// A sequence table (`InstallUISequence`, `InstallExecuteSequence`, …):
/// each action with its condition and number.
pub fn sequence(name: &'static str, actions: &[(&str, Option<&str>, i32)]) -> Table {
    let mut t = schema::sequence(name);
    for (action, condition, number) in actions {
        t.row(vec![s(action), condition.map(str::to_string), n(*number)]);
    }
    t
}

/// `version` if Windows Installer takes it as a ProductVersion:
/// major.minor.build, numbers only, at most 255.255.65535, so no
/// pre-release or build suffixes.
pub fn product_version(version: &str) -> Result<&str> {
    let parts: Vec<&str> = version.split('.').collect();
    let fits = parts.len() == 3
        && parts[0].parse::<u8>().is_ok()
        && parts[1].parse::<u8>().is_ok()
        && parts[2].parse::<u16>().is_ok();
    if !fits {
        return Err(format!("{version} isn't a version Windows Installer takes (major.minor.build)").into());
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_is_idt_text() {
        let mut t = schema::property();
        t.row(vec![s("ProductName"), s("Warlock")]).row(vec![s("Empty"), None]);
        assert_eq!(
            t.idt().unwrap(),
            "Property\tValue\r\ns72\tl0\r\nProperty\tProperty\r\nProductName\tWarlock\r\nEmpty\t\r\n"
        );
    }

    #[test]
    fn cells_idt_cant_carry_are_refused() {
        for bad in ["a\tb", "a\nb", "é"] {
            let mut t = schema::property();
            t.row(vec![s("P"), s(bad)]);
            assert!(t.idt().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn product_versions_are_three_small_numbers() {
        assert!(product_version("0.2.5").is_ok());
        assert!(product_version("255.255.65535").is_ok());
        for bad in ["0.2", "0.2.5.1", "256.0.0", "0.2.5-rc.1", "1.0.65536"] {
            assert!(product_version(bad).is_err(), "{bad}");
        }
    }
}
