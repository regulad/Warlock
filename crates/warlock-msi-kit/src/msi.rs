// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! The Windows Installer API (`msi.dll`): writing a package, and reading a
//! finished one's properties.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIDBOPEN_CREATE, MSIDBOPEN_READONLY, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiDatabaseCommit,
    MsiDatabaseImportW, MsiDatabaseOpenViewW, MsiGetSummaryInformationW, MsiOpenDatabaseW, MsiRecordGetStringW,
    MsiRecordSetStreamW, MsiRecordSetStringW, MsiSummaryInfoPersist, MsiSummaryInfoSetPropertyW, MsiViewClose,
    MsiViewExecute, MsiViewFetch,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::core::GUID;

use crate::files::{Payload, cabinet};
use crate::{Result, Table};

/// A string as a NUL-terminated UTF-16 one, for the API.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub fn wide_path(p: &Path) -> Vec<u16> {
    wide(&p.to_string_lossy())
}

/// A new GUID, braced and upper-case as Windows Installer writes them: a
/// product code or package code, new for every build.
pub fn new_guid() -> Result<String> {
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
pub struct Handle(pub MSIHANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle Windows Installer gave us.
        unsafe { MsiCloseHandle(self.0) };
    }
}

/// A Windows Installer return code as a result, `what` saying what failed.
pub fn check(what: &str, rc: u32) -> Result<()> {
    if rc == 0 { Ok(()) } else { Err(format!("{what}: Windows Installer error {rc}").into()) }
}

/// What the summary information says of a package, besides what this kit
/// always writes: that it's an installation database for Windows Installer
/// 5.0, with long file names, compressed, and best opened read-only.
pub struct Summary<'a> {
    /// The product (`PID_SUBJECT`).
    pub subject: &'a str,
    /// Its manufacturer (`PID_AUTHOR`).
    pub author: &'a str,
    /// `PID_KEYWORDS`.
    pub keywords: &'a str,
    /// `PID_COMMENTS`.
    pub comments: &'a str,
    /// The platform and language (`PID_TEMPLATE`): `x64;1033`.
    pub template: &'a str,
    /// The package code (`PID_REVNUMBER`), new for every build
    /// ([`new_guid`]).
    pub package_code: &'a str,
    /// What wrote the package (`PID_APPNAME`).
    pub application: &'a str,
}

/// A package being written: created empty, given its tables, cabinet and
/// binaries and its summary information, then committed. What it imports
/// is written first to a work folder beside it (its path, with the
/// extension `work`), which the commit removes.
pub struct Database {
    handle: Handle,
    work: PathBuf,
}

impl Database {
    /// Creates an empty package at `path`, replacing any there.
    pub fn create(path: &Path) -> Result<Self> {
        let work = path.with_extension("work");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("idt"))?;
        let _ = std::fs::remove_file(path);
        let mut db: MSIHANDLE = 0;
        // SAFETY: valid paths and out-parameter.
        check("creating the database", unsafe {
            MsiOpenDatabaseW(wide_path(path).as_ptr(), MSIDBOPEN_CREATE, &mut db)
        })?;
        Ok(Self { handle: Handle(db), work })
    }

    /// Imports a table, as `.idt` text.
    pub fn import(&self, table: &Table) -> Result<()> {
        let idt = self.work.join("idt");
        let file = format!("{}.idt", table.name);
        std::fs::write(idt.join(&file), table.idt()?)?;
        // SAFETY: valid handle and paths.
        let rc = unsafe { MsiDatabaseImportW(self.handle.0, wide_path(&idt).as_ptr(), wide(&file).as_ptr()) };
        check(&format!("importing {}", table.name), rc)
    }

    /// Packs `files` into one cabinet with `makecab`, each named by its File
    /// key, in File table order ([`crate::file_table`]), and adds it as the
    /// package's stream `name`, which the Media table names `#name`
    /// ([`crate::media_table`]).
    pub fn cabinet(&self, name: &str, files: &[(Payload, u64)]) -> Result<()> {
        let cab = cabinet(&self.work, name, files)?;
        self.stream("_Streams", name, &cab, "the cabinet")
    }

    /// Adds `path`'s data as the Binary table's row `name`. The tables
    /// imported must include the Binary table ([`crate::schema::binary`]).
    pub fn binary(&self, name: &str, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Err(format!("{}: not built", path.display()).into());
        }
        self.stream("Binary", name, path, &format!("binary {name}"))
    }

    /// A row of a table of streams, `_Streams` or Binary, whose data is
    /// `path`'s.
    fn stream(&self, table: &str, name: &str, path: &Path, what: &str) -> Result<()> {
        let mut view: MSIHANDLE = 0;
        let query = wide(&format!("INSERT INTO `{table}` (`Name`, `Data`) VALUES (?, ?)"));
        // SAFETY: valid handles, strings and paths throughout.
        unsafe {
            check(&format!("opening {table}"), MsiDatabaseOpenViewW(self.handle.0, query.as_ptr(), &mut view))?;
            let view = Handle(view);
            let record = Handle(MsiCreateRecord(2));
            check(&format!("naming {what}"), MsiRecordSetStringW(record.0, 1, wide(name).as_ptr()))?;
            check(&format!("reading {what}"), MsiRecordSetStreamW(record.0, 2, wide_path(path).as_ptr()))?;
            check(&format!("adding {what}"), MsiViewExecute(view.0, record.0))?;
            check(&format!("closing {table}"), MsiViewClose(view.0))?;
        }
        Ok(())
    }

    /// Writes the summary information.
    pub fn summary(&self, summary: &Summary) -> Result<()> {
        let mut handle: MSIHANDLE = 0;
        // SAFETY: valid handle; strings outlive each call.
        unsafe {
            check("summary information", MsiGetSummaryInformationW(self.handle.0, std::ptr::null(), 20, &mut handle))?;
            let handle = Handle(handle);
            const VT_I4: u32 = 3;
            const VT_LPSTR: u32 = 30;
            for (pid, text) in [
                (2, "Installation Database"),
                (3, summary.subject),
                (4, summary.author),
                (5, summary.keywords),
                (6, summary.comments),
                (7, summary.template),
                (9, summary.package_code),
                (18, summary.application),
            ] {
                let text = wide(text);
                let rc = MsiSummaryInfoSetPropertyW(handle.0, pid, VT_LPSTR, 0, std::ptr::null_mut(), text.as_ptr());
                check(&format!("summary property {pid}"), rc)?;
            }
            // Windows Installer 5.0; long names, compressed; read-only
            // recommended.
            for (pid, value) in [(14, 500), (15, 2), (19, 2)] {
                let rc =
                    MsiSummaryInfoSetPropertyW(handle.0, pid, VT_I4, value, std::ptr::null_mut(), std::ptr::null());
                check(&format!("summary property {pid}"), rc)?;
            }
            check("saving the summary information", MsiSummaryInfoPersist(handle.0))?;
        }
        Ok(())
    }

    /// Commits the package, and removes the work folder.
    pub fn commit(self) -> Result<()> {
        // SAFETY: a valid handle.
        check("committing the database", unsafe { MsiDatabaseCommit(self.handle.0) })?;
        let Self { handle, work } = self;
        drop(handle);
        std::fs::remove_dir_all(&work)?;
        Ok(())
    }
}

/// A record's string field.
pub fn record_string(record: MSIHANDLE, field: u32) -> Result<String> {
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
pub fn package_properties(msi: &Path) -> Result<BTreeMap<String, String>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{s, schema};

    #[test]
    fn guids_are_braced_and_upper_case() {
        let g = new_guid().unwrap();
        assert_eq!(g.len(), 38, "{g}");
        assert!(g.starts_with('{') && g.ends_with('}'), "{g}");
        assert!(!g.chars().any(|c| c.is_ascii_lowercase()), "{g}");
        assert_ne!(g, new_guid().unwrap());
    }

    /// What a package records reads back.
    #[test]
    fn a_package_reads_back_its_properties() {
        let dir = std::env::temp_dir().join(format!("warlock-msi-kit-properties-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("properties.msi");
        let db = Database::create(&path).unwrap();
        let mut property = schema::property();
        property.row(vec![s("ProductName"), s("Test")]).row(vec![s("ProductVersion"), s("1.2.3")]);
        db.import(&property).unwrap();
        db.commit().unwrap();
        assert!(!path.with_extension("work").exists(), "the work folder stays");
        let p = package_properties(&path).unwrap();
        assert_eq!(p.get("ProductName").map(String::as_str), Some("Test"));
        assert_eq!(p.get("ProductVersion").map(String::as_str), Some("1.2.3"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
