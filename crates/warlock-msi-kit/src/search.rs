// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! What a package looks for before it installs (AppSearch): files, registry
//! values, installed components; and the Visual C++ runtime, which a fresh
//! Windows lacks.

use std::path::Path;

use crate::{Result, Table, n, s, schema, winget};

/// The AppSearch table and the locator tables its signatures come from.
/// Each method adds a signature, and an AppSearch row for each property the
/// search sets when it finds it.
pub struct Search {
    pub app_search: Table,
    pub signature: Table,
    pub dr_locator: Table,
    pub reg_locator: Table,
    pub comp_locator: Table,
}

impl Default for Search {
    fn default() -> Self {
        Self {
            app_search: schema::app_search(),
            signature: schema::signature(),
            dr_locator: schema::dr_locator(),
            reg_locator: schema::reg_locator(),
            comp_locator: schema::comp_locator(),
        }
    }
}

impl Search {
    pub fn new() -> Self {
        Self::default()
    }

    fn sets(&mut self, signature: &str, properties: &[&str]) {
        for property in properties {
            self.app_search.row(vec![s(property), s(signature)]);
        }
    }

    /// The file `file_name` (`short|long`) in `folder` itself, which may
    /// name properties (`[System64Folder]`), at `min_version` or later if
    /// given: each of `properties` gets its path.
    ///
    /// A file whose version equals `min_version` passes only if its
    /// language matches the Signature's, which is left null; so a floor a
    /// real file can equal goes one below it, as Microsoft's documentation
    /// of the Signature table says (2.0.2600.1182 for 2.0.2600.1183).
    pub fn file(
        &mut self,
        signature: &str,
        file_name: &str,
        min_version: Option<&str>,
        folder: &str,
        properties: &[&str],
    ) -> &mut Self {
        self.sets(signature, properties);
        let min = min_version.map(str::to_string);
        self.signature.row(vec![s(signature), s(file_name), min, None, None, None, None, None, None]);
        self.dr_locator.row(vec![s(signature), None, s(folder), n(0)]);
        self
    }

    /// The registry value `name` under `key` (`root` [`crate::HKLM`]), read
    /// as `kind` says ([`crate::LOCATOR_DIRECTORY`],
    /// [`crate::LOCATOR_64BIT`], …): each of `properties` gets it.
    pub fn registry(
        &mut self,
        signature: &str,
        root: i32,
        key: &str,
        name: &str,
        kind: i32,
        properties: &[&str],
    ) -> &mut Self {
        self.sets(signature, properties);
        self.reg_locator.row(vec![s(signature), n(root), s(key), s(name), n(kind)]);
        self
    }

    /// The component `component_id`, if installed: each of `properties` gets
    /// its key path, a file ([`crate::LOCATOR_FILE`]) or folder.
    pub fn component(&mut self, signature: &str, component_id: &str, kind: i32, properties: &[&str]) -> &mut Self {
        self.sets(signature, properties);
        self.comp_locator.row(vec![s(signature), s(component_id), n(kind)]);
        self
    }

    pub fn into_tables(self) -> [Table; 5] {
        [self.app_search, self.signature, self.dr_locator, self.reg_locator, self.comp_locator]
    }
}

/// The Visual C++ runtime's winget package, which a package can depend on so
/// winget installs it first.
pub const VC_RUNTIME_PACKAGE: &str = "Microsoft.VCRedist.2015+.x64";

/// The Visual C++ runtime a package's binaries link to. A fresh Windows has
/// none, and then they don't start (Warlock's PLAN.md, W5): the package
/// installs only where it's there, at least as new as the toolset that
/// linked them, and its winget manifest depends on it. The runtime isn't
/// shipped, so Microsoft's isn't ours to redistribute.
pub struct VcRuntime<'a> {
    /// The runtime DLLs the binaries import, each with the property its
    /// search sets and its `short|long` name. The short name only counts
    /// where long names don't.
    pub dlls: &'a [(&'a str, &'a str)],
    /// The least runtime version they need, as `14.50` ([`runtime_min`]).
    pub min: String,
}

impl VcRuntime<'_> {
    /// Any build of that minor version or later. (The version is compared
    /// with the language only when equal, which a real build number isn't.)
    fn floor(&self) -> String {
        format!("{}.0.0", self.min)
    }

    /// Searches System32 for each DLL at [`Self::min`] or later, as the
    /// signature `Sig<property>`.
    pub fn search(&self, search: &mut Search) {
        let floor = self.floor();
        for (property, file_name) in self.dlls {
            search.file(&format!("Sig{property}"), file_name, Some(&floor), "[System64Folder]", &[property]);
        }
    }

    /// The launch condition: every DLL found, or the product installed
    /// already (it isn't needed to uninstall); and what `product`'s package
    /// says when it doesn't hold.
    pub fn launch_condition(&self, product: &str) -> (String, String) {
        let found = self.dlls.iter().map(|(p, _)| *p).collect::<Vec<_>>().join(" AND ");
        (
            format!("Installed OR ({found})"),
            format!(
                "{product} needs the Microsoft Visual C++ v14 Redistributable (x64), version {} or later: winget \
                 install {VC_RUNTIME_PACKAGE}",
                self.min
            ),
        )
    }

    /// The runtime's winget package, at [`Self::min`] or later.
    pub fn dependency(&self) -> winget::Dependency<'static> {
        winget::Dependency { package: VC_RUNTIME_PACKAGE, min_version: Some(self.floor()) }
    }
}

/// The least Visual C++ runtime version the binaries need, as `14.50`: a
/// runtime at least as new as the newest toolset that linked any of them
/// ("C++ binary compatibility between Visual Studio versions", Microsoft
/// Learn). The toolset is read from each one's PE header.
pub fn runtime_min(exes: &[&Path]) -> Result<String> {
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
pub fn linker_version(path: &Path) -> Result<(u8, u8)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// This test binary, linked by the MSVC toolset this kit's builders use.
    #[test]
    fn the_linker_version_is_read_from_the_header() {
        let exe = std::env::current_exe().unwrap();
        let min = runtime_min(&[&exe]).unwrap();
        assert!(min.starts_with("14."), "{min}");
        assert!(linker_version(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml").as_path()).is_err());
    }

    #[test]
    fn the_runtime_is_searched_for_and_named() {
        let runtime = VcRuntime { dlls: &[("VCRUNTIME140", "VCRT140.DLL|vcruntime140.dll")], min: "14.50".into() };
        let mut search = Search::new();
        runtime.search(&mut search);
        let [app_search, signature, dr_locator, ..] = search.into_tables();
        assert_eq!(app_search.rows, [vec![s("VCRUNTIME140"), s("SigVCRUNTIME140")]]);
        assert_eq!(signature.rows[0][..3], [s("SigVCRUNTIME140"), s("VCRT140.DLL|vcruntime140.dll"), s("14.50.0.0")]);
        assert_eq!(dr_locator.rows, [vec![s("SigVCRUNTIME140"), None, s("[System64Folder]"), n(0)]]);
        let (condition, message) = runtime.launch_condition("Koala");
        assert_eq!(condition, "Installed OR (VCRUNTIME140)");
        assert!(message.starts_with("Koala needs") && message.ends_with(VC_RUNTIME_PACKAGE), "{message}");
        assert_eq!(runtime.dependency().min_version.as_deref(), Some("14.50.0.0"));
    }
}
