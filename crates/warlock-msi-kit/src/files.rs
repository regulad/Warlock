// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! The package's files: the File and Media tables, and the one cabinet,
//! embedded in the package, that carries them.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{FILE_VITAL, Result, Table, n, s, schema};

/// A file going into the package.
pub struct Payload {
    /// The File table key, and its name in the cabinet.
    pub key: String,
    pub component: String,
    /// `short|long` when the long name isn't a valid 8.3 one.
    pub name: String,
    pub source: PathBuf,
    pub vital: bool,
}

/// Each file with its size, which the File table records.
pub fn with_sizes(payload: impl IntoIterator<Item = Payload>) -> Result<Vec<(Payload, u64)>> {
    let mut files = Vec::new();
    for p in payload {
        let size = std::fs::metadata(&p.source).map_err(|e| format!("{}: {e}", p.source.display()))?.len();
        files.push((p, size));
    }
    Ok(files)
}

/// The File table: a row for each file, numbered in order, which is the
/// cabinet's order too ([`crate::Database::cabinet`]).
pub fn file_table(files: &[(Payload, u64)]) -> Table {
    let mut file = schema::file();
    for (i, (p, size)) in files.iter().enumerate() {
        let size = i32::try_from(*size).expect("files under 2 GiB");
        let attributes = p.vital.then_some(FILE_VITAL).map(|a| a.to_string());
        file.row(vec![s(&p.key), s(&p.component), s(&p.name), n(size), None, None, attributes, n(i as i32 + 1)]);
    }
    file
}

/// The Media table: one disk, holding all `files` files, whose cabinet is
/// the package's stream `cabinet`.
pub fn media_table(cabinet: &str, files: usize) -> Table {
    let mut media = schema::media();
    // `#` means the cabinet is a stream inside the package.
    media.row(vec![n(1), n(files as i32), None, s(&format!("#{cabinet}")), None, None]);
    media
}

/// Packs the files into one cabinet `name` in `work` with `makecab`, each
/// named by its File key, in File table order.
pub(crate) fn cabinet(work: &Path, name: &str, files: &[(Payload, u64)]) -> Result<PathBuf> {
    let mut ddf = String::new();
    writeln!(ddf, ".OPTION EXPLICIT")?;
    for (k, v) in [
        ("CabinetNameTemplate", name),
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
    Ok(work.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(key: &str, vital: bool) -> Payload {
        Payload {
            key: key.into(),
            component: "C".into(),
            name: key.into(),
            source: Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
            vital,
        }
    }

    fn cells(r: &[crate::Cell]) -> Vec<Option<&str>> {
        r.iter().map(|c| c.as_deref()).collect()
    }

    #[test]
    fn files_are_numbered_in_order_and_one_disk_holds_them() {
        let files = with_sizes([payload("a.exe", true), payload("b.txt", false)]).unwrap();
        let size = files[0].1.to_string();
        let file = file_table(&files);
        assert_eq!(
            cells(&file.rows[0]),
            [Some("a.exe"), Some("C"), Some("a.exe"), Some(size.as_str()), None, None, Some("512"), Some("1")]
        );
        assert_eq!(cells(&file.rows[1])[6..], [None, Some("2")]);
        let media = media_table("x.cab", files.len());
        assert_eq!(cells(&media.rows[0]), [Some("1"), Some("2"), None, Some("#x.cab"), None, None]);
    }

    #[test]
    fn a_missing_file_is_named() {
        let mut p = payload("a.exe", true);
        p.source = PathBuf::from("no-such-file.exe");
        let e = with_sizes([p]).err().unwrap().to_string();
        assert!(e.starts_with("no-such-file.exe: "), "{e}");
    }
}
