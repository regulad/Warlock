// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! winget's three manifests (version, installer, default locale) for a
//! finished package, from what the package itself records (version, product
//! and upgrade codes, manufacturer) and its SHA-256. So they're written for
//! the package as published: after signing, which changes the hash.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Result;

/// winget's manifest schema the manifests are written to.
const MANIFEST_VERSION: &str = "1.10.0";

/// A winget package the package needs, which winget installs first.
pub struct Dependency<'a> {
    /// Its identifier, as `Microsoft.VCRedist.2015+.x64`.
    pub package: &'a str,
    /// The least version that will do, if any.
    pub min_version: Option<String>,
}

/// What the manifests say of a package besides what it records.
pub struct Manifest<'a> {
    /// The winget package, as `Regulad.Warlock`.
    pub package: &'a str,
    /// Its name, as winget shows it.
    pub name: &'a str,
    /// What wrote the manifests, for their first line: `warlock-msi`.
    pub generator: &'a str,
    /// The licence, as an SPDX expression.
    pub license: &'a str,
    pub short_description: &'a str,
    pub privacy_url: Option<String>,
    /// Why the package has its dependencies, as a comment above them.
    pub dependencies_note: Option<&'a str>,
    pub dependencies: &'a [Dependency<'a>],
    /// The package's version in winget, where it isn't its ProductVersion:
    /// Koala's dates, as `2026.11.22`, which Windows Installer can't take
    /// (Koala's package records `26.11.22`). winget then knows the installed
    /// product by its ProductVersion, given as `AppsAndFeaturesEntries`'
    /// `DisplayVersion`. `None`: the ProductVersion is the version.
    pub package_version: Option<&'a str>,
}

/// Single-quoted YAML scalars: only `'` needs escaping, as `''`.
fn quoted(v: &str) -> String {
    format!("'{}'", v.replace('\'', "''"))
}

/// A YAML scalar, plain when it can't be read as anything but the text.
fn plain(v: &str) -> String {
    let safe = v.starts_with(|c: char| c.is_ascii_alphabetic())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || " .-_+".contains(c))
        && !v.ends_with(' ');
    if safe { v.to_string() } else { quoted(v) }
}

/// The three manifests, as (file name, text), for the package at `msi`,
/// whose Property table is `properties` ([`crate::package_properties`]), to
/// be downloaded from `url`.
pub fn manifests(
    manifest: &Manifest,
    msi: &Path,
    properties: &BTreeMap<String, String>,
    url: &str,
) -> Result<Vec<(String, String)>> {
    if !url.starts_with("https://") {
        return Err(format!("{url}: winget downloads installers over https").into());
    }
    let get =
        |k: &str| properties.get(k).map(String::as_str).ok_or_else(|| format!("{}: no {k} property", msi.display()));
    let product_version = get("ProductVersion")?;
    let version = manifest.package_version.unwrap_or(product_version);
    // The installed product's version, where winget's differs from it.
    let display_version = manifest
        .package_version
        .filter(|v| *v != product_version)
        .map_or_else(String::new, |_| format!("  DisplayVersion: {}\n", quoted(product_version)));
    let product_code = get("ProductCode")?;
    let upgrade_code = get("UpgradeCode")?;
    let publisher = get("Manufacturer")?;
    let sha256: String = Sha256::digest(std::fs::read(msi)?).iter().map(|b| format!("{b:02X}")).collect();
    let file = msi.file_name().map_or_else(String::new, |f| f.to_string_lossy().into_owned());
    let package = manifest.package;
    let header = |kind: &str| {
        format!(
            "# Written by {} for {file}.\n\
             # yaml-language-server: $schema=https://aka.ms/winget-manifest.{kind}.{MANIFEST_VERSION}.schema.json\n\n\
             PackageIdentifier: {package}\nPackageVersion: {}\n",
            manifest.generator,
            quoted(version)
        )
    };
    let footer = |kind: &str| format!("ManifestType: {kind}\nManifestVersion: {MANIFEST_VERSION}\n");
    let mut dependencies = String::new();
    if !manifest.dependencies.is_empty() {
        if let Some(note) = manifest.dependencies_note {
            dependencies += &format!("# {note}\n");
        }
        dependencies += "Dependencies:\n  PackageDependencies:\n";
        for d in manifest.dependencies {
            dependencies += &format!("  - PackageIdentifier: {}\n", d.package);
            if let Some(min) = &d.min_version {
                dependencies += &format!("    MinimumVersion: {}\n", quoted(min));
            }
        }
    }
    let privacy = manifest.privacy_url.as_ref().map_or_else(String::new, |u| format!("PrivacyUrl: {}\n", quoted(u)));
    Ok(vec![
        (format!("{package}.yaml"), format!("{}DefaultLocale: en-US\n{}", header("version"), footer("version"))),
        (
            format!("{package}.installer.yaml"),
            format!(
                "{}InstallerType: msi\nScope: machine\nInstallModes:\n- interactive\n- silent\n- silentWithProgress\n\
                 UpgradeBehavior: install\n{dependencies}\
                 ProductCode: {}\nAppsAndFeaturesEntries:\n- Publisher: {}\n  ProductCode: {}\n  UpgradeCode: {}\n\
                 {display_version}Installers:\n- Architecture: x64\n  InstallerUrl: {}\n  InstallerSha256: {sha256}\n{}",
                header("installer"),
                quoted(product_code),
                quoted(publisher),
                quoted(product_code),
                quoted(upgrade_code),
                quoted(url),
                footer("installer")
            ),
        ),
        (
            format!("{package}.locale.en-US.yaml"),
            format!(
                "{}PackageLocale: en-US\nPublisher: {}\n{privacy}PackageName: {}\nLicense: {}\nShortDescription: {}\n{}",
                header("defaultLocale"),
                quoted(publisher),
                plain(manifest.name),
                quoted(manifest.license),
                quoted(manifest.short_description),
                footer("defaultLocale")
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn properties() -> BTreeMap<String, String> {
        [("ProductVersion", "1.2.3"), ("ProductCode", "{P}"), ("UpgradeCode", "{U}"), ("Manufacturer", "Regulad")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn installer(m: &Manifest) -> String {
        // Any file stands in for the package: only its hash and name are read.
        let msi = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        manifests(m, &msi, &properties(), "https://example.com/x.msi").unwrap().swap_remove(1).1
    }

    #[test]
    fn dependencies_are_listed_with_their_least_versions() {
        let dependencies = [
            Dependency { package: "vadimgrn.usbip-win2", min_version: Some("0.9.8.0".into()) },
            Dependency { package: "Regulad.Warlock", min_version: None },
        ];
        let m = Manifest {
            package: "Regulad.Koala",
            name: "Koala",
            generator: "koala-msi",
            license: "AGPL-3.0-or-later",
            short_description: "d",
            privacy_url: None,
            dependencies_note: Some("What Koala needs."),
            dependencies: &dependencies,
            package_version: None,
        };
        let text = installer(&m);
        let expected = concat!(
            "UpgradeBehavior: install\n",
            "# What Koala needs.\n",
            "Dependencies:\n",
            "  PackageDependencies:\n",
            "  - PackageIdentifier: vadimgrn.usbip-win2\n",
            "    MinimumVersion: '0.9.8.0'\n",
            "  - PackageIdentifier: Regulad.Warlock\n",
            "ProductCode: '{P}'\n",
        );
        assert!(text.contains(expected), "{text}");
        let none = Manifest { dependencies: &[], ..m };
        assert!(installer(&none).contains("UpgradeBehavior: install\nProductCode: "));
    }

    #[test]
    fn only_https_will_do() {
        let m = Manifest {
            package: "A.B",
            name: "B",
            generator: "g",
            license: "MIT",
            short_description: "d",
            privacy_url: None,
            dependencies_note: None,
            dependencies: &[],
            package_version: None,
        };
        let msi = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(manifests(&m, &msi, &properties(), "http://example.com/x.msi").is_err());
    }

    /// A version of winget's own (a date) goes in every manifest, and the
    /// installed product is known by its ProductVersion; without one, the
    /// ProductVersion is the version, and there's no DisplayVersion.
    #[test]
    fn a_package_version_of_its_own_maps_the_product_version() {
        let m = Manifest {
            package: "Regulad.Koala",
            name: "Koala",
            generator: "koala-msi",
            license: "AGPL-3.0-or-later",
            short_description: "d",
            privacy_url: None,
            dependencies_note: None,
            dependencies: &[],
            package_version: Some("2026.11.22"),
        };
        let msi = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let all = manifests(&m, &msi, &properties(), "https://example.com/x.msi").unwrap();
        for (name, text) in &all {
            assert!(text.contains("PackageVersion: '2026.11.22'\n"), "{name}: {text}");
        }
        assert!(all[1].1.contains("  UpgradeCode: '{U}'\n  DisplayVersion: '1.2.3'\nInstallers:"), "{}", all[1].1);
        let same = Manifest { package_version: None, ..m };
        let text = installer(&same);
        assert!(text.contains("PackageVersion: '1.2.3'\n") && !text.contains("DisplayVersion"), "{text}");
    }

    #[test]
    fn names_are_plain_only_when_safe() {
        assert_eq!(plain("Warlock"), "Warlock");
        assert_eq!(plain("Koala 2"), "Koala 2");
        assert_eq!(plain("Koala: the app"), "'Koala: the app'");
        assert_eq!(plain("#1"), "'#1'");
        assert_eq!(plain("it's"), "'it''s'");
    }
}
