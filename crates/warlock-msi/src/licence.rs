// SPDX-License-Identifier: GPL-2.0-only
//! The licence page's text: which part of Warlock is under which licence,
//! then the licences themselves, from the repository's own files; and the
//! privacy page's, `PRIVACY.md`. `warlock_msi_kit::rtf` makes them the RTF
//! a ScrollableText control shows.

use std::path::Path;

use warlock_msi_kit::{Result, rtf as convert};

/// What the page says before the licences.
const INTRO: [&str; 5] = [
    "**Warlock is free software.**",
    "`warlock.exe`, the Warlock service, is licensed under the GNU General Public License, version 2 only, \
     with an exception that permits combining it with Wintun.",
    "`warlockctl.exe`, its command-line tool, `warlock-extcap.exe`, its Wireshark plugin, and the installer's \
     own code are licensed under the GNU Affero General Public License, version 3 only.",
    "Their texts follow, and are installed with Warlock. Its source code is at https://github.com/regulad/Warlock.",
    "The programs are built with other free software, Sentry's SDKs among it, which send Warlock's diagnostics \
     (PRIVACY.md says what, and how to turn them off): THIRD-PARTY-NOTICES.txt, installed with Warlock, has its \
     licences.",
];

/// The licences, in the order the page shows them.
const FILES: [&str; 3] = ["LICENSE.md", "LICENSE-WINTUN-EXCEPTION.md", "LICENSE-AGPL-3.0.md"];

/// The privacy page's RTF, on one line: `PRIVACY.md`, as it's installed.
pub fn privacy(root: &Path) -> Result<String> {
    let text = std::fs::read_to_string(root.join("PRIVACY.md")).map_err(|e| format!("PRIVACY.md: {e}"))?;
    Ok(convert::document(&text))
}

/// The licence page's RTF, on one line.
pub fn rtf(root: &Path) -> Result<String> {
    let mut texts = Vec::new();
    for f in FILES {
        texts.push(std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"))?);
    }
    Ok(convert::page(&INTRO, &texts.iter().map(String::as_str).collect::<Vec<_>>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_privacy_page_is_the_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let rtf = privacy(&root).unwrap();
        assert!(rtf.is_ascii() && !rtf.contains(['\n', '\r', '\t', '[', ']']));
        assert!(rtf.contains("privacy policy") && rtf.contains("DO_NOT_TRACK"), "{rtf}");
        assert!(!rtf.contains('*'), "{rtf}");
    }

    #[test]
    fn the_page_is_one_ascii_line() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let rtf = rtf(&root).unwrap();
        assert!(rtf.is_ascii() && !rtf.contains(['\n', '\r', '\t', '[', ']']));
        assert!(rtf.contains("GNU GENERAL PUBLIC LICENSE") && rtf.contains("GNU AFFERO GENERAL PUBLIC LICENSE"));
        assert!(rtf.contains("Wintun exception"));
    }
}
