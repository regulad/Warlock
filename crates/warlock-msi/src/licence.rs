// SPDX-License-Identifier: GPL-2.0-only
//! The licence page's text: which part of Warlock is under which licence,
//! then the licences themselves, from the repository's own files, as the RTF
//! a ScrollableText control shows; and the privacy page's, `PRIVACY.md`.
//!
//! The files are Markdown, as the FSF publishes its licences, and use little
//! of it: headings, `**bold**`, `*italics*`, `-` lists whose items continue
//! on indented lines, indented blocks kept line by line, links and code
//! spans. That is all this converts.
//!
//! The control's text is formatted text, so `[` and `]` would be read as
//! property references; they go in as RTF hex escapes instead.

use std::path::Path;

use crate::Result;

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

/// The start of a page's RTF.
const HEADER: &str = r"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\fswiss\fcharset0 Segoe UI;}}\uc1\f0\fs18 ";

/// The privacy page's RTF, on one line: `PRIVACY.md`, as it's installed.
pub fn privacy(root: &Path) -> Result<String> {
    let text = std::fs::read_to_string(root.join("PRIVACY.md")).map_err(|e| format!("PRIVACY.md: {e}"))?;
    Ok(format!("{HEADER}{}}}", markdown(&text)))
}

/// The licence page's RTF, on one line.
pub fn rtf(root: &Path) -> Result<String> {
    let mut out = String::from(HEADER);
    for p in INTRO {
        out += &paragraph(p);
    }
    for f in FILES {
        let text = std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"))?;
        out += r"\pard\sa120\par ";
        out += &markdown(&text);
    }
    out.push('}');
    Ok(out)
}

fn paragraph(text: &str) -> String {
    format!(r"\pard\sa120 {}\par ", inline(text))
}

/// A Markdown document as RTF paragraphs.
fn markdown(text: &str) -> String {
    let mut out = String::new();
    let mut block: Vec<&str> = Vec::new();
    for line in text.lines().chain(Some("")) {
        if line.trim().is_empty() {
            if !block.is_empty() {
                out += &render(&block);
                block.clear();
            }
        } else {
            block.push(line);
        }
    }
    out
}

/// One block of lines between blank lines.
fn render(block: &[&str]) -> String {
    let first = block[0];
    if first.starts_with('#') {
        let level = first.chars().take_while(|&c| c == '#').count();
        let size = if level == 1 { 24 } else { 20 };
        return format!(r"\pard\sb120\sa120\b\fs{size} {}\b0\fs18\par ", inline(first[level..].trim()));
    }
    if first.starts_with('-') {
        // Items start with `-`; their other lines are indented.
        let mut items: Vec<String> = Vec::new();
        for line in block {
            match line.strip_prefix('-') {
                Some(item) => items.push(item.trim().to_string()),
                None => {
                    if let Some(last) = items.last_mut() {
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                }
            }
        }
        let mut out = String::new();
        for item in &items {
            out += &format!(r"\pard\li360\sa60 {}\par ", inline(item));
        }
        return out + r"\pard\sa60\par ";
    }
    if block.iter().all(|l| l.starts_with("    ")) {
        let lines: Vec<String> = block.iter().map(|l| inline(l[4..].trim_end())).collect();
        return format!(r"\pard\li360\sa120 {}\par ", lines.join(r"\line "));
    }
    let joined: Vec<&str> = block.iter().map(|l| l.trim()).collect();
    paragraph(&joined.join(" "))
}

/// Inline Markdown (code spans, links, `**bold**`, `*italics*`) as escaped
/// RTF.
fn inline(text: &str) -> String {
    let text = links(&text.replace('`', ""));
    let mut out = String::new();
    for (i, part) in text.split("**").enumerate() {
        if i % 2 == 1 {
            out += &format!(r"{{\b {}}}", italics(part));
        } else {
            out += &italics(part);
        }
    }
    out
}

/// `*italics*` (an asterisk next to a word on its inner side) as RTF, the
/// rest escaped.
fn italics(text: &str) -> String {
    let mut out = String::new();
    let mut parts = text.split('*').peekable();
    let mut open = false;
    let mut first = true;
    while let Some(part) = parts.next() {
        if !first {
            // An asterisk between `before` and `part`: opens before a word,
            // closes after one; otherwise it stays.
            let opens = !open && part.starts_with(|c: char| !c.is_whitespace()) && parts.peek().is_some();
            let closes = open && !out.ends_with(char::is_whitespace);
            if opens {
                out += r"{\i ";
                open = true;
            } else if closes {
                out += "}";
                open = false;
            } else {
                out.push('*');
            }
        }
        out += &escape(part);
        first = false;
    }
    if open {
        out += "}";
    }
    out
}

/// `[text](target)` as its text.
fn links(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        let after = &rest[open..];
        if let Some(mid) = after.find("](")
            && let Some(close) = after[mid..].find(')')
            && !after[1..mid].contains('[')
        {
            out += &rest[..open];
            out += &after[1..mid];
            rest = &after[mid + close + 1..];
            continue;
        }
        out += &rest[..=open];
        rest = &rest[open + 1..];
    }
    out + rest
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '\\' => out += r"\\",
            '{' => out += r"\{",
            '}' => out += r"\}",
            // Not property references in the control's formatted text.
            '[' => out += r"\'5b",
            ']' => out += r"\'5d",
            c if c.is_ascii() => out.push(c),
            // RTF's Unicode escape, a signed 16-bit code unit each.
            c => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out += &format!(r"\u{}?", *u as i16);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brackets_never_reach_the_formatted_text() {
        let rtf = markdown("Copyright (C) [year] [name of author]\n");
        assert!(!rtf.contains('[') && !rtf.contains(']'), "{rtf}");
        assert!(rtf.contains(r"\'5byear\'5d"));
    }

    #[test]
    fn markdown_becomes_rtf() {
        let md = "# Title\n\n**0.** This License\napplies.\n\n-   a) one\n    more\n-   b) two\n\n    kept\n    as is\n\n\
                  See [LICENSE.md](LICENSE.md) and `x`.\n";
        let rtf = markdown(md);
        assert!(rtf.contains(r"\b\fs24 Title\b0"), "{rtf}");
        assert!(rtf.contains(r"{\b 0.} This License applies.\par"), "{rtf}");
        assert!(rtf.contains(r"\li360\sa60 a) one more\par"), "{rtf}");
        assert!(rtf.contains(r"\li360\sa60 b) two\par"), "{rtf}");
        assert!(rtf.contains(r"kept\line as is"), "{rtf}");
        assert!(rtf.contains("See LICENSE.md and x."), "{rtf}");
    }

    #[test]
    fn italics_become_rtf_and_lone_asterisks_stay() {
        assert_eq!(inline("*Effective 21 November 2026.*"), r"{\i Effective 21 November 2026.}");
        assert_eq!(inline("a * b"), "a * b");
        assert_eq!(inline("**bold** and *it*"), r"{\b bold} and {\i it}");
    }

    #[test]
    fn the_privacy_page_is_the_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let rtf = privacy(&root).unwrap();
        assert!(rtf.is_ascii() && !rtf.contains(['\n', '\r', '\t', '[', ']']));
        assert!(rtf.contains("privacy policy") && rtf.contains("DO_NOT_TRACK"), "{rtf}");
        assert!(!rtf.contains('*'), "{rtf}");
    }

    #[test]
    fn rtf_specials_and_non_ascii_are_escaped() {
        assert_eq!(escape(r"a\b{c}"), r"a\\b\{c\}");
        assert_eq!(escape("é"), r"\u233?");
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
