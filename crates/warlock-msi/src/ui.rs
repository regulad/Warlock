// SPDX-License-Identifier: GPL-2.0-only
//! The package's own dialogs, for an install started by hand (winget's
//! silent installs never show them):
//!
//! - Licences: the licence page ([`crate::licence`]). It asks nothing: the
//!   GPL and the AGPL don't need accepting to install or run a program.
//! - Privacy: the privacy policy, `PRIVACY.md`, as it's installed. It asks
//!   nothing either: the policy says how to turn diagnostics off.
//! - Install folder: where Warlock goes, with a folder browser, and what its
//!   service will do.
//! - Options: adding the account installing to `warlock-users`, to
//!   `warlock-admin` below it, and the Wireshark plugin.
//! - Progress, then Done, Cancelled or Failed; a confirmation before
//!   cancelling; the error dialog Windows Installer reports through.
//! - After Done, when the install added the account to a group: sign out
//!   now?
//! - Repair or remove, when the package is opened again on a PC that has it.
//!
//! The Options page and the sign-out prompt are Warlock's own; the others
//! are `warlock_msi_kit::ui`'s standard pages, in Warlock's words.

use warlock_msi_kit::s;
use warlock_msi_kit::ui::{BUTTON, Ends, MODAL, Step, Ui};

/// The first page of an install.
pub const FIRST: &str = "LicenseDlg";

/// The pages. `licence` and `privacy` are the licence and privacy pages'
/// RTF.
pub fn build(licence: &str, privacy: &str) -> Ui {
    let mut ui = Ui::new("Warlock");

    // Licences: read, then Next.
    let step = Step {
        dialog: FIRST,
        title: "Licences",
        description: "Warlock is free software, under these licences.",
        back: None,
        next: Some("PrivacyDlg"),
        before: &[],
    };
    let note = "You don't have to accept these licences to install or use Warlock. They say what you may do when you \
                copy, change or share it.";
    ui.document_page(&step, "LicenseText", licence, note);

    // Privacy: the privacy policy itself (Parker, 2026-11-21), which says
    // what Warlock's programs send and how to turn that off. It asks and
    // changes nothing.
    let step = Step {
        dialog: "PrivacyDlg",
        title: "Privacy",
        description: "What Warlock sends to find and fix problems, and how to turn it off.",
        back: Some(FIRST),
        next: Some("InstallDirDlg"),
        before: &[],
    };
    let note =
        "This is Warlock's privacy policy, which is installed with it. Nothing on this page changes your computer.";
    ui.document_page(&step, "PrivacyText", privacy, note);

    // Install folder, then Next.
    let d = "InstallDirDlg";
    let step = Step {
        dialog: d,
        title: "Install folder",
        description: "Where Warlock's programs go.",
        back: Some("PrivacyDlg"),
        next: Some("OptionsDlg"),
        before: &[],
    };
    ui.folder_page(&step);
    ui.text(
        d,
        "ServiceNote",
        (20, 116, 330, 40),
        "Warlock installs the Warlock service, which starts with Windows. While Warlock is installed, it takes every \
         supported USB Wi-Fi adapter it finds away from Windows' Wi-Fi driver; uninstalling gives them back.",
    );

    options(&mut ui);

    ui.maintenance_page(
        "Puts Warlock's files, service and settings back as installed.",
        "Removes Warlock, and gives the adapter it had back to Windows.",
    );
    ui.progress_page();

    // The install added this account to a group (`FindJoined`, run in the
    // UI sequence after the install, has said so before this page): the
    // Done page's Finish goes on to the sign-out prompt, which ends setup.
    // Otherwise it ends setup itself. A button changes dialogs once per
    // press: given both a SpawnDialog and an EndDialog, Windows Installer did
    // only the last (0.2.0, 2026-11-19), so the two conditions are each
    // other's opposite. The Cancelled and Failed pages' Finish reports how
    // setup ended, for the diagnostics (warlock-msi-ca), then ends it.
    let joined = crate::JOINED_PROPERTY;
    let not_joined = format!("NOT {joined}");
    ui.ends(&Ends {
        installed: "Warlock is installed, and its service is running. Plug in a supported USB Wi-Fi adapter, and \
                    Warlock takes it over within about ten seconds.",
        removed: "Warlock is removed, and the adapter it had is back with Windows.",
        finish: &[("NewDialog", "SignOutDlg", joined), ("EndDialog", "Return", &not_joined)],
        cancelled: Some("WarlockCancelled"),
        failed: Some("WarlockFailed"),
    });
    ui.cancel_dialog();
    sign_out(&mut ui);
    ui.error_dialog();

    // What the progress page says during our own actions.
    ui.action_text
        .row(vec![s("WarlockSetup"), s("Setting up Warlock's events, group and service"), None])
        .row(vec![s("WarlockSetupRollback"), s("Undoing Warlock's setup"), None])
        .row(vec![s("WarlockTeardown"), s("Giving the adapter back to Windows"), None]);
    for g in &crate::GROUPS {
        ui.action_text.row(vec![s(g.action), s(&format!("Adding you to the {} group", g.name)), None]);
    }
    ui
}

/// Options, then Install: the groups (warlock-admin below warlock-users,
/// Parker, 2026-11-19) and the Wireshark plugin. Their own page, since
/// three checkboxes and their notes don't fit under the folder.
fn options(ui: &mut Ui) {
    let d = "OptionsDlg";
    // Windows Installer decides the features in CostFinalize, before the
    // pages, and a property set here doesn't decide again: Install says what
    // the checkbox chose, or ticking it does nothing (0.1.2, 2026-11-19).
    let wanted = "WIRESHARKPLUGIN AND WIRESHARKDIR";
    let unwanted = format!("NOT ({wanted})");
    let step = Step {
        dialog: d,
        title: "Options",
        description: "What else Warlock sets up for you.",
        back: Some("InstallDirDlg"),
        next: None,
        before: &[("AddLocal", "WiresharkPlugin", wanted), ("Remove", "WiresharkPlugin", &unwanted)],
    };
    let first = crate::GROUPS[0].control;
    ui.step(&step, first, first);
    // Each group: unticked by default; ticked and greyed out, saying so, when
    // the account installing is already a member. The admin group's purpose
    // takes two lines; a checkbox's label fits one (`warlock_msi_kit::ui`).
    let places = [(56, 12), (92, 26)];
    let next = [crate::GROUPS[1].control, "WiresharkPlugin"];
    for ((g, (y, note_height)), next) in crate::GROUPS.iter().zip(places).zip(next) {
        ui.control(d, g.control, "CheckBox", (20, y, 330, 14), BUTTON, Some(g.join), Some(g.label), Some(next));
        ui.condition.row(vec![s(d), s(g.control), s("Disable"), s(g.member)]);
        ui.condition.row(vec![s(d), s(g.control), s("Enable"), s(&format!("NOT {}", g.member))]);
        let note = (34, y + 14, 316, note_height);
        let not_member = format!("NOT {}", g.member);
        ui.shown_if(d, &format!("{}Note", g.control), note, g.purpose, &not_member);
        let already = format!("You're already in {}.", g.name);
        ui.shown_if(d, &format!("{}Member", g.control), (34, y + 14, 316, 12), &already, g.member);
    }
    // The optional Wireshark plugin (PLAN.md, W6): unticked unless already
    // installed, and greyed out, saying why in place of what it is, when
    // Wireshark wasn't found.
    ui.control(
        d,
        "WiresharkPlugin",
        "CheckBox",
        (20, 142, 330, 14),
        BUTTON,
        Some(crate::WIRESHARK_PLUGIN_PROPERTY),
        Some("Also install the &Wireshark plugin"),
        Some("Back"),
    );
    ui.condition.row(vec![s(d), s("WiresharkPlugin"), s("Disable"), s("NOT WIRESHARKDIR")]);
    ui.condition.row(vec![s(d), s("WiresharkPlugin"), s("Enable"), s("WIRESHARKDIR")]);
    // One note in three: what the plugin is; on an upgrade with it unticked,
    // that the installed one goes; or that there's no Wireshark.
    let note = (34, 156, 316, 12);
    let removing = format!(
        "WIRESHARKDIR AND {} AND NOT {}",
        crate::WIRESHARK_PLUGIN_FOUND_PROPERTY,
        crate::WIRESHARK_PLUGIN_PROPERTY
    );
    let what = format!("WIRESHARKDIR AND NOT ({removing})");
    ui.shown_if(d, "WiresharkNote", note, "Warlock's radio as a capture interface in Wireshark.", &what);
    ui.shown_if(d, "WiresharkRemoved", note, "The previous version of the plugin will be removed.", &removing);
    ui.shown_if(d, "WiresharkMissing", note, "Wireshark was not detected.", "NOT WIRESHARKDIR");

    // What a ticked checkbox sets its property to.
    ui.check_box.row(vec![s(crate::WIRESHARK_PLUGIN_PROPERTY), s("1")]);
    for g in &crate::GROUPS {
        ui.check_box.row(vec![s(g.join), s("1")]);
    }
}

/// Sign out now? After the Done page, in its place, when the install added
/// this account to a group. Either button ends setup, as Finish would have.
/// Later is the default: signing out closes every program.
fn sign_out(ui: &mut Ui) {
    let d = "SignOutDlg";
    ui.dialog(d, 280, 110, MODAL, "Later", Some("Later"), Some("Later"));
    ui.text(
        d,
        "Text",
        (20, 12, 240, 42),
        &format!(
            "Warlock added you to [{}]. Windows applies that the next time you sign in; until then, Warlock still \
             needs administrator rights.",
            crate::JOINED_GROUPS_PROPERTY
        ),
    );
    ui.text(d, "Ask", (20, 58, 240, 14), "Sign out now? Save your work in other programs first.");
    ui.button(d, "SignOut", (114, 82, 84, 17), BUTTON, "Sign &out now", "Later");
    ui.button(d, "Later", (204, 82, 56, 17), BUTTON, "&Later", "SignOut");
    ui.events(d, "SignOut", &[("DoAction", "WarlockSignOut"), ("EndDialog", "Return")]);
    ui.events(d, "Later", &[("EndDialog", "Return")]);
}

#[cfg(test)]
mod tests {
    use warlock_msi_kit::{Cell, Table};

    use super::*;

    fn tables() -> Vec<Table> {
        build("{\\rtf1 x}", "{\\rtf1 y}").into_tables()
    }

    fn rows<'a>(tables: &'a [Table], name: &str) -> &'a [Vec<Cell>] {
        &tables.iter().find(|t| t.name == name).unwrap().rows
    }

    fn cell(row: &[Cell], i: usize) -> Option<&str> {
        row[i].as_deref()
    }

    /// The features are decided before the install page, so its Install
    /// button carries the plugin checkbox's choice, both ways, before it
    /// ends the dialog.
    #[test]
    fn install_carries_the_plugin_checkbox() {
        let tables = tables();
        let install: Vec<(&str, &str, &str, i32)> = rows(&tables, "ControlEvent")
            .iter()
            .filter(|r| cell(r, 0) == Some("OptionsDlg") && cell(r, 1) == Some("Install"))
            .map(|r| {
                (cell(r, 2).unwrap(), cell(r, 3).unwrap(), cell(r, 4).unwrap(), cell(r, 5).unwrap().parse().unwrap())
            })
            .collect();
        let at = |event: &str| install.iter().find(|e| e.0 == event).unwrap();
        assert_eq!(at("AddLocal").1, "WiresharkPlugin");
        assert_eq!(at("Remove").1, "WiresharkPlugin");
        assert_eq!(at("Remove").2, format!("NOT ({})", at("AddLocal").2));
        assert!(at("AddLocal").2.contains(crate::WIRESHARK_PLUGIN_PROPERTY));
        assert!(at("AddLocal").3 < at("EndDialog").3 && at("Remove").3 < at("EndDialog").3);
    }

    /// Exactly one of the plugin's three notes holds in each case, as the
    /// checkbox changes: Show and Hide conditions are each other's opposite.
    #[test]
    fn the_plugin_has_one_note_at_a_time() {
        let tables = tables();
        let conditions = rows(&tables, "ControlCondition");
        let show = |control: &str| {
            conditions
                .iter()
                .find(|r| cell(r, 0) == Some("OptionsDlg") && cell(r, 1) == Some(control) && cell(r, 2) == Some("Show"))
                .and_then(|r| cell(r, 3))
                .unwrap()
                .to_string()
        };
        let hide = |control: &str| {
            conditions
                .iter()
                .find(|r| cell(r, 0) == Some("OptionsDlg") && cell(r, 1) == Some(control) && cell(r, 2) == Some("Hide"))
                .and_then(|r| cell(r, 3))
                .unwrap()
                .to_string()
        };
        // (Wireshark found, plugin installed before, ticked) -> the note shown.
        let cases = [
            ((true, true, false), "WiresharkRemoved"),
            ((true, true, true), "WiresharkNote"),
            ((true, false, false), "WiresharkNote"),
            ((true, false, true), "WiresharkNote"),
            ((false, true, false), "WiresharkMissing"),
            ((false, false, true), "WiresharkMissing"),
        ];
        for ((dir, found, ticked), expected) in cases {
            for control in ["WiresharkNote", "WiresharkRemoved", "WiresharkMissing"] {
                let eval = |c: &str| {
                    let c = c
                        .replace(crate::WIRESHARK_PLUGIN_FOUND_PROPERTY, if found { "true" } else { "false" })
                        .replace(crate::WIRESHARK_PLUGIN_PROPERTY, if ticked { "true" } else { "false" })
                        .replace("WIRESHARKDIR", if dir { "true" } else { "false" });
                    evaluate(&c)
                };
                assert_eq!(eval(&show(control)), control == expected, "{control} in {dir}/{found}/{ticked}");
                assert_eq!(eval(&hide(control)), control != expected, "{control} hidden in {dir}/{found}/{ticked}");
            }
        }
    }

    /// Enough of Windows Installer's condition syntax for the tests: `true`,
    /// `false`, `NOT`, `AND` and parentheses, `NOT` binding tightest.
    fn evaluate(condition: &str) -> bool {
        let spaced = condition.replace('(', " ( ").replace(')', " ) ");
        let tokens: Vec<&str> = spaced.split_whitespace().collect();
        fn and(t: &[&str], i: &mut usize) -> bool {
            let mut v = not(t, i);
            while t.get(*i) == Some(&"AND") {
                *i += 1;
                v &= not(t, i);
            }
            v
        }
        fn not(t: &[&str], i: &mut usize) -> bool {
            match t[*i] {
                "NOT" => {
                    *i += 1;
                    !not(t, i)
                }
                "(" => {
                    *i += 1;
                    let v = and(t, i);
                    assert_eq!(t[*i], ")");
                    *i += 1;
                    v
                }
                v => {
                    *i += 1;
                    v == "true"
                }
            }
        }
        let mut i = 0;
        let v = and(&tokens, &mut i);
        assert_eq!(i, tokens.len(), "{condition}");
        v
    }

    /// Done's Finish goes on to the sign-out prompt for an account the
    /// install added to a group, and otherwise ends; the prompt's buttons
    /// end setup too.
    #[test]
    fn finish_asks_a_new_member_to_sign_out() {
        let tables = tables();
        let events = |d: &str, c: &str| -> Vec<(&str, &str, &str)> {
            let mut v: Vec<(i32, &str, &str, &str)> = rows(&tables, "ControlEvent")
                .iter()
                .filter(|r| cell(r, 0) == Some(d) && cell(r, 1) == Some(c))
                .map(|r| {
                    (
                        cell(r, 5).unwrap().parse().unwrap(),
                        cell(r, 2).unwrap(),
                        cell(r, 3).unwrap(),
                        cell(r, 4).unwrap(),
                    )
                })
                .collect();
            v.sort();
            v.into_iter().map(|e| (e.1, e.2, e.3)).collect()
        };
        let joined = crate::JOINED_PROPERTY;
        let not_joined = format!("NOT {joined}");
        assert_eq!(
            events("ExitDlg", "Finish"),
            [("NewDialog", "SignOutDlg", joined), ("EndDialog", "Return", not_joined.as_str())]
        );
        assert_eq!(
            events("SignOutDlg", "SignOut"),
            [("DoAction", "WarlockSignOut", "1"), ("EndDialog", "Return", "1")]
        );
        assert_eq!(events("SignOutDlg", "Later"), [("EndDialog", "Return", "1")]);
    }

    /// Warlock's own pages pass what the standard ones do: one tab cycle a
    /// dialog, controls that exist, one change of dialog a press.
    #[test]
    fn every_dialog_is_well_formed() {
        warlock_msi_kit::ui::check(&tables()).unwrap();
    }
}
