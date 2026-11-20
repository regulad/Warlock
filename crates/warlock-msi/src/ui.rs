// SPDX-License-Identifier: GPL-2.0-only
//! The package's own dialogs, for an install started by hand (winget's
//! silent installs never show them):
//!
//! - Licences: the licence page ([`crate::licence`]). It asks nothing: the
//!   GPL and the AGPL don't need accepting to install or run a program.
//! - Install folder: where Warlock goes, with a folder browser, and what its
//!   service will do.
//! - Options: adding the account installing to `warlock-users`, to
//!   `warlock-admin` below it, and the Wireshark plugin.
//! - Progress, then Done, Cancelled or Failed; a confirmation before
//!   cancelling; the error dialog Windows Installer reports through.
//! - Repair or remove, when the package is opened again on a PC that has it.
//!
//! The tables' column definitions are copied from an MSI Windows installed
//! (exported from `C:\Windows\Installer` on 2026-11-18), as the rest are.
//! Sizes are in installer units, on the 370 × 270 layout Windows Installer's
//! own examples use.

use crate::{Cell, Table, n, s};

const WIDTH: i32 = 370;
const HEIGHT: i32 = 270;

// Dialog attributes.
const DLG_VISIBLE: i32 = 1;
const DLG_MODAL: i32 = 2;
const DLG_MINIMIZE: i32 = 4;
const DLG_ERROR: i32 = 65536;
const MODAL: i32 = DLG_VISIBLE | DLG_MODAL | DLG_MINIMIZE;

// Control attributes.
const VISIBLE: i32 = 1;
const ENABLED: i32 = 2;
const SUNKEN: i32 = 4;
const TRANSPARENT: i32 = 65536;
const NO_PREFIX: i32 = 131072;
const PROGRESS95: i32 = 65536;
const FIXED_VOLUMES: i32 = 131072;
const REMOTE_VOLUMES: i32 = 262144;
const ELEVATION_SHIELD: i32 = 8388608;
/// Static text: no mnemonics.
const TEXT: i32 = VISIBLE | ENABLED | TRANSPARENT | NO_PREFIX;
/// A label whose `&` marks the mnemonic of the control after it.
const LABEL: i32 = VISIBLE | ENABLED | TRANSPARENT;
const BUTTON: i32 = VISIBLE | ENABLED;

/// The text styles: `{\WarlockUI_Title}` in a control's text.
const NORMAL: &str = "WarlockUI_Normal";
const TITLE: &str = "WarlockUI_Title";

// Conditions shared by dialogs that say what's happening.
const INSTALLING: &str = "NOT Installed";
const REPAIRING: &str = "Installed AND NOT REMOVE~=\"ALL\"";
const REMOVING: &str = "REMOVE~=\"ALL\"";

struct Ui {
    dialog: Table,
    control: Table,
    event: Table,
    condition: Table,
    mapping: Table,
}

impl Ui {
    fn new() -> Self {
        Self {
            dialog: Table::new(
                "Dialog",
                &[
                    ("Dialog", "s72"),
                    ("HCentering", "i2"),
                    ("VCentering", "i2"),
                    ("Width", "i2"),
                    ("Height", "i2"),
                    ("Attributes", "I4"),
                    ("Title", "L128"),
                    ("Control_First", "s50"),
                    ("Control_Default", "S50"),
                    ("Control_Cancel", "S50"),
                ],
                &["Dialog"],
            ),
            control: Table::new(
                "Control",
                &[
                    ("Dialog_", "s72"),
                    ("Control", "s50"),
                    ("Type", "s20"),
                    ("X", "i2"),
                    ("Y", "i2"),
                    ("Width", "i2"),
                    ("Height", "i2"),
                    ("Attributes", "I4"),
                    ("Property", "S72"),
                    ("Text", "L0"),
                    ("Control_Next", "S50"),
                    ("Help", "L50"),
                ],
                &["Dialog_", "Control"],
            ),
            event: Table::new(
                "ControlEvent",
                &[
                    ("Dialog_", "s72"),
                    ("Control_", "s50"),
                    ("Event", "s50"),
                    ("Argument", "s255"),
                    ("Condition", "S255"),
                    ("Ordering", "I2"),
                ],
                &["Dialog_", "Control_", "Event", "Argument", "Condition"],
            ),
            condition: Table::new(
                "ControlCondition",
                &[("Dialog_", "s72"), ("Control_", "s50"), ("Action", "s50"), ("Condition", "s255")],
                &["Dialog_", "Control_", "Action", "Condition"],
            ),
            mapping: Table::new(
                "EventMapping",
                &[("Dialog_", "s72"), ("Control_", "s50"), ("Event", "s50"), ("Attribute", "s50")],
                &["Dialog_", "Control_", "Event"],
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dialog(&mut self, name: &str, w: i32, h: i32, attributes: i32, first: &str, default: Cell, cancel: Cell) {
        self.dialog.row(vec![
            s(name),
            n(50),
            n(50),
            n(w),
            n(h),
            n(attributes),
            s("[ProductName] Setup"),
            s(first),
            default,
            cancel,
        ]);
    }

    #[allow(clippy::too_many_arguments)]
    fn control(
        &mut self,
        dialog: &str,
        name: &str,
        kind: &str,
        (x, y, w, h): (i32, i32, i32, i32),
        attributes: i32,
        property: Option<&str>,
        text: Option<&str>,
        next: Option<&str>,
    ) {
        self.control.row(vec![
            s(dialog),
            s(name),
            s(kind),
            n(x),
            n(y),
            n(w),
            n(h),
            n(attributes),
            property.map(str::to_string),
            text.map(str::to_string),
            next.map(str::to_string),
            None,
        ]);
    }

    fn text(&mut self, dialog: &str, name: &str, at: (i32, i32, i32, i32), text: &str) {
        self.control(dialog, name, "Text", at, TEXT, None, Some(text), None);
    }

    fn button(&mut self, dialog: &str, name: &str, at: (i32, i32, i32, i32), attributes: i32, text: &str, next: &str) {
        self.control(dialog, name, "PushButton", at, attributes, None, Some(text), Some(next));
    }

    /// Events a control publishes, in order.
    fn events(&mut self, dialog: &str, control: &str, events: &[(&str, &str)]) {
        for (i, (event, argument)) in events.iter().enumerate() {
            self.event.row(vec![s(dialog), s(control), s(event), s(argument), s("1"), n(i as i32 + 1)]);
        }
    }

    /// A control shown only while `condition` holds (it starts hidden).
    /// Windows Installer evaluates control conditions again as properties
    /// change on the page, so it's hidden again when `condition` stops
    /// holding.
    fn shown_if(&mut self, dialog: &str, name: &str, at: (i32, i32, i32, i32), text: &str, condition: &str) {
        self.control(dialog, name, "Text", at, TEXT & !VISIBLE, None, Some(text), None);
        self.condition.row(vec![s(dialog), s(name), s("Show"), s(condition)]);
        self.condition.row(vec![s(dialog), s(name), s("Hide"), s(&format!("NOT ({condition})"))]);
    }

    /// The parts every page has: its title and description, the two rules,
    /// and Back, Next and Cancel at the bottom.
    fn page(&mut self, dialog: &str, title: &str, description: &str) {
        self.text(dialog, "Title", (15, 6, 340, 15), &format!("{{\\{TITLE}}}{title}"));
        self.text(dialog, "Description", (25, 23, 330, 15), description);
        self.control(dialog, "BannerLine", "Line", (0, 44, WIDTH, 0), VISIBLE, None, None, None);
        self.control(dialog, "BottomLine", "Line", (0, 234, WIDTH, 0), VISIBLE, None, None, None);
    }
}

const BACK: (i32, i32, i32, i32) = (180, 243, 56, 17);
const NEXT: (i32, i32, i32, i32) = (236, 243, 56, 17);
const CANCEL: (i32, i32, i32, i32) = (304, 243, 56, 17);

/// The UI's tables. `licence` is the licence page's RTF.
pub fn tables(licence: &str) -> Vec<Table> {
    let mut ui = Ui::new();

    // Licences: read, then Next.
    let d = "LicenseDlg";
    ui.dialog(d, WIDTH, HEIGHT, MODAL, "Next", s("Next"), s("Cancel"));
    ui.page(d, "Licences", "Warlock is free software, under these licences.");
    ui.control(
        d,
        "LicenseText",
        "ScrollableText",
        (20, 52, 330, 146),
        VISIBLE | ENABLED | SUNKEN,
        None,
        Some(licence),
        Some("Back"),
    );
    ui.text(
        d,
        "Note",
        (20, 203, 330, 28),
        "You don't have to accept these licences to install or use Warlock. They say what you may do when you copy, \
         change or share it.",
    );
    ui.button(d, "Back", BACK, VISIBLE, "&Back", "Next");
    ui.button(d, "Next", NEXT, BUTTON, "&Next", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "LicenseText");
    ui.events(d, "Next", &[("NewDialog", "InstallDirDlg")]);
    ui.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);

    // Install folder, then Next.
    let d = "InstallDirDlg";
    ui.dialog(d, WIDTH, HEIGHT, MODAL, "FolderLabel", s("Next"), s("Cancel"));
    ui.page(d, "Install folder", "Where Warlock's programs go.");
    // A line of text is about 12.3 units high and 4.1 units a character
    // (measured on this page, 2026-11-19): a checkbox's label fits one line,
    // and what more it needs to say goes on a line under it.
    ui.control(d, "FolderLabel", "Text", (20, 56, 330, 12), LABEL, None, Some("&Install Warlock to:"), Some("Folder"));
    ui.control(
        d,
        "Folder",
        "PathEdit",
        (20, 69, 330, 18),
        VISIBLE | ENABLED | SUNKEN,
        Some("INSTALLDIR"),
        None,
        Some("ChangeFolder"),
    );
    ui.button(d, "ChangeFolder", (20, 91, 66, 17), BUTTON, "&Change...", "Back");
    ui.text(
        d,
        "ServiceNote",
        (20, 116, 330, 40),
        "Warlock installs the Warlock service, which starts with Windows. While Warlock is installed, it takes every \
         supported USB Wi-Fi adapter it finds away from Windows' Wi-Fi driver; uninstalling gives them back.",
    );
    ui.button(d, "Back", BACK, BUTTON, "&Back", "Next");
    ui.button(d, "Next", NEXT, BUTTON, "&Next", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "FolderLabel");
    ui.events(d, "ChangeFolder", &[("SpawnDialog", "BrowseDlg")]);
    ui.events(d, "Back", &[("NewDialog", "LicenseDlg")]);
    ui.events(d, "Next", &[("SetTargetPath", "INSTALLDIR"), ("NewDialog", "OptionsDlg")]);
    ui.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);

    // Options, then Install: the groups (warlock-admin below warlock-users,
    // Parker, 2026-11-19) and the Wireshark plugin. Their own page, since
    // three checkboxes and their notes don't fit under the folder.
    let d = "OptionsDlg";
    ui.dialog(d, WIDTH, HEIGHT, MODAL, crate::GROUPS[0].control, s("Install"), s("Cancel"));
    ui.page(d, "Options", "What else Warlock sets up for you.");
    // Each group: unticked by default; ticked and greyed out, saying so, when
    // the account installing is already a member. The admin group's purpose
    // takes two lines.
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
    ui.button(d, "Back", BACK, BUTTON, "&Back", "Install");
    ui.button(d, "Install", NEXT, BUTTON | ELEVATION_SHIELD, "&Install", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", crate::GROUPS[0].control);
    ui.events(d, "Back", &[("NewDialog", "InstallDirDlg")]);
    // Windows Installer decides the features in CostFinalize, before the
    // pages, and a property set here doesn't decide again: Install says what
    // the checkbox chose, or ticking it does nothing (0.1.2, 2026-11-19).
    let wanted = "WIRESHARKPLUGIN AND WIRESHARKDIR";
    for (i, (event, argument, condition)) in [
        ("AddLocal", "WiresharkPlugin", wanted.to_string()),
        ("Remove", "WiresharkPlugin", format!("NOT ({wanted})")),
        ("EndDialog", "Return", "1".to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        ui.event.row(vec![s(d), s("Install"), s(event), s(argument), s(&condition), n(i as i32 + 1)]);
    }
    ui.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);

    // The folder browser Change opens.
    let d = "BrowseDlg";
    ui.dialog(d, WIDTH, HEIGHT, MODAL, "ComboLabel", s("OK"), s("Cancel"));
    ui.page(d, "Change the install folder", "Browse to the folder to install Warlock to.");
    ui.control(d, "ComboLabel", "Text", (25, 58, 44, 12), LABEL, None, Some("&Look in:"), Some("DirectoryCombo"));
    ui.control(
        d,
        "DirectoryCombo",
        "DirectoryCombo",
        (70, 55, 200, 80),
        VISIBLE | ENABLED | FIXED_VOLUMES | REMOTE_VOLUMES,
        Some("INSTALLDIR"),
        None,
        Some("Up"),
    );
    ui.button(d, "Up", (276, 55, 34, 17), BUTTON, "&Up", "NewFolder");
    ui.button(d, "NewFolder", (314, 55, 36, 17), BUTTON, "Ne&w", "DirectoryList");
    ui.control(
        d,
        "DirectoryList",
        "DirectoryList",
        (25, 80, 325, 100),
        VISIBLE | ENABLED | SUNKEN,
        Some("INSTALLDIR"),
        None,
        Some("PathLabel"),
    );
    ui.control(d, "PathLabel", "Text", (25, 186, 325, 12), LABEL, None, Some("&Folder name:"), Some("PathEdit"));
    ui.control(
        d,
        "PathEdit",
        "PathEdit",
        (25, 199, 325, 18),
        VISIBLE | ENABLED | SUNKEN,
        Some("INSTALLDIR"),
        None,
        Some("OK"),
    );
    ui.button(d, "OK", (240, 243, 56, 17), BUTTON, "OK", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "ComboLabel");
    ui.events(d, "Up", &[("DirectoryListUp", "0")]);
    ui.events(d, "NewFolder", &[("DirectoryListNew", "0")]);
    ui.events(d, "OK", &[("SetTargetPath", "INSTALLDIR"), ("EndDialog", "Return")]);
    ui.events(d, "Cancel", &[("Reset", "0"), ("EndDialog", "Return")]);

    // Repair or remove, when it's already installed.
    let d = "MaintenanceDlg";
    ui.dialog(d, WIDTH, HEIGHT, MODAL, "Repair", None, s("Cancel"));
    ui.page(d, "Repair or remove", "Warlock is already installed on this PC.");
    ui.button(d, "Repair", (20, 65, 80, 17), BUTTON | ELEVATION_SHIELD, "&Repair", "Remove");
    ui.text(d, "RepairText", (110, 67, 240, 30), "Puts Warlock's files, service and settings back as installed.");
    ui.button(d, "Remove", (20, 105, 80, 17), BUTTON | ELEVATION_SHIELD, "Re&move", "Back");
    ui.text(d, "RemoveText", (110, 107, 240, 30), "Removes Warlock, and gives the adapter it had back to Windows.");
    ui.button(d, "Back", BACK, VISIBLE, "&Back", "Next");
    ui.button(d, "Next", NEXT, VISIBLE, "&Next", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "Repair");
    ui.events(d, "Repair", &[("[REINSTALL]", "ALL"), ("[REINSTALLMODE]", "ecmus"), ("EndDialog", "Return")]);
    ui.events(d, "Remove", &[("[REMOVE]", "ALL"), ("EndDialog", "Return")]);
    ui.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);

    // Progress, while Windows Installer works.
    let d = "ProgressDlg";
    ui.dialog(d, WIDTH, HEIGHT, DLG_VISIBLE | DLG_MINIMIZE, "Cancel", s("Cancel"), s("Cancel"));
    ui.control(d, "BannerLine", "Line", (0, 44, WIDTH, 0), VISIBLE, None, None, None);
    ui.control(d, "BottomLine", "Line", (0, 234, WIDTH, 0), VISIBLE, None, None, None);
    let title = |t: &str| format!("{{\\{TITLE}}}{t}");
    ui.shown_if(d, "TitleInstalling", (15, 6, 340, 15), &title("Installing Warlock"), INSTALLING);
    ui.shown_if(d, "TitleRepairing", (15, 6, 340, 15), &title("Repairing Warlock"), REPAIRING);
    ui.shown_if(d, "TitleRemoving", (15, 6, 340, 15), &title("Removing Warlock"), REMOVING);
    ui.text(d, "Description", (25, 23, 330, 15), "This takes a moment.");
    ui.text(d, "StatusLabel", (20, 70, 50, 12), "Status:");
    ui.control(d, "ActionText", "Text", (70, 70, 280, 12), VISIBLE | ENABLED | NO_PREFIX, None, None, None);
    ui.control(d, "ProgressBar", "ProgressBar", (20, 88, 330, 12), VISIBLE | PROGRESS95, None, Some("Progress"), None);
    ui.button(d, "Back", BACK, VISIBLE, "&Back", "Next");
    ui.button(d, "Next", NEXT, VISIBLE, "&Next", "Cancel");
    ui.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "Back");
    ui.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);
    ui.mapping.row(vec![s(d), s("ActionText"), s("ActionText"), s("Text")]);
    ui.mapping.row(vec![s(d), s("ProgressBar"), s("SetProgress"), s("Progress")]);

    // The ends: done, cancelled, failed.
    let finish = |ui: &mut Ui, d: &str, title: &str| {
        ui.dialog(d, WIDTH, HEIGHT, MODAL, "Finish", s("Finish"), s("Finish"));
        ui.page(d, title, "");
        ui.button(d, "Back", BACK, VISIBLE, "&Back", "Finish");
        ui.button(d, "Finish", NEXT, BUTTON, "&Finish", "Cancel");
        ui.button(d, "Cancel", CANCEL, VISIBLE, "Cancel", "Back");
    };
    let body = (20, 60, 330, 60);
    let d = "ExitDlg";
    finish(&mut ui, d, "Done");
    // Asked to join a group it wasn't in before: is it in now? Then the
    // sign-out modal, then the end.
    let asked: Vec<String> = crate::GROUPS.iter().map(|g| format!("({} AND NOT {})", g.join, g.member)).collect();
    for (i, (event, argument, condition)) in [
        ("DoAction", "WarlockFindJoined", asked.join(" OR ")),
        ("SpawnDialog", "SignOutDlg", crate::JOINED_PROPERTY.to_string()),
        ("EndDialog", "Return", "1".to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        ui.event.row(vec![s(d), s("Finish"), s(event), s(argument), s(&condition), n(i as i32 + 1)]);
    }
    ui.shown_if(
        d,
        "Installed",
        body,
        "Warlock is installed, and its service is running. Plug in a supported USB Wi-Fi adapter, and Warlock takes \
         it over within about ten seconds.",
        INSTALLING,
    );
    ui.shown_if(d, "Repaired", body, "Warlock is repaired.", REPAIRING);
    ui.shown_if(d, "Removed", body, "Warlock is removed, and the adapter it had is back with Windows.", REMOVING);
    let d = "UserExitDlg";
    finish(&mut ui, d, "Cancelled");
    ui.events(d, "Finish", &[("EndDialog", "Exit")]);
    ui.text(d, "Body", body, "Warlock's setup was cancelled. Nothing was changed.");
    let d = "FatalErrorDlg";
    finish(&mut ui, d, "Setup failed");
    ui.events(d, "Finish", &[("EndDialog", "Exit")]);
    ui.text(
        d,
        "Body",
        body,
        "Warlock's setup stopped because of an error, and nothing was changed. A log (msiexec /l*v) tells why.",
    );

    // Are you sure?
    let d = "CancelDlg";
    ui.dialog(d, 260, 85, MODAL, "No", s("No"), s("No"));
    ui.text(d, "Text", (20, 15, 220, 30), "Cancel Warlock's setup?");
    ui.button(d, "Yes", (72, 57, 56, 17), BUTTON, "&Yes", "No");
    ui.button(d, "No", (132, 57, 56, 17), BUTTON, "&No", "Yes");
    ui.events(d, "Yes", &[("EndDialog", "Exit")]);
    ui.events(d, "No", &[("EndDialog", "Return")]);

    // Sign out now? Over the Done page, when the install added this account
    // to warlock-users. Later is the default: signing out closes every
    // program.
    let d = "SignOutDlg";
    ui.dialog(d, 280, 110, MODAL, "Later", s("Later"), s("Later"));
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

    // Windows Installer's own messages: it shows the buttons each needs.
    let d = "ErrorDlg";
    ui.dialog(d, 270, 105, MODAL | DLG_ERROR, "ErrorText", None, None);
    ui.control(d, "ErrorText", "Text", (48, 15, 205, 60), TEXT, None, None, None);
    for (button, text, event) in [
        ("A", "&Abort", "ErrorAbort"),
        ("C", "&Cancel", "ErrorCancel"),
        ("I", "&Ignore", "ErrorIgnore"),
        ("N", "&No", "ErrorNo"),
        ("O", "&OK", "ErrorOk"),
        ("R", "&Retry", "ErrorRetry"),
        ("Y", "&Yes", "ErrorYes"),
    ] {
        ui.control(d, button, "PushButton", (100, 80, 56, 17), BUTTON, None, Some(text), None);
        ui.events(d, button, &[("EndDialog", event)]);
    }

    let mut style = Table::new(
        "TextStyle",
        &[("TextStyle", "s72"), ("FaceName", "s32"), ("Size", "i2"), ("Color", "I4"), ("StyleBits", "I2")],
        &["TextStyle"],
    );
    style.row(vec![s(NORMAL), s("Segoe UI"), n(9), None, n(0)]).row(vec![s(TITLE), s("Segoe UI"), n(12), None, n(1)]);

    // What a ticked checkbox sets its property to.
    let mut check_box = Table::new("CheckBox", &[("Property", "s72"), ("Value", "S64")], &["Property"]);
    check_box.row(vec![s(crate::WIRESHARK_PLUGIN_PROPERTY), s("1")]);
    for g in &crate::GROUPS {
        check_box.row(vec![s(g.join), s("1")]);
    }

    // The name a new folder gets in the browser.
    let mut ui_text = Table::new("UIText", &[("Key", "s72"), ("Text", "L255")], &["Key"]);
    ui_text.row(vec![s("NewFolder"), s("Folder|New Folder")]);

    // What the progress page says during our own actions.
    let mut action_text =
        Table::new("ActionText", &[("Action", "s72"), ("Description", "L0"), ("Template", "L0")], &["Action"]);
    action_text
        .row(vec![s("WarlockSetup"), s("Setting up Warlock's events, group and service"), None])
        .row(vec![s("WarlockSetupRollback"), s("Undoing Warlock's setup"), None])
        .row(vec![s("WarlockTeardown"), s("Giving the adapter back to Windows"), None]);
    for g in &crate::GROUPS {
        action_text.row(vec![s(g.action), s(&format!("Adding you to the {} group", g.name)), None]);
    }

    vec![ui.dialog, ui.control, ui.event, ui.condition, ui.mapping, style, check_box, ui_text, action_text]
}

/// The properties the UI needs.
pub const PROPERTIES: [(&str, &str); 2] = [("DefaultUIFont", NORMAL), ("ErrorDialog", "ErrorDlg")];

/// The UI sequence's dialogs, with their conditions and sequence numbers:
/// the first page (licences, or repair or remove), the progress page just
/// before the install runs, and the ends.
pub const SEQUENCE: [(&str, Option<&str>, i32); 6] = [
    ("LicenseDlg", Some(INSTALLING), 1290),
    ("MaintenanceDlg", Some("Installed AND NOT REMOVE"), 1291),
    ("ProgressDlg", None, 1299),
    ("ExitDlg", None, -1),
    ("UserExitDlg", None, -2),
    ("FatalErrorDlg", None, -3),
];

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

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
        let tables = tables("{\\rtf1 x}");
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
        let tables = tables("{\\rtf1 x}");
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

    /// Done's Finish asks the group, then asks to sign out only an account
    /// it added, then ends.
    #[test]
    fn finish_asks_a_new_member_to_sign_out() {
        let tables = tables("{\\rtf1 x}");
        let mut finish: Vec<(i32, &str, &str, &str)> = rows(&tables, "ControlEvent")
            .iter()
            .filter(|r| cell(r, 0) == Some("ExitDlg") && cell(r, 1) == Some("Finish"))
            .map(|r| {
                (cell(r, 5).unwrap().parse().unwrap(), cell(r, 2).unwrap(), cell(r, 3).unwrap(), cell(r, 4).unwrap())
            })
            .collect();
        finish.sort();
        let steps: Vec<(&str, &str)> = finish.iter().map(|f| (f.1, f.2)).collect();
        assert_eq!(steps, [("DoAction", "WarlockFindJoined"), ("SpawnDialog", "SignOutDlg"), ("EndDialog", "Return")]);
        assert_eq!(finish[1].3, crate::JOINED_PROPERTY);
        assert!(rows(&tables, "Dialog").iter().any(|d| cell(d, 0) == Some("SignOutDlg")));
    }

    /// Windows Installer refuses a dialog whose tab order isn't one cycle
    /// (error 2810), or whose references name no control.
    #[test]
    fn every_dialog_is_well_formed() {
        let tables = tables("{\\rtf1 x}");
        let controls = rows(&tables, "Control");
        for dialog in rows(&tables, "Dialog") {
            let d = cell(dialog, 0).unwrap();
            let names: BTreeSet<&str> =
                controls.iter().filter(|c| cell(c, 0) == Some(d)).map(|c| cell(c, 1).unwrap()).collect();
            for i in [7, 8, 9] {
                if let Some(c) = cell(dialog, i) {
                    assert!(names.contains(c), "{d}: no control {c}");
                }
            }
            let next: BTreeMap<&str, &str> = controls
                .iter()
                .filter(|c| cell(c, 0) == Some(d))
                .filter_map(|c| Some((cell(c, 1).unwrap(), cell(c, 10)?)))
                .collect();
            if next.is_empty() {
                continue;
            }
            let mut pointed = BTreeSet::new();
            for (from, to) in &next {
                assert!(names.contains(to), "{d}: {from} points to no control {to}");
                assert!(pointed.insert(*to), "{d}: two controls point to {to}");
            }
            // From the first control, the cycle passes every one once.
            let start = cell(dialog, 7).unwrap();
            let (mut at, mut seen) = (start, 0);
            loop {
                at = next[at];
                seen += 1;
                if at == start {
                    break;
                }
                assert!(seen <= next.len(), "{d}: the cycle doesn't return to {start}");
            }
            assert_eq!(seen, next.len(), "{d}: controls outside the cycle");
        }
        for (table, control) in [("ControlEvent", 1), ("ControlCondition", 1), ("EventMapping", 1)] {
            for row in rows(&tables, table) {
                let (d, c) = (cell(row, 0).unwrap(), cell(row, control).unwrap());
                assert!(controls.iter().any(|x| cell(x, 0) == Some(d) && cell(x, 1) == Some(c)), "{table}: {d}.{c}");
            }
        }
    }
}
