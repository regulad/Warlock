// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! A package's own pages, for an install started by hand (silent installs,
//! winget's among them, never show them), as ordinary Windows Installer UI
//! tables: [`Ui`] adds dialogs and their controls, and the standard pages
//! with the product's words:
//!
//! - before the install, pages that Back and Next move between ([`Step`]):
//!   a document to read ([`Ui::document_page`]: licences, a privacy
//!   policy), the install folder with its browser ([`Ui::folder_page`]),
//!   and any of the product's own ([`Ui::step`], then its controls). The
//!   last one's Next is Install;
//! - repair or remove, when the package is opened again on a PC that has it
//!   ([`Ui::maintenance_page`]);
//! - progress, then Done, Cancelled or Failed ([`Ui::progress_page`],
//!   [`Ui::ends`]); a confirmation before cancelling
//!   ([`Ui::cancel_dialog`]); the error dialog Windows Installer reports
//!   through ([`Ui::error_dialog`]).
//!
//! [`sequence`] puts them in the UI sequence, and [`check`] finds what
//! Windows Installer would refuse in them.
//!
//! Sizes are in installer units, on the 370 × 270 layout Windows Installer's
//! own examples use. A line of text is about 12.3 units high and 4.1 units a
//! character (measured on Warlock's folder page, 2026-11-19): a checkbox's
//! label fits one line, and what more it needs to say goes on a line under
//! it.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Cell, Result, Table, n, s, schema};

pub const WIDTH: i32 = 370;
pub const HEIGHT: i32 = 270;

// Dialog attributes.
pub const DLG_VISIBLE: i32 = 1;
pub const DLG_MODAL: i32 = 2;
pub const DLG_MINIMIZE: i32 = 4;
pub const DLG_ERROR: i32 = 65536;
pub const MODAL: i32 = DLG_VISIBLE | DLG_MODAL | DLG_MINIMIZE;

// Control attributes.
pub const VISIBLE: i32 = 1;
pub const ENABLED: i32 = 2;
pub const SUNKEN: i32 = 4;
pub const TRANSPARENT: i32 = 65536;
pub const NO_PREFIX: i32 = 131072;
pub const PROGRESS95: i32 = 65536;
pub const FIXED_VOLUMES: i32 = 131072;
pub const REMOTE_VOLUMES: i32 = 262144;
pub const ELEVATION_SHIELD: i32 = 8388608;
/// Static text: no mnemonics.
pub const TEXT: i32 = VISIBLE | ENABLED | TRANSPARENT | NO_PREFIX;
/// A label whose `&` marks the mnemonic of the control after it.
pub const LABEL: i32 = VISIBLE | ENABLED | TRANSPARENT;
pub const BUTTON: i32 = VISIBLE | ENABLED;

// Conditions shared by dialogs that say what's happening.
pub const INSTALLING: &str = "NOT Installed";
pub const REPAIRING: &str = "Installed AND NOT REMOVE~=\"ALL\"";
pub const REMOVING: &str = "REMOVE~=\"ALL\"";

/// The buttons along a page's foot.
pub const BACK: (i32, i32, i32, i32) = (180, 243, 56, 17);
pub const NEXT: (i32, i32, i32, i32) = (236, 243, 56, 17);
pub const CANCEL: (i32, i32, i32, i32) = (304, 243, 56, 17);

/// The dialog Windows Installer reports its errors through.
const ERROR_DIALOG: &str = "ErrorDlg";

/// The UI's tables, filled in as the pages are added.
pub struct Ui {
    pub dialog: Table,
    pub control: Table,
    pub event: Table,
    pub condition: Table,
    pub mapping: Table,
    pub style: Table,
    /// What a ticked checkbox sets its property to.
    pub check_box: Table,
    pub ui_text: Table,
    /// What the progress page says during the product's own actions.
    pub action_text: Table,
    product: String,
    normal: String,
    title: String,
}

/// One of the pages before the install, which Back and Next move between.
#[derive(Clone, Copy)]
pub struct Step<'a> {
    pub dialog: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    /// The page Back goes to: none on the first page, whose Back is greyed
    /// out.
    pub back: Option<&'a str>,
    /// The page Next goes to: none on the last, whose Next is Install
    /// instead, with the elevation shield, and ends the pages for the
    /// install to run.
    pub next: Option<&'a str>,
    /// Events Next (or Install) publishes before it moves on, each under
    /// its condition: what the page's own controls chose.
    pub before: &'a [(&'a str, &'a str, &'a str)],
}

impl Step<'_> {
    /// The button that moves on, and the page's default: Next, or Install on
    /// the last page.
    pub fn forward(&self) -> &'static str {
        if self.next.is_some() { "Next" } else { "Install" }
    }
}

/// What the ends say and do.
pub struct Ends<'a> {
    /// What the Done page says after an install. After a repair, it says the
    /// product is repaired.
    pub installed: &'a str,
    /// … after a removal.
    pub removed: &'a str,
    /// Events Done's Finish publishes, each under its condition; none, and
    /// it ends setup. A button changes dialogs once per press ([`check`]).
    pub finish: &'a [(&'a str, &'a str, &'a str)],
    /// A custom action that Cancelled's Finish runs before it ends setup,
    /// such as one reporting how setup ended.
    pub cancelled: Option<&'a str>,
    /// … that Failed's Finish runs.
    pub failed: Option<&'a str>,
}

impl Ui {
    /// The tables for `product`'s pages, with its text styles:
    /// `{\<product>UI_Title}` in a control's text, `<product>UI_Normal` by
    /// default ([`Ui::properties`]).
    pub fn new(product: &str) -> Self {
        let normal = format!("{product}UI_Normal");
        let title = format!("{product}UI_Title");
        let mut style = schema::text_style();
        style.row(vec![s(&normal), s("Segoe UI"), n(9), None, n(0)]).row(vec![
            s(&title),
            s("Segoe UI"),
            n(12),
            None,
            n(1),
        ]);
        Self {
            dialog: schema::dialog(),
            control: schema::control(),
            event: schema::control_event(),
            condition: schema::control_condition(),
            mapping: schema::event_mapping(),
            style,
            check_box: schema::check_box(),
            ui_text: schema::ui_text(),
            action_text: schema::action_text(),
            product: product.to_string(),
            normal,
            title,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dialog(
        &mut self,
        name: &str,
        w: i32,
        h: i32,
        attributes: i32,
        first: &str,
        default: Option<&str>,
        cancel: Option<&str>,
    ) {
        let cell = |c: Option<&str>| -> Cell { c.map(str::to_string) };
        self.dialog.row(vec![
            s(name),
            n(50),
            n(50),
            n(w),
            n(h),
            n(attributes),
            s("[ProductName] Setup"),
            s(first),
            cell(default),
            cell(cancel),
        ]);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn control(
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

    pub fn text(&mut self, dialog: &str, name: &str, at: (i32, i32, i32, i32), text: &str) {
        self.control(dialog, name, "Text", at, TEXT, None, Some(text), None);
    }

    pub fn button(
        &mut self,
        dialog: &str,
        name: &str,
        at: (i32, i32, i32, i32),
        attributes: i32,
        text: &str,
        next: &str,
    ) {
        self.control(dialog, name, "PushButton", at, attributes, None, Some(text), Some(next));
    }

    /// Events a control publishes, in order.
    pub fn events(&mut self, dialog: &str, control: &str, events: &[(&str, &str)]) {
        let events: Vec<(&str, &str, &str)> = events.iter().map(|(e, a)| (*e, *a, "1")).collect();
        self.events_if(dialog, control, &events);
    }

    /// Events a control publishes, in order, each under its condition.
    pub fn events_if(&mut self, dialog: &str, control: &str, events: &[(&str, &str, &str)]) {
        for (i, (event, argument, condition)) in events.iter().enumerate() {
            self.event.row(vec![s(dialog), s(control), s(event), s(argument), s(condition), n(i as i32 + 1)]);
        }
    }

    /// A text shown only while `condition` holds (it starts hidden).
    /// Windows Installer evaluates control conditions again as properties
    /// change on the page, so it's hidden again when `condition` stops
    /// holding.
    pub fn shown_if(&mut self, dialog: &str, name: &str, at: (i32, i32, i32, i32), text: &str, condition: &str) {
        self.control(dialog, name, "Text", at, TEXT & !VISIBLE, None, Some(text), None);
        self.condition.row(vec![s(dialog), s(name), s("Show"), s(condition)]);
        self.condition.row(vec![s(dialog), s(name), s("Hide"), s(&format!("NOT ({condition})"))]);
    }

    /// `text` in the title style.
    pub fn title(&self, text: &str) -> String {
        format!("{{\\{}}}{text}", self.title)
    }

    /// The parts every page has: its title and description, and the two
    /// rules.
    pub fn page(&mut self, dialog: &str, title: &str, description: &str) {
        let title = self.title(title);
        self.text(dialog, "Title", (15, 6, 340, 15), &title);
        self.text(dialog, "Description", (25, 23, 330, 15), description);
        self.control(dialog, "BannerLine", "Line", (0, 44, WIDTH, 0), VISIBLE, None, None, None);
        self.control(dialog, "BottomLine", "Line", (0, 234, WIDTH, 0), VISIBLE, None, None, None);
    }

    /// A page before the install: its dialog, its parts ([`Ui::page`]),
    /// and Back, Next (or Install) and Cancel. `focus` is the control that
    /// has the focus as it opens; the page's own controls follow Cancel in
    /// the tab order from `first`, and the last of them leads to Back.
    pub fn step(&mut self, step: &Step, focus: &str, first: &str) {
        let d = step.dialog;
        let forward = step.forward();
        self.dialog(d, WIDTH, HEIGHT, MODAL, focus, Some(forward), Some("Cancel"));
        self.page(d, step.title, step.description);
        match step.back {
            Some(back) => {
                self.button(d, "Back", BACK, BUTTON, "&Back", forward);
                self.events(d, "Back", &[("NewDialog", back)]);
            }
            None => self.button(d, "Back", BACK, VISIBLE, "&Back", forward),
        }
        let then = match step.next {
            Some(next) => {
                self.button(d, "Next", NEXT, BUTTON, "&Next", "Cancel");
                ("NewDialog", next, "1")
            }
            None => {
                self.button(d, "Install", NEXT, BUTTON | ELEVATION_SHIELD, "&Install", "Cancel");
                ("EndDialog", "Return", "1")
            }
        };
        self.button(d, "Cancel", CANCEL, BUTTON, "Cancel", first);
        let events: Vec<(&str, &str, &str)> = step.before.iter().copied().chain([then]).collect();
        self.events_if(d, forward, &events);
        self.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);
    }

    /// A page with a document to read, the RTF `rtf` in the ScrollableText
    /// control `control`, and `note` under it. It asks nothing.
    pub fn document_page(&mut self, step: &Step, control: &str, rtf: &str, note: &str) {
        self.step(step, step.forward(), control);
        let d = step.dialog;
        self.control(
            d,
            control,
            "ScrollableText",
            (20, 52, 330, 146),
            VISIBLE | ENABLED | SUNKEN,
            None,
            Some(rtf),
            Some("Back"),
        );
        self.text(d, "Note", (20, 203, 330, 28), note);
    }

    /// The install folder, `INSTALLDIR`, with Change… opening a folder
    /// browser (`BrowseDlg`). Next sets the folder first. The space below
    /// the button, from y 116, is the product's, for a note.
    pub fn folder_page(&mut self, step: &Step) {
        let product = self.product.clone();
        let before: Vec<(&str, &str, &str)> =
            [("SetTargetPath", "INSTALLDIR", "1")].into_iter().chain(step.before.iter().copied()).collect();
        self.step(&Step { before: &before, ..*step }, "FolderLabel", "FolderLabel");
        let d = step.dialog;
        let label = format!("&Install {product} to:");
        self.control(d, "FolderLabel", "Text", (20, 56, 330, 12), LABEL, None, Some(&label), Some("Folder"));
        self.control(
            d,
            "Folder",
            "PathEdit",
            (20, 69, 330, 18),
            VISIBLE | ENABLED | SUNKEN,
            Some("INSTALLDIR"),
            None,
            Some("ChangeFolder"),
        );
        self.button(d, "ChangeFolder", (20, 91, 66, 17), BUTTON, "&Change...", "Back");
        self.events(d, "ChangeFolder", &[("SpawnDialog", "BrowseDlg")]);

        // The folder browser Change opens.
        let d = "BrowseDlg";
        self.dialog(d, WIDTH, HEIGHT, MODAL, "ComboLabel", Some("OK"), Some("Cancel"));
        self.page(d, "Change the install folder", &format!("Browse to the folder to install {product} to."));
        self.control(d, "ComboLabel", "Text", (25, 58, 44, 12), LABEL, None, Some("&Look in:"), Some("DirectoryCombo"));
        self.control(
            d,
            "DirectoryCombo",
            "DirectoryCombo",
            (70, 55, 200, 80),
            VISIBLE | ENABLED | FIXED_VOLUMES | REMOTE_VOLUMES,
            Some("INSTALLDIR"),
            None,
            Some("Up"),
        );
        self.button(d, "Up", (276, 55, 34, 17), BUTTON, "&Up", "NewFolder");
        self.button(d, "NewFolder", (314, 55, 36, 17), BUTTON, "Ne&w", "DirectoryList");
        self.control(
            d,
            "DirectoryList",
            "DirectoryList",
            (25, 80, 325, 100),
            VISIBLE | ENABLED | SUNKEN,
            Some("INSTALLDIR"),
            None,
            Some("PathLabel"),
        );
        self.control(d, "PathLabel", "Text", (25, 186, 325, 12), LABEL, None, Some("&Folder name:"), Some("PathEdit"));
        self.control(
            d,
            "PathEdit",
            "PathEdit",
            (25, 199, 325, 18),
            VISIBLE | ENABLED | SUNKEN,
            Some("INSTALLDIR"),
            None,
            Some("OK"),
        );
        self.button(d, "OK", (240, 243, 56, 17), BUTTON, "OK", "Cancel");
        self.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "ComboLabel");
        self.events(d, "Up", &[("DirectoryListUp", "0")]);
        self.events(d, "NewFolder", &[("DirectoryListNew", "0")]);
        self.events(d, "OK", &[("SetTargetPath", "INSTALLDIR"), ("EndDialog", "Return")]);
        self.events(d, "Cancel", &[("Reset", "0"), ("EndDialog", "Return")]);
        // The name a new folder gets in the browser.
        self.ui_text.row(vec![s("NewFolder"), s("Folder|New Folder")]);
    }

    /// Repair or remove (`MaintenanceDlg`), when it's already installed:
    /// `repair` and `remove` say what each does.
    pub fn maintenance_page(&mut self, repair: &str, remove: &str) {
        let d = "MaintenanceDlg";
        self.dialog(d, WIDTH, HEIGHT, MODAL, "Repair", None, Some("Cancel"));
        self.page(d, "Repair or remove", &format!("{} is already installed on this PC.", self.product));
        self.button(d, "Repair", (20, 65, 80, 17), BUTTON | ELEVATION_SHIELD, "&Repair", "Remove");
        self.text(d, "RepairText", (110, 67, 240, 30), repair);
        self.button(d, "Remove", (20, 105, 80, 17), BUTTON | ELEVATION_SHIELD, "Re&move", "Back");
        self.text(d, "RemoveText", (110, 107, 240, 30), remove);
        self.button(d, "Back", BACK, VISIBLE, "&Back", "Next");
        self.button(d, "Next", NEXT, VISIBLE, "&Next", "Cancel");
        self.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "Repair");
        self.events(d, "Repair", &[("[REINSTALL]", "ALL"), ("[REINSTALLMODE]", "ecmus"), ("EndDialog", "Return")]);
        self.events(d, "Remove", &[("[REMOVE]", "ALL"), ("EndDialog", "Return")]);
        self.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);
    }

    /// Progress (`ProgressDlg`), while Windows Installer works.
    pub fn progress_page(&mut self) {
        let d = "ProgressDlg";
        let product = self.product.clone();
        self.dialog(d, WIDTH, HEIGHT, DLG_VISIBLE | DLG_MINIMIZE, "Cancel", Some("Cancel"), Some("Cancel"));
        self.control(d, "BannerLine", "Line", (0, 44, WIDTH, 0), VISIBLE, None, None, None);
        self.control(d, "BottomLine", "Line", (0, 234, WIDTH, 0), VISIBLE, None, None, None);
        for (name, doing, condition) in [
            ("TitleInstalling", "Installing", INSTALLING),
            ("TitleRepairing", "Repairing", REPAIRING),
            ("TitleRemoving", "Removing", REMOVING),
        ] {
            let title = self.title(&format!("{doing} {product}"));
            self.shown_if(d, name, (15, 6, 340, 15), &title, condition);
        }
        self.text(d, "Description", (25, 23, 330, 15), "This takes a moment.");
        self.text(d, "StatusLabel", (20, 70, 50, 12), "Status:");
        self.control(d, "ActionText", "Text", (70, 70, 280, 12), VISIBLE | ENABLED | NO_PREFIX, None, None, None);
        self.control(
            d,
            "ProgressBar",
            "ProgressBar",
            (20, 88, 330, 12),
            VISIBLE | PROGRESS95,
            None,
            Some("Progress"),
            None,
        );
        self.button(d, "Back", BACK, VISIBLE, "&Back", "Next");
        self.button(d, "Next", NEXT, VISIBLE, "&Next", "Cancel");
        self.button(d, "Cancel", CANCEL, BUTTON, "Cancel", "Back");
        self.events(d, "Cancel", &[("SpawnDialog", "CancelDlg")]);
        self.mapping.row(vec![s(d), s("ActionText"), s("ActionText"), s("Text")]);
        self.mapping.row(vec![s(d), s("ProgressBar"), s("SetProgress"), s("Progress")]);
    }

    /// The ends: done (`ExitDlg`), cancelled (`UserExitDlg`), failed
    /// (`FatalErrorDlg`).
    pub fn ends(&mut self, ends: &Ends) {
        let product = self.product.clone();
        let finish = |ui: &mut Ui, d: &str, title: &str| {
            ui.dialog(d, WIDTH, HEIGHT, MODAL, "Finish", Some("Finish"), Some("Finish"));
            ui.page(d, title, "");
            ui.button(d, "Back", BACK, VISIBLE, "&Back", "Finish");
            ui.button(d, "Finish", NEXT, BUTTON, "&Finish", "Cancel");
            ui.button(d, "Cancel", CANCEL, VISIBLE, "Cancel", "Back");
        };
        let body = (20, 60, 330, 60);
        let d = "ExitDlg";
        finish(self, d, "Done");
        if ends.finish.is_empty() {
            self.events(d, "Finish", &[("EndDialog", "Return")]);
        } else {
            self.events_if(d, "Finish", ends.finish);
        }
        self.shown_if(d, "Installed", body, ends.installed, INSTALLING);
        self.shown_if(d, "Repaired", body, &format!("{product} is repaired."), REPAIRING);
        self.shown_if(d, "Removed", body, ends.removed, REMOVING);
        for (d, title, action, text) in [
            (
                "UserExitDlg",
                "Cancelled",
                ends.cancelled,
                format!("{product}'s setup was cancelled. Nothing was changed."),
            ),
            (
                "FatalErrorDlg",
                "Setup failed",
                ends.failed,
                format!(
                    "{product}'s setup stopped because of an error, and nothing was changed. A log (msiexec /l*v) \
                     tells why."
                ),
            ),
        ] {
            finish(self, d, title);
            let events: Vec<(&str, &str)> =
                action.map(|a| ("DoAction", a)).into_iter().chain([("EndDialog", "Exit")]).collect();
            self.events(d, "Finish", &events);
            self.text(d, "Body", body, &text);
        }
    }

    /// Are you sure? (`CancelDlg`, which every page's Cancel opens.)
    pub fn cancel_dialog(&mut self) {
        let d = "CancelDlg";
        self.dialog(d, 260, 85, MODAL, "No", Some("No"), Some("No"));
        let text = format!("Cancel {}'s setup?", self.product);
        self.text(d, "Text", (20, 15, 220, 30), &text);
        self.button(d, "Yes", (72, 57, 56, 17), BUTTON, "&Yes", "No");
        self.button(d, "No", (132, 57, 56, 17), BUTTON, "&No", "Yes");
        self.events(d, "Yes", &[("EndDialog", "Exit")]);
        self.events(d, "No", &[("EndDialog", "Return")]);
    }

    /// Windows Installer's own messages (`ErrorDlg`): it shows the buttons
    /// each needs.
    pub fn error_dialog(&mut self) {
        let d = ERROR_DIALOG;
        self.dialog(d, 270, 105, MODAL | DLG_ERROR, "ErrorText", None, None);
        self.control(d, "ErrorText", "Text", (48, 15, 205, 60), TEXT, None, None, None);
        for (button, text, event) in [
            ("A", "&Abort", "ErrorAbort"),
            ("C", "&Cancel", "ErrorCancel"),
            ("I", "&Ignore", "ErrorIgnore"),
            ("N", "&No", "ErrorNo"),
            ("O", "&OK", "ErrorOk"),
            ("R", "&Retry", "ErrorRetry"),
            ("Y", "&Yes", "ErrorYes"),
        ] {
            self.control(d, button, "PushButton", (100, 80, 56, 17), BUTTON, None, Some(text), None);
            self.events(d, button, &[("EndDialog", event)]);
        }
    }

    /// The properties the UI needs: its default font, and its error dialog.
    pub fn properties(&self) -> [(&'static str, String); 2] {
        [("DefaultUIFont", self.normal.clone()), ("ErrorDialog", ERROR_DIALOG.to_string())]
    }

    pub fn into_tables(self) -> Vec<Table> {
        vec![
            self.dialog,
            self.control,
            self.event,
            self.condition,
            self.mapping,
            self.style,
            self.check_box,
            self.ui_text,
            self.action_text,
        ]
    }
}

/// The UI sequence's dialogs, with their conditions and sequence numbers:
/// the first page (`first`, or repair or remove), the progress page just
/// before the install runs, and the ends.
pub fn sequence(first: &str) -> [(&str, Option<&str>, i32); 6] {
    [
        (first, Some(INSTALLING), 1290),
        ("MaintenanceDlg", Some("Installed AND NOT REMOVE"), 1291),
        ("ProgressDlg", None, 1299),
        ("ExitDlg", None, -1),
        ("UserExitDlg", None, -2),
        ("FatalErrorDlg", None, -3),
    ]
}

/// What Windows Installer would refuse in the UI's tables, found before a
/// page is shown:
/// - a dialog whose tab order isn't one cycle through each of its controls
///   that has a next control, from the first (error 2810, which it reported
///   for one of Warlock's), or whose first, default or cancel control isn't
///   its own;
/// - an event, condition or mapping of a control the dialog hasn't got;
/// - a button that changes dialogs twice in one press. Given two dialog
///   events whose conditions both hold, Windows Installer does only the last
///   (seen with Warlock 0.2.0's SpawnDialog then EndDialog), so a control's
///   dialog events must be one, or two whose conditions are each other's
///   opposite.
pub fn check(tables: &[Table]) -> Result<()> {
    fn rows<'a>(tables: &'a [Table], name: &str) -> Result<&'a [Vec<Cell>]> {
        Ok(&tables.iter().find(|t| t.name == name).ok_or_else(|| format!("no {name} table"))?.rows)
    }
    fn cell(row: &[Cell], i: usize) -> Option<&str> {
        row.get(i).and_then(|c| c.as_deref())
    }
    let controls = rows(tables, "Control")?;
    for dialog in rows(tables, "Dialog")? {
        let d = cell(dialog, 0).unwrap_or("");
        let names: BTreeSet<&str> =
            controls.iter().filter(|c| cell(c, 0) == Some(d)).filter_map(|c| cell(c, 1)).collect();
        for i in [7, 8, 9] {
            if let Some(c) = cell(dialog, i)
                && !names.contains(c)
            {
                return Err(format!("{d}: no control {c}").into());
            }
        }
        let next: BTreeMap<&str, &str> = controls
            .iter()
            .filter(|c| cell(c, 0) == Some(d))
            .filter_map(|c| Some((cell(c, 1)?, cell(c, 10)?)))
            .collect();
        if next.is_empty() {
            continue;
        }
        let mut pointed = BTreeSet::new();
        for (from, to) in &next {
            if !names.contains(to) {
                return Err(format!("{d}: {from} points to no control {to}").into());
            }
            if !pointed.insert(*to) {
                return Err(format!("{d}: two controls point to {to}").into());
            }
        }
        // From the first control, the cycle passes every one once.
        let start = cell(dialog, 7).unwrap_or("");
        let (mut at, mut seen) = (start, 0);
        loop {
            at = next.get(at).ok_or_else(|| format!("{d}: {at} leads nowhere in the tab order"))?;
            seen += 1;
            if at == start {
                break;
            }
            if seen > next.len() {
                return Err(format!("{d}: the cycle doesn't return to {start}").into());
            }
        }
        if seen != next.len() {
            return Err(format!("{d}: controls outside the cycle").into());
        }
    }
    for table in ["ControlEvent", "ControlCondition", "EventMapping"] {
        for row in rows(tables, table)? {
            let (d, c) = (cell(row, 0), cell(row, 1));
            if !controls.iter().any(|x| cell(x, 0) == d && cell(x, 1) == c) {
                return Err(format!("{table}: {}.{} isn't a control", d.unwrap_or(""), c.unwrap_or("")).into());
            }
        }
    }
    let mut by_control: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for r in rows(tables, "ControlEvent")? {
        if ["NewDialog", "SpawnDialog", "SpawnWaitDialog", "EndDialog"].contains(&cell(r, 2).unwrap_or("")) {
            by_control
                .entry((cell(r, 0).unwrap_or(""), cell(r, 1).unwrap_or("")))
                .or_default()
                .push(cell(r, 4).unwrap_or(""));
        }
    }
    for ((d, c), conditions) in by_control {
        match conditions.as_slice() {
            [_] => {}
            [a, b] if *b == format!("NOT {a}") || *a == format!("NOT {b}") => {}
            [a, b] => return Err(format!("{d}.{c}: dialog events under {a:?} and {b:?} can both happen").into()),
            more => return Err(format!("{d}.{c}: {} dialog events", more.len()).into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard pages, for a product with a licence page and the folder
    /// page, whose Next is Install.
    fn standard() -> Vec<Table> {
        let mut ui = Ui::new("Test");
        let licence = Step {
            dialog: "LicenseDlg",
            title: "Licences",
            description: "Test is free software.",
            back: None,
            next: Some("InstallDirDlg"),
            before: &[],
        };
        ui.document_page(&licence, "LicenseText", r"{\rtf1 x}", "A note.");
        let folder = Step {
            dialog: "InstallDirDlg",
            title: "Install folder",
            description: "Where Test goes.",
            back: Some("LicenseDlg"),
            next: None,
            before: &[],
        };
        ui.folder_page(&folder);
        ui.maintenance_page("Repairs it.", "Removes it.");
        ui.progress_page();
        ui.ends(&Ends { installed: "Installed.", removed: "Removed.", finish: &[], cancelled: None, failed: None });
        ui.cancel_dialog();
        ui.error_dialog();
        ui.into_tables()
    }

    fn table<'a>(tables: &'a mut [Table], name: &str) -> &'a mut Table {
        tables.iter_mut().find(|t| t.name == name).unwrap()
    }

    #[test]
    fn every_dialog_is_well_formed() {
        check(&standard()).unwrap();
    }

    #[test]
    fn a_broken_tab_order_is_found() {
        let mut tables = standard();
        let control = table(&mut tables, "Control");
        let row = control.rows.iter_mut().find(|r| r[0] == s("LicenseDlg") && r[1] == s("Next")).unwrap();
        row[10] = s("Back");
        let e = check(&tables).unwrap_err().to_string();
        assert!(e.starts_with("LicenseDlg: two controls point to Back"), "{e}");
    }

    #[test]
    fn a_button_changes_dialogs_once() {
        let mut tables = standard();
        table(&mut tables, "ControlEvent").row(vec![
            s("ExitDlg"),
            s("Finish"),
            s("NewDialog"),
            s("CancelDlg"),
            s("1"),
            n(2),
        ]);
        let e = check(&tables).unwrap_err().to_string();
        assert!(e.starts_with("ExitDlg.Finish: dialog events"), "{e}");
    }

    /// The last page's Next is Install, which sets the folder first, then
    /// ends the pages.
    #[test]
    fn the_last_page_installs() {
        let tables = standard();
        let events: Vec<(&str, &str)> = tables
            .iter()
            .find(|t| t.name == "ControlEvent")
            .unwrap()
            .rows
            .iter()
            .filter(|r| r[0] == s("InstallDirDlg") && r[1] == s("Install"))
            .map(|r| (r[2].as_deref().unwrap(), r[3].as_deref().unwrap()))
            .collect();
        assert_eq!(events, [("SetTargetPath", "INSTALLDIR"), ("EndDialog", "Return")]);
        let dialog = &tables[0].rows.iter().find(|r| r[0] == s("InstallDirDlg")).unwrap();
        assert_eq!(dialog[8], s("Install"));
    }

    #[test]
    fn the_sequence_names_the_pages() {
        let tables = standard();
        for (dialog, _, _) in sequence("LicenseDlg") {
            assert!(tables[0].rows.iter().any(|r| r[0] == s(dialog)), "no {dialog}");
        }
    }
}
