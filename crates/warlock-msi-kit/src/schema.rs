// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! Windows Installer's standard tables, each empty, with its columns and
//! primary key. The column definitions are copied from MSIs Windows itself
//! installed, exported from `C:\Windows\Installer`: on 2026-11-18 for
//! Warlock's builder, and the Registry and Shortcut tables, which Warlock
//! doesn't use, on 2026-11-21 (alike in every package there that had them).

use crate::Table;

pub fn property() -> Table {
    Table::new("Property", &[("Property", "s72"), ("Value", "l0")], &["Property"])
}

pub fn directory() -> Table {
    Table::new(
        "Directory",
        &[("Directory", "s72"), ("Directory_Parent", "S72"), ("DefaultDir", "l255")],
        &["Directory"],
    )
}

pub fn component() -> Table {
    Table::new(
        "Component",
        &[
            ("Component", "s72"),
            ("ComponentId", "S38"),
            ("Directory_", "s72"),
            ("Attributes", "i2"),
            ("Condition", "S255"),
            ("KeyPath", "S72"),
        ],
        &["Component"],
    )
}

pub fn feature() -> Table {
    Table::new(
        "Feature",
        &[
            ("Feature", "s38"),
            ("Feature_Parent", "S38"),
            ("Title", "L64"),
            ("Description", "L255"),
            ("Display", "I2"),
            ("Level", "i2"),
            ("Directory_", "S72"),
            ("Attributes", "i2"),
        ],
        &["Feature"],
    )
}

/// A feature's level under a condition.
pub fn condition() -> Table {
    Table::new("Condition", &[("Feature_", "s38"), ("Level", "i2"), ("Condition", "S255")], &["Feature_", "Level"])
}

pub fn feature_components() -> Table {
    Table::new("FeatureComponents", &[("Feature_", "s38"), ("Component_", "s72")], &["Feature_", "Component_"])
}

/// The files; [`crate::file_table`] fills it in from the payload.
pub fn file() -> Table {
    Table::new(
        "File",
        &[
            ("File", "s72"),
            ("Component_", "s72"),
            ("FileName", "l255"),
            ("FileSize", "i4"),
            ("Version", "S72"),
            ("Language", "S20"),
            ("Attributes", "I2"),
            ("Sequence", "i4"),
        ],
        &["File"],
    )
}

/// The disks; [`crate::media_table`] fills it in.
pub fn media() -> Table {
    Table::new(
        "Media",
        &[
            ("DiskId", "i2"),
            ("LastSequence", "i4"),
            ("DiskPrompt", "L64"),
            ("Cabinet", "S255"),
            ("VolumeLabel", "S32"),
            ("Source", "S72"),
        ],
        &["DiskId"],
    )
}

pub fn upgrade() -> Table {
    Table::new(
        "Upgrade",
        &[
            ("UpgradeCode", "s38"),
            ("VersionMin", "S20"),
            ("VersionMax", "S20"),
            ("Language", "S255"),
            ("Attributes", "i4"),
            ("Remove", "S255"),
            ("ActionProperty", "s72"),
        ],
        &["UpgradeCode", "VersionMin", "VersionMax", "Language", "Attributes"],
    )
}

pub fn app_search() -> Table {
    Table::new("AppSearch", &[("Property", "s72"), ("Signature_", "s72")], &["Property", "Signature_"])
}

pub fn signature() -> Table {
    Table::new(
        "Signature",
        &[
            ("Signature", "s72"),
            ("FileName", "s255"),
            ("MinVersion", "S20"),
            ("MaxVersion", "S20"),
            ("MinSize", "I4"),
            ("MaxSize", "I4"),
            ("MinDate", "I4"),
            ("MaxDate", "I4"),
            ("Languages", "S255"),
        ],
        &["Signature"],
    )
}

pub fn dr_locator() -> Table {
    Table::new(
        "DrLocator",
        &[("Signature_", "s72"), ("Parent", "S72"), ("Path", "S255"), ("Depth", "I2")],
        &["Signature_", "Parent", "Path"],
    )
}

pub fn reg_locator() -> Table {
    Table::new(
        "RegLocator",
        &[("Signature_", "s72"), ("Root", "i2"), ("Key", "s255"), ("Name", "S255"), ("Type", "I2")],
        &["Signature_"],
    )
}

pub fn comp_locator() -> Table {
    Table::new("CompLocator", &[("Signature_", "s72"), ("ComponentId", "s38"), ("Type", "I2")], &["Signature_"])
}

pub fn launch_condition() -> Table {
    Table::new("LaunchCondition", &[("Condition", "s255"), ("Description", "l255")], &["Condition"])
}

pub fn service_install() -> Table {
    Table::new(
        "ServiceInstall",
        &[
            ("ServiceInstall", "s72"),
            ("Name", "s255"),
            ("DisplayName", "L255"),
            ("ServiceType", "i4"),
            ("StartType", "i4"),
            ("ErrorControl", "i4"),
            ("LoadOrderGroup", "S255"),
            ("Dependencies", "S255"),
            ("StartName", "S255"),
            ("Password", "S255"),
            ("Arguments", "S255"),
            ("Component_", "s72"),
            ("Description", "L255"),
        ],
        &["ServiceInstall"],
    )
}

pub fn service_control() -> Table {
    Table::new(
        "ServiceControl",
        &[
            ("ServiceControl", "s72"),
            ("Name", "l255"),
            ("Event", "i2"),
            ("Arguments", "L255"),
            ("Wait", "I2"),
            ("Component_", "s72"),
        ],
        &["ServiceControl"],
    )
}

pub fn msi_service_config() -> Table {
    Table::new(
        "MsiServiceConfig",
        &[
            ("MsiServiceConfig", "s72"),
            ("Name", "l255"),
            ("Event", "i2"),
            ("ConfigType", "i4"),
            ("Argument", "S0"),
            ("Component_", "s72"),
        ],
        &["MsiServiceConfig"],
    )
}

pub fn custom_action() -> Table {
    Table::new(
        "CustomAction",
        &[("Action", "s72"), ("Type", "i2"), ("Source", "S72"), ("Target", "S255"), ("ExtendedType", "I4")],
        &["Action"],
    )
}

/// Binaries; [`crate::Database::binary`] adds the rows, as streams.
pub fn binary() -> Table {
    Table::new("Binary", &[("Name", "s72"), ("Data", "v0")], &["Name"])
}

pub fn environment() -> Table {
    Table::new(
        "Environment",
        &[("Environment", "s72"), ("Name", "l255"), ("Value", "L255"), ("Component_", "s72")],
        &["Environment"],
    )
}

pub fn registry() -> Table {
    Table::new(
        "Registry",
        &[
            ("Registry", "s72"),
            ("Root", "i2"),
            ("Key", "l255"),
            ("Name", "L255"),
            ("Value", "L0"),
            ("Component_", "s72"),
        ],
        &["Registry"],
    )
}

pub fn shortcut() -> Table {
    Table::new(
        "Shortcut",
        &[
            ("Shortcut", "s72"),
            ("Directory_", "s72"),
            ("Name", "l128"),
            ("Component_", "s72"),
            ("Target", "s72"),
            ("Arguments", "S255"),
            ("Description", "L255"),
            ("Hotkey", "I2"),
            ("Icon_", "S72"),
            ("IconIndex", "I2"),
            ("ShowCmd", "I2"),
            ("WkDir", "S72"),
            ("DisplayResourceDLL", "S255"),
            ("DisplayResourceId", "I2"),
            ("DescriptionResourceDLL", "S255"),
            ("DescriptionResourceId", "I2"),
        ],
        &["Shortcut"],
    )
}

/// A sequence table by its name; [`crate::sequence`] fills one in.
pub fn sequence(name: &'static str) -> Table {
    Table::new(name, &[("Action", "s72"), ("Condition", "S255"), ("Sequence", "I2")], &["Action"])
}

// The UI's tables, which `ui::Ui` fills in.

pub fn dialog() -> Table {
    Table::new(
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
    )
}

pub fn control() -> Table {
    Table::new(
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
    )
}

pub fn control_event() -> Table {
    Table::new(
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
    )
}

pub fn control_condition() -> Table {
    Table::new(
        "ControlCondition",
        &[("Dialog_", "s72"), ("Control_", "s50"), ("Action", "s50"), ("Condition", "s255")],
        &["Dialog_", "Control_", "Action", "Condition"],
    )
}

pub fn event_mapping() -> Table {
    Table::new(
        "EventMapping",
        &[("Dialog_", "s72"), ("Control_", "s50"), ("Event", "s50"), ("Attribute", "s50")],
        &["Dialog_", "Control_", "Event"],
    )
}

pub fn text_style() -> Table {
    Table::new(
        "TextStyle",
        &[("TextStyle", "s72"), ("FaceName", "s32"), ("Size", "i2"), ("Color", "I4"), ("StyleBits", "I2")],
        &["TextStyle"],
    )
}

pub fn check_box() -> Table {
    Table::new("CheckBox", &[("Property", "s72"), ("Value", "S64")], &["Property"])
}

pub fn ui_text() -> Table {
    Table::new("UIText", &[("Key", "s72"), ("Text", "L255")], &["Key"])
}

pub fn action_text() -> Table {
    Table::new("ActionText", &[("Action", "s72"), ("Description", "L0"), ("Template", "L0")], &["Action"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    /// Windows Installer takes every definition: each table imports into a
    /// new package.
    #[test]
    fn windows_installer_takes_every_table() {
        let dir = std::env::temp_dir().join(format!("warlock-msi-kit-schema-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("schema.msi");
        let db = Database::create(&path).unwrap();
        for t in [
            property(),
            directory(),
            component(),
            feature(),
            condition(),
            feature_components(),
            file(),
            media(),
            upgrade(),
            app_search(),
            signature(),
            dr_locator(),
            reg_locator(),
            comp_locator(),
            launch_condition(),
            service_install(),
            service_control(),
            msi_service_config(),
            custom_action(),
            binary(),
            environment(),
            registry(),
            shortcut(),
            sequence("InstallExecuteSequence"),
            dialog(),
            control(),
            control_event(),
            control_condition(),
            event_mapping(),
            text_style(),
            check_box(),
            ui_text(),
            action_text(),
        ] {
            db.import(&t).unwrap_or_else(|e| panic!("{}: {e}", t.name));
        }
        db.commit().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
