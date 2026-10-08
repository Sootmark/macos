//! plaso's macOS property lists (Apache-2.0, `tests/fixtures/plaso/`, see
//! its NOTICE): every event plaso's plist plugins (`macos_bluetooth`,
//! `apple_id`, `airport`, `time_machine`, `macos_software_update`,
//! `macuser`, `macos_login_items_plist`, `macos_login_window_plist`,
//! `macos_startup_item_plist`) read, read the same
//! (`tests/oracle/plaso-prefs.tsv`, written from plaso's output); and
//! `InstallHistory.plist`, which plaso's command line doesn't read,
//! against the values the file holds; and the Spotlight property lists,
//! every event its `spotlight` and `spotlight_volume` plugins read
//! (`tests/oracle/plaso-spotlight-prefs.tsv`, written by
//! `tests/oracle/gen_events.py`).

mod support;

use std::collections::BTreeSet;

use macos::{detect, read_prefs, Artifact, PrefEntry, PrefKind};

/// An entry as plaso's events: one row per time (or one without), the
/// values each plugin shows.
fn rows(name: &str, kind: PrefKind, entry: &PrefEntry) -> Vec<String> {
    let get = |field: &str| entry.get(field).unwrap_or_default().to_owned();
    let values: Vec<String> = match kind {
        PrefKind::Bluetooth => vec![get("Address"), get("Name"), get("Paired")],
        PrefKind::AppleAccount => vec![get("AppleId"), get("FirstName"), get("LastName")],
        PrefKind::Airport => vec![get("Ssid"), get("Security")],
        PrefKind::TimeMachine => vec![get("DestinationId"), get("Name")],
        PrefKind::SoftwareUpdate => vec![get("SystemVersion"), get("RecommendedUpdates")],
        PrefKind::User => vec![
            get("Name"),
            get("FullName"),
            get("Home"),
            get("Uid"),
            get("FailedLogins"),
        ],
        PrefKind::LoginItems => vec![
            get("Name"),
            get("Hidden"),
            get("TargetPath"),
            get("VolumeName"),
            get("VolumeMountPoint"),
        ],
        PrefKind::LoginWindow => {
            let mut values = vec![get("Kind"), get("Path")];
            if entry.get("Hidden").is_some() {
                values.push(get("Hidden"));
            }
            values
        }
        PrefKind::StartupItem => vec![
            get("Description"),
            get("Provides"),
            get("Uses"),
            get("OrderPreference"),
        ],
        PrefKind::InstallHistory => vec![get("Name")],
        PrefKind::SpotlightShortcuts => vec![get("Term"), get("DisplayName"), get("Path")],
        PrefKind::SpotlightVolume => vec![get("Kind"), get("StoreId"), get("PartialPath")],
    };
    let row = |when: String| {
        [vec![name.to_owned(), when], values.clone()]
            .concat()
            .join("\t")
    };
    // plaso keeps one of the software update's times, the full one.
    let times: Vec<&(&str, common::time::Ts)> = entry
        .times
        .iter()
        .filter(|(n, _)| kind != PrefKind::SoftwareUpdate || *n == "LastFullSuccessful")
        .filter(|(n, _)| kind != PrefKind::User || *n == "PasswordLastSet")
        .collect();
    if times.is_empty() {
        return vec![row(String::new())];
    }
    times
        .iter()
        .map(|(n, t)| row(format!("{n}={}", (t.ticks().unwrap() + 5).div_euclid(10))))
        .collect()
}

#[test]
fn as_plaso_reads_them() {
    let mut got = BTreeSet::new();
    let mut login_window = Vec::new();
    for name in [
        "StartupParameters.plist",
        "com.apple.SoftwareUpdate.plist",
        "com.apple.airport.preferences.plist",
        "com.apple.bluetooth.plist",
        "com.apple.coreservices.appleidauthenticationinfo.ABC0ABC1-ABC0-ABC0-ABC0-ABC0ABC1ABC2.plist",
        "com.apple.loginitems.plist",
        "loginwindow.plist",
        "user.plist",
        "com.apple.TimeMachine.plist",
    ] {
        let path = if name == "user.plist" {
            format!("private/var/db/dslocal/nodes/Default/users/{name}")
        } else {
            name.to_owned()
        };
        let Some(Artifact::Prefs(kind)) = detect(&path) else {
            panic!("{name}: not detected");
        };
        let prefs = read_prefs(kind, &support::fixture(&format!("plaso/{name}")));
        assert_eq!(prefs.problems, Vec::<String>::new(), "{name}");
        for entry in &prefs.entries {
            let entry_rows = rows(name, kind, entry);
            if kind == PrefKind::LoginWindow && entry.get("Hidden").is_none() {
                login_window.extend(entry_rows);
            } else {
                got.extend(entry_rows);
            }
        }
    }
    // plaso puts both hooks in one event.
    let hooks: Vec<String> = login_window
        .iter()
        .map(|r| r.splitn(3, '\t').nth(2).unwrap_or_default().to_owned())
        .collect();
    got.insert(format!("loginwindow.plist\t\t{}", hooks.join("\t")));
    let expected: BTreeSet<&str> = include_str!("oracle/plaso-prefs.tsv").lines().collect();
    let got_refs: BTreeSet<&str> = got.iter().map(String::as_str).collect();
    let missing: Vec<&&str> = expected.difference(&got_refs).collect();
    let extra: Vec<&&str> = got_refs.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "missing {missing:#?}\nextra {extra:#?}"
    );
}

#[test]
fn install_history() {
    let prefs = read_prefs(
        PrefKind::InstallHistory,
        &support::fixture("plaso/InstallHistory.plist"),
    );
    assert_eq!(prefs.problems, Vec::<String>::new());
    let first = &prefs.entries[0];
    assert_eq!(first.get("Name"), Some("OS X"));
    assert_eq!(first.get("Version"), Some("10.9 (13A603)"));
    assert_eq!(
        first.times[0].1.to_iso8601().as_deref(),
        Some("2013-11-12T02:59:35.0000000Z")
    );
    assert!(first
        .get("Packages")
        .unwrap()
        .starts_with("com.apple.pkg.BaseSystemBinaries, "));
}

/// A Spotlight entry as plaso's events: data type, which time, the time in
/// microseconds, values.
fn spotlight_lines(kind: PrefKind, entry: &PrefEntry) -> Vec<String> {
    let get = |field: &str| entry.get(field).map(str::to_owned);
    let (data_type, time, desc, values) = match kind {
        PrefKind::SpotlightShortcuts => (
            "spotlight_searched_terms:entry",
            "LastUsed",
            "Last Used Time",
            vec![
                ("application_display_name", get("DisplayName")),
                ("path", get("Path")),
                ("search_term", get("Term")),
            ],
        ),
        // plaso reads the stores, not the exclusions.
        _ if entry.get("Kind") == Some("exclusion") => return Vec::new(),
        _ => (
            "spotlight_volume_configuration:store",
            "Created",
            "Creation Time",
            vec![
                ("partial_path", get("PartialPath")),
                ("volume_identifier", get("StoreId")),
            ],
        ),
    };
    entry
        .times
        .iter()
        .filter(|(name, _)| *name == time)
        .map(|(_, ts)| {
            let mut cells = vec![
                data_type.to_owned(),
                desc.to_owned(),
                (ts.ticks().unwrap() / 10).to_string(),
            ];
            cells.extend(
                values
                    .iter()
                    .filter_map(|(key, value)| Some(format!("{key}={}", value.as_ref()?))),
            );
            cells.join("\t")
        })
        .collect()
}

#[test]
fn spotlight_as_plaso_reads_them() {
    let mut got = Vec::new();
    for (name, path) in [
        (
            "com.apple.spotlight.plist",
            "Users/a/Library/Preferences/com.apple.spotlight.plist",
        ),
        (
            "VolumeConfiguration.plist",
            ".Spotlight-V100/VolumeConfiguration.plist",
        ),
    ] {
        let Some(Artifact::Prefs(kind)) = detect(path) else {
            panic!("{path}: not detected");
        };
        let prefs = read_prefs(kind, &support::fixture(&format!("plaso/{name}")));
        assert_eq!(prefs.problems, Vec::<String>::new(), "{name}");
        for entry in &prefs.entries {
            got.extend(spotlight_lines(kind, entry));
        }
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-spotlight-prefs.tsv")
        .lines()
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn spotlight_beyond_plaso() {
    let prefs = read_prefs(
        PrefKind::SpotlightVolume,
        &support::fixture("plaso/VolumeConfiguration.plist"),
    );
    let root = prefs
        .entries
        .iter()
        .find(|e| e.get("PartialPath") == Some("/"))
        .unwrap();
    assert_eq!(
        root.get("PolicyLevel"),
        Some("kMDConfigSearchLevelReadWrite")
    );
    assert_eq!(
        root.times[1].1.to_iso8601().as_deref(),
        Some("2013-05-27T12:27:37.0000000Z")
    );
    // The test file excludes nothing; one that does.
    assert!(prefs.entries.iter().all(|e| e.get("Kind") == Some("store")));
    let excluding = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Exclusions</key><array><string>/Users/a/Hidden</string></array>
</dict></plist>"#;
    let prefs = read_prefs(PrefKind::SpotlightVolume, excluding);
    assert_eq!(prefs.entries.len(), 1);
    assert_eq!(prefs.entries[0].get("Kind"), Some("exclusion"));
    assert_eq!(prefs.entries[0].get("Path"), Some("/Users/a/Hidden"));
}
