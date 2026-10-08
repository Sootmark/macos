//! plaso's macOS property lists (Apache-2.0, `tests/fixtures/plaso/`, see
//! its NOTICE): every event plaso's plist plugins (`macos_bluetooth`,
//! `apple_id`, `airport`, `time_machine`, `macos_software_update`,
//! `macuser`, `macos_login_items_plist`, `macos_login_window_plist`,
//! `macos_startup_item_plist`) read, read the same
//! (`tests/oracle/plaso-prefs.tsv`, written from plaso's output); and
//! `InstallHistory.plist`, which plaso's command line doesn't read,
//! against the values the file holds.

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
