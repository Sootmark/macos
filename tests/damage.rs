//! Arbitrary bytes, and real databases damaged and cut anywhere, read or
//! are refused: never a panic.

mod support;

use proptest::prelude::*;

/// Every artifact, every schema version.
const DATABASES: [&str; 11] = [
    "plaso/quarantine.db",
    "plaso/TCC-test.db",
    "plaso/knowledgec-10.13.db.gz",
    "plaso/knowledgec-10.14.db.gz",
    "synthetic/TCC.db",
    "synthetic/knowledgeC.db",
    "plaso/application_usage.sqlite",
    "plaso/document_versions.sql",
    "plaso/NotesV7.storedata",
    "plaso/mac_notificationcenter.db",
    "plaso/imessage_chat.db.gz",
];

const DATABASE: &str = "synthetic/knowledgeC.db";
const LOG: &str = "synthetic/knowledgeC.db-wal";

/// Every reader on the same bytes: each must read or refuse them.
fn read_everything(data: &[u8], wal: &[u8]) {
    let _ = macos::read_quarantine(data, wal);
    let _ = macos::read_tcc(data, wal);
    let _ = macos::read_knowledgec(data, wal);
    if let Ok(read) = macos::read_launchd(data, "Library/LaunchAgents/x.plist") {
        let _ = (read.job.flags(), read.job.command_line());
    }
    let _ = macos::read_fsevents(data);
    let _ = macos::read_background_items(data);
    let _ = macos::read_asl(data);
    let _ = macos::read_launchd_log(data);
    let _ = macos::read_wifi_log(
        data,
        macos::Years {
            earliest: 2014,
            latest: 2026,
            current: 2026,
        },
    );
    let _ = macos::read_app_usage(data, wal);
    let _ = macos::read_document_versions(data, wal);
    let _ = macos::read_notes(data, wal);
    let _ = macos::read_notifications(data, wal);
    let _ = macos::read_messages(data, wal);
    if let Ok(keychain) = macos::read_keychain(data) {
        for item in &keychain.items {
            let _ = (
                item.name(),
                item.protocol(),
                item.created(),
                item.four_cc("crtr"),
            );
        }
    }
    for kind in [
        macos::PrefKind::InstallHistory,
        macos::PrefKind::SoftwareUpdate,
        macos::PrefKind::Airport,
        macos::PrefKind::Bluetooth,
        macos::PrefKind::AppleAccount,
        macos::PrefKind::LoginItems,
        macos::PrefKind::LoginWindow,
        macos::PrefKind::User,
        macos::PrefKind::StartupItem,
        macos::PrefKind::TimeMachine,
        macos::PrefKind::SpotlightShortcuts,
        macos::PrefKind::SpotlightVolume,
    ] {
        let _ = macos::read_prefs(kind, data);
    }
}

proptest! {
    #[test]
    fn damaged_launchd_plists_never_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40),
    ) {
        let mut data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/plaso/launchd.plist"
        ))
        .unwrap();
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        read_everything(&data, &[]);
    }


    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        read_everything(&data, &[]);
    }

    /// A keychain's header with arbitrary tables behind it.
    #[test]
    fn arbitrary_keychain_tables_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut data = b"kych\x00\x01\x00\x00\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00\x00".to_vec();
        data.extend(tail);
        read_everything(&data, &[]);
    }

    /// A real keychain damaged anywhere, many times over.
    #[test]
    fn damaged_keychains_never_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..60),
        cut in any::<usize>(),
    ) {
        let mut data = support::fixture("plaso/login.keychain");
        for &(at, byte) in &flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(1 + cut % data.len());
        read_everything(&data, &[]);
    }

    #[test]
    fn arbitrary_names_never_panic(name in ".{0,200}") {
        let _ = macos::detect(&name);
    }

    /// A real header with arbitrary pages behind it.
    #[test]
    fn arbitrary_pages_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let mut data = support::fixture("plaso/TCC-test.db")[..100].to_vec();
        data.extend(tail);
        read_everything(&data, &[]);
    }

    #[test]
    fn damaged_databases_never_panic(
        which in 0..DATABASES.len(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40),
        cut in any::<usize>(),
    ) {
        let mut data = support::fixture(DATABASES[which]);
        for &(at, byte) in &flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(1 + cut % data.len());
        read_everything(&data, &[]);
    }

    #[test]
    fn damaged_logs_never_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..20),
        cut in any::<usize>(),
    ) {
        let database = support::fixture(DATABASE);
        let mut wal = support::fixture(LOG);
        for &(at, byte) in &flips {
            let at = at % wal.len();
            wal[at] = byte;
        }
        wal.truncate(cut % (wal.len() + 1));
        read_everything(&database, &wal);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn damaged_fsevents_and_background_items(
        at in 0usize..2000,
        bytes in proptest::collection::vec(any::<u8>(), 1..32),
        cut in 0usize..2000,
    ) {
        for name in [
            "plaso/backgrounditems.btm",
            "plaso/fsevents-0000000002d89b58",
            "plaso/com.apple.loginitems.plist",
            "plaso/user.plist",
            "plaso/applesystemlog.asl",
            "plaso/login.keychain",
            "plaso/com.apple.spotlight.plist",
        ] {
            let mut data = support::fixture(name);
            for (i, b) in bytes.iter().enumerate() {
                if let Some(slot) = data.get_mut(at + i) {
                    *slot = *b;
                }
            }
            data.truncate(cut);
            let _ = macos::read_fsevents(&data);
            let _ = macos::read_background_items(&data);
            let _ = macos::read_prefs(macos::PrefKind::LoginItems, &data);
            let _ = macos::read_prefs(macos::PrefKind::User, &data);
            let _ = macos::read_asl(&data);
            let _ = macos::read_keychain(&data);
            let _ = macos::read_prefs(macos::PrefKind::SpotlightShortcuts, &data);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Text logs: lines of log-like text, any years asked for.
    #[test]
    fn arbitrary_log_text_and_years_never_panic(
        text in "[ -~\t\n<>\\[\\]():.“”]{0,600}",
        earliest in any::<i64>(),
        latest in any::<i64>(),
        current in any::<i64>(),
    ) {
        let years = macos::Years { earliest, latest, current };
        let _ = macos::read_wifi_log(text.as_bytes(), years);
        let _ = macos::read_launchd_log(text.as_bytes());
        let lines = format!("Thu Dec 31 23:59:38.165 {text}\nFri Jan  1 00:00:00.000 x\n");
        let _ = macos::read_wifi_log(lines.as_bytes(), years);
    }

    /// plaso's Wi-Fi and launchd logs damaged and cut anywhere.
    #[test]
    fn damaged_text_logs_never_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40),
        cut in any::<usize>(),
    ) {
        for name in ["plaso/wifi.log", "plaso/wifi_turned_over.log"] {
            let mut data = support::fixture(name);
            for &(at, byte) in &flips {
                let at = at % data.len();
                data[at] = byte;
            }
            data.truncate(cut % (data.len() + 1));
            let years = macos::Years { earliest: 2014, latest: 2026, current: 2026 };
            let _ = macos::read_wifi_log(&data, years);
        }
        let mut data = support::fixture("plaso/macos_launchd.log.gz")[..20_000].to_vec();
        for &(at, byte) in &flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        let _ = macos::read_launchd_log(&data);
    }
}
