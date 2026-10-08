//! Arbitrary bytes, and real databases damaged and cut anywhere, read or
//! are refused: never a panic.

mod support;

use proptest::prelude::*;

/// Every artifact, every schema version.
const DATABASES: [&str; 6] = [
    "plaso/quarantine.db",
    "plaso/TCC-test.db",
    "plaso/knowledgec-10.13.db.gz",
    "plaso/knowledgec-10.14.db.gz",
    "synthetic/TCC.db",
    "synthetic/knowledgeC.db",
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
        }
    }
}
