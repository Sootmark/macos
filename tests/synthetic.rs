//! Databases made by `tests/fixtures/synthetic/gen.sh` with the sqlite3
//! shell: a TCC database with the `access` table of macOS 14 (every
//! authorization value, reasons, a client by path, an Apple Events target,
//! a process and boot session, a reminder), and a KnowledgeC database with
//! macOS 10.14's tables, an event only in its write-ahead log and an
//! object whose source row is missing. And files that aren't these
//! artifacts.

mod support;

use std::time::Duration;

use common::time::Ts;
use macos::{read_knowledgec, read_quarantine, read_tcc, AuthReason, Authorization, ClientType};

fn fixture(name: &str) -> Vec<u8> {
    support::fixture(&format!("synthetic/{name}"))
}

/// 2026-09-01 08:00:00 UTC, the generator's first time, plus `seconds`.
fn at(seconds: i64) -> Ts {
    Ts::from_unix_seconds(1_788_249_600 + seconds)
}

#[test]
fn tcc_macos_14_decisions_and_reasons() {
    let tcc = read_tcc(&fixture("TCC.db"), &[]).unwrap();
    assert!(tcc.problems.is_empty(), "{:?}", tcc.problems);
    let decisions: Vec<_> = tcc
        .entries
        .iter()
        .map(|e| {
            (
                e.service.as_str(),
                e.client.as_str(),
                e.authorization,
                e.reason,
            )
        })
        .collect();
    assert_eq!(
        decisions,
        [
            (
                "kTCCServiceCamera",
                "com.example.meet",
                Some(Authorization::Allowed),
                Some(AuthReason::UserConsent)
            ),
            (
                "kTCCServiceScreenCapture",
                "com.example.recorder",
                Some(Authorization::Denied),
                Some(AuthReason::UserSet)
            ),
            (
                "kTCCServiceSystemPolicyAllFiles",
                "/usr/local/bin/backup-agent",
                Some(Authorization::Allowed),
                Some(AuthReason::UserSet)
            ),
            (
                "kTCCServiceAccessibility",
                "com.example.helper",
                Some(Authorization::Allowed),
                Some(AuthReason::MdmPolicy)
            ),
            (
                "kTCCServiceAppleEvents",
                "com.example.automation",
                Some(Authorization::Allowed),
                Some(AuthReason::UserConsent)
            ),
            (
                "kTCCServicePhotos",
                "com.example.gallery",
                Some(Authorization::Limited),
                Some(AuthReason::UserConsent)
            ),
            (
                "kTCCServiceMicrophone",
                "com.example.meet",
                Some(Authorization::Unknown),
                Some(AuthReason::Other(99))
            ),
        ]
    );

    let camera = &tcc.entries[0];
    assert_eq!(camera.client_type, Some(ClientType::BundleId));
    assert_eq!(camera.auth_version, Some(1));
    assert_eq!(camera.prompt_count, None);
    assert_eq!(camera.last_modified, Some(at(0)));
    assert_eq!(
        camera.code_requirement.as_deref().map(|b| &b[..4]),
        Some(&[0xfa, 0xde, 0x0c, 0x00][..])
    );
    // `UNUSED` and 0 mean none.
    assert_eq!(
        (camera.indirect_object.as_ref(), camera.boot_uuid.as_ref()),
        (None, None)
    );
    assert_eq!((camera.pid, camera.last_reminded), (None, None));

    let agent = &tcc.entries[2];
    assert_eq!(agent.client_type, Some(ClientType::Path));
    assert_eq!(agent.pid, Some(4242));
    assert_eq!(
        agent.boot_uuid.as_deref(),
        Some("5B1E3C2A-9D4F-4E61-8A7B-0C9D8E7F6A5B")
    );
    assert_eq!(agent.last_reminded, Some(at(86_400)));

    let events = &tcc.entries[4];
    assert_eq!(events.indirect_object.as_deref(), Some("com.apple.finder"));
    assert_eq!(events.indirect_object_type, Some(ClientType::BundleId));

    assert_eq!(Authorization::Limited.to_string(), "limited");
    assert_eq!(AuthReason::MdmPolicy.to_string(), "MDM policy");
    assert_eq!(AuthReason::Other(99).to_string(), "99");
}

#[test]
fn knowledgec_with_its_log() {
    let knowledgec =
        read_knowledgec(&fixture("knowledgeC.db"), &fixture("knowledgeC.db-wal")).unwrap();
    // Object 6 names source 9, which isn't there: kept, reported.
    assert_eq!(
        knowledgec.problems,
        ["ZOBJECT: row 6's ZSOURCE 9 is not in ZSOURCE"]
    );
    let streams: Vec<_> = knowledgec
        .events
        .iter()
        .map(|e| (e.rowid, e.stream.as_str(), e.app(), e.value_integer))
        .collect();
    assert_eq!(
        streams,
        [
            (1, "/device/isLocked", None, Some(0)),
            (2, "/display/isBacklit", None, Some(1)),
            (
                3,
                "/app/inFocus",
                Some("com.apple.Terminal"),
                Some(8_999_410_902_659_233_531)
            ),
            (
                4,
                "/safari/history",
                Some("com.apple.Safari"),
                Some(1_903_245_748_545_110_053)
            ),
            (
                5,
                "/app/usage",
                Some("com.apple.Terminal"),
                Some(8_999_410_902_659_233_531)
            ),
            (
                6,
                "/app/activity",
                Some("com.apple.Safari"),
                Some(2_939_589_157_913_874_707)
            ),
            (7, "/device/isLocked", None, Some(1)),
            // Only in the log.
            (8, "/app/inFocus", Some("com.example.editor"), None),
        ]
    );

    let safari = &knowledgec.events[3];
    assert_eq!(safari.value_string.as_deref(), Some("https://example.com/"));
    assert_eq!(safari.title.as_deref(), Some("Example Domain"));
    assert_eq!(safari.bundle_id.as_deref(), Some("com.apple.Safari"));
    assert_eq!(
        safari.device_id.as_deref(),
        Some("7F3E2D1C-0B9A-4877-8665-544332211000")
    );

    let locked = &knowledgec.events[0];
    // Mac absolute time read to the microsecond: compare the instants.
    let instant = |ts: Option<Ts>| ts.and_then(|ts| ts.ticks());
    assert_eq!(instant(locked.start), at(0).ticks());
    assert_eq!(instant(locked.end), at(5).ticks());
    assert_eq!(
        instant(locked.created),
        Ts::from_unix_micros(1_788_249_605_250_000).ticks()
    );
    assert_eq!(locked.seconds_from_gmt, Some(7200));
    assert_eq!(
        locked.uuid.as_deref(),
        Some("00000000-0000-4000-8000-000000000001")
    );
    assert_eq!(
        knowledgec.events[4].duration(),
        Some(Duration::from_secs(295))
    );

    // Without its log, the database as last checkpointed.
    let checkpointed = read_knowledgec(&fixture("knowledgeC.db"), &[]).unwrap();
    assert_eq!(checkpointed.events.len(), 7);
}

#[test]
fn other_files_are_refused() {
    let tcc = fixture("TCC.db");
    let knowledgec = fixture("knowledgeC.db");
    assert!(read_quarantine(&tcc, &[]).is_err());
    assert!(read_knowledgec(&tcc, &[]).is_err());
    assert!(read_tcc(&knowledgec, &[]).is_err());
    assert!(read_tcc(b"not a database", &[]).is_err());
    assert!(read_tcc(&[], &[]).is_err());
    assert_eq!(
        read_quarantine(&tcc, &[]).unwrap_err().to_string(),
        "not a quarantine events database: no LSQuarantineEvent table"
    );
}
