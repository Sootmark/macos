//! plaso's macOS test files (Apache-2.0, `tests/fixtures/plaso/`, see its
//! NOTICE), against what plaso's own tests expect of them
//! (`tests/parsers/sqlite_plugins/ls_quarantine.py`, `macos_tcc.py`,
//! `macos_knowledgec.py`, at the same commit).

mod support;

use std::time::Duration;

use common::time::Ts;
use macos::{read_knowledgec, read_quarantine, read_tcc, Authorization, ClientType, KnowledgeC};

fn fixture(name: &str) -> Vec<u8> {
    support::fixture(&format!("plaso/{name}"))
}

/// `2013-07-12T19:30:16.000000` from `Ts::to_iso8601`'s seven digits:
/// plaso's form, without its `+00:00`.
fn micros(ts: Option<Ts>) -> String {
    let iso = ts.and_then(|ts| ts.to_iso8601()).unwrap();
    iso[..26].to_owned()
}

#[test]
fn quarantine_events_as_plaso_expects() {
    let quarantine = read_quarantine(&fixture("quarantine.db"), &[]).unwrap();
    assert!(quarantine.problems.is_empty(), "{:?}", quarantine.problems);
    // plaso: 14 events.
    assert_eq!(quarantine.events.len(), 14);

    let event = &quarantine.events[10];
    assert_eq!(event.agent_name.as_deref(), Some("Google Chrome"));
    assert_eq!(
        event.data_url.as_deref(),
        Some(
            "http://download.mackeeper.zeobit.com/package.php?key=460245286&trt=5&landpr=Speedtest"
        )
    );
    assert_eq!(micros(event.time), "2013-07-12T19:30:16.000000");
    assert_eq!(
        event.origin_url.as_deref(),
        Some(concat!(
            "http://mackeeperapp.zeobit.com/aff/speedtest.net.6/download.php?",
            "affid=460245286&trt=5&utm_campaign=3ES&tid_ext=P107fSKcSfqpMbcP3",
            "sI4fhKmeMchEB3dkAGpX4YIsvM;US;L;1"
        ))
    );
    // Beyond what plaso reads.
    assert_eq!(event.id, "C63B3AE4-5FAB-4DB6-9773-1D5E6500A46A");
    assert_eq!(event.agent_bundle_id.as_deref(), Some("com.google.Chrome"));
    assert_eq!(event.type_number, Some(0));
    assert_eq!(
        (event.sender_name.as_ref(), event.origin_alias.as_ref()),
        (None, None)
    );

    // The one time with a fraction, to the microsecond.
    assert_eq!(
        micros(quarantine.events[0].time),
        "2013-07-08T16:24:27.020743"
    );
}

#[test]
fn tcc_before_macos_11_as_plaso_expects() {
    let tcc = read_tcc(&fixture("TCC-test.db"), &[]).unwrap();
    assert!(tcc.problems.is_empty(), "{:?}", tcc.problems);
    // plaso: 21 entries.
    assert_eq!(tcc.entries.len(), 21);

    let first = &tcc.entries[0];
    assert_eq!(first.service, "kTCCServiceUbiquity");
    assert_eq!(first.client, "com.apple.weather");
    assert_eq!(first.authorization, Some(Authorization::Allowed));
    assert_eq!(first.prompt_count, Some(1));
    assert_eq!(
        first.last_modified.unwrap().to_iso8601().unwrap(),
        "2020-05-29T12:09:51.0000000Z"
    );
    // Beyond what plaso reads; no `auth_value` here, so no reason.
    assert_eq!(first.client_type, Some(ClientType::BundleId));
    assert_eq!((first.reason, first.auth_version), (None, None));
    assert_eq!(first.indirect_object, None);
    assert_eq!(first.code_requirement.as_ref().map(Vec::len), Some(48));

    let camera = &tcc.entries[19];
    assert_eq!(
        (camera.service.as_str(), camera.client.as_str()),
        ("kTCCServiceCamera", "com.google.Chrome")
    );
    assert_eq!(camera.flags, None);
}

/// plaso reads the `/app/…` and `/safari/…` streams only.
fn plaso_events(knowledgec: &KnowledgeC) -> Vec<&macos::KnowledgeEvent> {
    knowledgec
        .events
        .iter()
        .filter(|e| e.stream.starts_with("/app/") || e.stream.starts_with("/safari/"))
        .collect()
}

#[test]
fn knowledgec_10_13_as_plaso_expects() {
    let knowledgec = read_knowledgec(&fixture("knowledgec-10.13.db.gz"), &[]).unwrap();
    assert!(knowledgec.problems.is_empty(), "{:?}", knowledgec.problems);
    // All 21 objects; plaso's 17 are the app streams.
    assert_eq!(knowledgec.events.len(), 21);
    let events = plaso_events(&knowledgec);
    assert_eq!(events.len(), 17);

    let first = events[0];
    assert_eq!(first.stream, "/app/inFocus");
    assert_eq!(first.app(), Some("com.apple.Installer-Progress"));
    // Stored 571510798.8606649637: plaso (dfdatetime) truncates to
    // .860664, `Ts::from_cocoa_seconds` rounds to the nearest microsecond.
    assert_eq!(micros(first.created), "2019-02-10T16:59:58.860665");
    assert_eq!(micros(first.start), "2019-02-10T16:59:57.000000");
    assert_eq!(micros(first.end), "2019-02-10T16:59:58.000000");
    assert_eq!(first.duration(), Some(Duration::from_secs(1)));
}

#[test]
fn knowledgec_10_14_as_plaso_expects() {
    let knowledgec = read_knowledgec(&fixture("knowledgec-10.14.db.gz"), &[]).unwrap();
    assert!(knowledgec.problems.is_empty(), "{:?}", knowledgec.problems);
    assert_eq!(knowledgec.events.len(), 92);
    let events = plaso_events(&knowledgec);
    assert_eq!(events.len(), 77);

    let terminal = events[75];
    assert_eq!(terminal.stream, "/app/usage");
    assert_eq!(terminal.app(), Some("com.apple.Terminal"));
    assert_eq!(micros(terminal.created), "2019-05-08T13:57:30.668998");
    assert_eq!(micros(terminal.start), "2019-05-08T13:40:09.000000");
    assert_eq!(micros(terminal.end), "2019-05-08T13:57:30.000000");
    assert_eq!(terminal.duration(), Some(Duration::from_secs(1041)));
    assert_eq!(terminal.seconds_from_gmt, Some(-25200));

    let safari = events[70];
    assert_eq!(safari.stream, "/safari/history");
    assert_eq!(
        safari.value_string.as_deref(),
        Some("https://www.instagram.com/")
    );
    assert_eq!(safari.title.as_deref(), Some("Instagram"));
    assert_eq!(micros(safari.created), "2019-05-08T13:57:20.626870");
    assert_eq!(micros(safari.start), "2019-05-08T13:57:20.000000");
    assert_eq!(micros(safari.end), "2019-05-08T13:57:20.000000");
    assert_eq!(safari.duration(), Some(Duration::ZERO));
    // Beyond what plaso reads: the donating app, through ZSOURCE.
    assert_eq!(safari.bundle_id.as_deref(), Some("com.apple.Safari"));
    assert_eq!(safari.app(), Some("com.apple.Safari"));
    assert_eq!(safari.device_id, None);

    // A yes/no stream plaso leaves out.
    let backlit = knowledgec
        .events
        .iter()
        .find(|e| e.stream == "/display/isBacklit")
        .unwrap();
    assert_eq!((backlit.rowid, backlit.value_integer), (13, Some(1)));
}
