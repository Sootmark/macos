//! Every entry of every test database, field by field, against the sqlite3
//! shell 3.46.1 reading the same files (`tests/oracle/`, made by its
//! `gen.sh`): plaso's four and the synthetic ones, the KnowledgeC one with
//! its write-ahead log.

mod support;

use std::fmt::Write;

use common::time::Ts;
use macos::{read_knowledgec, read_quarantine, read_tcc, ClientType};

/// The oracle's lines, each split into its fields; `\N` is NULL.
fn oracle(name: &str) -> Vec<Vec<Option<String>>> {
    let path = format!("{}/tests/oracle/{name}.tsv", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| {
            line.split('\t')
                .map(|field| (field != "\\N").then(|| field.to_owned()))
                .collect()
        })
        .collect()
}

fn integer(field: Option<&str>) -> Option<i64> {
    field.map(|value| value.parse().unwrap())
}

/// A Mac absolute time as the shell printed it, six decimals.
fn mac_time(field: Option<&str>) -> Option<Ts> {
    field.map(|value| Ts::from_cocoa_seconds(value.parse().unwrap()))
}

/// Bytes as the shell's `hex()` prints them: NULL and empty alike.
fn hex(bytes: Option<&Vec<u8>>) -> String {
    bytes.map_or_else(String::new, |bytes| {
        bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02X}");
            hex
        })
    })
}

#[test]
fn quarantine_events_match_sqlite3() {
    let data = support::fixture("plaso/quarantine.db");
    let events = read_quarantine(&data, &[]).unwrap().events;
    let expected = oracle("quarantine.db");
    assert_eq!(events.len(), expected.len());
    for (e, row) in events.iter().zip(&expected) {
        assert_eq!(Some(e.rowid), integer(row[0].as_deref()));
        assert_eq!(Some(&e.id), row[1].as_ref());
        assert_eq!(e.time, mac_time(row[2].as_deref()), "row {}", e.rowid);
        assert_eq!(e.agent_bundle_id, row[3]);
        assert_eq!(e.agent_name, row[4]);
        assert_eq!(e.data_url, row[5]);
        assert_eq!(e.sender_name, row[6]);
        assert_eq!(e.sender_address, row[7]);
        assert_eq!(e.type_number, integer(row[8].as_deref()));
        assert_eq!(e.origin_title, row[9]);
        assert_eq!(e.origin_url, row[10]);
        assert_eq!(Some(hex(e.origin_alias.as_ref())), row[11]);
    }
}

#[test]
fn tcc_entries_match_sqlite3() {
    for (fixture, name, modern) in [
        ("plaso/TCC-test.db", "TCC-test.db", false),
        ("synthetic/TCC.db", "TCC.db", true),
    ] {
        let entries = read_tcc(&support::fixture(fixture), &[]).unwrap().entries;
        let expected = oracle(name);
        assert_eq!(entries.len(), expected.len(), "{name}");
        for (e, row) in entries.iter().zip(&expected) {
            assert_eq!(Some(e.rowid), integer(row[0].as_deref()), "{name}");
            assert_eq!(Some(&e.service), row[1].as_ref());
            assert_eq!(Some(&e.client), row[2].as_ref());
            let client_type = e.client_type.map(|t| match t {
                ClientType::BundleId => 0,
                ClientType::Path => 1,
                ClientType::Other(value) => value,
            });
            assert_eq!(client_type, integer(row[3].as_deref()));
            // The decision's raw value: `auth_value`, or `allowed`.
            let decision = e.authorization.map(|a| match a {
                macos::Authorization::Denied => 0,
                macos::Authorization::Unknown => 1,
                macos::Authorization::Allowed => i64::from(modern) + 1,
                macos::Authorization::Limited => 3,
                macos::Authorization::Other(value) => value,
            });
            assert_eq!(
                decision,
                integer(row[4].as_deref()),
                "{name} row {}",
                e.rowid
            );
            assert_eq!(e.reason.is_some(), row[5].is_some());
            assert_eq!(
                e.last_modified,
                integer(row[6].as_deref()).map(Ts::from_unix_seconds)
            );
            let indirect = row[7].clone().filter(|object| object != "UNUSED");
            assert_eq!(e.indirect_object, indirect);
            assert_eq!(Some(hex(e.code_requirement.as_ref())), row[8]);
        }
    }
}

#[test]
fn knowledgec_events_match_sqlite3() {
    for (fixture, wal, name) in [
        ("plaso/knowledgec-10.13.db.gz", None, "knowledgec-10.13.db"),
        ("plaso/knowledgec-10.14.db.gz", None, "knowledgec-10.14.db"),
        (
            "synthetic/knowledgeC.db",
            Some("synthetic/knowledgeC.db-wal"),
            "knowledgeC.db",
        ),
    ] {
        let data = support::fixture(fixture);
        let wal = wal.map(support::fixture).unwrap_or_default();
        let events = read_knowledgec(&data, &wal).unwrap().events;
        let expected = oracle(name);
        assert_eq!(events.len(), expected.len(), "{name}");
        for (e, row) in events.iter().zip(&expected) {
            assert_eq!(Some(e.rowid), integer(row[0].as_deref()), "{name}");
            assert_eq!(Some(&e.stream), row[1].as_ref());
            assert_eq!(e.value_string, row[2]);
            assert_eq!(e.value_integer, integer(row[3].as_deref()));
            assert_eq!(
                e.start,
                mac_time(row[4].as_deref()),
                "{name} row {}",
                e.rowid
            );
            assert_eq!(e.end, mac_time(row[5].as_deref()));
            assert_eq!(e.created, mac_time(row[6].as_deref()));
            assert_eq!(e.seconds_from_gmt, integer(row[7].as_deref()));
            assert_eq!(e.uuid, row[8]);
            assert_eq!(e.bundle_id, row[9]);
            assert_eq!(e.device_id, row[10]);
            assert_eq!(e.title, row[11]);
        }
    }
}
