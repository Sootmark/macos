//! plaso's application usage, document versions, Notes and Notification
//! Center databases (Apache-2.0, `tests/fixtures/plaso/`, see its NOTICE):
//! every event plaso reads from them, read the same
//! (`tests/oracle/plaso-usage.tsv`, written by `tests/oracle/gen_usage.py`
//! from plaso's output).

mod support;

use common::time::Ts;
use macos::{read_app_usage, read_document_versions, read_notes, read_notifications};

fn fixture(name: &str) -> Vec<u8> {
    support::fixture(&format!("plaso/{name}"))
}

fn micros(ts: Ts) -> i64 {
    ts.ticks().unwrap() / 10
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// An event line: kind, which time, the time, values (`None`s left out).
fn line(kind: &str, desc: &str, ts: Ts, values: &[(&str, Option<String>)]) -> String {
    let mut cells = vec![kind.to_owned(), desc.to_owned(), micros(ts).to_string()];
    for (key, value) in values {
        if let Some(value) = value {
            cells.push(format!("{key}={}", escape(value)));
        }
    }
    cells.join("\t")
}

fn app_usage() -> Vec<String> {
    let usage = read_app_usage(&fixture("application_usage.sqlite"), &[]).unwrap();
    assert!(usage.problems.is_empty(), "{:?}", usage.problems);
    usage
        .uses
        .iter()
        .map(|u| {
            line(
                "application_usage",
                "Last Used Time",
                u.last_time.unwrap(),
                &[
                    ("activity", u.event.clone()),
                    ("application", u.path.clone()),
                    ("application_version", u.version.clone()),
                    ("bundle_identifier", u.bundle_id.clone()),
                    ("count", u.count.map(|c| c.to_string())),
                ],
            )
        })
        .collect()
}

fn document_versions() -> Vec<String> {
    let versions = read_document_versions(&fixture("document_versions.sql"), &[]).unwrap();
    assert!(versions.problems.is_empty(), "{:?}", versions.problems);
    let mut lines = Vec::new();
    for v in &versions.versions {
        let values = [
            ("name", v.name.clone()),
            // plaso gives the folder.
            (
                "path",
                v.path
                    .as_deref()
                    .and_then(|p| p.rsplit_once('/'))
                    .map(|(folder, _)| folder.to_owned()),
            ),
            ("user_sid", v.uid.map(|u| u.to_string())),
            ("version_path", Some(v.version_path.clone())),
        ];
        for (desc, time) in [("Creation Time", v.saved), ("Last Seen Time", v.last_seen)] {
            lines.push(line("document_versions", desc, time.unwrap(), &values));
        }
    }
    lines
}

fn notes() -> Vec<String> {
    let notes = read_notes(&fixture("NotesV7.storedata"), &[]).unwrap();
    assert!(notes.problems.is_empty(), "{:?}", notes.problems);
    let mut lines = Vec::new();
    for n in &notes.notes {
        let values = [("text", Some(n.text.clone())), ("title", n.title.clone())];
        for (desc, time) in [
            ("Creation Time", n.created),
            ("Content Modification Time", n.edited),
        ] {
            lines.push(line("notes", desc, time.unwrap(), &values));
        }
    }
    lines
}

fn notifications() -> Vec<String> {
    let center = read_notifications(&fixture("mac_notificationcenter.db"), &[]).unwrap();
    assert!(center.problems.is_empty(), "{:?}", center.problems);
    center
        .notifications
        .iter()
        .map(|n| {
            line(
                "notification_center",
                "Creation Time",
                n.delivered.unwrap(),
                &[
                    ("bundle_name", n.app.clone()),
                    ("message_body", n.body.clone()),
                    ("presented", n.presented.map(|p| u8::from(p).to_string())),
                    ("subtitle", n.subtitle.clone()),
                    ("title", n.title.clone()),
                ],
            )
        })
        .collect()
}

#[test]
fn every_event_as_plaso_reads_it() {
    let mut got: Vec<String> =
        [app_usage(), document_versions(), notes(), notifications()].concat();
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-usage.tsv").lines().collect();
    assert_eq!(got.len(), expected.len());
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
}

#[test]
fn beyond_plaso() {
    let versions = read_document_versions(&fixture("document_versions.sql"), &[]).unwrap();
    let first = &versions.versions[0];
    assert_eq!(first.client.as_deref(), Some("com.apple.documentVersions"));
    assert!(first.size.is_some_and(|s| s > 0));
}
