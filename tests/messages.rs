//! plaso's Messages database (Apache-2.0, `tests/fixtures/plaso/`, see its
//! NOTICE): every event its `imessage` plugin reads, read the same
//! (`tests/oracle/plaso-messages.tsv`, written by
//! `tests/oracle/gen_events.py` from plaso's output).

mod support;

use macos::{detect, read_messages, Artifact, Message};

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// A message as plaso's events: one per attachment (its query joins them),
/// or one without.
fn lines(message: &Message, client_version: Option<i64>) -> Vec<String> {
    let flag = |value: Option<bool>| value.map(|v| u8::from(v).to_string());
    let micros = message.date.unwrap().ticks().unwrap() / 10;
    let attachments: Vec<Option<&String>> = if message.attachments.is_empty() {
        vec![None]
    } else {
        message.attachments.iter().map(Some).collect()
    };
    attachments
        .into_iter()
        .map(|attachment| {
            let values = [
                ("attachment_location", attachment.cloned()),
                ("client_version", client_version.map(|v| v.to_string())),
                ("imessage_id", message.handle.clone()),
                ("message_type", flag(message.from_me)),
                ("offset", Some(message.rowid.to_string())),
                ("read_receipt", flag(message.read)),
                ("service", message.service.clone()),
                ("text", message.text.clone()),
            ];
            let mut cells = vec![
                "imessage:event:chat".to_owned(),
                "Creation Time".to_owned(),
                micros.to_string(),
            ];
            cells.extend(
                values
                    .iter()
                    .filter_map(|(key, value)| Some(format!("{key}={}", escape(value.as_ref()?)))),
            );
            cells.join("\t")
        })
        .collect()
}

#[test]
fn every_message_as_plaso_reads_it() {
    let read = read_messages(&support::fixture("plaso/imessage_chat.db.gz"), &[]).unwrap();
    assert!(read.problems.is_empty(), "{:?}", read.problems);
    let mut got: Vec<String> = read
        .messages
        .iter()
        .flat_map(|m| lines(m, read.client_version))
        .collect();
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-messages.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn beyond_plaso() {
    let read = read_messages(&support::fixture("plaso/imessage_chat.db.gz"), &[]).unwrap();
    let first = &read.messages[0];
    assert_eq!(
        first.guid.as_deref(),
        Some("C78A4031-C135-4746-A974-C455B0C4F5E4")
    );
    assert_eq!(first.account.as_deref(), Some("e:ken.doh@icloud.com"));
    assert_eq!(first.chat.as_deref(), Some("+447775446518"));
    let iso = |t: Option<common::time::Ts>| t.and_then(|t| t.to_iso8601());
    assert_eq!(
        iso(first.date_read).as_deref(),
        Some("2015-11-22T18:13:22.0000000Z")
    );
    assert_eq!(iso(read.messages[1].date_read), None);
    assert_eq!(
        detect("/Users/a/Library/Messages/chat.db"),
        Some(Artifact::Messages)
    );
}
