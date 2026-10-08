//! Messages: `~/Library/Messages/chat.db` (and iOS's `sms.db`), the
//! iMessage and SMS store.
//!
//! A SQLite database: each message is a `message` row, with the other
//! party in the `handle` row its `handle_id` names (a phone number or an
//! email address; 0 for none, as in a group's messages), the conversation
//! in the `chat` row `chat_message_join` pairs it with, and its files in
//! the `attachment` rows `message_attachment_join` pairs it with.
//! `is_from_me` says which way it went, `is_read` whether it was read.
//!
//! Dates are Mac absolute time, UTC: seconds since 2001-01-01 until about
//! macOS 10.13, nanoseconds since (a value beyond ±10⁹ is nanoseconds, as
//! one of seconds would be after 2032); 0 means none. From macOS 13 the
//! `text` column is often empty and the text is only in `attributedBody`,
//! an archived `NSAttributedString` (a `typedstream`), whose string is read
//! from there. `_SqliteDatabaseProperties` holds the client's version.

use std::collections::HashMap;

use common::time::Ts;
use sqlite::Database;

use crate::table::{self, Named};
use crate::{open, Error};

/// A message, sent or received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// `ROWID`: the order messages were stored in.
    pub rowid: i64,
    /// `guid`: the message's identifier across devices.
    pub guid: Option<String>,
    /// Its text: `text`, or the string in `attributedBody` when `text` is
    /// empty.
    pub text: Option<String>,
    /// The other party (`handle.id`): a phone number or an email address.
    pub handle: Option<String>,
    /// `service`: `iMessage` or `SMS`.
    pub service: Option<String>,
    /// `account`: the local account (`e:alice@icloud.com`).
    pub account: Option<String>,
    /// `is_from_me`: sent from this account, rather than received.
    pub from_me: Option<bool>,
    /// `is_read`: read (a received message), or its read receipt received.
    pub read: Option<bool>,
    /// `date`: when it was sent or received.
    pub date: Option<Ts>,
    /// `date_read`: when it was read.
    pub date_read: Option<Ts>,
    /// `date_delivered`: when it was delivered.
    pub date_delivered: Option<Ts>,
    /// The conversation (`chat.chat_identifier`): the other party, or a
    /// group's identifier.
    pub chat: Option<String>,
    /// Its attachments' paths (`attachment.filename`, in
    /// `~/Library/Messages/Attachments/`).
    pub attachments: Vec<String>,
}

/// A Messages database's messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Messages {
    /// One per `message` row, in row order.
    pub messages: Vec<Message>,
    /// `_ClientVersion` in `_SqliteDatabaseProperties`.
    pub client_version: Option<i64>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read a Messages database (`chat.db`, `sms.db`), with its `-wal` file's
/// committed changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database with `message`.
pub fn read_messages(database: &[u8], wal: &[u8]) -> Result<Messages, Error> {
    let db = open(database, wal, "message", "Messages")?;
    let mut problems = db.problems.clone();
    let client_version = table::read(&db, "_SqliteDatabaseProperties", &mut problems, |row| {
        (row.text("key"), row.text("value"))
    })
    .into_iter()
    .find(|(key, _)| key.as_deref() == Some("_ClientVersion"))
    .and_then(|(_, value)| value?.parse().ok());
    let handles = names(&db, "handle", "id", &mut problems);
    let chats = names(&db, "chat", "chat_identifier", &mut problems);
    let files = names(&db, "attachment", "filename", &mut problems);
    let mut chat_of = HashMap::new();
    for (message, chat) in pairs(&db, "chat_message_join", "chat_id", &mut problems) {
        chat_of.entry(message).or_insert(chat);
    }
    let mut files_of: HashMap<i64, Vec<i64>> = HashMap::new();
    for (message, file) in pairs(
        &db,
        "message_attachment_join",
        "attachment_id",
        &mut problems,
    ) {
        files_of.entry(message).or_default().push(file);
    }
    let messages = table::read(&db, "message", &mut problems, |row| {
        let chat = chat_of.get(&row.rowid).and_then(|chat| chats.get(chat));
        let attachments = files_of
            .get(&row.rowid)
            .into_iter()
            .flatten()
            .filter_map(|file| files.get(file).cloned())
            .collect();
        Message {
            rowid: row.rowid,
            guid: row.text("guid"),
            text: row
                .text("text")
                .filter(|text| !text.is_empty())
                .or_else(|| row.blob("attributedBody").and_then(|b| archived_string(&b))),
            handle: row
                .integer("handle_id")
                .and_then(|id| handles.get(&id))
                .cloned(),
            service: row.text("service"),
            account: row.text("account"),
            from_me: flag(row, "is_from_me"),
            read: flag(row, "is_read"),
            date: date(row, "date"),
            date_read: date(row, "date_read"),
            date_delivered: date(row, "date_delivered"),
            chat: chat.cloned(),
            attachments,
        }
    });
    Ok(Messages {
        messages,
        client_version,
        problems,
    })
}

/// A table's `column` by rowid, where it has one.
fn names(
    db: &Database<'_>,
    table: &str,
    column: &str,
    problems: &mut Vec<String>,
) -> HashMap<i64, String> {
    table::read(db, table, problems, |row| {
        Some((row.rowid, row.text(column)?))
    })
    .into_iter()
    .flatten()
    .collect()
}

/// A join table's rows: the message and what `column` pairs it with.
fn pairs(
    db: &Database<'_>,
    table: &str,
    column: &str,
    problems: &mut Vec<String>,
) -> Vec<(i64, i64)> {
    table::read(db, table, problems, |row| {
        Some((row.integer("message_id")?, row.integer(column)?))
    })
    .into_iter()
    .flatten()
    .collect()
}

/// A 0 or 1 column as a yes or no.
fn flag(row: &Named<'_>, column: &str) -> Option<bool> {
    row.integer(column).map(|value| value != 0)
}

/// Seconds between the Unix epoch and Mac absolute time's, 2001-01-01.
const MAC_EPOCH_UNIX_SECONDS: i64 = 978_307_200;

/// A message date: Mac absolute time in seconds or, beyond ±10⁹,
/// nanoseconds; none when 0, absent, or out of range.
fn date(row: &Named<'_>, column: &str) -> Option<Ts> {
    const NANOS_PER_SECOND: i64 = 1_000_000_000;
    let value = row.integer(column).filter(|&value| value != 0)?;
    let time = if value.unsigned_abs() > NANOS_PER_SECOND.unsigned_abs() {
        Ts::from_unix_nanos(value.checked_add(MAC_EPOCH_UNIX_SECONDS * NANOS_PER_SECOND)?)
    } else {
        Ts::from_unix_seconds(value + MAC_EPOCH_UNIX_SECONDS)
    };
    time.ticks().map(|_| time)
}

/// The string an archived `NSAttributedString` holds (`attributedBody`):
/// in the `typedstream`, the `NSString` class name is followed by its
/// object, a `+` type tag, the string's length in bytes and its UTF-8
/// bytes. The length is one byte below 0x80, else 0x81 then 2 bytes or
/// 0x82 then 4 bytes, little-endian.
fn archived_string(body: &[u8]) -> Option<String> {
    const CLASS: &[u8] = b"NSString";
    let after_class = body.windows(CLASS.len()).position(|w| w == CLASS)? + CLASS.len();
    let rest = body.get(after_class..)?;
    // The type tag is a few bytes on: the class's version and references.
    let tag = rest.iter().take(8).position(|&b| b == b'+')?;
    let rest = rest.get(tag + 1..)?;
    let (length, rest) = match *rest.first()? {
        0x81 => (
            usize::from(u16::from_le_bytes(rest.get(1..3)?.try_into().ok()?)),
            rest.get(3..)?,
        ),
        0x82 => (
            usize::try_from(u32::from_le_bytes(rest.get(1..5)?.try_into().ok()?)).ok()?,
            rest.get(5..)?,
        ),
        short if short < 0x80 => (usize::from(short), rest.get(1..)?),
        _ => return None,
    };
    let text = String::from_utf8_lossy(rest.get(..length)?).into_owned();
    Some(text).filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of an archived `NSAttributedString`, as Messages writes it.
    fn body(text: &str, length: &[u8]) -> Vec<u8> {
        let mut body = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+".to_vec();
        body.extend_from_slice(length);
        body.extend_from_slice(text.as_bytes());
        body.extend_from_slice(b"\x86\x84\x02iI\x01\x05\x92");
        body
    }

    #[test]
    fn strings_from_archived_bodies() {
        assert_eq!(
            archived_string(&body("Hello", b"\x05")).as_deref(),
            Some("Hello")
        );
        let long = "é".repeat(100);
        assert_eq!(
            archived_string(&body(&long, b"\x81\xc8\x00")).as_deref(),
            Some(long.as_str())
        );
        assert_eq!(
            archived_string(&body("x", b"\x82\x01\x00\x00\x00")).as_deref(),
            Some("x")
        );
        assert_eq!(archived_string(&body("Hello", b"\x7f")), None);
        assert_eq!(archived_string(b"NSString"), None);
        assert_eq!(archived_string(b""), None);
    }
}
