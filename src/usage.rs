//! What was used and kept, in four databases:
//!
//! - application usage (`/var/db/application_usage.sqlite`, written by
//!   Google's crankd where Macs are managed with it): each app's launches
//!   and quits, with the last time and how many;
//! - document versions (`/.DocumentRevisions-V100/db-V1/db.sqlite`): every
//!   saved version of a document, with where the version is kept and the
//!   user who saved it, even after the document is gone;
//! - Notes before macOS 10.11 (`Library/Containers/com.apple.Notes/Data/
//!   Library/Notes/NotesV7.storedata`): each note's title, text and times;
//! - Notification Center (`…/com.apple.notificationcenter/db2/db`): each
//!   notification an app showed, with its title, subtitle and body.

use common::time::Ts;
use plist::Value;

use crate::table::{self, Named};
use crate::{mac_time, open, Error};

/// An app's launches or quits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUse {
    /// `event`: `launch` or `quit`.
    pub event: Option<String>,
    /// `bundle_id` (`com.apple.Safari`).
    pub bundle_id: Option<String>,
    /// `app_version`.
    pub version: Option<String>,
    /// `app_path`.
    pub path: Option<String>,
    /// `number_times`: how many.
    pub count: Option<i64>,
    /// `last_time`: the last one (Unix seconds).
    pub last_time: Option<Ts>,
}

/// An application usage database's rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUsage {
    /// One per app and event, in row order.
    pub uses: Vec<AppUse>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read an `application_usage.sqlite`, with its `-wal` file's committed
/// changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database with `application_usage`.
pub fn read_app_usage(database: &[u8], wal: &[u8]) -> Result<AppUsage, Error> {
    const TABLE: &str = "application_usage";
    let db = open(database, wal, TABLE, "application usage")?;
    let mut problems = db.problems.clone();
    let uses = table::read(&db, TABLE, &mut problems, |row| AppUse {
        event: row.text("event"),
        bundle_id: row.text("bundle_id"),
        version: row.text("app_version"),
        path: row.text("app_path"),
        count: row.integer("number_times"),
        last_time: unix(row, "last_time"),
    });
    Ok(AppUsage { uses, problems })
}

/// A saved version of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentVersion {
    /// The document's name (`files.file_name`).
    pub name: Option<String>,
    /// Its path, name included (`files.file_path`).
    pub path: Option<String>,
    /// When the document was last seen (`files.file_last_seen`).
    pub last_seen: Option<Ts>,
    /// Where the version is kept, from the volume's root
    /// (`/.DocumentRevisions-V100/PerUID/501/…`).
    pub version_path: String,
    /// When the version was saved (`generations.generation_add_time`).
    pub saved: Option<Ts>,
    /// The user who saved it: the id in `PerUID/<id>/`.
    pub uid: Option<u32>,
    /// The app that saved it (`generations.generation_client_id`).
    pub client: Option<String>,
    /// The version's size (`generations.generation_size`).
    pub size: Option<i64>,
}

/// A document revisions database's versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentVersions {
    /// One per version, in the generations' row order.
    pub versions: Vec<DocumentVersion>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// The folder versions are kept under, at the volume's root.
const REVISIONS_ROOT: &str = "/.DocumentRevisions-V100/";

/// Read a document revisions database (`db.sqlite`), with its `-wal`
/// file's committed changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database with `generations`.
pub fn read_document_versions(database: &[u8], wal: &[u8]) -> Result<DocumentVersions, Error> {
    let db = open(database, wal, "generations", "document revisions")?;
    let mut problems = db.problems.clone();
    let files = table::read(&db, "files", &mut problems, |row| {
        let file = (
            row.text("file_name"),
            row.text("file_path"),
            unix(row, "file_last_seen"),
        );
        (row.integer("file_storage_id"), file)
    });
    let versions = table::read(&db, "generations", &mut problems, |row| {
        let storage = row.integer("generation_storage_id");
        let path = row.text("generation_path").unwrap_or_default();
        let generation = DocumentVersion {
            name: None,
            path: None,
            last_seen: None,
            uid: per_uid(&path),
            version_path: format!("{REVISIONS_ROOT}{path}"),
            saved: unix(row, "generation_add_time"),
            client: row.text("generation_client_id"),
            size: row.integer("generation_size"),
        };
        (storage, generation)
    });
    let versions = versions
        .into_iter()
        .filter_map(|(storage, version)| {
            let (_, (name, path, last_seen)) = files.iter().find(|(s, _)| *s == storage)?;
            Some(DocumentVersion {
                name: name.clone(),
                path: path.clone(),
                last_seen: *last_seen,
                ..version
            })
        })
        .collect();
    Ok(DocumentVersions { versions, problems })
}

/// The user id in a version's path, `PerUID/<id>/…`.
fn per_uid(path: &str) -> Option<u32> {
    path.split('/').nth(1)?.parse().ok()
}

/// A note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// `ZNOTE.ZTITLE`.
    pub title: Option<String>,
    /// The body's text, its HTML (`ZNOTEBODY.ZHTMLSTRING`) removed.
    pub text: String,
    /// `ZNOTE.ZDATECREATED`.
    pub created: Option<Ts>,
    /// `ZNOTE.ZDATEEDITED`.
    pub edited: Option<Ts>,
}

/// A Notes database's notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes {
    /// One per note with a body, in row order.
    pub notes: Vec<Note>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read a `NotesV7.storedata`, with its `-wal` file's committed changes
/// (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database with `ZNOTE`.
pub fn read_notes(database: &[u8], wal: &[u8]) -> Result<Notes, Error> {
    let db = open(database, wal, "ZNOTE", "Notes")?;
    let mut problems = db.problems.clone();
    let bodies = table::read(&db, "ZNOTEBODY", &mut problems, |row| {
        (row.rowid, row.text("ZHTMLSTRING"))
    });
    let notes = table::read(&db, "ZNOTE", &mut problems, |row| {
        (
            row.rowid,
            row.text("ZTITLE"),
            row.number("ZDATECREATED").map(mac_time),
            row.number("ZDATEEDITED").map(mac_time),
        )
    });
    let notes = notes
        .into_iter()
        .filter_map(|(id, title, created, edited)| {
            let (_, html) = bodies.iter().find(|(body, _)| *body == id)?;
            Some(Note {
                title,
                text: html_text(html.as_deref().unwrap_or_default()),
                created,
                edited,
            })
        })
        .collect();
    Ok(Notes { notes, problems })
}

/// The text of HTML: each run of text between tags and comments, its
/// character references decoded and its ends trimmed, joined with spaces
/// (as plaso extracts it). A `<` that doesn't open a tag is text.
fn html_text(html: &str) -> String {
    let mut runs = Vec::new();
    let mut text = String::new();
    let mut rest = html;
    while let Some(c) = rest.chars().next() {
        let skipped = if rest.starts_with("<!--") {
            Some(rest.find("-->").map_or("", |at| &rest[at + 3..]))
        } else if c == '<'
            && rest[1..].starts_with(|n: char| n.is_ascii_alphabetic() || n == '/' || n == '!')
        {
            Some(rest.find('>').map_or("", |at| &rest[at + 1..]))
        } else {
            None
        };
        if let Some(after) = skipped {
            flush(&mut text, &mut runs);
            rest = after;
        } else {
            text.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    flush(&mut text, &mut runs);
    runs.join(" ")
}

/// A run of text, decoded and trimmed, added to `runs` if there was one.
fn flush(text: &mut String, runs: &mut Vec<String>) {
    if !text.is_empty() {
        runs.push(decode_references(text).trim().to_owned());
        text.clear();
    }
}

/// `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&nbsp;` and numeric
/// references decoded; others kept.
fn decode_references(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let decoded = after.split_once(';').and_then(|(name, tail)| {
            let c = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                "nbsp" => '\u{a0}',
                _ => {
                    let number = name.strip_prefix('#')?;
                    let code = match number.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse().ok()?,
                    };
                    char::from_u32(code)?
                }
            };
            Some((c, tail))
        });
        if let Some((c, tail)) = decoded {
            out.push(c);
            rest = tail;
        } else {
            out.push('&');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// A notification.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// The app's bundle identifier (`app.identifier`).
    pub app: Option<String>,
    /// When it was delivered (`record.delivered_date`).
    pub delivered: Option<Ts>,
    /// Whether it was shown (`record.presented`).
    pub presented: Option<bool>,
    /// Its title (`req.titl` in the record's property list).
    pub title: Option<String>,
    /// Its subtitle (`req.subt`).
    pub subtitle: Option<String>,
    /// Its body (`req.body`).
    pub body: Option<String>,
}

/// A Notification Center database's notifications.
#[derive(Debug, Clone, PartialEq)]
pub struct Notifications {
    /// One per record, in row order.
    pub notifications: Vec<Notification>,
    /// Damage in the database, its log or a record's property list.
    pub problems: Vec<String>,
}

/// Read a Notification Center database (`db2/db`), with its `-wal` file's
/// committed changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database with `record`.
pub fn read_notifications(database: &[u8], wal: &[u8]) -> Result<Notifications, Error> {
    let db = open(database, wal, "record", "Notification Center")?;
    let mut problems = db.problems.clone();
    let apps = table::read(&db, "app", &mut problems, |row| {
        (row.integer("app_id"), row.text("identifier"))
    });
    let records = table::read(&db, "record", &mut problems, |row| {
        let request = row.blob("data").map(|data| plist::parse(&data));
        let app = apps
            .iter()
            .find(|(id, _)| *id == row.integer("app_id"))
            .and_then(|(_, name)| name.clone());
        (
            row.rowid,
            app,
            row.number("delivered_date").map(mac_time),
            row.integer("presented"),
            request,
        )
    });
    let mut notifications = Vec::new();
    for (rowid, app, delivered, presented, request) in records {
        let request = match request {
            Some(Ok(parsed)) => parsed.value.get("req").cloned(),
            Some(Err(e)) => {
                problems.push(format!("record {rowid}: {e}"));
                None
            }
            None => None,
        };
        let field = |key: &str| {
            request
                .as_ref()
                .and_then(|r| r.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        notifications.push(Notification {
            app,
            delivered,
            presented: presented.map(|p| p != 0),
            title: field("titl"),
            subtitle: field("subt"),
            body: field("body"),
        });
    }
    Ok(Notifications {
        notifications,
        problems,
    })
}

/// A column of Unix seconds; none when 0 or absent.
fn unix(row: &Named<'_>, column: &str) -> Option<Ts> {
    row.integer(column)
        .filter(|&seconds| seconds != 0)
        .map(Ts::from_unix_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_runs_are_trimmed_and_joined() {
        assert_eq!(
            html_text("<html><body>a &amp; b <div>c&#33;</div><!-- x --> </body></html>"),
            "a & b c! "
        );
        assert_eq!(html_text("1 < 2"), "1 < 2");
    }

    #[test]
    fn user_ids_from_version_paths() {
        assert_eq!(
            per_uid("PerUID/501/1/com.apple.documentVersions/x.rtf"),
            Some(501)
        );
        assert_eq!(per_uid("x"), None);
    }
}
