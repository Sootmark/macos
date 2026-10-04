//! KnowledgeC: `knowledgeC.db`, the CoreDuet knowledge store.
//!
//! A Core Data store: each event is a `ZOBJECT` row of a stream
//! (`ZSTREAMNAME`: `/app/inFocus` while an app is in front, `/app/usage`,
//! `/app/activity`, `/display/isBacklit`, `/device/isLocked`,
//! `/safari/history`, …) with a value and a time span. The value is text
//! (`ZVALUESTRING`: the app's bundle identifier for `/app/…`, the URL for
//! `/safari/history`) or a number (`ZVALUEINTEGER`, `ZVALUEDOUBLE`: 0 or
//! 1 for `/display/isBacklit` and `/device/isLocked`; when there is
//! text, a number the same for the same text, apparently a hash of it).
//! Its `ZSOURCE` column names a `ZSOURCE` row (the donating app's bundle,
//! the device), its `ZSTRUCTUREDMETADATA` column a `ZSTRUCTUREDMETADATA`
//! row (a Safari page's title, an app activity's title and type). Dates
//! are Mac absolute time, UTC; `ZSECONDSFROMGMT` is the local offset when
//! the event was recorded.
//!
//! There is a system database (`/private/var/db/CoreDuet/Knowledge/`) and
//! one per user (`~/Library/Application Support/Knowledge/`). Rows of
//! `ZOBJECT` without a stream name are Core Data objects of other
//! entities, not events, and are left out.

use std::collections::HashMap;

use common::time::{Ts, TICKS_PER_SECOND};
use sqlite::Database;

use crate::table::{self, Named};
use crate::{mac_time, open, Error};

const OBJECTS: &str = "ZOBJECT";
const SOURCES: &str = "ZSOURCE";
const METADATA: &str = "ZSTRUCTUREDMETADATA";

/// One event of a stream.
#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeEvent {
    /// `Z_PK`: its row id, the order events were recorded in.
    pub rowid: i64,
    /// `ZSTREAMNAME`: `/app/inFocus`, `/display/isBacklit`, …
    pub stream: String,
    /// `ZVALUESTRING`: the bundle identifier for `/app/…`, the URL for
    /// `/safari/history`.
    pub value_string: Option<String>,
    /// `ZVALUEINTEGER`: the value of a number or yes/no stream (1 for
    /// backlit, locked); when there is text, apparently a hash of it.
    pub value_integer: Option<i64>,
    /// `ZVALUEDOUBLE`: the value as a real.
    pub value_double: Option<f64>,
    /// `ZSTARTDATE`: when the state began (Mac absolute time).
    pub start: Option<Ts>,
    /// `ZENDDATE`: when it ended.
    pub end: Option<Ts>,
    /// `ZCREATIONDATE`: when the event was written.
    pub created: Option<Ts>,
    /// `ZSECONDSFROMGMT`: the local time's offset from UTC when it was
    /// recorded, in seconds (-25200 for UTC-7).
    pub seconds_from_gmt: Option<i64>,
    /// `ZUUID`.
    pub uuid: Option<String>,
    /// The source's `ZBUNDLEID`: the app that donated the event
    /// (`com.apple.Safari` for `/safari/history`).
    pub bundle_id: Option<String>,
    /// The source's `ZDEVICEID`: the device it came from, when synced.
    pub device_id: Option<String>,
    /// The metadata's title: a Safari page's
    /// (`Z_DKSAFARIHISTORYMETADATAKEY__TITLE`), else an app activity's
    /// (`Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE`).
    pub title: Option<String>,
    /// The metadata's app activity type
    /// (`Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE`).
    pub activity_type: Option<String>,
}

impl KnowledgeEvent {
    /// The app the event is about: the value of an `/app/…` stream, else
    /// the source's bundle.
    #[must_use]
    pub fn app(&self) -> Option<&str> {
        if self.stream.starts_with("/app/") {
            if let Some(app) = self.value_string.as_deref() {
                return Some(app);
            }
        }
        self.bundle_id.as_deref()
    }

    /// How long the state lasted: end minus start, when both are times
    /// and the end isn't before the start.
    #[must_use]
    pub fn duration(&self) -> Option<std::time::Duration> {
        let ticks = self.end?.ticks()?.checked_sub(self.start?.ticks()?)?;
        let ticks = u64::try_from(ticks).ok()?;
        let per_second = TICKS_PER_SECOND as u64;
        Some(std::time::Duration::new(
            ticks / per_second,
            ((ticks % per_second) * 100) as u32,
        ))
    }
}

/// A KnowledgeC database's events.
#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeC {
    /// In row order: the order they were recorded in.
    pub events: Vec<KnowledgeEvent>,
    /// Damage in the database or its log, and references to source or
    /// metadata rows that aren't there.
    pub problems: Vec<String>,
}

/// Read a `knowledgeC.db`, with its `-wal` file's committed changes (`wal`
/// may be empty).
///
/// # Errors
/// When it isn't a SQLite database, or has no `ZOBJECT` table.
pub fn read_knowledgec(database: &[u8], wal: &[u8]) -> Result<KnowledgeC, Error> {
    let db = open(database, wal, OBJECTS, "KnowledgeC")?;
    let mut problems = db.problems.clone();
    let sources = keyed(&db, SOURCES, &mut problems, Source::from_row);
    let metadata = keyed(&db, METADATA, &mut problems, Metadata::from_row);
    let mut missing = Vec::new();
    let events = table::read(&db, OBJECTS, &mut problems, |row| {
        event(row, &sources, &metadata, &mut missing)
    })
    .into_iter()
    .flatten()
    .collect();
    problems.extend(missing);
    Ok(KnowledgeC { events, problems })
}

/// Every row of `table`, converted, by its `Z_PK`.
fn keyed<T>(
    db: &Database<'_>,
    table: &str,
    problems: &mut Vec<String>,
    convert: fn(&Named<'_>) -> T,
) -> HashMap<i64, T> {
    table::read(db, table, problems, |row| (primary_key(row), convert(row)))
        .into_iter()
        .collect()
}

/// `Z_PK`, the rowid Core Data keys its rows by.
fn primary_key(row: &Named<'_>) -> i64 {
    row.integer("Z_PK").unwrap_or(row.rowid)
}

/// What an event takes from its `ZSOURCE` row.
struct Source {
    bundle_id: Option<String>,
    device_id: Option<String>,
}

impl Source {
    fn from_row(row: &Named<'_>) -> Self {
        Self {
            bundle_id: row.text("ZBUNDLEID"),
            device_id: row.text("ZDEVICEID"),
        }
    }
}

/// What an event takes from its `ZSTRUCTUREDMETADATA` row.
struct Metadata {
    title: Option<String>,
    activity_type: Option<String>,
}

impl Metadata {
    fn from_row(row: &Named<'_>) -> Self {
        Self {
            title: row
                .text("Z_DKSAFARIHISTORYMETADATAKEY__TITLE")
                .or_else(|| row.text("Z_DKAPPLICATIONACTIVITYMETADATAKEY__TITLE")),
            activity_type: row.text("Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE"),
        }
    }
}

/// The row named by `row`'s `column` in `rows` (`table`'s), if it names
/// one; one it names that isn't there is added to `missing`.
fn referenced<'r, T>(
    row: &Named<'_>,
    (column, table): (&str, &str),
    rows: &'r HashMap<i64, T>,
    missing: &mut Vec<String>,
) -> Option<&'r T> {
    let key = row.integer(column).filter(|&key| key != 0)?;
    let found = rows.get(&key);
    if found.is_none() {
        missing.push(format!(
            "{OBJECTS}: row {}'s {column} {key} is not in {table}",
            primary_key(row)
        ));
    }
    found
}

/// A `ZOBJECT` row as an event; `None` when it has no stream name.
fn event(
    row: &Named<'_>,
    sources: &HashMap<i64, Source>,
    metadata: &HashMap<i64, Metadata>,
    missing: &mut Vec<String>,
) -> Option<KnowledgeEvent> {
    let stream = row.text("ZSTREAMNAME")?;
    let source = referenced(row, ("ZSOURCE", SOURCES), sources, missing);
    let meta = referenced(row, ("ZSTRUCTUREDMETADATA", METADATA), metadata, missing);
    Some(KnowledgeEvent {
        rowid: primary_key(row),
        stream,
        value_string: row.text("ZVALUESTRING"),
        value_integer: row.integer("ZVALUEINTEGER"),
        value_double: row.number("ZVALUEDOUBLE"),
        start: row.number("ZSTARTDATE").map(mac_time),
        end: row.number("ZENDDATE").map(mac_time),
        created: row.number("ZCREATIONDATE").map(mac_time),
        seconds_from_gmt: row.integer("ZSECONDSFROMGMT"),
        uuid: row.text("ZUUID"),
        bundle_id: source.and_then(|s| s.bundle_id.clone()),
        device_id: source.and_then(|s| s.device_id.clone()),
        title: meta.and_then(|m| m.title.clone()),
        activity_type: meta.and_then(|m| m.activity_type.clone()),
    })
}
