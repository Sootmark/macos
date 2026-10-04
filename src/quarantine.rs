//! Quarantine events: `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
//!
//! When an app that opts in to quarantine (browsers, mail, messaging)
//! saves a file from the network, Launch Services gives the file a
//! `com.apple.quarantine` extended attribute and records the event in
//! this database, table `LSQuarantineEvent`, one row per event, keyed by
//! the UUID the attribute also carries. The table is the same from
//! Mac OS X 10.7 on; rows outlive the files they describe.

use common::time::Ts;

use crate::table::{self, Named};
use crate::{mac_time, open, Error};

const TABLE: &str = "LSQuarantineEvent";

/// One download, as Launch Services recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEvent {
    /// Its row id: the order events were recorded in.
    pub rowid: i64,
    /// `LSQuarantineEventIdentifier`: a UUID, the one in the file's
    /// `com.apple.quarantine` attribute.
    pub id: String,
    /// `LSQuarantineTimeStamp`: when (Mac absolute time).
    pub time: Option<Ts>,
    /// `LSQuarantineAgentBundleIdentifier`: the app that saved the file
    /// (`com.google.Chrome`).
    pub agent_bundle_id: Option<String>,
    /// `LSQuarantineAgentName`: its name (`Google Chrome`).
    pub agent_name: Option<String>,
    /// `LSQuarantineDataURLString`: where the file itself was fetched
    /// from.
    pub data_url: Option<String>,
    /// `LSQuarantineSenderName`: who sent it, for an attachment.
    pub sender_name: Option<String>,
    /// `LSQuarantineSenderAddress`: the sender's address, for an
    /// attachment.
    pub sender_address: Option<String>,
    /// `LSQuarantineTypeNumber`: the kind of quarantine, as stored. Apple
    /// documents the kinds as strings (`LSQuarantine.h`: web download,
    /// other download, email, instant message and calendar attachments,
    /// other attachment), not their numbers here; browser downloads
    /// read 0.
    pub type_number: Option<i64>,
    /// `LSQuarantineOriginTitle`: the title of the page or message it
    /// came from.
    pub origin_title: Option<String>,
    /// `LSQuarantineOriginURLString`: the page it was downloaded from (the
    /// referrer), or the message.
    pub origin_url: Option<String>,
    /// `LSQuarantineOriginAlias`: an alias record of the origin, as
    /// stored.
    pub origin_alias: Option<Vec<u8>>,
}

/// A quarantine events database's downloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// In row order: the order they were recorded in.
    pub events: Vec<QuarantineEvent>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read a `QuarantineEventsV2` database, with its `-wal` file's committed
/// changes (`wal` may be empty).
///
/// # Errors
/// When it isn't a SQLite database, or has no `LSQuarantineEvent` table.
pub fn read_quarantine(database: &[u8], wal: &[u8]) -> Result<Quarantine, Error> {
    let db = open(database, wal, TABLE, "quarantine events")?;
    let mut problems = db.problems.clone();
    let events = table::read(&db, TABLE, &mut problems, event);
    Ok(Quarantine { events, problems })
}

fn event(row: &Named<'_>) -> QuarantineEvent {
    QuarantineEvent {
        rowid: row.rowid,
        id: row.text("LSQuarantineEventIdentifier").unwrap_or_default(),
        time: row.number("LSQuarantineTimeStamp").map(mac_time),
        agent_bundle_id: row.text("LSQuarantineAgentBundleIdentifier"),
        agent_name: row.text("LSQuarantineAgentName"),
        data_url: row.text("LSQuarantineDataURLString"),
        sender_name: row.text("LSQuarantineSenderName"),
        sender_address: row.text("LSQuarantineSenderAddress"),
        type_number: row.integer("LSQuarantineTypeNumber"),
        origin_title: row.text("LSQuarantineOriginTitle"),
        origin_url: row.text("LSQuarantineOriginURLString"),
        origin_alias: row.blob("LSQuarantineOriginAlias"),
    }
}
