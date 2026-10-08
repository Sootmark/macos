//! macOS artifacts kept in SQLite databases, for forensics, read without
//! SQLite.
//!
//! - Quarantine events, `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`
//!   ([`read_quarantine`]): where each downloaded file came from, by which
//!   app, when.
//! - TCC, `/Library/Application Support/com.apple.TCC/TCC.db` (the
//!   system's) and `~/Library/Application Support/com.apple.TCC/TCC.db`
//!   (each user's) ([`read_tcc`]): which apps were allowed or denied the
//!   camera, the microphone, screen recording, full disk access,
//!   accessibility and the other protected services, why, and when.
//! - KnowledgeC, `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` (the
//!   system's) and `~/Library/Application Support/Knowledge/knowledgeC.db`
//!   (each user's) ([`read_knowledgec`]): app focus and usage, display
//!   backlight, device lock, Safari visits and the other event streams
//!   over time.
//!
//! Times are Mac absolute time (seconds since 2001-01-01 UTC) except TCC's,
//! which are Unix seconds; both are UTC. Columns are read by name: one a
//! macOS version lacks reads as `None`, one it added is ignored. Each
//! `read_*` takes the database with its write-ahead log (the `-wal` file
//! beside it, empty when there is none), whose committed changes it
//! applies: the latest events are often only there. Damage is listed in
//! `problems`, never a panic.

use common::time::Ts;
use sqlite::Database;

mod asl;
mod btm;
mod fsevents;
mod knowledgec;
mod launchd;
mod prefs;
mod quarantine;
mod table;
mod tcc;
mod usage;

pub use asl::{is_asl, read_asl, Asl, AslRecord};
pub use btm::{is_background_items_name, read_background_items, BackgroundItem, BackgroundItems};
pub use fsevents::{is_fsevents_name, read_fsevents, FsEvent, FsEvents};
pub use knowledgec::{read_knowledgec, KnowledgeC, KnowledgeEvent};
pub use launchd::{read_launchd, JobFlag, JobKind, LaunchJob, Launchd, Triggers};
pub use prefs::{read_prefs, PrefEntry, PrefKind, Prefs};
pub use quarantine::{read_quarantine, Quarantine, QuarantineEvent};
pub use tcc::{read_tcc, AuthReason, Authorization, ClientType, Tcc, TccEntry};
pub use usage::{
    read_app_usage, read_document_versions, read_notes, read_notifications, AppUsage, AppUse,
    DocumentVersion, DocumentVersions, Note, Notes, Notification, Notifications,
};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which artifact a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Artifact {
    /// `com.apple.LaunchServices.QuarantineEventsV2`, in each user's
    /// `Library/Preferences`: read with [`read_quarantine`].
    QuarantineEvents,
    /// `TCC.db`: read with [`read_tcc`].
    Tcc(Scope),
    /// `knowledgeC.db`: read with [`read_knowledgec`].
    KnowledgeC(Scope),
    /// A launchd job's property list in a `LaunchAgents` or
    /// `LaunchDaemons` folder: read with [`read_launchd`].
    Launchd(JobKind),
    /// An FSEvents log (`.fseventsd/<16 hex digits>`): read with
    /// [`read_fsevents`].
    FsEvents,
    /// A background items file (`backgrounditems.btm`,
    /// `BackgroundItems-v<n>.btm`): read with [`read_background_items`].
    BackgroundItems,
    /// A property list of what the Mac did and was set to: read with
    /// [`read_prefs`].
    Prefs(PrefKind),
    /// An Apple System Log file (`asl/*.asl`): read with [`read_asl`].
    Asl,
    /// `application_usage.sqlite`: read with [`read_app_usage`].
    AppUsage,
    /// The document revisions database
    /// (`.DocumentRevisions-V100/db-V1/db.sqlite`): read with
    /// [`read_document_versions`].
    DocumentVersions,
    /// `NotesV7.storedata`: read with [`read_notes`].
    Notes,
    /// A Notification Center database (`com.apple.notificationcenter/db2/
    /// db`, `group.com.apple.usernoted/db2/db`): read with
    /// [`read_notifications`].
    Notifications,
}

/// Whose a database is, as its path says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The system's: `/Library/Application Support/com.apple.TCC/TCC.db`,
    /// `/private/var/db/CoreDuet/Knowledge/knowledgeC.db`.
    System,
    /// A user's, under a home folder (`Users/<name>/`, `~/`, root's
    /// `var/root/`).
    User,
    /// Not said: a bare file name, or a path elsewhere.
    Unknown,
}

/// Which artifact a file is, from its name or path (`/` or `\`, case
/// ignored, as APFS and HFS+ ignore it by default).
///
/// A path to a mounted image works as well as one on a live system: a TCC
/// database under `Users/<name>/` is a user's, one under
/// `Library/Application Support/com.apple.TCC/` elsewhere the system's.
/// The `-wal` and `-shm` files beside a database are `None`.
#[must_use]
pub fn detect(name: &str) -> Option<Artifact> {
    let path = name.replace('\\', "/").to_ascii_lowercase();
    let base = path.rsplit('/').next().unwrap_or(&path);
    match base {
        "com.apple.launchservices.quarantineeventsv2" => Some(Artifact::QuarantineEvents),
        "tcc.db" => Some(Artifact::Tcc(tcc_scope(&path))),
        "knowledgec.db" => Some(Artifact::KnowledgeC(knowledgec_scope(&path))),
        "application_usage.sqlite" => Some(Artifact::AppUsage),
        "notesv7.storedata" => Some(Artifact::Notes),
        _ if path.ends_with(".documentrevisions-v100/db-v1/db.sqlite") => {
            Some(Artifact::DocumentVersions)
        }
        _ if NOTIFICATION_PATHS.iter().any(|p| path.ends_with(p)) => Some(Artifact::Notifications),
        _ if is_fsevents_name(base) && path.contains(".fseventsd/") => Some(Artifact::FsEvents),
        _ if is_background_items_name(base) => Some(Artifact::BackgroundItems),
        _ if std::path::Path::new(base)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("asl")) =>
        {
            Some(Artifact::Asl)
        }
        _ if PrefKind::of_path(&path).is_some() => PrefKind::of_path(&path).map(Artifact::Prefs),
        _ if base
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension == "plist") =>
        {
            launchd::kind_of(&path).map(Artifact::Launchd)
        }
        _ => None,
    }
}

/// Where Notification Center keeps its database, before and from macOS 15.
const NOTIFICATION_PATHS: [&str; 2] = [
    "com.apple.notificationcenter/db2/db",
    "group.com.apple.usernoted/db2/db",
];
const TCC_PATH: &str = "library/application support/com.apple.tcc/tcc.db";
const SYSTEM_KNOWLEDGEC_PATH: &str = "var/db/coreduet/knowledge/knowledgec.db";
const USER_KNOWLEDGEC_PATH: &str = "library/application support/knowledge/knowledgec.db";

/// A TCC database's scope from its lowercased path: in a home folder, a
/// user's; in `Library` elsewhere, the system's.
fn tcc_scope(path: &str) -> Scope {
    match folder_before(path, TCC_PATH) {
        Some(prefix) if is_home(prefix) => Scope::User,
        Some(_) => Scope::System,
        None => Scope::Unknown,
    }
}

/// A KnowledgeC database's scope from its lowercased path: the two
/// locations differ.
fn knowledgec_scope(path: &str) -> Scope {
    if folder_before(path, SYSTEM_KNOWLEDGEC_PATH).is_some() {
        Scope::System
    } else if folder_before(path, USER_KNOWLEDGEC_PATH).is_some() {
        Scope::User
    } else {
        Scope::Unknown
    }
}

/// The folder `path` has before `suffix`, when it ends with it as whole
/// path components: `""` for a path that starts with `suffix`.
fn folder_before<'p>(path: &'p str, suffix: &str) -> Option<&'p str> {
    let prefix = path.strip_suffix(suffix)?;
    (prefix.is_empty() || prefix.ends_with('/')).then_some(prefix)
}

/// Whether a folder (lowercased, `/` separated) is a home folder:
/// `…/users/<name>/`, `~/`, root's `…/var/root/`.
fn is_home(folder: &str) -> bool {
    let parts: Vec<&str> = folder.trim_end_matches('/').split('/').collect();
    match parts.as_slice() {
        [.., "~"] | [.., "var", "root"] => true,
        [.., "users", name] => !name.is_empty(),
        _ => false,
    }
}

/// Why a file can't be read as the artifact asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The database with its log's committed changes, when it has `table`.
fn open<'a>(
    database: &'a [u8],
    wal: &'a [u8],
    table: &str,
    artifact: &str,
) -> Result<Database<'a>, Error> {
    let db = Database::open_with_wal(database, wal).map_err(|e| Error(e.to_string()))?;
    if db.table(table).is_none() {
        return Err(Error(format!(
            "not a {artifact} database: no {table} table"
        )));
    }
    Ok(db)
}

/// Mac absolute time: seconds since 2001-01-01 UTC.
fn mac_time(seconds: f64) -> Ts {
    Ts::from_cocoa_seconds(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_name_and_path() {
        let user_tcc = Some(Artifact::Tcc(Scope::User));
        let system_tcc = Some(Artifact::Tcc(Scope::System));
        for (name, artifact) in [
            (
                "/Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
                Some(Artifact::QuarantineEvents),
            ),
            ("TCC.db", Some(Artifact::Tcc(Scope::Unknown))),
            (
                "/Library/Application Support/com.apple.TCC/TCC.db",
                system_tcc,
            ),
            (
                "/Users/alice/Library/Application Support/com.apple.TCC/TCC.db",
                user_tcc,
            ),
            (
                "~/Library/Application Support/com.apple.TCC/TCC.db",
                user_tcc,
            ),
            (
                "/private/var/root/Library/Application Support/com.apple.TCC/TCC.db",
                user_tcc,
            ),
            (
                r"E:\image\Users\bob\Library\Application Support\com.apple.TCC\tcc.db",
                user_tcc,
            ),
            (
                "/Volumes/image/Library/Application Support/com.apple.TCC/TCC.db",
                system_tcc,
            ),
            ("/tmp/TCC.db", Some(Artifact::Tcc(Scope::Unknown))),
            (
                "/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
                Some(Artifact::KnowledgeC(Scope::System)),
            ),
            (
                "/Users/alice/Library/Application Support/Knowledge/knowledgeC.db",
                Some(Artifact::KnowledgeC(Scope::User)),
            ),
            ("knowledgeC.db", Some(Artifact::KnowledgeC(Scope::Unknown))),
            ("knowledgeC.db-wal", None),
            (
                "/private/var/db/application_usage.sqlite",
                Some(Artifact::AppUsage),
            ),
            (
                "/.DocumentRevisions-V100/db-V1/db.sqlite",
                Some(Artifact::DocumentVersions),
            ),
            ("/tmp/db-V1/db.sqlite", None),
            (
                "/Users/a/Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV7.storedata",
                Some(Artifact::Notes),
            ),
            (
                "/private/var/folders/xy/abc/0/com.apple.notificationcenter/db2/db",
                Some(Artifact::Notifications),
            ),
            (
                "/Users/a/Library/Group Containers/group.com.apple.usernoted/db2/db",
                Some(Artifact::Notifications),
            ),
            ("TCC.db-shm", None),
            ("History", None),
            ("", None),
        ] {
            assert_eq!(detect(name), artifact, "{name}");
        }
    }
}
