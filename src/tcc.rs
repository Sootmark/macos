//! TCC (Transparency, Consent and Control): `TCC.db`, table `access`.
//!
//! One row per decision: a client (an app's bundle identifier, or a
//! program's path) allowed or denied a service (`kTCCServiceCamera`,
//! `kTCCServiceMicrophone`, `kTCCServiceScreenCapture`,
//! `kTCCServiceSystemPolicyAllFiles` for full disk access,
//! `kTCCServiceAccessibility`, `kTCCServiceAppleEvents` towards a target
//! app, …). The system's database (`/Library/Application Support/com.apple.TCC/`)
//! holds the services granted machine-wide, each user's (`~/Library/…`)
//! the rest.
//!
//! The table changed with macOS: up to 10.15 the decision is `allowed`
//! (0 or 1) with a `prompt_count`; from macOS 11 it is `auth_value` with
//! an `auth_reason` and an `auth_version`; macOS 14 added `pid`,
//! `pid_version`, `boot_uuid` and `last_reminded`. Both are read, by
//! column name. TCC is closed source: the values of `auth_value`,
//! `auth_reason` and `client_type` are those public write-ups give
//! (Rainforest QA, "A deep dive into macOS TCC.db", 2021; HackTricks,
//! "macOS TCC"), any other is kept as a number.

use common::time::Ts;

use crate::table::{self, has_column, Named};
use crate::{open, Error};

const TABLE: &str = "access";

/// What a client is, by `client_type` (and `indirect_object_identifier_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientType {
    /// 0: a bundle identifier (`com.apple.Terminal`).
    BundleId,
    /// 1: an absolute path to a program.
    Path,
    /// Any other value, as written.
    Other(i64),
}

impl ClientType {
    fn from_value(value: i64) -> Self {
        match value {
            0 => Self::BundleId,
            1 => Self::Path,
            other => Self::Other(other),
        }
    }
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authorization {
    /// `auth_value` 0, `allowed` 0.
    Denied,
    /// `auth_value` 1.
    Unknown,
    /// `auth_value` 2, `allowed` 1.
    Allowed,
    /// `auth_value` 3: some of the service only (Photos: selected photos).
    Limited,
    /// Any other value, as written.
    Other(i64),
}

impl Authorization {
    /// From `auth_value`, macOS 11 and later.
    fn from_auth_value(value: i64) -> Self {
        match value {
            0 => Self::Denied,
            1 => Self::Unknown,
            2 => Self::Allowed,
            3 => Self::Limited,
            other => Self::Other(other),
        }
    }

    /// From `allowed`, up to macOS 10.15.
    fn from_allowed(value: i64) -> Self {
        match value {
            0 => Self::Denied,
            1 => Self::Allowed,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => f.write_str("denied"),
            Self::Unknown => f.write_str("unknown"),
            Self::Allowed => f.write_str("allowed"),
            Self::Limited => f.write_str("limited"),
            Self::Other(value) => write!(f, "{value}"),
        }
    }
}

/// Why the decision is what it is: `auth_value`'s companion
/// `auth_reason`, macOS 11 and later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthReason {
    /// 1.
    Error,
    /// 2: the user answered a prompt.
    UserConsent,
    /// 3: set by the user.
    UserSet,
    /// 4: set by the system.
    SystemSet,
    /// 5.
    ServicePolicy,
    /// 6: a device-management profile.
    MdmPolicy,
    /// 7.
    OverridePolicy,
    /// 8: the app lacks the usage description the prompt needs.
    MissingUsageString,
    /// 9: the prompt went unanswered.
    PromptTimeout,
    /// 10.
    PreflightUnknown,
    /// 11: the app's entitlements grant it.
    Entitled,
    /// 12.
    AppTypePolicy,
    /// Any other value, as written.
    Other(i64),
}

impl AuthReason {
    fn from_value(value: i64) -> Self {
        match value {
            1 => Self::Error,
            2 => Self::UserConsent,
            3 => Self::UserSet,
            4 => Self::SystemSet,
            5 => Self::ServicePolicy,
            6 => Self::MdmPolicy,
            7 => Self::OverridePolicy,
            8 => Self::MissingUsageString,
            9 => Self::PromptTimeout,
            10 => Self::PreflightUnknown,
            11 => Self::Entitled,
            12 => Self::AppTypePolicy,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for AuthReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Error => "error",
            Self::UserConsent => "user consent",
            Self::UserSet => "user set",
            Self::SystemSet => "system set",
            Self::ServicePolicy => "service policy",
            Self::MdmPolicy => "MDM policy",
            Self::OverridePolicy => "override policy",
            Self::MissingUsageString => "missing usage string",
            Self::PromptTimeout => "prompt timeout",
            Self::PreflightUnknown => "preflight unknown",
            Self::Entitled => "entitled",
            Self::AppTypePolicy => "app type policy",
            Self::Other(value) => return write!(f, "{value}"),
        };
        f.write_str(name)
    }
}

/// One `access` row: a client's standing for a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TccEntry {
    /// Its row id.
    pub rowid: i64,
    /// `service`: `kTCCServiceCamera`, `kTCCServiceScreenCapture`, …
    pub service: String,
    /// `client`: a bundle identifier or a path, as `client_type` says.
    pub client: String,
    /// `client_type`.
    pub client_type: Option<ClientType>,
    /// The decision: `auth_value`, else (before macOS 11) `allowed`.
    pub authorization: Option<Authorization>,
    /// `auth_reason` (macOS 11 and later).
    pub reason: Option<AuthReason>,
    /// `auth_version` (macOS 11 and later; 1 so far).
    pub auth_version: Option<i64>,
    /// `prompt_count` (before macOS 11).
    pub prompt_count: Option<i64>,
    /// `csreq`: the code requirement the client must meet, a compiled
    /// requirement blob (`0xfade0c00`), as stored.
    pub code_requirement: Option<Vec<u8>>,
    /// `policy_id`: the `policies` row of the profile that set it.
    pub policy_id: Option<i64>,
    /// `indirect_object_identifier`: the target of the access (for
    /// `kTCCServiceAppleEvents`, the app being controlled); `None` when
    /// `UNUSED`.
    pub indirect_object: Option<String>,
    /// `indirect_object_identifier_type`.
    pub indirect_object_type: Option<ClientType>,
    /// `flags`, as stored.
    pub flags: Option<i64>,
    /// `last_modified`: when the decision was last written (Unix
    /// seconds).
    pub last_modified: Option<Ts>,
    /// `pid`: the client's process when it asked (macOS 14 and later).
    pub pid: Option<i64>,
    /// `boot_uuid`: the boot session that process ran in (macOS 14 and
    /// later); `None` when `UNUSED`.
    pub boot_uuid: Option<String>,
    /// `last_reminded`: when the user was last reminded of the grant
    /// (macOS 14 and later, Unix seconds); `None` when 0 (never).
    pub last_reminded: Option<Ts>,
}

/// A TCC database's decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcc {
    /// In row order.
    pub entries: Vec<TccEntry>,
    /// Damage in the database or its log.
    pub problems: Vec<String>,
}

/// Read a `TCC.db`, with its `-wal` file's committed changes (`wal` may be
/// empty).
///
/// # Errors
/// When it isn't a SQLite database, or has no `access` table.
pub fn read_tcc(database: &[u8], wal: &[u8]) -> Result<Tcc, Error> {
    let db = open(database, wal, TABLE, "TCC")?;
    let mut problems = db.problems.clone();
    // Read `allowed` only where `auth_value` isn't: a database has one.
    let modern = has_column(&db, TABLE, "auth_value");
    let entries = table::read(&db, TABLE, &mut problems, |row| entry(row, modern));
    Ok(Tcc { entries, problems })
}

fn entry(row: &Named<'_>, modern: bool) -> TccEntry {
    let authorization = if modern {
        row.integer("auth_value")
            .map(Authorization::from_auth_value)
    } else {
        row.integer("allowed").map(Authorization::from_allowed)
    };
    TccEntry {
        rowid: row.rowid,
        service: row.text("service").unwrap_or_default(),
        client: row.text("client").unwrap_or_default(),
        client_type: row.integer("client_type").map(ClientType::from_value),
        authorization,
        reason: row.integer("auth_reason").map(AuthReason::from_value),
        auth_version: row.integer("auth_version"),
        prompt_count: row.integer("prompt_count"),
        code_requirement: row.blob("csreq"),
        policy_id: row.integer("policy_id"),
        indirect_object: row.text_used("indirect_object_identifier"),
        indirect_object_type: row
            .integer("indirect_object_identifier_type")
            .map(ClientType::from_value),
        flags: row.integer("flags"),
        last_modified: row.integer("last_modified").map(Ts::from_unix_seconds),
        pid: row.integer("pid"),
        boot_uuid: row.text_used("boot_uuid"),
        last_reminded: row
            .integer("last_reminded")
            .filter(|&seconds| seconds != 0)
            .map(Ts::from_unix_seconds),
    }
}
