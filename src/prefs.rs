//! macOS property lists that record what a Mac did and was set to: one
//! record per thing they describe (a package installed, a Wi-Fi network, a
//! Bluetooth device, an Apple account, a login item or hook, a local
//! account, a startup item, a Time Machine destination), with its times
//! and values.
//!
//! - `/Library/Receipts/InstallHistory.plist`: each installation, its
//!   time, name, version, installer and packages.
//! - `/Library/Preferences/com.apple.SoftwareUpdate.plist`: the last
//!   checks and the updates recommended.
//! - `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`:
//!   the Wi-Fi networks remembered (`RememberedNetworks`, or `KnownNetworks`
//!   from macOS 10.10), each last joined when, with which security.
//! - `/Library/Preferences/com.apple.Bluetooth.plist`: the devices seen and
//!   paired (`DeviceCache`, `PairedDevices`) and when their name, services
//!   and presence were last updated.
//! - `~/Library/Preferences/com.apple.coreservices.appleidauthenticationinfo.<UUID>.plist`:
//!   the Apple accounts signed in, when created, last connected and
//!   validated.
//! - `~/Library/Preferences/com.apple.loginitems.plist` (before macOS
//!   10.13): the login items, their targets read from each item's alias
//!   record.
//! - `/Library/Preferences/com.apple.loginwindow.plist`: the login and
//!   logout hooks and the applications launched at login.
//! - `/private/var/db/dslocal/nodes/Default/users/<name>.plist`: a local
//!   account's name, full name, identifiers, home and shell, and from its
//!   account policy when it was created, its password last set and its
//!   last failed login. Password hashes are never read.
//! - `/Library/StartupItems/<item>/StartupParameters.plist`: a startup item
//!   (legacy persistence): what it provides and uses.
//! - `/Library/Preferences/com.apple.TimeMachine.plist`: each backup
//!   destination, its name and every snapshot's time.

use common::time::Ts;
use plist::Value;

use crate::btm;

/// Which property list a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrefKind {
    /// `InstallHistory.plist`.
    InstallHistory,
    /// `com.apple.SoftwareUpdate.plist`.
    SoftwareUpdate,
    /// `com.apple.airport.preferences.plist`.
    Airport,
    /// `com.apple.Bluetooth.plist`.
    Bluetooth,
    /// `com.apple.coreservices.appleidauthenticationinfo.<UUID>.plist`.
    AppleAccount,
    /// `com.apple.loginitems.plist`.
    LoginItems,
    /// `com.apple.loginwindow.plist`.
    LoginWindow,
    /// A local account's `dslocal` property list.
    User,
    /// `StartupParameters.plist`.
    StartupItem,
    /// `com.apple.TimeMachine.plist`.
    TimeMachine,
}

impl PrefKind {
    /// A short name (`install_history`, `wifi`, `bluetooth`, …).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InstallHistory => "install_history",
            Self::SoftwareUpdate => "software_update",
            Self::Airport => "wifi",
            Self::Bluetooth => "bluetooth",
            Self::AppleAccount => "apple_account",
            Self::LoginItems => "login_items",
            Self::LoginWindow => "login_window",
            Self::User => "user",
            Self::StartupItem => "startup_item",
            Self::TimeMachine => "time_machine",
        }
    }

    /// The property list a path names, by its name (and, for local
    /// accounts, its folder); case ignored.
    #[must_use]
    pub fn of_path(path: &str) -> Option<Self> {
        let lower = path.replace('\\', "/").to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or(&lower);
        Some(match base {
            "installhistory.plist" => Self::InstallHistory,
            "com.apple.softwareupdate.plist" => Self::SoftwareUpdate,
            "com.apple.airport.preferences.plist" => Self::Airport,
            "com.apple.bluetooth.plist" => Self::Bluetooth,
            "com.apple.loginitems.plist" => Self::LoginItems,
            "com.apple.loginwindow.plist" | "loginwindow.plist" => Self::LoginWindow,
            "startupparameters.plist" => Self::StartupItem,
            "com.apple.timemachine.plist" => Self::TimeMachine,
            _ if base.starts_with("com.apple.coreservices.appleidauthenticationinfo.") => {
                Self::AppleAccount
            }
            _ if lower.contains("dslocal/nodes/default/users/")
                && std::path::Path::new(base)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("plist")) =>
            {
                Self::User
            }
            _ => return None,
        })
    }
}

/// One thing a property list describes.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefEntry {
    /// What it is about: a package, a network, a device, an account, a
    /// path.
    pub subject: String,
    /// Its times, by name (`Installed`, `LastConnected`, `Snapshot`, …).
    pub times: Vec<(&'static str, Ts)>,
    /// Its values, by name.
    pub fields: Vec<(&'static str, String)>,
}

impl PrefEntry {
    fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            times: Vec::new(),
            fields: Vec::new(),
        }
    }

    fn time(&mut self, name: &'static str, value: Option<&Value>) {
        if let Some(time) = value.and_then(Value::as_date) {
            self.times.push((name, time));
        }
    }

    fn field(&mut self, name: &'static str, value: Option<String>) {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            self.fields.push((name, value));
        }
    }

    /// A value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A property list's entries and what couldn't be read.
#[derive(Debug, Clone, PartialEq)]
pub struct Prefs {
    /// Which property list.
    pub kind: PrefKind,
    /// Its entries.
    pub entries: Vec<PrefEntry>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Read a property list of `kind`.
#[must_use]
pub fn read_prefs(kind: PrefKind, data: &[u8]) -> Prefs {
    let mut prefs = Prefs {
        kind,
        entries: Vec::new(),
        problems: Vec::new(),
    };
    let root = match plist::parse(data) {
        Ok(parsed) => {
            prefs.problems.extend(parsed.problems);
            parsed.value
        }
        Err(why) => {
            prefs.problems.push(format!("not a property list: {why}"));
            return prefs;
        }
    };
    prefs.entries = match kind {
        PrefKind::InstallHistory => install_history(&root),
        PrefKind::SoftwareUpdate => software_update(&root),
        PrefKind::Airport => airport(&root),
        PrefKind::Bluetooth => bluetooth(&root),
        PrefKind::AppleAccount => apple_accounts(&root),
        PrefKind::LoginItems => login_items(&root),
        PrefKind::LoginWindow => login_window(&root),
        PrefKind::User => user(&root),
        PrefKind::StartupItem => startup_item(&root),
        PrefKind::TimeMachine => time_machine(&root),
    };
    prefs
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Integer(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Real(r) => Some(r.to_string()),
        Value::Array(items) => items.first().and_then(|first| text(Some(first))),
        _ => None,
    }
}

fn texts(value: Option<&Value>) -> Option<String> {
    let items: Vec<String> = value?
        .as_array()?
        .iter()
        .filter_map(|v| text(Some(v)))
        .collect();
    Some(items.join(", "))
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).unwrap_or_default()
}

fn dictionary(value: Option<&Value>) -> &[(String, Value)] {
    value.and_then(Value::as_dictionary).unwrap_or_default()
}

fn install_history(root: &Value) -> Vec<PrefEntry> {
    array(Some(root))
        .iter()
        .map(|item| {
            let name = text(item.get("displayName")).unwrap_or_default();
            let mut entry = PrefEntry::new(name.clone());
            entry.time("Installed", item.get("date"));
            entry.field("Name", Some(name));
            entry.field("Version", text(item.get("displayVersion")));
            entry.field("Installer", text(item.get("processName")));
            entry.field("Packages", texts(item.get("packageIdentifiers")));
            entry
        })
        .collect()
}

fn software_update(root: &Value) -> Vec<PrefEntry> {
    let mut entry = PrefEntry::new("Software Update");
    entry.time("LastFullSuccessful", root.get("LastFullSuccessfulDate"));
    entry.time("LastSuccessful", root.get("LastSuccessfulDate"));
    entry.time(
        "LastBackgroundSuccessful",
        root.get("LastBackgroundSuccessfulDate"),
    );
    entry.field("SystemVersion", text(root.get("LastAttemptSystemVersion")));
    let updates: Vec<String> = array(root.get("RecommendedUpdates"))
        .iter()
        .map(|update| {
            format!(
                "{} ({})",
                text(update.get("Identifier")).unwrap_or_default(),
                text(update.get("Product Key")).unwrap_or_default()
            )
        })
        .collect();
    entry.field("RecommendedUpdates", Some(updates.join(", ")));
    vec![entry]
}

fn airport(root: &Value) -> Vec<PrefEntry> {
    let mut entries: Vec<PrefEntry> = array(root.get("RememberedNetworks"))
        .iter()
        .map(|network| {
            let ssid = text(network.get("SSIDString")).unwrap_or_default();
            let mut entry = PrefEntry::new(ssid.clone());
            entry.time("LastConnected", network.get("LastConnected"));
            entry.field("Ssid", Some(ssid));
            entry.field("Security", text(network.get("SecurityType")));
            entry
        })
        .collect();
    for (_, network) in dictionary(root.get("KnownNetworks")) {
        let ssid = text(network.get("SSIDString")).unwrap_or_default();
        let mut entry = PrefEntry::new(ssid.clone());
        entry.time("LastConnected", network.get("LastConnected"));
        entry.time("LastAutoJoin", network.get("LastAutoJoinAt"));
        entry.time("Added", network.get("AddedAt"));
        entry.field("Ssid", Some(ssid));
        entry.field("Security", text(network.get("SecurityType")));
        entries.push(entry);
    }
    entries
}

fn bluetooth(root: &Value) -> Vec<PrefEntry> {
    let paired: Vec<String> = array(root.get("PairedDevices"))
        .iter()
        .filter_map(|d| text(Some(d)))
        .collect();
    dictionary(root.get("DeviceCache"))
        .iter()
        .map(|(address, device)| {
            let mut entry = PrefEntry::new(address.clone());
            entry.time("LastInquiryUpdate", device.get("LastInquiryUpdate"));
            entry.time("LastNameUpdate", device.get("LastNameUpdate"));
            entry.time("LastServicesUpdate", device.get("LastServicesUpdate"));
            entry.field("Address", Some(address.clone()));
            entry.field("Name", text(device.get("Name")));
            entry.field("Paired", Some(paired.contains(address).to_string()));
            entry
        })
        .collect()
}

fn apple_accounts(root: &Value) -> Vec<PrefEntry> {
    dictionary(root.get("Accounts"))
        .iter()
        .map(|(id, account)| {
            let mut entry = PrefEntry::new(id.clone());
            entry.time("Created", account.get("CreationDate"));
            entry.time(
                "LastSuccessfulConnect",
                account.get("LastSuccessfulConnect"),
            );
            entry.time("Validated", account.get("ValidationDate"));
            entry.field(
                "AppleId",
                text(account.get("AppleID")).or_else(|| Some(id.clone())),
            );
            entry.field("FirstName", text(account.get("FirstName")));
            entry.field("LastName", text(account.get("LastName")));
            entry
        })
        .collect()
}

fn login_items(root: &Value) -> Vec<PrefEntry> {
    let items = root
        .get("SessionItems")
        .and_then(|s| s.get("CustomListItems"));
    array(items)
        .iter()
        .map(|item| {
            let name = text(item.get("Name")).unwrap_or_default();
            let mut entry = PrefEntry::new(name.clone());
            entry.field("Name", Some(name));
            let properties = item.get("CustomItemProperties");
            let hidden = properties
                .and_then(|p| p.get("com.apple.LSSharedFileList.ItemIsHidden"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            entry.field("Hidden", Some(hidden.to_string()));
            let alias = item
                .get("Alias")
                .and_then(Value::as_data)
                .unwrap_or_default();
            if let Some(target) = alias_record(alias) {
                entry.field("TargetPath", target.target_path);
                entry.field("VolumeName", target.volume_name);
                entry.field("VolumeMountPoint", target.volume_mount_point);
                if let Some(created) = target.target_created {
                    entry.times.push(("TargetCreated", created));
                }
                if let Some(created) = target.volume_created {
                    entry.times.push(("VolumeCreated", created));
                }
            }
            entry
        })
        .collect()
}

/// A classic alias record (version 3, big-endian): its volume's and
/// target's creation times (HFS seconds, times 65536), then tagged values
/// (`0x000F` volume name in UTF-16, `0x0012` path from the volume's root,
/// `0x0013` mount point), as plaso and libyal's dtformats read them.
fn alias_record(alias: &[u8]) -> Option<btm::BackgroundItem> {
    let u16_at = |at: usize| Some(u16::from_be_bytes(alias.get(at..at + 2)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_be_bytes(alias.get(at..at + 8)?.try_into().ok()?));
    if alias.get(..4)? != [0; 4] || usize::from(u16_at(4)?) != alias.len() || u16_at(6)? != 3 {
        return None;
    }
    let hfs = |value: u64| {
        u32::try_from(value / 65_536)
            .ok()
            .filter(|&s| s != 0)
            .map(Ts::from_hfs_seconds)
    };
    let mut item = btm::BackgroundItem {
        volume_created: hfs(u64_at(10)?),
        target_created: hfs(u64_at(32)?),
        ..btm::BackgroundItem::default()
    };
    let mut relative = None;
    let mut at = 58;
    while at + 4 <= alias.len() {
        let tag = u16_at(at)?;
        let size = usize::from(u16_at(at + 2)?);
        let data = alias.get(at + 4..at + 4 + size)?;
        at += 4 + size + size % 2;
        match tag {
            0xFFFF => break,
            0x000F => {
                let units: Vec<u16> = data
                    .get(2..)?
                    .chunks_exact(2)
                    .map(|p| u16::from_be_bytes([p[0], p[1]]))
                    .collect();
                item.volume_name = Some(String::from_utf16_lossy(&units));
            }
            0x0012 => relative = Some(String::from_utf8_lossy(data).into_owned()),
            0x0013 => item.volume_mount_point = Some(String::from_utf8_lossy(data).into_owned()),
            _ => {}
        }
    }
    item.target_path = relative.map(|path| match &item.volume_mount_point {
        Some(mount) => format!("{mount}{path}"),
        None => path,
    });
    Some(item)
}

fn login_window(root: &Value) -> Vec<PrefEntry> {
    let mut entries = Vec::new();
    for (key, name) in [("LoginHook", "login hook"), ("LogoutHook", "logout hook")] {
        if let Some(path) = text(root.get(key)) {
            let mut entry = PrefEntry::new(path.clone());
            entry.field("Kind", Some(name.to_owned()));
            entry.field("Path", Some(path));
            entries.push(entry);
        }
    }
    for app in array(root.get("AutoLaunchedApplicationDictionary")) {
        let path = text(app.get("Path")).unwrap_or_default();
        let mut entry = PrefEntry::new(path.clone());
        entry.field("Kind", Some("login application".to_owned()));
        entry.field("Path", Some(path));
        entry.field("Hidden", text(app.get("Hide")));
        entries.push(entry);
    }
    entries
}

fn user(root: &Value) -> Vec<PrefEntry> {
    let name = text(root.get("name")).unwrap_or_default();
    let mut entry = PrefEntry::new(name.clone());
    entry.field("Name", Some(name));
    entry.field("FullName", text(root.get("realname")));
    entry.field("Uid", text(root.get("uid")));
    entry.field("Gid", text(root.get("gid")));
    entry.field("Home", text(root.get("home")));
    entry.field("Shell", text(root.get("shell")));
    entry.field("GeneratedUid", text(root.get("generateduid")));
    // The account policy: a property list in a data value, with dates
    // (`passwordpolicyoptions`) or Unix seconds (`accountPolicyData`, from
    // macOS 10.10).
    for key in ["passwordpolicyoptions", "accountPolicyData"] {
        let Some(policy) = array(root.get(key))
            .first()
            .and_then(Value::as_data)
            .and_then(|data| plist::parse(data).ok())
            .map(|parsed| parsed.value)
        else {
            continue;
        };
        for (key, name) in [
            ("creationTime", "Created"),
            ("passwordLastSetTime", "PasswordLastSet"),
            ("lastLoginTimestamp", "LastLogin"),
            ("failedLoginTimestamp", "LastFailedLogin"),
        ] {
            if let Some(time) = policy.get(key).and_then(policy_time) {
                entry.times.push((name, time));
            }
        }
        entry.field("FailedLogins", text(policy.get("failedLoginCount")));
    }
    vec![entry]
}

/// A policy time: a date, or Unix seconds; 2001-01-01 (Cocoa's zero) and
/// zero mean never.
fn policy_time(value: &Value) -> Option<Ts> {
    match value {
        Value::Date(time) => {
            Some(*time).filter(|t| t.ticks() != Ts::from_cocoa_seconds(0.0).ticks())
        }
        other => other
            .as_f64()
            .filter(|t| t.is_finite() && *t > 0.0)
            .map(|t| Ts::from_unix_micros((t * 1e6).round() as i64)),
    }
}

fn startup_item(root: &Value) -> Vec<PrefEntry> {
    let description = text(root.get("Description")).unwrap_or_default();
    let mut entry = PrefEntry::new(description.clone());
    entry.field("Description", Some(description));
    entry.field("Provides", texts(root.get("Provides")));
    entry.field("Uses", texts(root.get("Uses")));
    entry.field("OrderPreference", text(root.get("OrderPreference")));
    vec![entry]
}

fn time_machine(root: &Value) -> Vec<PrefEntry> {
    array(root.get("Destinations"))
        .iter()
        .map(|destination| {
            let id = text(destination.get("DestinationID")).unwrap_or_default();
            let mut entry = PrefEntry::new(id.clone());
            entry.field("DestinationId", Some(id));
            entry.field(
                "Name",
                destination
                    .get("BackupAlias")
                    .and_then(Value::as_data)
                    .and_then(alias_volume_name),
            );
            for snapshot in array(destination.get("SnapshotDates")) {
                entry.time("Snapshot", Some(snapshot));
            }
            entry
        })
        .collect()
}

/// The volume name a classic alias record holds (a length byte at offset
/// 10, then the name).
fn alias_volume_name(alias: &[u8]) -> Option<String> {
    let length = usize::from(*alias.get(10)?);
    let name = alias.get(11..11 + length)?;
    Some(String::from_utf8_lossy(name).into_owned())
}
