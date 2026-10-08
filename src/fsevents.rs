//! FSEvents (`/.fseventsd/<16 hex digits>` on each volume): the file
//! system's change log, kept by `fseventsd`: which paths were created,
//! removed, renamed, modified, their permissions or extended attributes
//! changed, months after the files themselves are gone.
//!
//! A file is gzip-compressed, then pages: a signature (`1SLD`, `2SLD` or
//! `3SLD`), 4 unknown bytes and the page's size (header included), then
//! records: the path (NUL-terminated, relative to the volume), the event
//! identifier (a counter, increasing with time), the flags, the node
//! identifier (version 2 and later) and 4 more bytes (version 3). Records
//! carry no time: a file's name is its last event's identifier, and its
//! modification time bounds them. The flags' names are those of
//! `sys/fsevents.h`, as plaso names them.

use std::io::Read;

/// The largest file read once decompressed: a log is a few megabytes.
const MAX_SIZE: usize = 256 << 20;

/// A change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEvent {
    /// The path, relative to the volume's root.
    pub path: String,
    /// The event's identifier.
    pub id: u64,
    /// Its flags (see [`FsEvent::flag_names`]).
    pub flags: u32,
    /// The file system node (version 2 and later).
    pub node: Option<u64>,
    /// The page's version (1, 2 or 3).
    pub version: u8,
}

impl FsEvent {
    /// The flags' names (`Created`, `Renamed`, `IsFile`, …).
    #[must_use]
    pub fn flag_names(&self) -> Vec<&'static str> {
        FLAGS
            .iter()
            .filter(|(bit, _)| self.flags & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

/// The flags, as `sys/fsevents.h` numbers them (bit = 1 << constant).
const FLAGS: [(u32, &str); 21] = [
    (0x0000_0001, "Created"),
    (0x0000_0002, "Removed"),
    (0x0000_0004, "InodeMetadataModified"),
    (0x0000_0008, "Renamed"),
    (0x0000_0010, "Modified"),
    (0x0000_0020, "Exchange"),
    (0x0000_0040, "FinderInfoModified"),
    (0x0000_0080, "DirectoryCreated"),
    (0x0000_0100, "PermissionChanged"),
    (0x0000_0200, "ExtendedAttributeModified"),
    (0x0000_0400, "ExtendedAttributeRemoved"),
    (0x0000_1000, "DocumentRevision"),
    (0x0000_4000, "ItemCloned"),
    (0x0008_0000, "LastHardLinkRemoved"),
    (0x0010_0000, "IsHardLink"),
    (0x0040_0000, "IsSymbolicLink"),
    (0x0080_0000, "IsFile"),
    (0x0100_0000, "IsDirectory"),
    (0x0200_0000, "Mount"),
    (0x0400_0000, "Unmount"),
    (0x2000_0000, "EndOfTransaction"),
];

/// A file's changes and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsEvents {
    /// The changes, in file order.
    pub events: Vec<FsEvent>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Whether a file name is an FSEvents log's (16 hexadecimal digits).
#[must_use]
pub fn is_fsevents_name(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read an FSEvents log, gzip-compressed as `fseventsd` writes it (or
/// already decompressed).
#[must_use]
pub fn read_fsevents(data: &[u8]) -> FsEvents {
    let mut log = FsEvents::default();
    let pages = if data.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        let decoder = common::gzip::Decoder::new(data);
        if let Err(why) = decoder.take(MAX_SIZE as u64).read_to_end(&mut out) {
            log.problems.push(format!("gzip: {why}"));
        }
        out
    } else {
        data.to_vec()
    };
    let mut at = 0;
    while at + 12 <= pages.len() {
        let version = match &pages[at..at + 4] {
            b"1SLD" => 1,
            b"2SLD" => 2,
            b"3SLD" => 3,
            other => {
                log.problems
                    .push(format!("offset {at}: no page signature ({other:02x?})"));
                break;
            }
        };
        let size = u32_at(&pages, at + 8) as usize;
        let Some(page) = pages.get(at + 12..at + size.max(12)) else {
            log.problems
                .push(format!("offset {at}: a page of {size} bytes past the end"));
            records(&pages[at + 12..], version, &mut log);
            break;
        };
        records(page, version, &mut log);
        at += size.max(12);
    }
    log
}

/// A page's records.
fn records(page: &[u8], version: u8, log: &mut FsEvents) {
    let tail = match version {
        1 => 12,
        2 => 20,
        _ => 24,
    };
    let mut at = 0;
    while at < page.len() {
        let Some(end) = page[at..].iter().position(|&b| b == 0) else {
            log.problems.push("a path without its end".to_owned());
            return;
        };
        let fields = at + end + 1;
        let Some(rest) = page.get(fields..fields + tail) else {
            log.problems.push("a record cut short".to_owned());
            return;
        };
        log.events.push(FsEvent {
            path: String::from_utf8_lossy(&page[at..at + end]).into_owned(),
            id: u64_at(rest, 0),
            flags: u32_at(rest, 8),
            node: (version >= 2).then(|| u64_at(rest, 12)),
            version,
        });
        at = fields + tail;
    }
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    data.get(at..at + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    data.get(at..at + 8).map_or(0, |b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(version: u8, records: &[(&str, u64, u32)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (path, id, flags) in records {
            body.extend(path.as_bytes());
            body.push(0);
            body.extend(id.to_le_bytes());
            body.extend(flags.to_le_bytes());
            if version >= 2 {
                body.extend(7u64.to_le_bytes());
            }
            if version == 3 {
                body.extend(0u32.to_le_bytes());
            }
        }
        let mut page = format!("{version}SLD").into_bytes();
        page.extend(0u32.to_le_bytes());
        page.extend(((body.len() + 12) as u32).to_le_bytes());
        page.extend(body);
        page
    }

    #[test]
    fn versions_and_flags() {
        let mut data = page(3, &[("Users/bob/a.txt", 9, 0x0080_0011)]);
        data.extend(page(1, &[("", 10, 0x0200_0000)]));
        let log = read_fsevents(&data);
        assert_eq!(log.problems, Vec::<String>::new());
        assert_eq!(log.events.len(), 2);
        assert_eq!(log.events[0].node, Some(7));
        assert_eq!(
            log.events[0].flag_names(),
            ["Created", "Modified", "IsFile"]
        );
        assert_eq!(log.events[1].node, None);
        assert!(!read_fsevents(b"nothing here at all").problems.is_empty());
    }
}
