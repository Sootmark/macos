//! Background items (`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`,
//! macOS 10.13 to 12, and `BackgroundItems-v<n>.btm`): the login items a
//! user's session starts, macOS's per-user persistence.
//!
//! The file is an NSKeyedArchiver property list. Its `backgroundItems`
//! (10.13 to 12) hold `allContainers`, each with a bookmark and
//! `internalItems` (an array or an `NSHashTable`) of items with theirs; its `store` (later versions) holds
//! `itemsByUserIdentifier`, each a list of items with a bookmark. A
//! bookmark (`book`, as libyal's dtformats documents it) is a header, a
//! data area and a table of contents of tagged values: the target's path
//! components (`0x1004`) and creation time (`0x1040`), the volume's mount
//! point (`0x2002`), name (`0x2010`), creation time (`0x2013`) and flags
//! (`0x2020`), and the display name (`0xf017`), read as plaso reads them.

use common::time::Ts;
use plist::Value;

/// The data area's offset in a bookmark.
const DATA_AREA: usize = 48;

/// A login item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackgroundItem {
    /// Its display name.
    pub name: Option<String>,
    /// What it starts: the volume's mount point and the path components.
    pub target_path: Option<String>,
    /// When the target was created (UTC).
    pub target_created: Option<Ts>,
    /// The target volume's name.
    pub volume_name: Option<String>,
    /// Where the volume is mounted.
    pub volume_mount_point: Option<String>,
    /// When the volume was created (UTC).
    pub volume_created: Option<Ts>,
    /// The volume's flags, masked by those valid.
    pub volume_flags: Option<u64>,
}

/// A file's items and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackgroundItems {
    /// The items, in file order.
    pub items: Vec<BackgroundItem>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Whether a file name is a background items file's.
#[must_use]
pub fn is_background_items_name(name: &str) -> bool {
    let btm = std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("btm"));
    let lower = name.to_ascii_lowercase();
    btm && (lower == "backgrounditems.btm" || lower.starts_with("backgrounditems-v"))
}

/// Read a background items file.
#[must_use]
pub fn read_background_items(data: &[u8]) -> BackgroundItems {
    let mut out = BackgroundItems::default();
    let archive = match plist::parse(data) {
        Ok(parsed) => parsed.value,
        Err(why) => {
            out.problems.push(format!("not a property list: {why}"));
            return out;
        }
    };
    let Some(unarchived) = plist::unarchive(&archive) else {
        out.problems
            .push("not an NSKeyedArchiver archive".to_owned());
        return out;
    };
    // The resolver's notes are left out: these archives point back at
    // their containers, which it reports as cycles; what an item lacks
    // shows below.
    let root = unarchived.value.get("root").unwrap_or(&unarchived.value);
    let mut bookmarks: Vec<&[u8]> = Vec::new();
    if let Some(items) = root.get("backgroundItems") {
        for container in items
            .get("allContainers")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            bookmarks.extend(bookmark_data(container.get("bookmark")));
            if let Some(internal) = container.get("internalItems") {
                for item in members(internal) {
                    bookmarks.extend(bookmark_data(item.get("bookmark")));
                }
            }
        }
    } else if let Some(store) = root.get("store") {
        let users = store
            .get("itemsByUserIdentifier")
            .and_then(Value::as_dictionary)
            .unwrap_or_default();
        for (_, items) in users {
            for item in items.as_array().unwrap_or_default() {
                bookmarks.extend(bookmark_data(item.get("bookmark")));
            }
        }
    } else {
        out.problems
            .push("neither backgroundItems nor store".to_owned());
    }
    for data in bookmarks {
        match bookmark(data) {
            Ok(item) => out.items.push(item),
            Err(why) => out.problems.push(format!("bookmark: {why}")),
        }
    }
    out
}

/// A collection's items: an array's elements, an `NSHashTable`'s (`$1`,
/// `$2`, … after its count in `$0`), or the value itself.
fn members(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    let table: Vec<&Value> = value
        .as_dictionary()
        .unwrap_or_default()
        .iter()
        .filter(|(key, _)| {
            key.strip_prefix('$')
                .is_some_and(|n| n != "0" && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|(_, item)| item)
        .collect();
    if table.is_empty() {
        vec![value]
    } else {
        table
    }
}

/// A bookmark's bytes: data, or a dictionary holding them under `data`.
fn bookmark_data(value: Option<&Value>) -> Option<&[u8]> {
    let value = value?;
    value
        .as_data()
        .or_else(|| value.get("data").and_then(Value::as_data))
}

/// A bookmark's tagged values, as plaso reads them.
fn bookmark(data: &[u8]) -> Result<BackgroundItem, String> {
    let signature = data.get(..4).ok_or("shorter than its header")?;
    if signature != b"book" && signature != b"alis" {
        return Err(format!("signature {signature:02x?}"));
    }
    if u32_at(data, 12) != Some(DATA_AREA as u32) {
        return Err("a data area not at offset 48".to_owned());
    }
    let toc = DATA_AREA + u32_at(data, DATA_AREA).ok_or("no data area")? as usize;
    if u32_at(data, toc + 4) != Some(0xffff_fffe) {
        return Err("no table of contents".to_owned());
    }
    let count = u32_at(data, toc + 16).ok_or("a table of contents cut short")? as usize;
    let mut item = BackgroundItem::default();
    let mut components: Option<Vec<String>> = None;
    for index in 0..count.min(4096) {
        let entry = toc + 20 + index * 12;
        let (Some(tag), Some(offset)) = (u32_at(data, entry), u32_at(data, entry + 4)) else {
            return Err("a tagged value cut short".to_owned());
        };
        let record = Record::at(data, DATA_AREA + offset as usize)?;
        match tag {
            0x1004 => {
                let parts: Result<Vec<String>, String> = record
                    .integers()
                    .iter()
                    .map(|&at| Record::at(data, DATA_AREA + at as usize).map(|r| r.string()))
                    .collect();
                components = Some(parts?);
            }
            0x1040 => item.target_created = record.cocoa_time(),
            0x2002 => item.volume_mount_point = Some(record.string()),
            0x2010 => item.volume_name = Some(record.string()),
            0x2013 => item.volume_created = record.cocoa_time(),
            0x2020 => {
                let flags = u64_at(record.data, 0).unwrap_or(0);
                let valid = u64_at(record.data, 8).unwrap_or(0);
                item.volume_flags = Some(flags & valid);
            }
            0xf017 => item.name = Some(record.string()),
            _ => {}
        }
    }
    if let Some(components) = components.filter(|c| !c.is_empty()) {
        let relative = components.join("/");
        item.target_path = Some(match &item.volume_mount_point {
            Some(mount) => format!("{mount}{relative}"),
            None => relative,
        });
    }
    Ok(item)
}

/// A data record: its type and data.
struct Record<'a> {
    kind: u32,
    data: &'a [u8],
}

impl<'a> Record<'a> {
    fn at(bookmark: &'a [u8], offset: usize) -> Result<Self, String> {
        let size = u32_at(bookmark, offset).ok_or("a record past the end")? as usize;
        let kind = u32_at(bookmark, offset + 4).ok_or("a record cut short")?;
        let data = bookmark
            .get(offset + 8..(offset + 8).saturating_add(size))
            .ok_or("a record's data past the end")?;
        Ok(Self { kind, data })
    }

    fn string(&self) -> String {
        String::from_utf8_lossy(self.data).into_owned()
    }

    /// An array of offsets (`0x0601`).
    fn integers(&self) -> Vec<u32> {
        if self.kind != 0x0601 {
            return Vec::new();
        }
        self.data
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// A date: big-endian seconds since 2001-01-01.
    fn cocoa_time(&self) -> Option<Ts> {
        let bytes: [u8; 8] = self.data.get(..8)?.try_into().ok()?;
        let seconds = f64::from_be_bytes(bytes);
        seconds.is_finite().then(|| Ts::from_cocoa_seconds(seconds))
    }
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_background_items_name("backgrounditems.btm"));
        assert!(is_background_items_name("BackgroundItems-v4.btm"));
        assert!(!is_background_items_name("items.btm"));
    }

    #[test]
    fn not_bookmarks() {
        assert!(bookmark(b"xxxx").is_err());
        assert!(bookmark(&[0; 8]).is_err());
        assert!(!read_background_items(b"not a plist").problems.is_empty());
    }
}
