//! The Apple System Log (`/private/var/log/asl/*.asl`, macOS 10.4 to
//! 10.12, still written by some daemons after): each message with its
//! time, level, sender, facility, host, process, user and group, and the
//! extra key-value pairs its sender added.
//!
//! A big-endian file: a header (`ASL DB`, version, the first and last
//! record's offsets), then records chained by offset: a fixed part (size,
//! next record, message id, seconds and nanoseconds, level, flags, pid,
//! uid, gid, read uid and gid, reference pid, and the host, sender,
//! facility and message strings' offsets), extra fields (pairs of string
//! offsets) and the previous record's offset. A string offset with its
//! top bit set holds a string of up to seven bytes itself; otherwise it
//! points at a size and the string.

use common::time::{Precision, Ts};

/// The header's signature.
const SIGNATURE: &[u8; 12] = b"ASL DB\0\0\0\0\0\0";
/// The fixed part of a record.
const FIXED: usize = 98;
/// The most records read, against a chain that loops.
const MAX_RECORDS: usize = 1 << 20;

/// A message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AslRecord {
    /// Its offset in the file.
    pub offset: u64,
    /// Its id.
    pub id: u64,
    /// When it was written (UTC, to the nanosecond as written).
    pub time: Option<Ts>,
    /// Its level (0 emergency … 7 debug).
    pub level: u16,
    /// The process.
    pub pid: u32,
    /// The user.
    pub uid: i32,
    /// The group.
    pub gid: i32,
    /// The user allowed to read it (-1: anyone).
    pub read_uid: i32,
    /// The group allowed to read it (-1: anyone).
    pub read_gid: i32,
    /// The host.
    pub host: Option<String>,
    /// The program that sent it.
    pub sender: Option<String>,
    /// Its facility.
    pub facility: Option<String>,
    /// The message.
    pub message: Option<String>,
    /// The extra key-value pairs, sorted by key.
    pub extra: Vec<(String, String)>,
}

/// A file's messages and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asl {
    /// When the file was created (UTC).
    pub created: Option<Ts>,
    /// The messages, in chain order.
    pub records: Vec<AslRecord>,
    /// What couldn't be read.
    pub problems: Vec<String>,
}

/// Whether `head` starts like an ASL file.
#[must_use]
pub fn is_asl(head: &[u8]) -> bool {
    head.starts_with(SIGNATURE)
}

/// Read an ASL file.
#[must_use]
pub fn read_asl(data: &[u8]) -> Asl {
    let mut asl = Asl::default();
    if !is_asl(data) {
        asl.problems.push("no ASL DB signature".to_owned());
        return asl;
    }
    asl.created = u64_at(data, 24)
        .and_then(|s| i64::try_from(s).ok())
        .filter(|&s| s > 0)
        .map(Ts::from_unix_seconds);
    let mut next = u64_at(data, 16).unwrap_or(0);
    let mut seen = 0;
    while next != 0 && seen < MAX_RECORDS {
        seen += 1;
        let Ok(offset) = usize::try_from(next) else {
            break;
        };
        match record(data, offset) {
            Ok((record, following)) => {
                asl.records.push(record);
                if following != 0 && following <= next {
                    asl.problems.push(format!(
                        "offset {offset:#x}: the chain goes backwards, stopped"
                    ));
                    break;
                }
                next = following;
            }
            Err(why) => {
                asl.problems.push(format!("offset {offset:#x}: {why}"));
                break;
            }
        }
    }
    asl
}

/// A record at `offset` and the next one's offset.
fn record(data: &[u8], offset: usize) -> Result<(AslRecord, u64), String> {
    let fixed = data
        .get(offset..offset.saturating_add(FIXED))
        .ok_or("a record cut short")?;
    let u16_ = |at: usize| u16::from_be_bytes([fixed[at], fixed[at + 1]]);
    let u32_ = |at: usize| u32::from_be_bytes(fixed[at..at + 4].try_into().unwrap_or_default());
    let u64_ = |at: usize| u64::from_be_bytes(fixed[at..at + 8].try_into().unwrap_or_default());
    let size = u32_(2) as usize;
    let next = u64_(6);
    let seconds = u64_(22);
    let nanoseconds = u32_(30);
    let string = |at: usize| string(data, u64_(at));
    let extra_size = size
        .saturating_add(6)
        .checked_sub(FIXED)
        .ok_or("a record smaller than its fixed part")?;
    let mut extra = Vec::new();
    let pairs = data
        .get(offset + FIXED..(offset + FIXED).saturating_add(extra_size.saturating_sub(8)))
        .ok_or("extra fields past the end")?;
    for pair in pairs.chunks_exact(16) {
        let key = string_at(data, &pair[..8]);
        let value = string_at(data, &pair[8..]);
        if let Some(key) = key {
            extra.push((key, value.unwrap_or_default()));
        }
    }
    extra.sort();
    let record = AslRecord {
        offset: offset as u64,
        id: u64_(14),
        time: i64::try_from(seconds)
            .ok()
            .filter(|&s| s > 0)
            .and_then(|s| s.checked_mul(10_000_000))
            .and_then(|ticks| ticks.checked_add(i64::from(nanoseconds / 100)))
            .map(|ticks| Ts::from_ticks(ticks, Precision::Tick)),
        level: u16_(34),
        pid: u32_(38),
        uid: u32_(42) as i32,
        gid: u32_(46) as i32,
        read_uid: u32_(50) as i32,
        read_gid: u32_(54) as i32,
        host: string(66),
        sender: string(74),
        facility: string(82),
        message: string(90),
        extra,
    };
    Ok((record, next))
}

fn string_at(data: &[u8], offset: &[u8]) -> Option<String> {
    string(data, u64::from_be_bytes(offset.try_into().ok()?))
}

/// A string: inline in the offset (top bit set: size in bits 56–59, bytes
/// in the low seven), or at the offset (a 16-bit unknown, a 32-bit size,
/// the bytes, a NUL).
fn string(data: &[u8], offset: u64) -> Option<String> {
    if offset == 0 {
        return None;
    }
    if offset >> 63 == 1 {
        let size = ((offset >> 56) & 0x0F) as usize;
        let bytes = offset.to_be_bytes();
        let text = bytes.get(1..1 + size.min(7))?;
        return Some(String::from_utf8_lossy(text).into_owned());
    }
    let at = usize::try_from(offset).ok()?;
    let start = at.checked_add(6)?;
    let size = u32::from_be_bytes(data.get(at + 2..start)?.try_into().ok()?) as usize;
    let bytes = data.get(start..start.saturating_add(size))?;
    Some(
        String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_strings() {
        // 0x8 flag, size 3, "abc".
        let offset = 0x8300_0000_0000_0000
            | (u64::from(b'a') << 48)
            | (u64::from(b'b') << 40)
            | (u64::from(b'c') << 32);
        assert_eq!(string(&[], offset).as_deref(), Some("abc"));
        assert_eq!(string(&[], 0), None);
    }

    #[test]
    fn other_files() {
        assert!(!read_asl(b"not an asl").problems.is_empty());
    }
}
