//! Keychains: `~/Library/Keychains/login.keychain` (before macOS 10.12),
//! `login.keychain-db` (from 10.12) and `/Library/Keychains/System.keychain`,
//! the file keychains (`kych`) of Apple's CSSM data store. Their items are
//! read; their secrets never are.
//!
//! A big-endian database: a header (`kych`, version 1.0, the offset of the
//! tables array), then tables, each of one relation (record type) with an
//! array of record offsets (0, or odd for a free-list link, where none is).
//! A record is a header (its size, number and the size of its data), one
//! offset per attribute of its relation (from the record's start, plus 1; 0
//! for none), its data, then the attributes' values. The data is the
//! secret: a password's encrypted blob (`ssgp`, a label, an IV and the
//! ciphertext), a key's wrapped key bytes, a certificate's DER; it is left
//! unread.
//!
//! The database describes itself: the schema relations (`0` names each
//! relation, `2` lists each relation's attributes: identifier, name and
//! format) give every other table its columns, as Apple's `securityd`
//! writes them. The items read are a relation's records outside the schema
//! and the database's own metadata: generic (application) passwords
//! (`0x80000000`), internet passwords (`0x80000001`), AppleShare passwords
//! (`0x80000002`), certificates (`0x80001000`) and public, private and
//! symmetric keys (`0x0F` to `0x11`), with their attributes by name: the
//! item's name (`PrintName`), account (`acct`), service (`svce`), server
//! (`srvr`), protocol (`ptcl`), creation and modification times (`cdat`,
//! `mdat`, `YYYYMMDDhhmmssZ` in UTC), creator (`crtr`) and the rest.

use common::time::Ts;

use crate::Error;

/// What a keychain item is, by its relation (record type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// `0x80000000`: an application password (Keychain Access's
    /// "application password", a secure note).
    GenericPassword,
    /// `0x80000001`: a password for a server, by protocol.
    InternetPassword,
    /// `0x80000002`: an AppleShare password.
    AppleSharePassword,
    /// `0x80001000`: an X.509 certificate.
    Certificate,
    /// `0x0000000F`.
    PublicKey,
    /// `0x00000010`.
    PrivateKey,
    /// `0x00000011`.
    SymmetricKey,
    /// Another relation, by its identifier.
    Other(u32),
}

impl ItemKind {
    fn of(relation: u32) -> Self {
        match relation {
            0x8000_0000 => Self::GenericPassword,
            0x8000_0001 => Self::InternetPassword,
            0x8000_0002 => Self::AppleSharePassword,
            0x8000_1000 => Self::Certificate,
            0x0F => Self::PublicKey,
            0x10 => Self::PrivateKey,
            0x11 => Self::SymmetricKey,
            other => Self::Other(other),
        }
    }
}

/// An attribute's value, by the format the schema gives it.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    /// A string (format 0).
    Text(String),
    /// A signed or unsigned 32-bit integer (formats 1 and 2); a four
    /// character code as such (`ptcl`, `crtr`, `type`).
    Integer(i64),
    /// A big number's bytes (format 3) or a blob (format 6): names,
    /// accounts and servers are blobs of UTF-8.
    Bytes(Vec<u8>),
    /// A real (format 4).
    Real(f64),
    /// A time (format 5), UTC to the second.
    Time(Ts),
    /// Unsigned 32-bit integers (format 7).
    Integers(Vec<u32>),
}

/// An item: a record of a keychain's relation, without its secret.
#[derive(Debug, Clone, PartialEq)]
pub struct KeychainItem {
    /// What it is.
    pub kind: ItemKind,
    /// Its relation's name in the schema (`CSSM_DL_DB_RECORD_SYMMETRIC_KEY`),
    /// when it has one: the password relations' are empty.
    pub relation: Option<String>,
    /// The record's number in its table.
    pub record_number: u32,
    /// Its attributes with a value, by name, in the schema's order.
    pub attributes: Vec<(String, AttributeValue)>,
}

impl KeychainItem {
    /// An attribute's value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AttributeValue> {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, value)| value)
    }

    /// An attribute as text: a string, or a blob's UTF-8 (invalid
    /// sequences replaced); `None` when empty or of another format.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<String> {
        let text = match self.get(name)? {
            AttributeValue::Text(text) => text.clone(),
            AttributeValue::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            _ => return None,
        };
        Some(text).filter(|text| !text.is_empty())
    }

    /// An integer attribute as its four character code (`htps`, `dflt`);
    /// `None` when 0.
    #[must_use]
    pub fn four_cc(&self, name: &str) -> Option<String> {
        match self.get(name)? {
            AttributeValue::Integer(code) if *code != 0 => {
                let bytes = u32::try_from(*code).ok()?.to_be_bytes();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            _ => None,
        }
    }

    /// A time attribute.
    #[must_use]
    pub fn time(&self, name: &str) -> Option<Ts> {
        match self.get(name)? {
            AttributeValue::Time(time) => Some(*time),
            _ => None,
        }
    }

    /// The name Keychain Access shows (`PrintName`).
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.text("PrintName")
    }

    /// The account (`acct`).
    #[must_use]
    pub fn account(&self) -> Option<String> {
        self.text("acct")
    }

    /// The service of an application password (`svce`).
    #[must_use]
    pub fn service(&self) -> Option<String> {
        self.text("svce")
    }

    /// The server of an internet password (`srvr`): a host name or address.
    #[must_use]
    pub fn server(&self) -> Option<String> {
        self.text("srvr")
    }

    /// The protocol of an internet password, named (`https` for `htps`;
    /// the code, trimmed, for one without a longer name).
    #[must_use]
    pub fn protocol(&self) -> Option<String> {
        let code = self.four_cc("ptcl")?;
        let name = PROTOCOLS.iter().find(|(c, _)| *c == code).map_or_else(
            || code.trim_end().to_owned(),
            |(_, name)| (*name).to_owned(),
        );
        Some(name)
    }

    /// When the item was created (`cdat`).
    #[must_use]
    pub fn created(&self) -> Option<Ts> {
        self.time("cdat")
    }

    /// When the item was last modified (`mdat`).
    #[must_use]
    pub fn modified(&self) -> Option<Ts> {
        self.time("mdat")
    }
}

/// Protocol codes (`SecProtocolType`) whose name isn't the code.
const PROTOCOLS: [(&str, &str); 16] = [
    ("htps", "https"),
    ("htpx", "http proxy"),
    ("htsx", "https proxy"),
    ("ftpa", "ftp account"),
    ("ftpx", "ftp proxy"),
    ("teln", "telnet"),
    ("tels", "telnets"),
    ("ntps", "nntps"),
    ("ldps", "ldaps"),
    ("imps", "imaps"),
    ("pops", "pop3s"),
    ("rtsx", "rtsp proxy"),
    ("atlk", "appletalk"),
    ("cvsp", "cvs pserver"),
    ("AdIM", "addressbook"),
    ("any ", "any"),
];

/// A keychain's items.
#[derive(Debug, Clone, PartialEq)]
pub struct Keychain {
    /// Its items, table by table in the file's order, records in each
    /// table's order.
    pub items: Vec<KeychainItem>,
    /// Damage: tables, records and values that couldn't be read.
    pub problems: Vec<String>,
}

const SCHEMA_INFO: u32 = 0;
const SCHEMA_INDEXES: u32 = 1;
const SCHEMA_ATTRIBUTES: u32 = 2;
const SCHEMA_PARSING_MODULE: u32 = 3;
/// The database's own blob: its wrapped master key.
const METADATA: u32 = 0x8000_8000;
/// A record's header: its size, number, two versions, the size of its
/// data and its semantic information.
const RECORD_HEADER: usize = 24;

/// Read a file keychain (`login.keychain`, `login.keychain-db`,
/// `System.keychain`).
///
/// # Errors
/// When it isn't a file keychain of version 1.0, or its tables array can't
/// be read.
pub fn read_keychain(data: &[u8]) -> Result<Keychain, Error> {
    if data.get(..4) != Some(b"kych") {
        return Err(Error("not a keychain: no kych signature".to_owned()));
    }
    let (major, minor) = (be16(data, 4), be16(data, 6));
    if (major, minor) != (Some(1), Some(0)) {
        return Err(Error(format!(
            "unsupported keychain version {}.{}",
            major.unwrap_or_default(),
            minor.unwrap_or_default()
        )));
    }
    let tables = tables(data)?;
    let mut reader = Reader::new(data);
    let schema = Schema::read(&mut reader, &tables);
    let mut items = Vec::new();
    for table in &tables {
        if matches!(
            table.relation,
            SCHEMA_INFO | SCHEMA_INDEXES | SCHEMA_ATTRIBUTES | SCHEMA_PARSING_MODULE | METADATA
        ) {
            continue;
        }
        let columns = schema.columns(table.relation);
        for &at in &table.records {
            let Some(record) = reader.record(at, columns.len()) else {
                continue;
            };
            let attributes = reader.values(&record, &columns);
            items.push(KeychainItem {
                kind: ItemKind::of(table.relation),
                relation: schema.relation_name(table.relation),
                record_number: record.number,
                attributes,
            });
        }
    }
    Ok(Keychain {
        items,
        problems: reader.problems,
    })
}

/// A table: its relation and where its records start in the file.
struct Table {
    relation: u32,
    records: Vec<usize>,
}

/// The tables the tables array lists. Their slot arrays don't overlap, so
/// a file listing more slots than it has words is damaged and refused.
fn tables(data: &[u8]) -> Result<Vec<Table>, Error> {
    let cut = || Error("keychain cut short in its tables array".to_owned());
    let word = |base: usize, offset: usize| {
        base.checked_add(offset)
            .and_then(|at| be32(data, at))
            .ok_or_else(cut)
    };
    let array = word(12, 0)? as usize;
    let count = word(array, 4)? as usize;
    let mut slots_left = data.len() / 4;
    let mut tables = Vec::new();
    for index in 0..count {
        let start = array
            .checked_add(word(array, index.saturating_mul(4).saturating_add(8))? as usize)
            .ok_or_else(cut)?;
        let relation = word(start, 4)?;
        let slots = word(start, 24)? as usize;
        slots_left = slots_left.checked_sub(slots).ok_or_else(|| {
            Error(format!(
                "keychain lists more records than its {} bytes can hold",
                data.len()
            ))
        })?;
        let mut records = Vec::new();
        for slot in 0..slots {
            let at = word(start, slot.saturating_mul(4).saturating_add(28))? as usize;
            // 0 is an empty slot, an odd offset a link in the free list.
            if at != 0 && at % 2 == 0 {
                records.push(start.checked_add(at).ok_or_else(cut)?);
            }
        }
        tables.push(Table { relation, records });
    }
    Ok(tables)
}

/// A record's header and attribute offsets.
struct Record {
    /// Where it starts in the file.
    start: usize,
    /// Its size, header included.
    size: usize,
    number: u32,
    /// Each attribute's offset from the record's start, plus 1; 0 for none.
    offsets: Vec<u32>,
}

/// An attribute of a relation, as the schema describes it.
#[derive(Clone)]
struct Column {
    name: String,
    format: u32,
}

impl Column {
    fn new(name: &str, format: u32) -> Self {
        Self {
            name: name.to_owned(),
            format,
        }
    }
}

/// Records and values read from the file, within a budget of four times its
/// size: damaged records can overlap, or point many values at the same
/// bytes, and what is read is copied.
struct Reader<'d> {
    data: &'d [u8],
    /// Bytes still to be copied into values.
    budget: usize,
    problems: Vec<String>,
}

impl<'d> Reader<'d> {
    fn new(data: &'d [u8]) -> Self {
        Self {
            data,
            budget: data.len().saturating_mul(4),
            problems: Vec::new(),
        }
    }

    /// The record at `start` with `columns` attributes; `None` when the
    /// budget is spent, or (with a problem) when the file or the record is
    /// too short for its header and offsets.
    fn record(&mut self, start: usize, columns: usize) -> Option<Record> {
        let size = be32(self.data, start).map_or(0, |size| size as usize);
        let offsets_end = columns.saturating_mul(4).saturating_add(RECORD_HEADER);
        let end = start.checked_add(size);
        if size < offsets_end || end.map_or(true, |end| end > self.data.len()) {
            self.problems
                .push(format!("record at {start:#x} is cut short"));
            return None;
        }
        if !self.spend(offsets_end) {
            return None;
        }
        let offsets = (0..columns)
            .map(|column| be32(self.data, start + RECORD_HEADER + column * 4))
            .collect::<Option<Vec<_>>>()?;
        Some(Record {
            start,
            size,
            number: be32(self.data, start + 4)?,
            offsets,
        })
    }

    /// Take `bytes` from the budget; when it is spent, say so once.
    fn spend(&mut self, bytes: usize) -> bool {
        if let Some(rest) = self.budget.checked_sub(bytes) {
            self.budget = rest;
            return true;
        }
        if self.budget != 0 {
            self.budget = 0;
            self.problems
                .push("records overlap: more is read than the file holds".to_owned());
        }
        false
    }

    /// A record's attribute values, by its relation's columns; those it
    /// doesn't have left out, those that can't be read added to
    /// `problems`.
    fn values(&mut self, record: &Record, columns: &[Column]) -> Vec<(String, AttributeValue)> {
        let mut values = Vec::new();
        for (column, &offset) in columns.iter().zip(&record.offsets) {
            if offset == 0 {
                continue;
            }
            // The value's bytes: from its offset to the record's end.
            let from = offset as usize - 1;
            let bytes = (from < record.size)
                .then(|| {
                    self.data
                        .get(record.start + from..record.start + record.size)
                })
                .flatten();
            match bytes.and_then(|bytes| value(bytes, column.format)) {
                Some(Ok(value)) => {
                    if !self.spend(column.name.len() + value.size()) {
                        return values;
                    }
                    values.push((column.name.clone(), value));
                }
                Some(Err(())) => {}
                None => self.problems.push(format!(
                    "record {} at {:#x}: {} can't be read",
                    record.number, record.start, column.name
                )),
            }
        }
        values
    }
}

impl AttributeValue {
    /// The bytes it takes in the file, at least.
    fn size(&self) -> usize {
        match self {
            Self::Text(text) => 4 + text.len(),
            Self::Bytes(bytes) => 4 + bytes.len(),
            Self::Integers(integers) => 4 + integers.len() * 4,
            Self::Integer(_) => 4,
            Self::Real(_) => 8,
            Self::Time(_) => 16,
        }
    }
}

/// The schema: relation names, and each relation's attributes in order.
struct Schema {
    relations: Vec<(u32, String)>,
    columns: Vec<(u32, Column)>,
}

impl Schema {
    /// The schema relations' records, read by their own attributes as
    /// `securityd` defines them.
    fn read(reader: &mut Reader<'_>, tables: &[Table]) -> Self {
        let records = |relation: u32| {
            tables
                .iter()
                .filter(move |t| t.relation == relation)
                .flat_map(|t| t.records.iter().copied())
        };
        let mut schema = Self {
            relations: Vec::new(),
            columns: Vec::new(),
        };
        let info = [Column::new("RelationID", 2), Column::new("RelationName", 0)];
        for at in records(SCHEMA_INFO) {
            let Some(values) = reader.schema_values(at, &info) else {
                continue;
            };
            match (
                integer(&values, "RelationID"),
                find(&values, "RelationName"),
            ) {
                (Some(id), Some(AttributeValue::Text(name))) if !name.is_empty() => {
                    schema.relations.push((id, name.clone()));
                }
                _ => {}
            }
        }
        let attributes = [
            Column::new("RelationID", 2),
            Column::new("AttributeID", 2),
            Column::new("AttributeNameFormat", 2),
            Column::new("AttributeName", 0),
            Column::new("AttributeNameID", 6),
            Column::new("AttributeFormat", 2),
        ];
        for at in records(SCHEMA_ATTRIBUTES) {
            let Some(values) = reader.schema_values(at, &attributes) else {
                continue;
            };
            let (Some(relation), Some(format)) = (
                integer(&values, "RelationID"),
                integer(&values, "AttributeFormat"),
            ) else {
                reader
                    .problems
                    .push(format!("schema: attribute record at {at:#x} is incomplete"));
                continue;
            };
            let name = match find(&values, "AttributeName") {
                Some(AttributeValue::Text(name)) if !name.is_empty() => name.clone(),
                // Named by its identifier: a four character code.
                _ => integer(&values, "AttributeID").map_or_else(String::new, |id| {
                    String::from_utf8_lossy(&id.to_be_bytes()).into_owned()
                }),
            };
            schema.columns.push((relation, Column { name, format }));
        }
        schema
    }

    fn relation_name(&self, relation: u32) -> Option<String> {
        self.relations
            .iter()
            .find(|(id, _)| *id == relation)
            .map(|(_, name)| name.clone())
    }

    fn columns(&self, relation: u32) -> Vec<Column> {
        self.columns
            .iter()
            .filter(|(r, _)| *r == relation)
            .map(|(_, column)| column.clone())
            .collect()
    }
}

impl Reader<'_> {
    /// A schema record's values; `None` when it can't be read.
    fn schema_values(
        &mut self,
        at: usize,
        columns: &[Column],
    ) -> Option<Vec<(String, AttributeValue)>> {
        let record = self.record(at, columns.len())?;
        Some(self.values(&record, columns))
    }
}

/// A value by name among a record's.
fn find<'v>(values: &'v [(String, AttributeValue)], name: &str) -> Option<&'v AttributeValue> {
    values.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

/// An unsigned integer value by name.
fn integer(values: &[(String, AttributeValue)], name: &str) -> Option<u32> {
    match find(values, name)? {
        AttributeValue::Integer(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

/// A value of `format` at the start of `bytes`: `None` when it can't be
/// read, `Some(Err(()))` for a format that isn't read (complex, 8).
fn value(bytes: &[u8], format: u32) -> Option<Result<AttributeValue, ()>> {
    let sized = || {
        let size = be32(bytes, 0)? as usize;
        bytes.get(4..4usize.checked_add(size)?)
    };
    let value = match format {
        0 => AttributeValue::Text(String::from_utf8_lossy(sized()?).into_owned()),
        1 => AttributeValue::Integer(i64::from(be32(bytes, 0)? as i32)),
        2 => AttributeValue::Integer(i64::from(be32(bytes, 0)?)),
        3 | 6 => AttributeValue::Bytes(sized()?.to_vec()),
        4 => AttributeValue::Real(f64::from_be_bytes(bytes.get(..8)?.try_into().ok()?)),
        5 => AttributeValue::Time(time(bytes.get(..16)?)?),
        7 => {
            let count = be32(bytes, 0)? as usize;
            let integers = bytes.get(4..4usize.checked_add(count.checked_mul(4)?)?)?;
            AttributeValue::Integers(
                integers
                    .chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect(),
            )
        }
        _ => return Some(Err(())),
    };
    Some(Ok(value))
}

/// A time value: `YYYYMMDDhhmmssZ` and a NUL, UTC.
fn time(bytes: &[u8]) -> Option<Ts> {
    let text = std::str::from_utf8(bytes.get(..15)?).ok()?;
    let digits = text
        .get(..14)
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))?;
    if !text.ends_with('Z') {
        return None;
    }
    let iso = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &digits[..4],
        &digits[4..6],
        &digits[6..8],
        &digits[8..10],
        &digits[10..12],
        &digits[12..14]
    );
    Ts::parse_iso8601_utc(&iso)
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc_seconds() {
        assert_eq!(
            time(b"20140126145148Z\0")
                .and_then(|t| t.to_iso8601())
                .as_deref(),
            Some("2014-01-26T14:51:48.0000000Z")
        );
        assert_eq!(time(b"20140230145148Z\0"), None);
        assert_eq!(time(b"2014012614514800"), None);
        assert_eq!(time(b"2014"), None);
    }

    #[test]
    fn values_by_format() {
        let text = [0, 0, 0, 3, b'a', b'b', b'c', 0];
        assert_eq!(
            value(&text, 0),
            Some(Ok(AttributeValue::Text("abc".to_owned())))
        );
        assert_eq!(
            value(&[0xFF, 0xFF, 0xFF, 0xFE], 1),
            Some(Ok(AttributeValue::Integer(-2)))
        );
        assert_eq!(
            value(&[0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 9], 7),
            Some(Ok(AttributeValue::Integers(vec![7, 9])))
        );
        assert_eq!(value(&[0, 0, 0, 9, 1], 6), None);
        assert_eq!(value(&[], 8), Some(Err(())));
    }
}
