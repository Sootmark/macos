//! Background items files: plaso's (Apache-2.0, `tests/fixtures/plaso/`)
//! and puffyCid's macos-loginitems test files (MIT, `tests/fixtures/puffycid/`,
//! see its NOTICE): a macOS 13 `BackgroundItems-v4.btm` as published (XML)
//! and in its binary form, and one written by `PoisonApple`. The login item
//! plaso's `macos_background_items_plist` plugin reads, read the same (its
//! output: name, target path and creation time, volume name, mount point,
//! creation time and flags), and every item read as Python's plistlib, an
//! NSKeyedArchiver resolver and a bookmark reader written apart from this
//! crate read it (`tests/oracle/btm.tsv`, written by
//! `tests/oracle/gen_btm.py`).

mod support;

use common::time::Ts;
use macos::{detect, read_background_items, Artifact, BackgroundItem, ItemRecord};

const FILES: [&str; 4] = [
    "plaso/backgrounditems.btm",
    "puffycid/backgrounditemsPoisonApple.btm",
    "puffycid/BackgroundItems-v4.btm",
    "puffycid/BackgroundItems-v4-binary.btm",
];

fn micros(time: Option<Ts>) -> Option<String> {
    time.and_then(|t| t.ticks()).map(|t| (t / 10).to_string())
}

/// An item as the oracle writes it: tab-separated, `\N` for what it lacks.
fn row(file: &str, item: &BackgroundItem) -> String {
    let (user, record) = match item.record.clone() {
        Some(record) => (Some(record.user.clone()), record),
        None => (None, ItemRecord::default()),
    };
    let cells = [
        user,
        record.uuid,
        record.name,
        record.identifier,
        record.url,
        record.executable_path,
        record.bundle_identifier,
        record.team_identifier,
        record.developer_name,
        record.container,
        record.kind.map(|n| n.to_string()),
        record.disposition.map(|n| n.to_string()),
        item.name.clone(),
        item.target_path.clone(),
        micros(item.target_created),
        micros(item.volume_created),
        item.volume_name.clone(),
        item.volume_mount_point.clone(),
        item.volume_flags.map(|n| n.to_string()),
    ];
    let cells: Vec<String> = cells
        .into_iter()
        .map(|c| c.unwrap_or_else(|| r"\N".to_owned()))
        .collect();
    format!("{file}\t{}", cells.join("\t"))
}

#[test]
fn every_item_as_the_oracle_reads_it() {
    let mut got = Vec::new();
    for file in FILES {
        let items = read_background_items(&support::fixture(file));
        assert_eq!(items.problems, Vec::<String>::new(), "{file}");
        got.extend(items.items.iter().map(|item| row(file, item)));
    }
    let expected: Vec<&str> = include_str!("oracle/btm.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn the_login_item_as_plaso_reads_it() {
    let items = read_background_items(&support::fixture("plaso/backgrounditems.btm"));
    assert_eq!(items.problems, Vec::<String>::new());
    let [item] = &items.items[..] else {
        panic!("{:?}", items.items);
    };
    assert_eq!(item.name.as_deref(), Some("iTunesHelper"));
    assert_eq!(
        item.target_path.as_deref(),
        Some("/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app")
    );
    assert_eq!(item.volume_name.as_deref(), Some("Macintosh HD"));
    assert_eq!(item.volume_mount_point.as_deref(), Some("/"));
    assert_eq!(item.volume_flags, Some(4_294_967_425));
    // plaso: 1499884172000000 and 1508485947000000 µs.
    let micros = |t: Option<common::time::Ts>| t.and_then(|t| t.ticks()).map(|t| t / 10);
    assert_eq!(micros(item.target_created), Some(1_499_884_172_000_000));
    assert_eq!(micros(item.volume_created), Some(1_508_485_947_000_000));
    assert_eq!(
        detect("Users/bob/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"),
        Some(Artifact::BackgroundItems)
    );
}
