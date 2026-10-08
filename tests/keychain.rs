//! plaso's keychain (Apache-2.0, `tests/fixtures/plaso/login.keychain`, see
//! its NOTICE): every event its `mac_keychain` parser reads, read the same
//! (`tests/oracle/plaso-keychain.tsv`, written by
//! `tests/oracle/gen_events.py` from plaso's output), but for plaso's
//! `ssgp_hash`: the encrypted secret, never read here.

mod support;

use macos::{detect, read_keychain, Artifact, AttributeValue, ItemKind, KeychainItem};

/// An item as plaso's events: one per time, with the values plaso shows.
fn lines(item: &KeychainItem) -> Vec<String> {
    let (kind, extra) = match item.kind {
        ItemKind::GenericPassword => ("macos:keychain:application", vec![]),
        ItemKind::InternetPassword => (
            "macos:keychain:internet",
            vec![
                ("protocol", item.protocol()),
                ("text_description", item.text("desc")),
                ("type_protocol", item.text("atyp")),
                ("where", item.server()),
            ],
        ),
        _ => return Vec::new(),
    };
    let mut values = vec![
        ("account_name", item.account()),
        ("comments", item.four_cc("crtr")),
        ("entry_name", item.name()),
    ];
    if extra.is_empty() {
        values.push(("text_description", item.text("desc")));
    }
    values.extend(extra);
    [
        ("Creation Time", item.created()),
        ("Content Modification Time", item.modified()),
    ]
    .into_iter()
    .map(|(desc, time)| {
        let micros = time.unwrap().ticks().unwrap() / 10;
        let mut cells = vec![kind.to_owned(), desc.to_owned(), micros.to_string()];
        cells.extend(
            values
                .iter()
                .filter_map(|(key, value)| Some(format!("{key}={}", value.as_ref()?))),
        );
        cells.join("\t")
    })
    .collect()
}

fn keychain() -> macos::Keychain {
    read_keychain(&support::fixture("plaso/login.keychain")).unwrap()
}

#[test]
fn every_password_as_plaso_reads_it() {
    let keychain = keychain();
    assert!(keychain.problems.is_empty(), "{:?}", keychain.problems);
    let mut got: Vec<String> = keychain.items.iter().flat_map(lines).collect();
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-keychain.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn beyond_plaso() {
    let keychain = keychain();
    let kinds: Vec<ItemKind> = keychain.items.iter().map(|i| i.kind).collect();
    // The two application and two internet passwords plaso reads, and
    // four symmetric keys.
    assert_eq!(
        kinds,
        [
            [ItemKind::SymmetricKey; 4].as_slice(),
            &[ItemKind::GenericPassword; 2],
            &[ItemKind::InternetPassword; 2],
        ]
        .concat()
    );
    let key = &keychain.items[0];
    assert_eq!(
        key.relation.as_deref(),
        Some("CSSM_DL_DB_RECORD_SYMMETRIC_KEY")
    );
    // A key's label is `ssgp` and the label of the item it encrypts.
    let label = match key.get("Label") {
        Some(AttributeValue::Bytes(label)) => label.clone(),
        other => panic!("{other:?}"),
    };
    assert!(label.starts_with(b"ssgp") && label.len() == 20);
    let internet = &keychain.items[6];
    assert_eq!(internet.relation, None);
    assert_eq!(internet.get("port"), Some(&AttributeValue::Integer(0)));
    // No password's attribute holds its encrypted secret (`ssgp`, the
    // label, IV and ciphertext): the record data is never read.
    for item in keychain
        .items
        .iter()
        .filter(|i| i.kind != ItemKind::SymmetricKey)
    {
        for (name, value) in &item.attributes {
            if let AttributeValue::Bytes(bytes) = value {
                assert!(!bytes.starts_with(b"ssgp"), "{name}");
            }
        }
    }
    assert_eq!(
        detect("/Users/a/Library/Keychains/login.keychain"),
        Some(Artifact::Keychain)
    );
}

#[test]
fn refuses_what_is_not_a_keychain() {
    assert!(read_keychain(b"").is_err());
    assert!(read_keychain(b"kych\x00\x02\x00\x00").is_err());
    let mut cut = support::fixture("plaso/login.keychain");
    cut.truncate(30);
    assert!(read_keychain(&cut).is_err());
}
