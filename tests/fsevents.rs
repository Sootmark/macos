//! plaso's FSEvents logs (Apache-2.0, `tests/fixtures/plaso/`, see its
//! NOTICE): every record plaso's `fseventsd` parser reads, read the same
//! (`tests/oracle/plaso-fsevents.tsv`: file, path, event id, flags, node
//! id; written from plaso's output).

mod support;

use macos::{detect, read_fsevents, Artifact};

#[test]
fn every_record_as_plaso_reads_it() {
    let mut got = Vec::new();
    for name in ["fsevents-00000000001a0b79", "fsevents-0000000002d89b58"] {
        let log = read_fsevents(&support::fixture(&format!("plaso/{name}")));
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
        for event in &log.events {
            let node = event.node.map_or_else(String::new, |n| n.to_string());
            got.push(format!(
                "{name}\t{}\t{}\t{}\t{node}",
                event.path, event.id, event.flags
            ));
        }
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-fsevents.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn flags_and_names() {
    let log = read_fsevents(&support::fixture("plaso/fsevents-0000000002d89b58"));
    let folder = log.events.iter().find(|e| e.path == "Test folder").unwrap();
    assert_eq!(folder.flag_names(), ["Renamed", "IsDirectory"]);
    assert_eq!(
        detect("Volumes/Data/.fseventsd/0000000002d89b58"),
        Some(Artifact::FsEvents)
    );
    assert_eq!(detect("tmp/0000000002d89b58"), None);
}
