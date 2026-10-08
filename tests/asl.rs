//! plaso's Apple System Log files (Apache-2.0, `tests/fixtures/plaso/`):
//! every message plaso's `asl_log` parser reads, read the same
//! (`tests/oracle/plaso-asl.tsv.gz`, written from plaso's output: file,
//! offset, id, time in nanoseconds, level, pid, uid, gid, read uid and gid,
//! host, sender, facility, message, extra fields).

mod support;

use std::io::Read;

use macos::{detect, read_asl, Artifact};

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn every_message_as_plaso_reads_it() {
    let mut got = Vec::new();
    for (name, stored) in [
        ("applesystemlog.asl", "applesystemlog.asl"),
        ("2019.09.26.asl", "2019.09.26.asl.gz"),
    ] {
        assert_eq!(
            detect(&format!("private/var/log/asl/{name}")),
            Some(Artifact::Asl)
        );
        let asl = read_asl(&support::fixture(&format!("plaso/{stored}")));
        assert_eq!(asl.problems, Vec::<String>::new(), "{name}");
        for r in &asl.records {
            let some = |v: &Option<String>| {
                v.clone()
                    .unwrap_or_default()
                    .replace('\n', "\\n")
                    .replace('\t', "\\t")
            };
            let extra: Vec<String> = r.extra.iter().map(|(k, v)| format!("{k}: {v}")).collect();
            let nanos = r.time.and_then(|t| t.ticks()).unwrap() * 100;
            got.push(
                [
                    name.to_owned(),
                    r.offset.to_string(),
                    r.id.to_string(),
                    nanos.to_string(),
                    r.level.to_string(),
                    r.pid.to_string(),
                    r.uid.to_string(),
                    r.gid.to_string(),
                    r.read_uid.to_string(),
                    r.read_gid.to_string(),
                    some(&r.host),
                    some(&r.sender),
                    some(&r.facility),
                    some(&r.message),
                    extra.join(", ").replace('\n', "\\n").replace('\t', "\\t"),
                ]
                .join("\t"),
            );
        }
    }
    got.sort();
    let oracle = String::from_utf8(gunzip(include_bytes!("oracle/plaso-asl.tsv.gz"))).unwrap();
    let expected: Vec<&str> = oracle.lines().collect();
    assert_eq!(got.len(), expected.len());
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
}
