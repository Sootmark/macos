//! Arbitrary bytes, and real databases damaged and cut anywhere, read or
//! are refused: never a panic.

mod support;

use proptest::prelude::*;

/// Every artifact, every schema version.
const DATABASES: [&str; 6] = [
    "plaso/quarantine.db",
    "plaso/TCC-test.db",
    "plaso/knowledgec-10.13.db.gz",
    "plaso/knowledgec-10.14.db.gz",
    "synthetic/TCC.db",
    "synthetic/knowledgeC.db",
];

const DATABASE: &str = "synthetic/knowledgeC.db";
const LOG: &str = "synthetic/knowledgeC.db-wal";

/// Every reader on the same bytes: each must read or refuse them.
fn read_everything(data: &[u8], wal: &[u8]) {
    let _ = macos::read_quarantine(data, wal);
    let _ = macos::read_tcc(data, wal);
    let _ = macos::read_knowledgec(data, wal);
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        read_everything(&data, &[]);
    }

    #[test]
    fn arbitrary_names_never_panic(name in ".{0,200}") {
        let _ = macos::detect(&name);
    }

    /// A real header with arbitrary pages behind it.
    #[test]
    fn arbitrary_pages_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let mut data = support::fixture("plaso/TCC-test.db")[..100].to_vec();
        data.extend(tail);
        read_everything(&data, &[]);
    }

    #[test]
    fn damaged_databases_never_panic(
        which in 0..DATABASES.len(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40),
        cut in any::<usize>(),
    ) {
        let mut data = support::fixture(DATABASES[which]);
        for &(at, byte) in &flips {
            let at = at % data.len();
            data[at] = byte;
        }
        data.truncate(1 + cut % data.len());
        read_everything(&data, &[]);
    }

    #[test]
    fn damaged_logs_never_panic(
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..20),
        cut in any::<usize>(),
    ) {
        let database = support::fixture(DATABASE);
        let mut wal = support::fixture(LOG);
        for &(at, byte) in &flips {
            let at = at % wal.len();
            wal[at] = byte;
        }
        wal.truncate(cut % (wal.len() + 1));
        read_everything(&database, &wal);
    }
}
