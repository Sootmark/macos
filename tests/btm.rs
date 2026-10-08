//! plaso's background items file (Apache-2.0, `tests/fixtures/plaso/`, see
//! its NOTICE): the login item plaso's `macos_background_items_plist`
//! plugin reads, read the same (its output: name, target path and creation
//! time, volume name, mount point, creation time and flags).

mod support;

use macos::{detect, read_background_items, Artifact};

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
