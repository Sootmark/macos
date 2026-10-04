//! plaso's launchd test plists (Apache-2.0, `tests/fixtures/plaso/`): the
//! values plaso's own launchd plugin test expects.

use macos::{detect, read_launchd, Artifact, JobKind};

fn read(name: &str, path: &str) -> macos::LaunchJob {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/plaso/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let read = read_launchd(&data, path).unwrap();
    assert!(read.problems.is_empty(), "{:?}", read.problems);
    read.job
}

#[test]
fn what_plaso_expects() {
    let path = "Library/LaunchDaemons/com.foobar.test.plist";
    assert_eq!(detect(path), Some(Artifact::Launchd(JobKind::Daemon)));
    let job = read("launchd.plist", path);
    assert_eq!(job.label.as_deref(), Some("com.foobar.test"));
    assert_eq!(job.command_line().as_deref(), Some("/Test --flag arg1"));
    assert_eq!(job.user_name.as_deref(), Some("nobody"));
    assert!(job.triggers.run_at_load && job.triggers.keep_alive && job.triggers.calendar);
    assert_eq!(job.triggers.watch_paths, ["/tmp/dir", "/tmp/exist"]);

    let minimal = read("launchd.minimal.plist", "Library/LaunchAgents/foo.plist");
    assert_eq!(minimal.label.as_deref(), Some("foo"));
    assert_eq!(minimal.command_line().as_deref(), Some("/usr/bin/true"));
    assert_eq!(minimal.user_name, None);

    let no_program = read("launchd.noprogram.plist", "Library/LaunchAgents/foo.plist");
    assert_eq!(no_program.executable(), Some("/usr/bin/true"));
}
