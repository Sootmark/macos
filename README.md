# macos

macOS artifacts for forensics: launchd jobs (LaunchAgents and LaunchDaemons, macOS's main persistence), and those kept in SQLite databases: where each downloaded file came from (quarantine events), which apps were allowed the camera, the microphone, the screen, the whole disk (TCC), and which apps were in front, when the screen was on and the device locked (KnowledgeC). Two dependencies, its siblings `sootmark-common` (times) and `sootmark-sqlite` (the databases, read without SQLite).

```toml
[dependencies]
sootmark-macos = "0.4"
```

```rust
let database = std::fs::read("com.apple.LaunchServices.QuarantineEventsV2")?;
let quarantine = macos::read_quarantine(&database, &[])?;
for e in &quarantine.events {
    println!("{:?} {:?} {:?} from {:?}", e.time, e.agent_name, e.data_url, e.origin_url);
}

let database = std::fs::read("TCC.db")?;
let wal = std::fs::read("TCC.db-wal").unwrap_or_default();
let tcc = macos::read_tcc(&database, &wal)?;
for e in &tcc.entries {
    println!("{} {} {:?} {:?} {:?}", e.service, e.client, e.authorization, e.reason, e.last_modified);
}

let database = std::fs::read("knowledgeC.db")?;
let wal = std::fs::read("knowledgeC.db-wal").unwrap_or_default();
let knowledgec = macos::read_knowledgec(&database, &wal)?;
for e in &knowledgec.events {
    println!("{:?}..{:?} {} {:?} {:?}", e.start, e.end, e.stream, e.app(), e.value_integer);
}
for problem in &knowledgec.problems {
    eprintln!("{problem}");
}
```

## What you get

- `read_quarantine(database, wal)`: `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`, table `LSQuarantineEvent`, one `QuarantineEvent` per download an app saved with quarantine: the event's UUID (the one in the file's `com.apple.quarantine` attribute), when, the app (bundle identifier and name), the file's URL, the page or message it came from (URL and title), the sender's name and address for an attachment, the type number as stored and the origin alias as stored. Rows outlive the files.
- `read_tcc(database, wal)`: `TCC.db`, the system's (`/Library/Application Support/com.apple.TCC/`) or a user's (`~/Library/Application Support/com.apple.TCC/`), table `access`, one `TccEntry` per decision: service (`kTCCServiceCamera`, `kTCCServiceScreenCapture`, `kTCCServiceSystemPolicyAllFiles`, `kTCCServiceAccessibility`, `kTCCServiceAppleEvents`, …), client and `ClientType` (bundle identifier or path), the decision (`Authorization`: denied, unknown, allowed, limited), why (`AuthReason`: user consent, user set, system set, service policy, MDM policy, override policy, entitled, …), when it was last modified, the code requirement (`csreq`) as stored, the policy, the target of an Apple Events grant (`indirect_object_identifier`), flags, and on macOS 14 the process id, boot UUID and last reminder.
- Both TCC schemas, by column name: up to macOS 10.15 `allowed` (0 or 1) with `prompt_count`; from macOS 11 `auth_value`, `auth_reason`, `auth_version`; from macOS 14 `pid`, `pid_version`, `boot_uuid`, `last_reminded`. TCC is closed source: the values of `auth_value` (0 denied, 1 unknown, 2 allowed, 3 limited), `auth_reason` (1 to 12) and `client_type` (0 bundle identifier, 1 path) are those public write-ups give (Rainforest QA, "A deep dive into macOS TCC.db", 2021; HackTricks, "macOS TCC"); any other value is kept as a number. `UNUSED` and a zero reminder read as `None`.
- `read_knowledgec(database, wal)`: `knowledgeC.db`, the system's (`/private/var/db/CoreDuet/Knowledge/`) or a user's (`~/Library/Application Support/Knowledge/`), one `KnowledgeEvent` per `ZOBJECT` row with a stream name: the stream (`/app/inFocus`, `/app/usage`, `/app/activity`, `/display/isBacklit`, `/device/isLocked`, `/safari/history`, …), the value (`ZVALUESTRING`, `ZVALUEINTEGER`, `ZVALUEDOUBLE`), start, end and creation, the local offset from UTC when recorded (`ZSECONDSFROMGMT`), the UUID; from its `ZSOURCE` row the donating app's bundle and the device; from its `ZSTRUCTUREDMETADATA` row a Safari page's or an app activity's title and the activity type. `app()` is the app an event is about (an `/app/…` stream's value, else the source's bundle); `duration()` end minus start.
- Times as `sootmark-common` `Ts`, UTC: Mac absolute time (seconds since 2001-01-01, real or integer, to the microsecond, rounded) for quarantine and KnowledgeC, Unix seconds for TCC.
- The write-ahead log's committed changes are applied (`wal` may be empty): KnowledgeC databases are in write-ahead log mode, and the latest events are often only in the log.
- `read_launchd(plist, path)`: a launchd job's property list (binary or XML, read with `sootmark-plist`) from a `LaunchAgents` or `LaunchDaemons` folder (`/Library`, `/System/Library`, a user's `~/Library`): label, program and arguments (the command line as launchd runs it), `RunAtLoad`, `KeepAlive`, `StartInterval`, `StartCalendarInterval`, `WatchPaths`, `UserName`, `Disabled`, `EnvironmentVariables`, and `flags()`: a program in a temporary or shared folder, a hidden path, an interpreter given an inline script (`sh -c`, `osascript -e`), `DYLD_INSERT_LIBRARIES` set, no program at all. Checked on plaso's launchd test plists, against plaso's launchd plugin test.
- `detect(name)`: which `Artifact` a file is from its name or path (`/` or `\`, case ignored), and for TCC and KnowledgeC its `Scope` (system, user, unknown): a path in a mounted image works, a TCC database under `Users/<name>/`, `~/` or `var/root/` is a user's, one in `Library/` elsewhere the system's.
- Columns are read by name: one a version lacks reads as `None`, one it added is ignored. Damage is reported in `problems`, never a panic: the SQLite reader's findings (damaged pages, a foreign log), and KnowledgeC objects naming a source or metadata row that isn't there (kept, without it). A database without the artifact's table is refused.
- `read_fsevents(data)`: an FSEvents log (`/.fseventsd/<16 hex digits>`, gzip-compressed as `fseventsd` writes it): each change's path, event identifier, flags (`flag_names()`: `Created`, `Removed`, `Renamed`, `Modified`, `IsFile`, `IsDirectory`, …) and, from version 2, node identifier; versions 1 to 3. Records carry no time: the file's name is its last event's identifier and its modification time bounds them.
- `read_background_items(data)`: `backgrounditems.btm` (macOS 10.13 to 12) and `BackgroundItems-v<n>.btm`: each login item's display name, target path and creation time, and its volume's name, mount point, creation time and flags, from the bookmarks the archive holds.

## Not yet

- Deleted records (`sootmark-sqlite`'s `recover()`): quarantine events cleared by the user, TCC decisions reset.
- TCC's other tables (`expired`, `policies`, `active_policy`, `access_overrides`), and decoding `csreq` into its requirement text.
- KnowledgeC's other metadata (`ZSTRUCTUREDMETADATA` has a hundred-odd keys), `ZCUSTOMMETADATA`, and naming `ZVALUEINTEGER`'s meaning per stream.
- The quarantine type number as a kind: Apple documents the kinds as strings (`LSQuarantine.h`), not their numbers in this table.
- Quarantine events V1 (Mac OS X 10.5 and 10.6, `com.apple.LaunchServices.QuarantineEvents`), and Biome (`SEGB` files, not SQLite), where recent macOS versions keep much of what KnowledgeC kept.

## How it's checked

| Check | Result |
|---|---|
| plaso's test files (Apache-2.0, `tests/fixtures/plaso/`, commit `a70dde8`): `quarantine.db`, `TCC-test.db` (the schema before macOS 11), `knowledgec-10.13.db` and `knowledgec-10.14.db`, against what plaso's own tests expect (`ls_quarantine.py`, `macos_tcc.py`, `macos_knowledgec.py`): counts, apps, URLs, titles, times, durations | all match: 14 quarantine events, 21 TCC entries, 17 and 77 app and Safari events (plaso reads those streams only; all 21 and 92 objects are read). One creation time is a microsecond later: stored `…58.8606649637`, plaso truncates to `.860664`, `Ts` rounds to `.860665` |
| Every entry of those four and the synthetic ones (14 + 21 + 7 + 21 + 92 + 8) against the `sqlite3` shell 3.46.1 reading the same files (`tests/oracle/`, made by `gen.sh`): every quarantine column; TCC service, client, client type, decision, reason, last modified, indirect object, `csreq`; KnowledgeC stream, values, start, end, creation, offset, UUID, source bundle and device, title | all match |
| Databases made by `tests/fixtures/synthetic/gen.sh` (the sqlite3 shell, synthetic rows): a TCC database with the macOS 14 `access` table as public write-ups give it (every authorization value, reasons, a client by path, an Apple Events target, a process, boot UUID and reminder, an unknown reason); a KnowledgeC database with plaso's macOS 10.14 tables, a Safari visit with its source and title, an object naming a missing source, an event only in the write-ahead log | as written; the log's event read with the log only |
| `detect`: system and user paths, Windows separators, mounted images, `-wal` and `-shm` files | as expected |
| Property tests: arbitrary bytes, arbitrary pages behind a real header, every fixture damaged and cut anywhere, the log damaged and cut anywhere, arbitrary names | read or refused, never a panic |
- FSEvents and background items: plaso's test files (`test_data/fsevents/`, `backgrounditems.btm`), every record and value plaso's `fseventsd` parser and `macos_background_items_plist` plugin read, read the same.

## Licence

MIT or Apache-2.0, at your option. The plaso test files are under the Apache licence 2.0 (`tests/fixtures/plaso/LICENSE`, `NOTICE`); the synthetic ones are made by the script beside them.
