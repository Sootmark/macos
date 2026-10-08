//! plaso's Wi-Fi and launchd logs (Apache-2.0, `tests/fixtures/plaso/`, see
//! its NOTICE): every event plaso 20260720's `text/mac_wifi` and
//! `text/macos_launchd_log` read, read the same (`tests/oracle/plaso-wifi.tsv`
//! and `plaso-launchd.tsv.gz`, written by `tests/oracle/gen_logs.py` from
//! plaso's output, see `tests/oracle/README`).
//!
//! plaso splits a Wi-Fi line into agent, function and message only for
//! `airportd`'s three functions it names; its other lines are one text,
//! rebuilt here from the parts this crate reads. Its `action` is rebuilt
//! from the event this crate decodes. Wi-Fi's years: plaso's oracle has
//! `wifi.log` in four copies whose times give each of plaso's three
//! choices of year.

mod support;

use std::io::Read;

use macos::{detect, read_launchd_log, read_wifi_log, Artifact, LogLine, WifiEvent, Years};

/// The functions plaso reads apart, and only from `airportd`.
const KNOWN_FUNCTIONS: [&str; 3] = [
    "airportdProcessDLILEvent",
    "_doAutoJoin",
    "_processSystemPSKAssoc",
];

/// The year plaso was run, and the copies' change time's.
const CURRENT: i64 = 2026;

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

fn time(line: &LogLine) -> String {
    line.time.and_then(|t| t.to_iso8601()).unwrap()
}

/// A line as the oracle's: file, time, its name, parser, then plaso's
/// values, sorted.
fn row(file: &str, time: String, desc: &str, parser: &str, values: &[(&str, String)]) -> String {
    let mut values: Vec<String> = values
        .iter()
        .map(|(name, value)| format!("{name}={}", escape(value)))
        .collect();
    values.sort();
    [
        vec![file.to_owned(), time, desc.to_owned(), parser.to_owned()],
        values,
    ]
    .concat()
    .join("\t")
}

/// `airportd[88]`.
fn agent(line: &LogLine) -> String {
    let process = line.process.clone().unwrap_or_default();
    line.pid
        .map_or_else(|| process.clone(), |pid| format!("{process}[{pid}]"))
}

/// What plaso names a known function's line.
fn action(function: &str, line: &LogLine) -> String {
    let or_unknown = |value: &Option<String>| value.clone().unwrap_or_else(|| "Unknown".into());
    match (function, &line.wifi) {
        ("airportdProcessDLILEvent", Some(WifiEvent::Interface { name, .. })) => {
            format!("Interface {name} turn up.")
        }
        ("_doAutoJoin", Some(WifiEvent::Associated { ssid })) => {
            format!("Wi-Fi connected to SSID: {ssid}")
        }
        ("_doAutoJoin", _) => "Wi-Fi connected to SSID: Unknown".into(),
        (
            "_processSystemPSKAssoc",
            Some(WifiEvent::Network {
                ssid,
                bssid,
                security,
                ..
            }),
        ) => format!(
            "New wifi configured. BSSID: {}, SSID: {}, Security: {}.",
            or_unknown(bssid),
            or_unknown(ssid),
            or_unknown(security)
        ),
        _ => line.message.clone(),
    }
}

/// A Wi-Fi line's values as plaso's.
fn wifi_values(line: &LogLine) -> Vec<(&'static str, String)> {
    let known = line
        .function
        .as_deref()
        .filter(|f| KNOWN_FUNCTIONS.contains(f) && line.process.as_deref() == Some("airportd"));
    if let Some(function) = known {
        return vec![
            ("action", action(function, line)),
            ("agent", agent(line)),
            ("function", function.to_owned()),
            ("text", line.message.clone()),
        ];
    }
    let text = match (&line.host, &line.function) {
        (Some(host), _) => format!("{host} {}: {}", agent(line), line.message),
        (None, Some(function)) => format!("<{}> {function}: {}", agent(line), line.message),
        (None, None) if line.process.is_some() => format!("<{}> {}", agent(line), line.message),
        (None, None) => line.message.clone(),
    };
    vec![("text", text)]
}

/// Each copy of plaso's oracle: its file, its name there, and the years of
/// its earliest and latest times.
const WIFI_COPIES: [(&str, &str, i64, i64); 5] = [
    ("wifi.log", "old/wifi.log", 2014, CURRENT),
    (
        "wifi_turned_over.log",
        "old/wifi_turned_over.log",
        2017,
        CURRENT,
    ),
    ("wifi.log", "y2025/wifi.log", 2025, CURRENT),
    ("wifi.log", "y2026/wifi.log", 2026, CURRENT),
    ("wifi.log", "gz/wifi.log.gz", 2025, 2025),
];

#[test]
fn every_wifi_line_as_plaso_reads_it() {
    let mut got = Vec::new();
    for (fixture, name, earliest, latest) in WIFI_COPIES {
        let years = Years {
            earliest,
            latest,
            current: CURRENT,
        };
        let log = read_wifi_log(&support::fixture(&format!("plaso/{fixture}")), years);
        assert!(log.problems.is_empty(), "{name}: {:?}", log.problems);
        got.extend(log.lines.iter().map(|line| {
            row(
                name,
                time(line),
                "Added Time",
                "text/mac_wifi",
                &wifi_values(line),
            )
        }));
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-wifi.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn every_launchd_line_as_plaso_reads_it() {
    let log = read_launchd_log(&support::fixture("plaso/macos_launchd.log.gz"));
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    let mut got: Vec<String> = log
        .lines
        .iter()
        .map(|line| {
            let mut values = vec![
                ("message_body", line.message.clone()),
                ("severity", line.level.clone().unwrap()),
            ];
            if let Some(process) = &line.process {
                values.push(("process_name", process.clone()));
            }
            row(
                "launchd/macos_launchd.log",
                time(line),
                "Content Modification Time",
                "text/macos_launchd_log",
                &values,
            )
        })
        .collect();
    got.sort();
    let mut oracle = String::new();
    common::gzip::Decoder::new(include_bytes!("oracle/plaso-launchd.tsv.gz").as_slice())
        .read_to_string(&mut oracle)
        .unwrap();
    let expected: Vec<&str> = oracle.lines().collect();
    assert_eq!(got.len(), 36_609);
    let differences: Vec<(&String, &&str)> = got
        .iter()
        .zip(&expected)
        .filter(|(g, e)| g != e)
        .take(5)
        .collect();
    assert!(differences.is_empty(), "{differences:#?}");
    assert_eq!(got.len(), expected.len());
}

#[test]
fn beyond_plaso() {
    let years = Years {
        earliest: 2014,
        latest: CURRENT,
        current: CURRENT,
    };
    let wifi = read_wifi_log(&support::fixture("plaso/wifi.log"), years).lines;
    assert!(wifi.iter().all(|line| line.year_inferred));
    assert_eq!(
        wifi[6].wifi,
        Some(WifiEvent::Network {
            ssid: Some("AndroidAP".into()),
            bssid: Some("88:30:8a:7a:61:88".into()),
            security: Some("WPA2 Personal".into()),
            rssi: Some(-21),
        })
    );
    assert_eq!(
        wifi[1].wifi,
        Some(WifiEvent::Interface {
            name: "en0".into(),
            event: "attached (up)".into(),
        })
    );
    // A function plaso doesn't name, read apart.
    assert_eq!(
        (
            wifi[3].process.as_deref(),
            wifi[3].pid,
            wifi[3].function.as_deref()
        ),
        (Some("airportd"), Some(88), Some("_handleLinkEvent"))
    );
    let rotated = read_wifi_log(&support::fixture("plaso/wifi_turned_over.log"), years).lines;
    assert_eq!(
        (
            rotated[0].host.as_deref(),
            rotated[0].process.as_deref(),
            rotated[0].pid,
            rotated[0].message.as_str()
        ),
        (
            Some("test-macbookpro"),
            Some("newsyslog"),
            Some(50498),
            "logfile turned over"
        )
    );
    assert_eq!(
        detect("/private/var/log/com.apple.xpc.launchd/launchd.log.1"),
        Some(Artifact::LaunchdLog)
    );
}

#[test]
fn lines_that_are_not_log_lines() {
    let years = Years {
        earliest: 2020,
        latest: 2020,
        current: 2026,
    };
    let wifi = read_wifi_log(b"garbage\n\nThu Nov 14 20:14:37.123 ok\n", years);
    assert_eq!(wifi.lines.len(), 1);
    assert_eq!(wifi.lines[0].line, 3);
    assert_eq!(wifi.problems.len(), 1);
    let launchd = read_launchd_log(b"2023-06-08 14:51:38.987368 no level\n");
    assert_eq!((launchd.lines.len(), launchd.problems.len()), (0, 1));
}
