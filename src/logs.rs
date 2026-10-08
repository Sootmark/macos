//! Text logs: Wi-Fi's (`/var/log/wifi.log`, written by `airportd` up to
//! macOS 10.15) and launchd's (`/var/log/com.apple.xpc.launchd/launchd.log*`).
//!
//! ```text
//! Thu Nov 14 21:52:09.883 <airportd[88]> _processSystemPSKAssoc: No password for network <CWNetwork: 0x7f…> [ssid=AndroidAP, bssid=88:30:8a:7a:61:88, security=WPA2 Personal, rssi=-21, …]
//! Jan  2 00:10:15 test-macbookpro newsyslog[50498]: logfile turned over
//! 2023-06-08 10:51:39.633266 (com.apple.cmio.AVCAssistant) <Error>: ThrottleInterval set to zero. …
//! ```
//!
//! A Wi-Fi line is a time without a year (to the millisecond, the weekday
//! first), the agent in angle brackets (`airportd[88]`, `kernel`), then the
//! function and its message; `newsyslog` adds a syslog line when it rotates
//! the file. The year is inferred as plaso infers it (see [`Years`]).
//!
//! A launchd line is a date and time to the microsecond, the job or domain
//! in parentheses (`system`, `pid/1660/com.apple.audio…`; absent for
//! launchd's own lines), the level in angle brackets, then the message.
//!
//! Times are the host's wall clock, its zone unknown. launchd's lines
//! before its `tzinit` boot task are in UTC: the zone isn't set yet.

use common::time::{civil_from_days, days_from_civil, Precision, Ts, TICKS_PER_SECOND};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// What dates a Wi-Fi log's lines, which have no year: as plaso does.
///
/// Lines are in order, so the year goes up whenever the month goes back by
/// more than one (December to January; April after May is a reordering, not
/// a new year), and back down for a December just after January. The first
/// line is in the year of the file's earliest time, unless the last line
/// would then be in or after the current year: then the last line is in
/// the year of the file's latest time if that is before the current year,
/// else in the current year.
///
/// The file's times are its modification, change and creation times, in
/// UTC. A copied file's change time is when it was copied, so most often
/// `latest` is the current year and the last line is dated in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Years {
    /// The year of the file's earliest time.
    pub earliest: i64,
    /// The year of the file's latest time.
    pub latest: i64,
    /// The year now (or when the image was taken).
    pub current: i64,
}

/// A line of a text log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogLine {
    /// Its line, from 1.
    pub line: usize,
    /// When it was written: the host's wall clock, its zone unknown;
    /// `None` when the date doesn't exist in the inferred year (February
    /// 29).
    pub time: Option<Ts>,
    /// Whether the year was inferred (Wi-Fi's lines).
    pub year_inferred: bool,
    /// The host, on a syslog line (`newsyslog`'s).
    pub host: Option<String>,
    /// Who wrote it: Wi-Fi's agent (`airportd`, `kernel`), launchd's job or
    /// domain (`system`, `com.apple.cmio.AVCAssistant`,
    /// `pid/1660 [com.apple.audio]`).
    pub process: Option<String>,
    /// The agent's process id (`airportd[88]`).
    pub pid: Option<u32>,
    /// The function, the word ending in `:` that starts a Wi-Fi line's
    /// message (`_doAutoJoin`; the kernel's driver or interface: `wl0`,
    /// `AirPort_Brcm43xx::syncPowerState`).
    pub function: Option<String>,
    /// launchd's level (`Notice`, `Error`, …).
    pub level: Option<String>,
    /// The message.
    pub message: String,
    /// What a Wi-Fi line says happened, when known.
    pub wifi: Option<WifiEvent>,
}

/// What a Wi-Fi line says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiEvent {
    /// An interface event (`airportdProcessDLILEvent: en0 attached (up)`).
    Interface {
        /// The interface (`en0`).
        name: String,
        /// What happened to it (`attached (up)`).
        event: String,
    },
    /// Auto-join found the Mac already on a network
    /// (`_doAutoJoin: Already associated to “CampusNet”. Bailing on auto-join.`).
    Associated {
        /// The network's name.
        ssid: String,
    },
    /// A network described (`[ssid=…, bssid=…, security=…, rssi=…`), as
    /// when joining one (`_processSystemPSKAssoc`).
    Network {
        /// Its name.
        ssid: Option<String>,
        /// Its access point's hardware address.
        bssid: Option<String>,
        /// Its security (`WPA2 Personal`).
        security: Option<String>,
        /// Its signal strength, dBm.
        rssi: Option<i32>,
    },
}

/// A text log's lines and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextLog {
    /// The lines, in order.
    pub lines: Vec<LogLine>,
    /// The lines that couldn't be read, with why.
    pub problems: Vec<String>,
}

/// A Wi-Fi line's time, before its year is known.
#[derive(Debug, Clone, Copy)]
struct Clock {
    month: u32,
    day: u32,
    /// Ticks since midnight.
    ticks: i64,
    precision: Precision,
}

/// Read `/var/log/wifi.log` (or a rotated copy, decompressed), its years
/// inferred from `years`.
#[must_use]
pub fn read_wifi_log(data: &[u8], years: Years) -> TextLog {
    let text = String::from_utf8_lossy(data);
    let mut log = TextLog::default();
    let mut clocks = Vec::new();
    for (index, line) in numbered(&text) {
        match wifi_line(line) {
            Ok((clock, mut entry)) => {
                entry.line = index;
                entry.year_inferred = true;
                clocks.push(clock);
                log.lines.push(entry);
            }
            Err(why) => log.problems.push(format!("line {index}: {why}")),
        }
    }
    let relative = relative_years(&clocks);
    let base = base_year(years, relative.last().copied().unwrap_or(0));
    for ((entry, clock), relative) in log.lines.iter_mut().zip(&clocks).zip(relative) {
        let year = base.saturating_add(relative);
        entry.time = date_ticks(year, clock.month, clock.day)
            .map(|day| Ts::from_local_ticks(day + clock.ticks, clock.precision));
        if entry.time.is_none() {
            log.problems.push(format!(
                "line {}: {} {} isn't a date in {year} (the inferred year)",
                entry.line,
                MONTHS[clock.month as usize - 1],
                clock.day
            ));
        }
    }
    log
}

/// Read a launchd log (`launchd.log`, `launchd.log.<n>`).
#[must_use]
pub fn read_launchd_log(data: &[u8]) -> TextLog {
    let text = String::from_utf8_lossy(data);
    let mut log = TextLog::default();
    for (index, line) in numbered(&text) {
        match launchd_line(line) {
            Ok(mut entry) => {
                entry.line = index;
                log.lines.push(entry);
            }
            Err(why) => log.problems.push(format!("line {index}: {why}")),
        }
    }
    log
}

/// The lines that aren't blank, numbered from 1, without their `\r`.
fn numbered(text: &str) -> impl Iterator<Item = (usize, &str)> {
    (1..)
        .zip(text.lines())
        .map(|(index, line)| (index, line.trim_end_matches('\r')))
        .filter(|(_, line)| !line.trim().is_empty())
}

/// Each line's years after the first's, as plaso counts them: up when the
/// month goes back by more than one, down for December just after January
/// once up.
fn relative_years(clocks: &[Clock]) -> Vec<i64> {
    let mut relative = 0;
    let mut last_month = None;
    clocks
        .iter()
        .map(|clock| {
            if let Some(last) = last_month {
                if clock.month + 1 < last {
                    relative += 1;
                } else if relative > 0 && last == 1 && clock.month == 12 {
                    relative -= 1;
                }
            }
            last_month = Some(clock.month);
            relative
        })
        .collect()
}

/// The first line's year, from the file's years and the last line's
/// relative year: plaso's timeliner's choice.
fn base_year(years: Years, last_relative: i64) -> i64 {
    if years.earliest.saturating_add(last_relative) < years.current {
        years.earliest
    } else if years.latest < years.current {
        years.latest.saturating_sub(last_relative)
    } else {
        years.current.saturating_sub(last_relative)
    }
}

/// Ticks of midnight on a date, when it exists (years 1 to 9999).
fn date_ticks(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=9999).contains(&year) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    (civil_from_days(days) == (year, month, day)).then(|| days * 86_400 * TICKS_PER_SECOND)
}

/// One Wi-Fi line: `Thu Nov 14 20:36:37.222 <agent> function: message`,
/// `Thu Nov 14 20:14:37.123 ***Starting Up***`, or a syslog line
/// (`Jan  2 00:10:15 host process[pid]: message`).
fn wifi_line(line: &str) -> Result<(Clock, LogLine), String> {
    let mut words = Words(line);
    let first = words.next().ok_or("empty")?;
    let syslog = !WEEKDAYS.contains(&first);
    let month_name = if syslog {
        first
    } else {
        words.next().ok_or("no month")?
    };
    let month = MONTHS
        .iter()
        .position(|m| *m == month_name)
        .ok_or_else(|| format!("no month where {month_name:?} is"))? as u32
        + 1;
    let day = words
        .next()
        .and_then(|d| d.parse().ok())
        .filter(|d| (1..=31).contains(d))
        .ok_or("no day")?;
    let stamp = words.next().ok_or("no time")?;
    let (ticks, precision) = clock(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?;
    let rest = words.rest();
    let entry = if syslog {
        syslog_line(rest)
    } else {
        agent_line(rest)
    };
    let time = Clock {
        month,
        day,
        ticks,
        precision,
    };
    Ok((time, entry))
}

/// `hh:mm:ss` or `hh:mm:ss.mmm` in ticks since midnight, and its precision.
fn clock(text: &str) -> Option<(i64, Precision)> {
    let (clock, millis) = match text.split_once('.') {
        Some((clock, millis)) => (clock, Some(millis)),
        None => (text, None),
    };
    let parts: Vec<&str> = clock.split(':').collect();
    let [hour, minute, second] = parts.as_slice() else {
        return None;
    };
    let number = |part: &str, max: i64| {
        Some(part)
            .filter(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse::<i64>().ok())
            .filter(|n| (0..=max).contains(n))
    };
    let seconds = number(hour, 23)? * 3600 + number(minute, 59)? * 60 + number(second, 60)?;
    let ticks = seconds * TICKS_PER_SECOND;
    match millis {
        None => Some((ticks, Precision::Second)),
        Some(millis) if millis.len() == 3 && millis.bytes().all(|b| b.is_ascii_digit()) => {
            let millis: i64 = millis.parse().ok()?;
            Some((ticks + millis * 10_000, Precision::Millisecond))
        }
        Some(_) => None,
    }
}

/// After a Wi-Fi line's time: `<agent> function: message`, or a message.
fn agent_line(rest: &str) -> LogLine {
    let Some((agent, after)) = rest
        .strip_prefix('<')
        .and_then(|r| r.split_once('>'))
        .filter(|(agent, _)| !agent.is_empty())
    else {
        return LogLine {
            message: rest.to_owned(),
            wifi: wifi_event(None, rest),
            ..LogLine::default()
        };
    };
    let (process, pid) = process_and_pid(agent);
    let after = after.trim_start();
    let (function, message) = match after
        .split_once(": ")
        .filter(|(function, _)| !function.is_empty() && !function.contains(' '))
    {
        Some((function, message)) => (Some(function), message),
        None => (None, after),
    };
    LogLine {
        process,
        pid,
        function: function.map(str::to_owned),
        message: message.to_owned(),
        wifi: wifi_event(function, message),
        ..LogLine::default()
    }
}

/// After a syslog line's time: `host process[pid]: message`.
fn syslog_line(rest: &str) -> LogLine {
    let Some((host, after)) = rest.split_once(' ') else {
        return LogLine {
            message: rest.to_owned(),
            ..LogLine::default()
        };
    };
    let ((process, pid), message) = match after.split_once(": ") {
        Some((process, message)) if !process.contains(' ') => (process_and_pid(process), message),
        _ => ((None, None), after),
    };
    LogLine {
        host: Some(host.to_owned()),
        process,
        pid,
        message: message.to_owned(),
        ..LogLine::default()
    }
}

/// `airportd[88]` into its name and process id; `kernel` alone.
fn process_and_pid(text: &str) -> (Option<String>, Option<u32>) {
    match text
        .strip_suffix(']')
        .and_then(|t| t.split_once('['))
        .and_then(|(name, pid)| Some((name, pid.parse().ok()?)))
    {
        Some((name, pid)) => (Some(name.to_owned()), Some(pid)),
        None => (Some(text.to_owned()), None),
    }
}

/// What a Wi-Fi message says happened: the events plaso names, from the
/// same functions' messages, and a network's description anywhere.
fn wifi_event(function: Option<&str>, message: &str) -> Option<WifiEvent> {
    match function {
        Some("airportdProcessDLILEvent") => {
            let (name, event) = message.split_once(' ').unwrap_or((message, ""));
            return Some(WifiEvent::Interface {
                name: name.to_owned(),
                event: event.to_owned(),
            });
        }
        Some("_doAutoJoin") => {
            if let Some(ssid) = message
                .strip_prefix("Already associated to ")
                .and_then(|m| m.rsplit_once(". Bailing"))
                .map(|(ssid, _)| unquote(ssid))
            {
                return Some(WifiEvent::Associated {
                    ssid: ssid.to_owned(),
                });
            }
        }
        _ => {}
    }
    network(message)
}

/// `“CampusNet”` or `"CampusNet"` without its quotes.
fn unquote(text: &str) -> &str {
    let pairs = [('“', '”'), ('"', '"')];
    pairs
        .iter()
        .find_map(|(open, close)| text.strip_prefix(*open)?.strip_suffix(*close))
        .unwrap_or(text)
}

/// A network's description: `[ssid=…, bssid=…, security=…, rssi=…`.
fn network(message: &str) -> Option<WifiEvent> {
    let (_, description) = message.split_once("[ssid=")?;
    let (ssid, rest) = description.split_once(", bssid=")?;
    let (bssid, rest) = rest.split_once(", security=")?;
    let (security, rest) = rest.split_once(", rssi=")?;
    let rssi = rest
        .split([',', ']'])
        .next()
        .and_then(|r| r.trim().parse().ok());
    let some = |text: &str| Some(text.to_owned()).filter(|t| !t.is_empty());
    Some(WifiEvent::Network {
        ssid: some(ssid),
        bssid: some(bssid),
        security: some(security),
        rssi,
    })
}

/// One launchd line: `2023-06-08 10:51:39.633266 (job) <Level>: message`,
/// the job optional.
fn launchd_line(line: &str) -> Result<LogLine, String> {
    let stamp = line.get(..26).ok_or("too short for a time")?;
    let time = launchd_time(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?;
    let rest = line[26..]
        .strip_prefix(' ')
        .ok_or("nothing after the time")?;
    let (process, rest) = match rest.strip_prefix('(').and_then(|r| r.split_once(") ")) {
        Some((process, after)) => (Some(process.to_owned()), after),
        None => (None, rest),
    };
    let (level, message) = rest
        .strip_prefix('<')
        .and_then(|r| r.split_once(">: "))
        .filter(|(level, _)| !level.is_empty())
        .ok_or("no <level>")?;
    Ok(LogLine {
        time: Some(time),
        process,
        level: Some(level.to_owned()),
        message: message.to_owned(),
        ..LogLine::default()
    })
}

/// `2023-06-08 14:51:38.987368`, local.
fn launchd_time(text: &str) -> Option<Ts> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b' ') {
        return None;
    }
    let day = date_ticks(
        digits(0..4)?,
        u32::try_from(digits(5..7)?).ok()?,
        u32::try_from(digits(8..10)?).ok()?,
    )?;
    let (since_midnight, _) = clock(text.get(11..19)?)?;
    if bytes.get(19) != Some(&b'.') {
        return None;
    }
    let micros = digits(20..26)?;
    Some(Ts::from_local_ticks(
        day + since_midnight + micros * 10,
        Precision::Microsecond,
    ))
}

/// Words split on runs of spaces (`Jan  2`), and what's left.
struct Words<'a>(&'a str);

impl<'a> Words<'a> {
    /// What's left after the words taken, its leading spaces removed.
    fn rest(&self) -> &'a str {
        self.0.trim_start_matches(' ')
    }
}

impl<'a> Iterator for Words<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let text = self.0.trim_start_matches(' ');
        if text.is_empty() {
            return None;
        }
        let end = text.find(' ').unwrap_or(text.len());
        self.0 = &text[end..];
        Some(&text[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso(ts: Option<Ts>) -> Option<String> {
        ts.and_then(|t| t.to_iso8601())
    }

    #[test]
    fn years_as_plaso_infers_them() {
        let log = "Tue Dec 31 23:59:38.165 x\nWed Jan  1 01:12:17.311 y\n";
        let at = |earliest, latest| {
            let years = Years {
                earliest,
                latest,
                current: 2026,
            };
            let lines = read_wifi_log(log.as_bytes(), years).lines;
            (iso(lines[0].time), iso(lines[1].time))
        };
        // An old file: its earliest year is the first line's.
        assert_eq!(
            at(2014, 2026),
            (
                Some("2014-12-31T23:59:38.1650000".to_owned()),
                Some("2015-01-01T01:12:17.3110000".to_owned())
            )
        );
        // A recent one: the last line is in the current year...
        assert_eq!(
            at(2025, 2026).1.as_deref(),
            Some("2026-01-01T01:12:17.3110000")
        );
        // ...or the latest time's, when that is earlier.
        assert_eq!(
            at(2025, 2025).1.as_deref(),
            Some("2025-01-01T01:12:17.3110000")
        );
    }

    #[test]
    fn reordered_months_and_leap_days() {
        let clocks: Vec<Clock> = [5, 4, 5, 1, 12, 1]
            .into_iter()
            .map(|month| Clock {
                month,
                day: 1,
                ticks: 0,
                precision: Precision::Second,
            })
            .collect();
        assert_eq!(relative_years(&clocks), [0, 0, 0, 1, 0, 1]);
        let log = read_wifi_log(
            b"Sat Feb 29 10:00:00.000 x\n",
            Years {
                earliest: 2019,
                latest: 2026,
                current: 2026,
            },
        );
        assert_eq!(log.lines[0].time, None);
        assert_eq!(log.problems.len(), 1);
    }

    #[test]
    fn wifi_lines() {
        let (_, line) = wifi_line(
            "Mon Jan  2 07:41:01.371 <kernel> AirPort_Brcm43xx::syncPowerState: WWEN[enabled]",
        )
        .unwrap();
        assert_eq!(line.process.as_deref(), Some("kernel"));
        assert_eq!(line.pid, None);
        assert_eq!(
            line.function.as_deref(),
            Some("AirPort_Brcm43xx::syncPowerState")
        );
        assert_eq!(line.message, "WWEN[enabled]");
        let (clock, line) =
            wifi_line("Jan  2 00:10:15 test-macbookpro newsyslog[50498]: logfile turned over")
                .unwrap();
        assert_eq!(clock.precision, Precision::Second);
        assert_eq!(line.host.as_deref(), Some("test-macbookpro"));
        assert_eq!(
            (line.process.as_deref(), line.pid),
            (Some("newsyslog"), Some(50498))
        );
        assert!(wifi_line("Thu Foo 14 20:14:37.123 x").is_err());
        assert!(wifi_line("Thu Nov 14 20:14:37.12 x").is_err());
        assert!(wifi_line("Thu Nov 14 24:14:37.123 x").is_err());
    }

    #[test]
    fn launchd_lines() {
        let line = launchd_line(
            "2023-06-08 11:20:20.231375 (pid/1660 [com.apple.audio]) <Notice>: cleaning up",
        )
        .unwrap();
        assert_eq!(line.process.as_deref(), Some("pid/1660 [com.apple.audio]"));
        assert_eq!(line.level.as_deref(), Some("Notice"));
        assert_eq!(line.message, "cleaning up");
        assert_eq!(
            iso(line.time).as_deref(),
            Some("2023-06-08T11:20:20.2313750")
        );
        let line = launchd_line("2023-06-08 14:51:39.012592 <Notice>: swap enabled").unwrap();
        assert_eq!(line.process, None);
        assert!(launchd_line("2023-02-30 14:51:39.012592 <Notice>: x").is_err());
        assert!(launchd_line("2023-06-08 14:51:39.012592 (x) Notice: x").is_err());
        assert!(launchd_line("2023-06-08 14:51:39.0125é <Notice>: x").is_err());
    }
}
