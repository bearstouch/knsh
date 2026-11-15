//! The argument protocol between `knshd` and `knsh-exec` (`specs/02-architecture/process-model.md#knsh-exec`).
//!
//! ```text
//! knsh-exec [--keep-fd <n>]... --profile <absolute path> --interpreter <absolute path> --line <line>
//! ```
//!
//! Every option except `--keep-fd` must appear exactly once, in any order; `--keep-fd` may appear up to
//! [`MAX_KEPT`] times. Anything else (an unknown option, a positional argument, a repeated option, a missing value)
//! is rejected: the trampoline never guesses what the supervisor meant, and never runs a command it could not fully
//! read (CLAUDE.md "Untrusted input").
//!
//! Error messages never repeat an argument's value: the line may hold secrets, and the messages go to stderr.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// The Seatbelt front end, always run by this absolute path and never searched in `PATH` (decision 1).
pub(crate) const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Descriptors above stdio that one invocation may keep open across the exec. The supervisor passes at most a few
/// (a status pipe, a pty); a long list means something is wrong.
pub(crate) const MAX_KEPT: usize = 16;

/// A complete, well-formed request to run one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    /// The compiled Seatbelt profile file, absolute and normal.
    pub(crate) profile: PathBuf,
    /// The interpreter that runs the line (for example `/bin/bash`), absolute and normal (FR-LC-14).
    pub(crate) interpreter: PathBuf,
    /// The line, passed to the interpreter's `-c`. Never empty.
    pub(crate) line: OsString,
    /// Descriptors above stdio to keep open across the exec, in the order given, without duplicates.
    pub(crate) keep: Vec<i32>,
}

/// Why the arguments were rejected. Holds option names only, never values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsageError {
    /// A required option is absent.
    Missing(&'static str),
    /// An option appeared more than once.
    Repeated(&'static str),
    /// An option is the last argument, with no value after it.
    NoValue(&'static str),
    /// An argument that is not one of the options (including any positional argument).
    Unexpected,
    /// A path is relative, or holds `.` or `..` components.
    NotAbsolute(&'static str),
    /// The line is empty.
    EmptyLine,
    /// A `--keep-fd` value is not a decimal descriptor number above stdio.
    BadDescriptor,
    /// A descriptor is listed twice.
    RepeatedDescriptor,
    /// More than [`MAX_KEPT`] descriptors are listed.
    TooManyDescriptors,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(option) => write!(f, "missing {option}"),
            Self::Repeated(option) => write!(f, "{option} given more than once"),
            Self::NoValue(option) => write!(f, "{option} needs a value"),
            Self::Unexpected => f.write_str("unexpected argument"),
            Self::NotAbsolute(option) => write!(f, "{option} must be an absolute path without '.' or '..'"),
            Self::EmptyLine => f.write_str("--line is empty"),
            Self::BadDescriptor => f.write_str("--keep-fd must be a descriptor number of 3 or more"),
            Self::RepeatedDescriptor => f.write_str("--keep-fd lists a descriptor twice"),
            Self::TooManyDescriptors => write!(f, "--keep-fd given more than {MAX_KEPT} times"),
        }
    }
}

impl std::error::Error for UsageError {}

const PROFILE: &str = "--profile";
const INTERPRETER: &str = "--interpreter";
const LINE: &str = "--line";
const KEEP_FD: &str = "--keep-fd";

/// Reads the arguments after `argv[0]`.
///
/// # Errors
///
/// A [`UsageError`] for anything but a complete, well-formed invocation (module documentation).
pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, UsageError> {
    let mut profile = None;
    let mut interpreter = None;
    let mut line = None;
    let mut keep = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        // Options are matched exactly; `--profile=/x` and other spellings are unexpected arguments.
        let Some(option) = [PROFILE, INTERPRETER, LINE, KEEP_FD]
            .into_iter()
            .find(|o| arg == OsStr::new(o))
        else {
            return Err(UsageError::Unexpected);
        };
        let value = args.next().ok_or(UsageError::NoValue(option))?;
        match option {
            PROFILE => set_once(&mut profile, option, value)?,
            INTERPRETER => set_once(&mut interpreter, option, value)?,
            LINE => set_once(&mut line, option, value)?,
            _ => keep_descriptor(&mut keep, &value)?,
        }
    }

    let profile = absolute(profile.ok_or(UsageError::Missing(PROFILE))?, PROFILE)?;
    let interpreter = absolute(interpreter.ok_or(UsageError::Missing(INTERPRETER))?, INTERPRETER)?;
    let line = line.ok_or(UsageError::Missing(LINE))?;
    if line.is_empty() {
        return Err(UsageError::EmptyLine);
    }
    Ok(Invocation {
        profile,
        interpreter,
        line,
        keep,
    })
}

/// Stores the first value of an option; a second one is an error rather than a silent override.
fn set_once(slot: &mut Option<OsString>, option: &'static str, value: OsString) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError::Repeated(option));
    }
    *slot = Some(value);
    Ok(())
}

/// Adds one `--keep-fd` value: plain decimal digits (no sign, no leading `+`), at least 3, listed once.
fn keep_descriptor(keep: &mut Vec<i32>, value: &OsStr) -> Result<(), UsageError> {
    let digits = value
        .to_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()));
    let fd = digits
        .and_then(|text| text.parse::<i32>().ok())
        .ok_or(UsageError::BadDescriptor)?;
    // Stdio is always inherited; listing it would suggest it could otherwise be closed.
    if fd < 3 {
        return Err(UsageError::BadDescriptor);
    }
    if keep.contains(&fd) {
        return Err(UsageError::RepeatedDescriptor);
    }
    if keep.len() == MAX_KEPT {
        return Err(UsageError::TooManyDescriptors);
    }
    keep.push(fd);
    Ok(())
}

/// Accepts an absolute path whose every component is a plain name: no `.`, no `..`, no empty component (`//` or a
/// trailing `/`). `sandbox-exec` and the kernel would resolve those themselves, but the supervisor always passes
/// resolved paths, so anything else is malformed input. Checked on the raw bytes: `Path::components` would quietly
/// drop an interior `.`.
fn absolute(value: OsString, option: &'static str) -> Result<PathBuf, UsageError> {
    let bytes = value.as_bytes();
    let normal = bytes.strip_prefix(b"/").is_some_and(|rest| {
        rest.split(|&b| b == b'/')
            .all(|name| !matches!(name, b"" | b"." | b".."))
    });
    if normal {
        Ok(PathBuf::from(value))
    } else {
        Err(UsageError::NotAbsolute(option))
    }
}

/// The exact `argv` for `execve`: `sandbox-exec -f <profile> <interpreter> -c -- <line>`.
///
/// `--` ends the interpreter's options, so a line that starts with `-` (for example `-i` or `--rcfile=…`) is run as
/// a command, never read as an interpreter option. `/bin/sh`, `/bin/bash` and `/bin/zsh` all accept it. The
/// interpreter is absolute, so `sandbox-exec` cannot read it as one of its own options either.
pub(crate) fn exec_argv(invocation: Invocation) -> Vec<OsString> {
    vec![
        SANDBOX_EXEC.into(),
        "-f".into(),
        invocation.profile.into_os_string(),
        invocation.interpreter.into_os_string(),
        "-c".into(),
        "--".into(),
        invocation.line,
    ]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    const VALID: &[&str] = &["--profile", "/p/x.sb", "--interpreter", "/bin/sh", "--line", "echo hi"];

    fn valid_with(extra: &[&str]) -> Vec<OsString> {
        let mut all = args(extra);
        all.extend(args(VALID));
        all
    }

    #[test]
    fn parses_a_complete_invocation_in_any_order() {
        let parsed = parse(args(&[
            "--line",
            "ls",
            "--keep-fd",
            "7",
            "--interpreter",
            "/bin/zsh",
            "--profile",
            "/a.sb",
        ]));
        assert_eq!(
            parsed,
            Ok(Invocation {
                profile: "/a.sb".into(),
                interpreter: "/bin/zsh".into(),
                line: "ls".into(),
                keep: vec![7],
            })
        );
    }

    // KNSH-046: malformed input never runs anything.
    #[test]
    fn rejects_relative_profile_path() {
        for profile in [
            "x.sb",
            "./x.sb",
            "../x.sb",
            "",
            "/a/../x.sb",
            "/a/./x.sb",
            "/",
            "//x.sb",
            "/a/",
            "/a/.",
            "/..",
        ] {
            let result = parse(args(&[
                "--profile",
                profile,
                "--interpreter",
                "/bin/sh",
                "--line",
                "true",
            ]));
            assert_eq!(result, Err(UsageError::NotAbsolute(PROFILE)), "{profile:?}");
        }
        let result = parse(args(&["--profile", "/x.sb", "--interpreter", "sh", "--line", "true"]));
        assert_eq!(result, Err(UsageError::NotAbsolute(INTERPRETER)));
    }

    // KNSH-046: every option is required, every value is required.
    #[test]
    fn rejects_missing_arguments() {
        assert_eq!(parse(args(&[])), Err(UsageError::Missing(PROFILE)));
        assert_eq!(
            parse(args(&["--interpreter", "/bin/sh", "--line", "true"])),
            Err(UsageError::Missing(PROFILE))
        );
        assert_eq!(
            parse(args(&["--profile", "/x.sb", "--line", "true"])),
            Err(UsageError::Missing(INTERPRETER))
        );
        assert_eq!(
            parse(args(&["--profile", "/x.sb", "--interpreter", "/bin/sh"])),
            Err(UsageError::Missing(LINE))
        );
        assert_eq!(parse(args(&["--profile"])), Err(UsageError::NoValue(PROFILE)));
        assert_eq!(
            parse(valid_with(&[]).into_iter().take(5)),
            Err(UsageError::NoValue(LINE))
        );
        let mut empty_line = args(VALID);
        empty_line[5] = OsString::new();
        assert_eq!(parse(empty_line), Err(UsageError::EmptyLine));
    }

    // KNSH-046: extra arguments are rejected, never ignored or passed on.
    #[test]
    fn rejects_extra_and_unknown_arguments() {
        let mut extra = args(VALID);
        extra.push("rm -rf /".into());
        assert_eq!(parse(extra), Err(UsageError::Unexpected));
        assert_eq!(parse(valid_with(&["--profile=/x.sb"])), Err(UsageError::Unexpected));
        assert_eq!(parse(valid_with(&["-f", "/x.sb"])), Err(UsageError::Unexpected));
        assert_eq!(parse(valid_with(&["--line", "a"])), Err(UsageError::Repeated(LINE)));
        assert_eq!(
            parse(valid_with(&["--profile", "/b.sb"])),
            Err(UsageError::Repeated(PROFILE))
        );
    }

    #[test]
    fn rejects_bad_descriptors() {
        for bad in ["0", "2", "-1", "+5", "x", "", "99999999999", " 5"] {
            assert_eq!(
                parse(valid_with(&["--keep-fd", bad])),
                Err(UsageError::BadDescriptor),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse(valid_with(&["--keep-fd", "5", "--keep-fd", "5"])),
            Err(UsageError::RepeatedDescriptor)
        );
        let mut many = Vec::new();
        for fd in 3..=(3 + MAX_KEPT) {
            many.push("--keep-fd".to_owned());
            many.push(fd.to_string());
        }
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(parse(valid_with(&many)), Err(UsageError::TooManyDescriptors));
    }

    // KNSH-046, decision 1: sandbox-exec by absolute path, `-f <profile>`, then the interpreter's `-c`.
    #[test]
    fn builds_exec_argv_with_absolute_paths() {
        let invocation = parse(args(VALID)).unwrap();
        assert_eq!(
            exec_argv(invocation),
            args(&[
                "/usr/bin/sandbox-exec",
                "-f",
                "/p/x.sb",
                "/bin/sh",
                "-c",
                "--",
                "echo hi"
            ])
        );
        // A line that looks like an option is still the command string, after `--`.
        let mut dashed = args(VALID);
        dashed[5] = "-i".into();
        let argv = exec_argv(parse(dashed).unwrap());
        assert_eq!(argv[5..], args(&["--", "-i"]));
        assert!(Path::new(&argv[0]).is_absolute());
        assert!(Path::new(&argv[3]).is_absolute());
    }

    #[test]
    fn messages_never_repeat_values() {
        let mut secret = args(VALID);
        secret.push("TOKEN=hunter2".into());
        let message = parse(secret).unwrap_err().to_string();
        assert!(!message.contains("hunter2"), "{message}");
    }
}
