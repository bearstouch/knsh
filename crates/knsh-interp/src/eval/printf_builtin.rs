//! The `printf` builtin (KNSH-102): options, then [`crate::printf`]'s engine over the shell.
//!
//! `printf [-v var] [--] format [arguments]`. With `-v` the output is assigned to `var` (cut at a NUL byte, as bash
//! keeps strings) instead of written. Bash's messages come before the output, as bash's buffered standard output
//! puts them when both go to one place. A usage error is status 2, as is a `-v` name that is not an identifier.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::sync::Arc;

use knsh_bash::Span;
use knsh_platform::{LocalTime, is_c_locale};

use super::{Flow, Interpreter, Run, unsupported};
use crate::error::{InterpError, Unsupported};
use crate::printf::{self, CountError, Host, Refusal};
use crate::state::{AssignError, ShellState, is_name, refuses_assignment};
use crate::status::Status;

/// Bash's usage line.
const USAGE: &str = "printf: usage: printf [-v var] format [arguments]";

/// Whether `locale` names a multibyte (UTF-8) character set.
pub(super) fn is_utf8_locale(locale: &str) -> bool {
    let lower = locale.to_ascii_lowercase();
    !is_c_locale(locale) && (lower.contains("utf-8") || lower.contains("utf8"))
}

/// What `printf` reads of the shell through [`Host`].
struct ShellHost<'a> {
    state: &'a mut ShellState,
    /// The clock, converter and start time, if the host gave them.
    local_time: Option<(Arc<dyn LocalTime>, i64)>,
    /// `LC_ALL`, `LC_TIME` or `LANG`.
    time_locale: String,
    /// `LC_ALL`, `LC_NUMERIC` or `LANG`.
    numeric_locale: String,
    multibyte: bool,
}

impl Host for ShellHost<'_> {
    fn time(&mut self, format: &str, seconds: i64) -> Result<Vec<u8>, Refusal> {
        let refused = Refusal::Unsupported(Unsupported::PrintfLocale);
        let Some((clock, started)) = &self.local_time else {
            return Err(refused);
        };
        // The conversion uses the process's zone; bash uses the shell's `TZ`. They must agree.
        if self.state.variable("TZ").map(ToOwned::to_owned) != clock.time_zone() {
            return Err(refused);
        }
        let seconds = match seconds {
            -1 => clock.now().map_err(|_| refused)?,
            -2 => *started,
            other => other,
        };
        clock.format(format, seconds, &self.time_locale).map_err(|_| refused)
    }

    fn assign_count(&mut self, name: &str, count: usize) -> Result<(), CountError> {
        if name.contains('[') {
            return Err(CountError::Refused(Refusal::Unsupported(Unsupported::Array)));
        }
        if !is_name(name) {
            return Err(CountError::Message(format!("`{name}': not a valid identifier")));
        }
        if refuses_assignment(name) || self.state.is_unemulated(name) {
            return Err(CountError::Refused(Refusal::Unsupported(Unsupported::ShellVariable)));
        }
        match self.state.assign(name, OsString::from(count.to_string()), false) {
            Ok(()) => Ok(()),
            Err(AssignError::Readonly) => Err(CountError::Message(format!("{name}: readonly variable"))),
            Err(AssignError::Invalid) => Err(CountError::Message(format!("`{name}': not a valid identifier"))),
            Err(
                AssignError::Arithmetic(_)
                | AssignError::Unsupported(_)
                | AssignError::BadSubscript
                | AssignError::Kind,
            ) => Err(CountError::Refused(Refusal::Unsupported(Unsupported::Builtin))),
        }
    }

    fn multibyte(&self) -> bool {
        self.multibyte
    }

    fn plain_numbers(&self, grouping: bool) -> bool {
        let locale = self.numeric_locale.as_str();
        if is_c_locale(locale) || locale.starts_with("C.") {
            return true;
        }
        // These locales write `.` as the decimal point, but group thousands.
        !grouping
            && ["en_", "ja_", "ko_", "zh_", "he_", "th_"]
                .iter()
                .any(|prefix| locale.starts_with(prefix))
    }
}

impl Interpreter {
    /// `printf` with `args`.
    pub(super) fn printf_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let mut rest = args;
        let mut target: Option<String> = None;
        while let Some(first) = rest.first() {
            if first == "--" {
                rest = &rest[1..];
                break;
            }
            if first.len() < 2 || !first.starts_with('-') {
                break;
            }
            if let Some(attached) = first.strip_prefix("-v") {
                if attached.is_empty() {
                    let Some(name) = rest.get(1) else {
                        self.report(span, run, format_args!("printf: -v: option requires an argument"));
                        self.report_plain(format_args!("{USAGE}"));
                        return Ok(Status::new(2));
                    };
                    target = Some(name.clone());
                    rest = &rest[2..];
                } else {
                    target = Some(attached.to_owned());
                    rest = &rest[1..];
                }
                continue;
            }
            let option: String = first.chars().take(2).collect();
            self.report(span, run, format_args!("printf: {option}: invalid option"));
            self.report_plain(format_args!("{USAGE}"));
            return Ok(Status::new(2));
        }
        // KNSH-103: `-v name[subscript]` assigns one element.
        let mut element = None;
        if let Some(name) = &target {
            let named = self.named(name, span, run)?;
            let array = match &named {
                Some(super::function::Named::Variable(array) | super::function::Named::Element(array, _)) => array,
                Some(super::function::Named::All(_)) | None => {
                    self.report(span, run, format_args!("printf: `{name}': not a valid identifier"));
                    return Ok(Status::new(2));
                }
            };
            if refuses_assignment(array) || self.state.is_unemulated(array) {
                return Err(unsupported(Unsupported::ShellVariable, span).into());
            }
            if let Some(super::function::Named::Element(array, key)) = named {
                element = Some((array, key));
            }
        }
        let Some((format, arguments)) = rest.split_first() else {
            self.report_plain(format_args!("{USAGE}"));
            return Ok(Status::new(2));
        };
        let time_locale = self.locale_for(&["LC_ALL", "LC_TIME", "LANG"], span)?;
        let numeric_locale = self.locale_for(&["LC_ALL", "LC_NUMERIC", "LANG"], span)?;
        let multibyte = is_utf8_locale(&self.locale_for(&["LC_ALL", "LC_CTYPE", "LANG"], span)?);
        let mut host = ShellHost {
            state: &mut self.state,
            local_time: self.local_time.clone(),
            time_locale,
            numeric_locale,
            multibyte,
        };
        let output = match printf::format(format, arguments, &mut host) {
            Ok(output) => output,
            Err(Refusal::Unsupported(feature)) => return Err(unsupported(feature, span).into()),
            Err(Refusal::Limit(what, limit)) => return Err(InterpError::ExpansionLimit { what, limit }.into()),
        };
        for message in &output.messages {
            self.report(span, run, format_args!("printf: {message}"));
        }
        let mut status = if output.failed {
            Status::FAILURE
        } else {
            Status::SUCCESS
        };
        match target {
            Some(name) => {
                let mut bytes = output.bytes;
                if let Some(nul) = bytes.iter().position(|&byte| byte == 0) {
                    bytes.truncate(nul);
                }
                let failed = match &element {
                    Some((array, key)) => {
                        let result = self.state.assign_element(array, key, OsString::from_vec(bytes), false);
                        self.assigned(array, &name, result, span, run)?
                    }
                    None => self.assign_or_report(&name, OsString::from_vec(bytes), false, span, run)?,
                };
                if let Some(failed) = failed {
                    status = failed;
                }
            }
            None => {
                if !self.print("printf", &output.bytes, span, run).is_success() {
                    status = Status::FAILURE;
                }
            }
        }
        Ok(status)
    }
}
