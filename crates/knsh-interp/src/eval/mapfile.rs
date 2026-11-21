//! `mapfile` and `readarray` (KNSH-103; NFR-COMPAT-02), following bash 5.2's `mapfile.def`: lines read from a
//! descriptor into an indexed array.
//!
//! Lines end at the delimiter (`-d`, a newline by default, NUL for an empty one), kept unless `-t`. `-n` reads at
//! most that many lines (0 for all), `-s` skips that many first, `-O` starts at that index (otherwise the array is
//! emptied first), `-u` reads another descriptor. `-c` is accepted (its callback never runs without `-C`); `-C`,
//! which runs code every so many lines, is refused. Input is read a byte at a time, as bash does when it cannot seek
//! back, so what follows stays for the commands after it; all of it together is bounded by [`MAX_MAPFILE`].

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use knsh_bash::Span;

use super::control::legal_number;
use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::error::{InterpError, Unsupported};
use crate::state::{AssignError, Key, Kind, is_name, refuses_assignment};
use crate::status::Status;

/// Most bytes one `mapfile` reads (64 MiB): past it the run fails with an error rather than holding endless input.
pub(crate) const MAX_MAPFILE: usize = 64 << 20;

/// `mapfile`'s options.
struct Options {
    delimiter: u8,
    count: u64,
    origin: Option<i64>,
    skip: u64,
    trim: bool,
    fd: u32,
}

impl Interpreter {
    /// `mapfile` and `readarray` (`name`) with `args`.
    pub(super) fn mapfile_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let usage = format!(
            "{name}: usage: {name} [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] \
             [-c quantum] [array]"
        );
        let (options, rest) = match self.mapfile_options(name, args, &usage, span, run)? {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let array = rest.first().map_or("MAPFILE", String::as_str);
        if !is_name(array) {
            self.report(span, run, format_args!("{name}: `{array}': not a valid identifier"));
            return Ok(Status::FAILURE);
        }
        if refuses_assignment(array) || self.state.is_unemulated(array) {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        if self.state.is_readonly(array) {
            self.report(span, run, format_args!("{name}: {array}: readonly variable"));
            return Ok(Status::FAILURE);
        }
        if self.state.kind(array) == Kind::Assoc {
            self.report(span, run, format_args!("{name}: {array}: not an indexed array"));
            return Ok(Status::FAILURE);
        }
        let Some(source) = self.shell_descriptor(options.fd, span)? else {
            self.report(
                span,
                run,
                format_args!("{name}: {}: invalid file descriptor: Bad file descriptor", options.fd),
            );
            return Ok(Status::FAILURE);
        };
        // Bash makes the variable an array (a string becoming its element 0) and empties it without `-O`.
        if let Err(error) = self.state.make_array(array, false) {
            return mapfile_failed(&error, span);
        }
        let mut next = options.origin.unwrap_or(0);
        if options.origin.is_none()
            && let Err(error) = self.state.assign_list(array, Vec::new(), false, false)
        {
            return mapfile_failed(&error, span);
        }
        let mut total = 0_usize;
        let mut lines_read = 0_u64;
        let mut stored = 0_u64;
        let mut line = Vec::new();
        loop {
            if options.count > 0 && stored >= options.count {
                break;
            }
            let mut byte = [0_u8];
            let ended = match self.descriptors.read(&source, &mut byte) {
                Ok(0) => true,
                Ok(_) => false,
                Err(error) => {
                    let reason = super::redirect::strerror(error.errno().unwrap_or(5));
                    self.report(span, run, format_args!("{name}: read error: {}: {reason}", options.fd));
                    return Ok(Status::FAILURE);
                }
            };
            if !ended {
                total += 1;
                if total > MAX_MAPFILE {
                    return Err(Stop::Error(InterpError::ExpansionLimit {
                        what: "mapfile bytes",
                        limit: MAX_MAPFILE,
                    }));
                }
                line.push(byte[0]);
                if byte[0] != options.delimiter {
                    continue;
                }
            }
            if line.is_empty() {
                break;
            }
            let mut text = std::mem::take(&mut line);
            lines_read += 1;
            if lines_read <= options.skip {
                continue;
            }
            if options.trim && text.last() == Some(&options.delimiter) {
                text.pop();
            }
            if let Err(error) = self
                .state
                .assign_element(array, &Key::Index(next), OsString::from_vec(text), false)
            {
                return mapfile_failed(&error, span);
            }
            next = next.saturating_add(1);
            stored += 1;
            if ended {
                break;
            }
        }
        Ok(Status::SUCCESS)
    }

    /// `mapfile`'s options and the rest of `args`, or the status of a usage error (already reported).
    fn mapfile_options<'a>(
        &mut self,
        name: &str,
        args: &'a [String],
        usage: &str,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Result<(Options, &'a [String]), Status>> {
        let mut options = Options {
            delimiter: b'\n',
            count: 0,
            origin: None,
            skip: 0,
            trim: false,
            fd: 0,
        };
        let mut at = 0;
        while let Some(arg) = args.get(at) {
            if arg == "--" {
                at += 1;
                break;
            }
            if arg.len() < 2 || !arg.starts_with('-') {
                break;
            }
            at += 1;
            let letters: Vec<char> = arg.chars().skip(1).collect();
            let mut index = 0;
            while let Some(&letter) = letters.get(index) {
                index += 1;
                match letter {
                    't' => options.trim = true,
                    'C' => return Err(unsupported(Unsupported::Builtin, span).into()),
                    'd' | 'n' | 'O' | 's' | 'u' | 'c' => {
                        let attached: String = letters[index..].iter().collect();
                        let value = if attached.is_empty() {
                            let Some(next) = args.get(at) else {
                                self.report(
                                    span,
                                    run,
                                    format_args!("{name}: -{letter}: option requires an argument"),
                                );
                                self.report_plain(format_args!("{usage}"));
                                return Ok(Err(Status::new(2)));
                            };
                            at += 1;
                            next.clone()
                        } else {
                            attached
                        };
                        index = letters.len();
                        if let Some(status) = self.mapfile_option(name, &mut options, letter, &value, span, run) {
                            return Ok(Err(status));
                        }
                    }
                    other => {
                        self.report(span, run, format_args!("{name}: -{other}: invalid option"));
                        self.report_plain(format_args!("{usage}"));
                        return Ok(Err(Status::new(2)));
                    }
                }
            }
        }
        Ok(Ok((options, &args[at..])))
    }

    /// Sets option `letter` to `value`; the status of an invalid value (reported, as bash words it).
    fn mapfile_option(
        &mut self,
        name: &str,
        options: &mut Options,
        letter: char,
        value: &str,
        span: Span,
        run: &Run<'_>,
    ) -> Option<Status> {
        let number = legal_number(value);
        let message = match letter {
            'd' => {
                options.delimiter = value.as_bytes().first().copied().unwrap_or(0);
                return None;
            }
            'n' | 's' => match number.and_then(|count| u64::try_from(count).ok()) {
                Some(count) => {
                    if letter == 'n' {
                        options.count = count;
                    } else {
                        options.skip = count;
                    }
                    return None;
                }
                None => "invalid line count",
            },
            'O' => match number.filter(|origin| *origin >= 0) {
                Some(origin) => {
                    options.origin = Some(origin);
                    return None;
                }
                None => "invalid array origin",
            },
            'c' => match number.filter(|quantum| *quantum > 0) {
                Some(_) => return None,
                None => "invalid callback quantum",
            },
            _ => match number.and_then(|fd| u32::try_from(fd).ok()) {
                Some(fd) if self.fds.get(fd).is_some() => {
                    options.fd = fd;
                    return None;
                }
                Some(fd) => {
                    self.report(
                        span,
                        run,
                        format_args!("{name}: {fd}: invalid file descriptor: Bad file descriptor"),
                    );
                    return Some(Status::FAILURE);
                }
                None => "invalid file descriptor specification",
            },
        };
        self.report(span, run, format_args!("{name}: {value}: {message}"));
        Some(Status::FAILURE)
    }
}

/// An assignment `mapfile` could not make: refused, as bash's messages for those are not reproduced.
fn mapfile_failed(error: &AssignError, span: Span) -> Flow<Status> {
    match error {
        AssignError::Unsupported(feature) => Err(unsupported(*feature, span).into()),
        AssignError::Readonly
        | AssignError::Invalid
        | AssignError::Arithmetic(_)
        | AssignError::BadSubscript
        | AssignError::Kind => Err(unsupported(Unsupported::Array, span).into()),
    }
}
