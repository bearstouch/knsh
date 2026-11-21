//! The `read` builtin (KNSH-102; NFR-COMPAT-02), as bash 5.2's `read.def`.
//!
//! `read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name …]`
//! reads one line (up to `delim`, a newline by default) from the shell's descriptor 0 (or `-u fd`) a byte at a time,
//! so what follows stays for the commands after it, then splits it on `IFS` into the names:
//!
//! - Without `-r` a backslash quotes the next character (it is kept, never a separator) and a backslash-newline is
//!   removed. NUL bytes are dropped (unless NUL is the delimiter, `-d ''`).
//! - `-n N` returns after `N` characters or the delimiter; `-N N` after exactly `N` characters, the delimiter read as
//!   data. In a UTF-8 locale a character is a whole UTF-8 sequence.
//! - Leading `IFS` whitespace is removed; each name but the last takes one field (bash's `get_word_from_string`);
//!   the last takes the rest, with trailing `IFS` whitespace removed, or its single field when only one is left.
//!   Without names the whole line, unsplit, goes to `REPLY`.
//! - `-t T` gives up after `T` seconds (fractions allowed): what was read is assigned and the status is 142
//!   (`128 + SIGALRM`), above 128 as bash's is. `-t 0` reads nothing: 0 when input is waiting, else 1.
//! - End of file before the delimiter is status 1, the variables still assigned. `-p` writes its prompt to standard
//!   error, and `-s` turns off echo, only when the input is a terminal; `-n`, `-N` and `-d` then read the terminal
//!   a character at a time. The terminal's settings are put back afterwards, however the read ended.
//!
//! `-a name` splits every field into the indexed array `name`, emptied first (KNSH-103). `-e` on a terminal (line
//! editing, KNSH-107) is refused ([`Unsupported::ReadOption`]).
//! A line is bounded ([`MAX_READ_LINE`]) instead of growing without limit on endless input.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::time::{Duration, Instant};

use knsh_bash::Span;
use knsh_platform::{SharedFd, TerminalInput};

use super::control::legal_number;
use super::printf_builtin::is_utf8_locale;
use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::error::{InterpError, Unsupported};
use crate::state::{DEFAULT_IFS, is_name, refuses_assignment};
use crate::status::Status;

/// Bash's usage line.
const USAGE: &str = "read: usage: read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] \
                     [-t timeout] [-u fd] [name ...]";

/// Longest line `read` takes (16 MiB): past it the read fails with an error rather than holding endless input.
pub(crate) const MAX_READ_LINE: usize = 16 << 20;

/// The status of a `read` that timed out: `128 + SIGALRM`, as bash's.
const TIMED_OUT: u8 = 128 + 14;

/// `read`'s options.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // One per flag, as bash's `read.def` keeps them.
struct Options {
    raw: bool,
    silent: bool,
    edit: bool,
    /// `-a name`: the array the fields go to (KNSH-103).
    array: Option<String>,
    delimiter: Option<u8>,
    /// `-N`: the delimiter is data.
    ignore_delimiter: bool,
    /// `-n` or `-N`; 0 means no limit, as in bash.
    count: usize,
    prompt: Option<String>,
    timeout: Option<Duration>,
    fd: u32,
}

/// One byte read, and whether a backslash quoted it (never a separator).
type Read = (u8, bool);

/// How reading ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The delimiter or the count.
    Line,
    /// End of file first.
    Eof,
    /// `-t` ran out.
    TimedOut,
}

/// A `-t` argument as bash's `uconvert` reads it: digits, optionally a point and more digits (microseconds kept).
fn timeout(text: &str) -> Option<Duration> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let seconds: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let micros: String = fraction.chars().chain(std::iter::repeat('0')).take(6).collect();
    Some(Duration::from_secs(seconds) + Duration::from_micros(micros.parse().ok()?))
}

/// Whether `byte` is `IFS` whitespace bash treats specially (`spctabnl`).
const fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n')
}

/// Bash's `get_word_from_string`: the next field of `rest` and `rest` moved past it and its separator, or `None`
/// when only `IFS` whitespace is left (then `rest` is emptied).
fn next_field(rest: &mut &[Read], ifs: &[u8]) -> Option<Vec<u8>> {
    let separator = |&(byte, quoted): &Read| !quoted && ifs.contains(&byte);
    let white = |read: &Read| separator(read) && is_blank(read.0);
    let skip_white = |rest: &mut &[Read]| {
        while rest.first().is_some_and(white) {
            *rest = &rest[1..];
        }
    };
    skip_white(rest);
    if rest.is_empty() {
        return None;
    }
    let end = rest.iter().position(separator).unwrap_or(rest.len());
    let field = rest[..end].iter().map(|&(byte, _)| byte).collect();
    let whitesep = rest.get(end).is_some_and(|&(byte, _)| is_blank(byte));
    *rest = rest.get(end + 1..).unwrap_or_default();
    skip_white(rest);
    // A non-whitespace separator after whitespace belongs to the same delimiter (POSIX: `a , b` is two fields).
    if whitesep && rest.first().is_some_and(|read| separator(read) && !is_blank(read.0)) {
        *rest = &rest[1..];
        skip_white(rest);
    }
    Some(field)
}

/// Bash's `strip_trailing_ifs_whitespace`: trailing `IFS` whitespace removed, quoted or not (bash's quirk), never
/// the first byte.
fn strip_trailing(text: &[Read], ifs: &[u8]) -> Vec<u8> {
    let mut end = text.len();
    while end > 1 && is_blank(text[end - 1].0) && ifs.contains(&text[end - 1].0) {
        end -= 1;
    }
    text[..end].iter().map(|&(byte, _)| byte).collect()
}

/// The values of `names` names from `line` split on `ifs`, as bash assigns them.
fn split_line(line: &[Read], ifs: &[u8], names: usize) -> Vec<Vec<u8>> {
    let mut rest = line;
    if !ifs.is_empty() {
        while rest
            .first()
            .is_some_and(|&(byte, quoted)| !quoted && is_blank(byte) && ifs.contains(&byte))
        {
            rest = &rest[1..];
        }
    }
    let mut values = Vec::with_capacity(names);
    for _ in 1..names {
        values.push(if rest.is_empty() {
            Vec::new()
        } else {
            next_field(&mut rest, ifs).unwrap_or_default()
        });
    }
    let last = if rest.is_empty() {
        Vec::new()
    } else {
        let whole = rest;
        let field = next_field(&mut rest, ifs);
        if rest.is_empty() {
            field.unwrap_or_default()
        } else {
            strip_trailing(whole, ifs)
        }
    };
    values.push(last);
    values
}

/// The number of continuation bytes a UTF-8 sequence starting with `lead` has.
const fn continuation_bytes(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 1,
        0xe0..=0xef => 2,
        0xf0..=0xf7 => 3,
        _ => 0,
    }
}

impl Interpreter {
    /// `read` with `args`.
    pub(super) fn read_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, names) = match self.read_options(args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        if let Some(array) = &options.array
            && let Some(status) = self.check_read_name(array, span, run)?
        {
            return Ok(status);
        }
        if let Some(first) = names.first().filter(|_| options.array.is_none())
            && let Some(status) = self.check_read_name(first, span, run)?
        {
            return Ok(status);
        }
        let Some(source) = self.shell_descriptor(options.fd, span)? else {
            // A closed descriptor: bash's read fails with `EBADF`.
            self.report(
                span,
                run,
                format_args!("read: read error: {}: Bad file descriptor", options.fd),
            );
            return Ok(Status::FAILURE);
        };
        if options.timeout == Some(Duration::ZERO) {
            let ready = self.descriptors.wait_readable(&source, Duration::ZERO)?;
            return Ok(if ready { Status::SUCCESS } else { Status::FAILURE });
        }
        let terminal = self.descriptors.is_terminal(&source);
        if terminal && options.edit {
            return Err(unsupported(Unsupported::ReadOption, span).into());
        }
        if terminal && let Some(prompt) = &options.prompt {
            self.write_shell(2, prompt.as_bytes());
        }
        let delimiter = options.delimiter.unwrap_or(b'\n');
        let input = TerminalInput {
            echo: !options.silent,
            canonical: !(options.count > 0 || delimiter != b'\n'),
        };
        let changed = if terminal && (!input.echo || !input.canonical) {
            self.descriptors.set_terminal_input(&source, input)?
        } else {
            None
        };
        let result = self.read_line(&source, &options, delimiter, span);
        if let Some(saved) = changed {
            // Put back even after a failed read; a failure to put back is reported after the read's own.
            self.descriptors.restore_terminal(&source, &saved)?;
        }
        let (line, end) = match result? {
            Ok(read) => read,
            Err(errno) => {
                let reason = super::redirect::strerror(errno);
                self.report(span, run, format_args!("read: read error: {}: {reason}", options.fd));
                return Ok(Status::FAILURE);
            }
        };
        let assigned = match &options.array {
            Some(array) => self.assign_read_array(array, &line, span, run)?,
            None => self.assign_read(names, &line, span, run)?,
        };
        if let Some(status) = assigned {
            return Ok(status);
        }
        Ok(match end {
            End::Line => Status::SUCCESS,
            End::Eof => Status::FAILURE,
            End::TimedOut => Status::new(TIMED_OUT),
        })
    }

    /// `read`'s options and names, or the status of a usage error (already reported).
    fn read_options<'a>(
        &mut self,
        args: &'a [String],
        span: Span,
        run: &Run<'_>,
    ) -> Result<(Options, &'a [String]), Status> {
        let mut options = Options::default();
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
                    'r' => options.raw = true,
                    's' => options.silent = true,
                    'e' => options.edit = true,
                    'a' | 'd' | 'i' | 'n' | 'N' | 'p' | 't' | 'u' => {
                        let attached: String = letters[index..].iter().collect();
                        let value = if attached.is_empty() {
                            let Some(next) = args.get(at) else {
                                self.report(span, run, format_args!("read: -{letter}: option requires an argument"));
                                self.report_plain(format_args!("{USAGE}"));
                                return Err(Status::new(2));
                            };
                            at += 1;
                            next.clone()
                        } else {
                            attached
                        };
                        index = letters.len();
                        if let Some(status) = self.read_option_value(&mut options, letter, &value, span, run) {
                            return Err(status);
                        }
                    }
                    other => {
                        self.report(span, run, format_args!("read: -{other}: invalid option"));
                        self.report_plain(format_args!("{USAGE}"));
                        return Err(Status::new(2));
                    }
                }
            }
        }
        Ok((options, &args[at..]))
    }

    /// Sets the option `letter` takes `value` for; the status of an invalid value (reported).
    fn read_option_value(
        &mut self,
        options: &mut Options,
        letter: char,
        value: &str,
        span: Span,
        run: &Run<'_>,
    ) -> Option<Status> {
        match letter {
            'a' => options.array = Some(value.to_owned()),
            'd' => options.delimiter = Some(value.as_bytes().first().copied().unwrap_or(0)),
            // Initial text for line editing: ignored without it, as in bash.
            'i' => {}
            'p' => options.prompt = Some(value.to_owned()),
            'n' | 'N' => match legal_number(value).and_then(|count| usize::try_from(count).ok()) {
                Some(count) if i32::try_from(count).is_ok() => {
                    options.count = count;
                    options.ignore_delimiter = letter == 'N';
                }
                _ => {
                    self.report(span, run, format_args!("read: {value}: invalid number"));
                    return Some(Status::FAILURE);
                }
            },
            't' => {
                let Some(duration) = timeout(value) else {
                    self.report(span, run, format_args!("read: {value}: invalid timeout specification"));
                    return Some(Status::FAILURE);
                };
                options.timeout = Some(duration);
            }
            _ => match legal_number(value).and_then(|fd| u32::try_from(fd).ok()) {
                Some(fd) if self.fds.get(fd).is_some() => options.fd = fd,
                Some(fd) => {
                    self.report(
                        span,
                        run,
                        format_args!("read: {fd}: invalid file descriptor: Bad file descriptor"),
                    );
                    return Some(Status::FAILURE);
                }
                None => {
                    self.report(
                        span,
                        run,
                        format_args!("read: {value}: invalid file descriptor specification"),
                    );
                    return Some(Status::FAILURE);
                }
            },
        }
        None
    }

    /// Checks a name `read` assigns: an identifier or an array element (`Some(1)`, reported, when neither), not a
    /// variable bash maintains (refused).
    fn check_read_name(&mut self, name: &str, span: Span, run: &Run<'_>) -> Flow<Option<Status>> {
        let base = name.split_once('[').map_or(name, |(base, _)| base);
        let valid = is_name(name) || (is_name(base) && name.ends_with(']') && name.len() > base.len() + 2);
        if !valid {
            self.report(span, run, format_args!("read: `{name}': not a valid identifier"));
            return Ok(Some(Status::FAILURE));
        }
        if refuses_assignment(base) || self.state.is_unemulated(base) {
            return Err(unsupported(Unsupported::ShellVariable, span).into());
        }
        Ok(None)
    }

    /// Assigns `value` to `name` for `read`, which may name an array element (KNSH-103).
    fn assign_read_name(&mut self, name: &str, value: OsString, span: Span, run: &Run<'_>) -> Flow<Option<Status>> {
        match self.named(name, span, run)? {
            Some(super::function::Named::Element(array, key)) => {
                let result = self.state.assign_element(&array, &key, value, false);
                self.assigned(&array, name, result, span, run)
            }
            Some(super::function::Named::Variable(_)) => self.assign_or_report(name, value, false, span, run),
            Some(super::function::Named::All(_)) | None => {
                self.report(span, run, format_args!("read: `{name}': not a valid identifier"));
                Ok(Some(Status::FAILURE))
            }
        }
    }

    /// Reads one line from `source`: the bytes and how reading ended, or the `errno` of a failed read.
    fn read_line(
        &mut self,
        source: &SharedFd,
        options: &Options,
        delimiter: u8,
        span: Span,
    ) -> Flow<Result<(Vec<Read>, End), i32>> {
        let utf8 = is_utf8_locale(&self.locale_for(&["LC_ALL", "LC_CTYPE", "LANG"], span)?);
        // A timeout too long to add to the clock (`-t 18446744073709551615`) never runs out: no deadline.
        let deadline = options.timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        let mut line: Vec<Read> = Vec::new();
        let mut quote_next = false;
        let mut characters = 0_usize;
        // Bytes still to come of a UTF-8 character already counted.
        let mut continuing = 0_usize;
        loop {
            if line.len() >= MAX_READ_LINE {
                return Err(Stop::Error(InterpError::ExpansionLimit {
                    what: "read line bytes",
                    limit: MAX_READ_LINE,
                }));
            }
            if let Some(deadline) = deadline {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() || !self.descriptors.wait_readable(source, left)? {
                    return Ok(Ok((line, End::TimedOut)));
                }
            }
            let mut byte = [0_u8];
            match self.descriptors.read(source, &mut byte) {
                Ok(0) => return Ok(Ok((line, End::Eof))),
                Ok(_) => {}
                Err(error) => return Ok(Err(error.errno().unwrap_or(5))),
            }
            let byte = byte[0];
            if continuing > 0 {
                continuing -= 1;
                line.push((byte, quote_next));
                if continuing == 0 {
                    quote_next = false;
                    if options.count > 0 && characters >= options.count {
                        return Ok(Ok((line, End::Line)));
                    }
                }
                continue;
            }
            let quoted = std::mem::take(&mut quote_next);
            if quoted {
                // A backslash-newline disappears, even with `-N`.
                if byte == b'\n' {
                    continue;
                }
            } else {
                if byte == b'\\' && !options.raw {
                    quote_next = true;
                    continue;
                }
                if !options.ignore_delimiter && byte == delimiter {
                    return Ok(Ok((line, End::Line)));
                }
                if byte == 0 && (options.ignore_delimiter || delimiter != 0) {
                    continue;
                }
            }
            line.push((byte, quoted));
            characters += 1;
            if utf8 && byte >= 0xc0 {
                continuing = continuation_bytes(byte);
                if continuing > 0 {
                    quote_next = quoted;
                    continue;
                }
            }
            if options.count > 0 && characters >= options.count {
                return Ok(Ok((line, End::Line)));
            }
        }
    }

    /// `read -a array`: every field of what was read, split as bash's `list_string` splits it, as the elements of
    /// `array` from 0; the status when the assignment failed (reported).
    fn assign_read_array(&mut self, array: &str, line: &[Read], span: Span, run: &Run<'_>) -> Flow<Option<Status>> {
        let ifs: Vec<u8> = match self.state.variable("IFS") {
            Some(value) => value.as_encoded_bytes().to_vec(),
            None => DEFAULT_IFS.as_bytes().to_vec(),
        };
        let mut rest = line;
        let mut items = Vec::new();
        while let Some(field) = next_field(&mut rest, &ifs) {
            items.push((None, OsString::from_vec(field), false));
        }
        let result = self.state.assign_list(array, items, false, false);
        self.assigned(array, array, result, span, run)
    }

    /// Assigns what was read to `names` (or `REPLY`); the status when an assignment failed (reported).
    fn assign_read(&mut self, names: &[String], line: &[Read], span: Span, run: &Run<'_>) -> Flow<Option<Status>> {
        if names.is_empty() {
            let bytes: Vec<u8> = line.iter().map(|&(byte, _)| byte).collect();
            return self.assign_or_report("REPLY", OsString::from_vec(bytes), false, span, run);
        }
        let ifs: Vec<u8> = match self.state.variable("IFS") {
            Some(value) => value.as_encoded_bytes().to_vec(),
            None => DEFAULT_IFS.as_bytes().to_vec(),
        };
        let values = split_line(line, &ifs, names.len());
        for (name, value) in names.iter().zip(values) {
            if let Some(status) = self.check_read_name(name, span, run)? {
                return Ok(Some(status));
            }
            if let Some(status) = self.assign_read_name(name, OsString::from_vec(value), span, run)? {
                return Ok(Some(status));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> Vec<Read> {
        // `\` quotes the next byte, as `read` without `-r` marks it.
        let mut out = Vec::new();
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'\\' {
                if let Some(next) = bytes.next() {
                    out.push((next, true));
                }
            } else {
                out.push((byte, false));
            }
        }
        out
    }

    fn split(text: &str, ifs: &str, names: usize) -> Vec<String> {
        split_line(&line(text), ifs.as_bytes(), names)
            .into_iter()
            .map(|value| String::from_utf8(value).unwrap())
            .collect()
    }

    // KNSH-102: field splitting as bash 3.2 and 5.2 assign (each case checked against /bin/bash).
    #[test]
    fn fields_split_like_bash() {
        assert_eq!(split("x:y:z:", ":", 2), ["x", "y:z:"]);
        assert_eq!(split("  one   two  three  ", " \t\n", 2), ["one", "two  three"]);
        assert_eq!(split("  one   two  ", " \t\n", 1), ["one   two"]);
        assert_eq!(split("1,,3", ",", 3), ["1", "", "3"]);
        assert_eq!(split("1 , 2,3", ", ", 3), ["1", "2", "3"]);
        assert_eq!(split("a b\\ ", " \t\n", 2), ["a", "b "]);
        assert_eq!(split("a b c\\ ", " \t\n", 2), ["a", "b c"]);
        assert_eq!(split("1,2,,", ",", 2), ["1", "2,,"]);
        assert_eq!(split("1,2,", ",", 2), ["1", "2"]);
        assert_eq!(split("1 ,  , 2 ,", " ,", 2), ["1", ", 2 ,"]);
        assert_eq!(split("  x y  ", "", 2), ["  x y  ", ""]);
        assert_eq!(split("  \\ x  ", " \t\n", 1), [" x"]);
        assert_eq!(split("", " \t\n", 2), ["", ""]);
    }

    #[test]
    fn timeouts_read_like_uconvert() {
        assert_eq!(timeout("1.5"), Some(Duration::from_millis(1500)));
        assert_eq!(timeout(".25"), Some(Duration::from_millis(250)));
        assert_eq!(timeout("0"), Some(Duration::ZERO));
        assert_eq!(timeout("2.0000009"), Some(Duration::from_secs(2)));
        for bad in ["", ".", "-1", "x", "1e3", "1.2.3"] {
            assert_eq!(timeout(bad), None, "{bad}");
        }
    }
}
