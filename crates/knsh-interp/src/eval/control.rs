//! The builtins that change the flow of the script or its parameters, and the two that only print or set one value
//! (KNSH-101; NFR-COMPAT-02): `exit`, `return`, `break`, `continue`, `shift`, `set` (positional parameters only;
//! options arrive with KNSH-104), `echo` and `umask`.
//!
//! Numbers are read as bash's `legal_number` reads them: optional blanks, an optional sign, decimal digits, and
//! nothing else. Messages and statuses follow bash 5.2: a word that is not a number is `numeric argument required`
//! (2 for `exit` and `return`, 1 for `shift`, and for `break` and `continue` the end of the script, as bash's
//! `throw_to_top_level` ends a script); a second number is `too many arguments`, which abandons the rest of the line.

use std::fmt::Write as _;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::error::Unsupported;
use crate::status::Status;

/// Bash's `legal_number`: `text` as a 64-bit integer, with blanks around it and a sign allowed.
pub(super) fn legal_number(text: &str) -> Option<i64> {
    let trimmed = text.trim_matches(|ch: char| ch == ' ' || ch == '\t' || ch == '\n');
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<i64>().ok()
}

/// `args` without a leading `--`, which bash's numeric builtins skip.
fn operands(args: &[String]) -> &[String] {
    match args.first() {
        Some(first) if first == "--" => &args[1..],
        _ => args,
    }
}

/// The status of a number, as `exit` and `return` keep it: its low 8 bits.
fn low_byte(value: i64) -> Status {
    Status::new(u8::try_from(value & 0xff).unwrap_or(0))
}

impl Interpreter {
    /// Bash's `get_exitstat` for `name`: the status `args` give (`$?` without one), 2 after a word that is not a
    /// number; a second word abandons the line.
    fn exit_status(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let args = operands(args);
        let Some((first, rest)) = args.split_first() else {
            return Ok(self.state.last_status());
        };
        let Some(value) = legal_number(first) else {
            self.report(span, run, format_args!("{name}: {first}: numeric argument required"));
            return Ok(Status::new(2));
        };
        if !rest.is_empty() {
            return Err(self.too_many(name, span, run));
        }
        Ok(low_byte(value))
    }

    /// Bash's `no_args`: `name: too many arguments`, and the rest of the line is abandoned with status 1.
    fn too_many(&mut self, name: &str, span: Span, run: &Run<'_>) -> Stop {
        self.report(span, run, format_args!("{name}: too many arguments"));
        self.state.set_last_status(Status::FAILURE);
        Stop::Discard
    }

    /// `exit [n]`: the shell (or subshell) ends with `n`, or `$?`. An interactive shell says `exit` first.
    pub(super) fn exit_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if self.state.is_interactive() && !self.is_subshell {
            self.write_shell(2, b"exit\n");
        }
        let status = self.exit_status("exit", args, span, run)?;
        Err(Stop::Exit(status))
    }

    /// `return [n]`: leaves the function or the file being sourced with `n`, or `$?` (KNSH-103). Outside both it is
    /// an error with status 2, bash's `EX_USAGE`.
    pub(super) fn return_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let status = self.exit_status("return", args, span, run)?;
        if self.sourcing > 0 || self.state.in_function() {
            return Err(Stop::Return(status));
        }
        self.report(
            span,
            run,
            format_args!("return: can only `return' from a function or sourced script"),
        );
        Ok(Status::new(2))
    }

    /// `break [n]` and `continue [n]` (`name`).
    pub(super) fn loop_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if self.loops == 0 {
            self.report(
                span,
                run,
                format_args!("{name}: only meaningful in a `for', `while', or `until' loop"),
            );
            return Ok(Status::SUCCESS);
        }
        let args = operands(args);
        let count = match args.first() {
            None => 1,
            Some(first) => {
                if let Some(count) = legal_number(first) {
                    count
                } else {
                    self.report(span, run, format_args!("{name}: {first}: numeric argument required"));
                    return Err(self.thrown_to_top_level());
                }
            }
        };
        if args.len() > 1 {
            return Err(self.too_many(name, span, run));
        }
        if count <= 0 {
            // Bash leaves every loop then, whichever builtin it was.
            let first = args.first().map_or("", String::as_str);
            self.report(span, run, format_args!("{name}: {first}: loop count out of range"));
            return Err(Stop::Break {
                levels: self.loops,
                status: Status::FAILURE,
            });
        }
        let levels = usize::try_from(count).unwrap_or(usize::MAX).min(self.loops);
        Err(if name == "break" {
            Stop::Break {
                levels,
                status: Status::SUCCESS,
            }
        } else {
            Stop::Continue {
                levels,
                status: Status::SUCCESS,
            }
        })
    }

    /// Bash's `throw_to_top_level` after a fatal builtin error: `$?` gets 128 added; a script ends with it, an
    /// interactive shell abandons the line.
    fn thrown_to_top_level(&mut self) -> Stop {
        let status = Status::new(self.state.last_status().code() | 0x80);
        self.state.set_last_status(status);
        if self.state.is_interactive() && !self.is_subshell {
            Stop::Discard
        } else {
            Stop::Exit(status)
        }
    }

    /// `shift [n]`: drops the first `n` positional parameters (1 by default); 1 if there are fewer.
    pub(super) fn shift_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let args = operands(args);
        let count = match args.first() {
            None => 1,
            Some(first) => {
                if let Some(count) = legal_number(first) {
                    count
                } else {
                    self.report(span, run, format_args!("shift: {first}: numeric argument required"));
                    return Ok(Status::FAILURE);
                }
            }
        };
        if args.len() > 1 {
            return Err(self.too_many("shift", span, run));
        }
        if count < 0 {
            let first = args.first().map_or("", String::as_str);
            self.report(span, run, format_args!("shift: {first}: shift count out of range"));
            return Ok(Status::FAILURE);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let positional = self.state.positional();
        if count > positional.len() {
            // Bash says nothing unless `shopt -s shift_verbose`.
            return Ok(Status::FAILURE);
        }
        let rest = positional[count..].to_vec();
        self.state.set_positional(rest);
        Ok(Status::SUCCESS)
    }

    /// `set -- args`, `set - args` and `set args`: the positional parameters. Listing variables (`set` alone) and
    /// options (`set -e`, `set -o …`) are refused: options arrive with KNSH-104, and the listing would miss the
    /// variables bash maintains itself.
    pub(super) fn set_builtin(&mut self, args: &[String], span: Span) -> Flow<Status> {
        let parameters = match args.split_first() {
            None => return Err(unsupported(Unsupported::Builtin, span).into()),
            Some((first, rest)) if first == "--" || first == "-" => rest,
            Some((first, _)) if first.starts_with(['-', '+']) => {
                return Err(unsupported(Unsupported::Builtin, span).into());
            }
            Some(_) => args,
        };
        self.state.set_positional(parameters.to_vec());
        Ok(Status::SUCCESS)
    }

    /// `echo [-neE] args`: the arguments separated by spaces, then a newline. `-n` drops the newline, `-e` (or
    /// `shopt -s xpg_echo`) interprets backslash escapes, `-E` stops that; any leading word of only those letters is
    /// options, as in bash.
    pub(super) fn echo_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let mut escapes = self.state.options().xpg_echo;
        let mut newline = true;
        let mut rest = args;
        while let Some(letters) = rest.first().and_then(|first| echo_options(first)) {
            for letter in letters.chars() {
                match letter {
                    'n' => newline = false,
                    'e' => escapes = true,
                    _ => escapes = false,
                }
            }
            rest = &rest[1..];
        }
        let mut out = Vec::new();
        for (index, arg) in rest.iter().enumerate() {
            if index > 0 {
                out.push(b' ');
            }
            if escapes {
                if echo_escapes(arg, &mut out) {
                    // `\c`: nothing more, not even the newline.
                    return self.print("echo", &out, span, run);
                }
            } else {
                out.extend_from_slice(arg.as_bytes());
            }
        }
        if newline {
            out.push(b'\n');
        }
        self.print("echo", &out, span, run)
    }

    /// `umask [-p] [-S] [mode]`: prints the umask (octal, symbolic with `-S`, reusable with `-p`) or sets it from
    /// an octal number or a symbolic mode.
    pub(super) fn umask_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, rest) = match self.options("umask", "[-p] [-S] [mode]", "pS", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let symbolic = options.contains('S');
        let Some(mode) = rest.first() else {
            // The host did not say what the process's umask is: printing it would be a guess.
            let Some(mask) = self.state.umask() else {
                return Err(unsupported(Unsupported::UnknownUmask, span).into());
            };
            let mut text = String::new();
            if options.contains('p') {
                text.push_str(if symbolic { "umask -S " } else { "umask " });
            }
            if symbolic {
                text.push_str(&symbolic_umask(mask));
            } else {
                let _ = write!(text, "{mask:04o}");
            }
            text.push('\n');
            return Ok(self.print("umask", text.as_bytes(), span, run));
        };
        let parsed = if mode.starts_with(|ch: char| ch.is_ascii_digit()) {
            read_octal(mode).ok_or_else(|| format!("umask: {mode}: octal number out of range"))
        } else {
            // A symbolic mode changes the current umask, which must be known.
            let Some(current) = self.state.umask() else {
                return Err(unsupported(Unsupported::UnknownUmask, span).into());
            };
            parse_symbolic(mode, !current & 0o777)
                .map(|bits| !bits & 0o777)
                .map_err(|message| format!("umask: {message}"))
        };
        match parsed {
            Ok(mask) => {
                self.state.set_umask(mask);
                if symbolic {
                    let text = format!("{}\n", symbolic_umask(mask & 0o777));
                    return Ok(self.print("umask", text.as_bytes(), span, run));
                }
                Ok(Status::SUCCESS)
            }
            Err(message) => {
                self.report(span, run, format_args!("{message}"));
                Ok(Status::FAILURE)
            }
        }
    }
}

/// The option letters of `word` if bash's `echo` reads it as options: `-` and only `n`, `e` and `E`.
fn echo_options(word: &str) -> Option<&str> {
    word.strip_prefix('-')
        .filter(|letters| !letters.is_empty() && letters.chars().all(|ch| matches!(ch, 'n' | 'e' | 'E')))
}

/// Appends `arg` to `out` with `echo -e`'s escapes decoded, as bash's `ansicstr` in `echo` mode: `\a \b \e \E \f
/// \n \r \t \v \\`, `\0nnn` (up to three octal digits after the `0`), `\xHH`, `\uHHHH`, `\UHHHHHHHH`, and `\c`,
/// which ends all output (`true` is returned). Any other backslash is kept with what follows it.
fn echo_escapes(arg: &str, out: &mut Vec<u8>) -> bool {
    let bytes = arg.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        at += 1;
        if byte != b'\\' || at == bytes.len() {
            out.push(byte);
            continue;
        }
        let escape = bytes[at];
        at += 1;
        match escape {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'e' | b'E' => out.push(0x1b),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' => out.push(b'\\'),
            b'c' => return true,
            b'0' => {
                let mut value: u32 = 0;
                let mut taken = 0;
                while taken < 3 && at < bytes.len() && (b'0'..=b'7').contains(&bytes[at]) {
                    value = value * 8 + u32::from(bytes[at] - b'0');
                    at += 1;
                    taken += 1;
                }
                out.push(u8::try_from(value & 0xff).unwrap_or(0));
            }
            b'x' => {
                let mut value: u32 = 0;
                let mut taken = 0;
                while taken < 2 && at < bytes.len() && bytes[at].is_ascii_hexdigit() {
                    value = value * 16 + hex_value(bytes[at]);
                    at += 1;
                    taken += 1;
                }
                if taken == 0 {
                    out.extend_from_slice(b"\\x");
                } else {
                    out.push(u8::try_from(value & 0xff).unwrap_or(0));
                }
            }
            b'u' | b'U' => {
                let most = if escape == b'u' { 4 } else { 8 };
                let mut value: u32 = 0;
                let mut taken = 0;
                while taken < most && at < bytes.len() && bytes[at].is_ascii_hexdigit() {
                    value = value.wrapping_mul(16).wrapping_add(hex_value(bytes[at]));
                    at += 1;
                    taken += 1;
                }
                if taken == 0 {
                    out.push(b'\\');
                    out.push(escape);
                } else {
                    match char::from_u32(value) {
                        Some(ch) => {
                            let mut buffer = [0; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                        }
                        // Bash's `u32cconv` falls back to the escape written out when the value is no character.
                        None => out.extend_from_slice(format!("\\u{value:04X}").as_bytes()),
                    }
                }
            }
            other => {
                // Not an escape in `echo` (`\1`, `\'`, `\q`): kept as written.
                out.push(b'\\');
                out.push(other);
            }
        }
    }
    false
}

/// The value of hexadecimal digit `byte`.
fn hex_value(byte: u8) -> u32 {
    char::from(byte).to_digit(16).unwrap_or(0)
}

/// Bash's `read_octal` for `umask`: octal digits only, at most `07777`; the mask keeps its permission bits.
fn read_octal(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return None;
    }
    let mut value: u32 = 0;
    for byte in text.bytes() {
        value = value * 8 + u32::from(byte - b'0');
        if value > 0o7777 {
            return None;
        }
    }
    Some(value & 0o777)
}

/// The permissions `mask` leaves, as `umask -S` prints them: `u=rwx,g=rx,o=rx`.
fn symbolic_umask(mask: u32) -> String {
    let allowed = !mask & 0o777;
    let class = |shift: u32| {
        let bits = (allowed >> shift) & 0o7;
        let mut text = String::new();
        if bits & 0o4 != 0 {
            text.push('r');
        }
        if bits & 0o2 != 0 {
            text.push('w');
        }
        if bits & 0o1 != 0 {
            text.push('x');
        }
        text
    };
    format!("u={},g={},o={}", class(6), class(3), class(0))
}

/// Bash's `parse_symbolic_mode`: applies `mode` (clauses `[ugoa]*[+-=][rwx]*` separated by commas) to the
/// permission bits `bits`, or bash's error message.
fn parse_symbolic(mode: &str, mut bits: u32) -> Result<u32, String> {
    let chars: Vec<char> = mode.chars().collect();
    let mut at = 0;
    loop {
        let mut who = 0;
        while let Some(&letter) = chars.get(at) {
            who |= match letter {
                'u' => 0o700,
                'g' => 0o070,
                'o' => 0o007,
                'a' => 0o777,
                _ => break,
            };
            at += 1;
        }
        let op = chars.get(at).copied();
        at += 1;
        if !matches!(op, Some('+' | '-' | '=')) {
            let shown = op.map(String::from).unwrap_or_default();
            return Err(format!("`{shown}': invalid symbolic mode operator"));
        }
        let mut perm = 0;
        while let Some(&letter) = chars.get(at) {
            perm |= match letter {
                'r' => 0o444,
                'w' => 0o222,
                'x' => 0o111,
                _ => break,
            };
            at += 1;
        }
        match chars.get(at) {
            None | Some(',') => {
                if who != 0 {
                    perm &= who;
                }
                match op {
                    Some('+') => bits |= perm,
                    Some('-') => bits &= !perm,
                    _ => {
                        let cleared = if who == 0 { 0o777 } else { who };
                        bits = (bits & !cleared) | perm;
                    }
                }
                if chars.get(at).is_none() {
                    return Ok(bits & 0o777);
                }
                at += 1;
            }
            Some(other) => return Err(format!("`{other}': invalid symbolic mode character")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_read_as_legal_number_reads_them() {
        assert_eq!(legal_number("12"), Some(12));
        assert_eq!(legal_number(" -3 "), Some(-3));
        assert_eq!(legal_number("+4"), Some(4));
        for bad in ["", "-", "1x", "0x10", "1 2", "99999999999999999999"] {
            assert_eq!(legal_number(bad), None, "{bad}");
        }
    }

    // KNSH-101 unit test (NFR-COMPAT-02): `echo -e` decodes as bash 5.2's `ansicstr` in echo mode.
    #[test]
    fn echo_escapes_decode_like_ansicstr() {
        let decode = |arg: &str| {
            let mut out = Vec::new();
            let stopped = echo_escapes(arg, &mut out);
            (out, stopped)
        };
        assert_eq!(decode("a\\tb\\x41\\0101"), (b"a\tbAA".to_vec(), false));
        assert_eq!(decode("\\e[0m\\E"), (b"\x1b[0m\x1b".to_vec(), false));
        assert_eq!(decode("x\\cy"), (b"x".to_vec(), true));
        // Not escapes in echo: kept with their backslash, as bash keeps them.
        assert_eq!(decode("\\1\\q\\'\\x\\u"), (b"\\1\\q\\'\\x\\u".to_vec(), false));
        assert_eq!(decode("\\08"), (b"\x008".to_vec(), false));
        assert_eq!(decode("\\u00e9\\U0001F600"), ("é😀".as_bytes().to_vec(), false));
        assert_eq!(decode("\\xffend\\"), (b"\xffend\\".to_vec(), false));
        assert_eq!(echo_options("-neE"), Some("neE"));
        assert_eq!(echo_options("-"), None);
        assert_eq!(echo_options("-nx"), None);
        assert_eq!(echo_options("--"), None);
    }

    // KNSH-101: `umask` reads modes as bash does (checked against bash: `u=rwx,g=rx,o=` is 0027).
    #[test]
    fn umask_modes_parse_like_bash() {
        assert_eq!(read_octal("077"), Some(0o077));
        assert_eq!(read_octal("999"), None);
        assert_eq!(read_octal("17777"), None);
        assert_eq!(symbolic_umask(0o022), "u=rwx,g=rx,o=rx");
        assert_eq!(symbolic_umask(0o077), "u=rwx,g=,o=");
        assert_eq!(
            parse_symbolic("u=rwx,g=rx,o=", 0o755).map(|bits| !bits & 0o777),
            Ok(0o027)
        );
        assert_eq!(parse_symbolic("go-w", 0o777).map(|bits| !bits & 0o777), Ok(0o022));
        assert_eq!(parse_symbolic("+x", 0o644), Ok(0o755));
        assert_eq!(
            parse_symbolic("a+q", 0o755),
            Err("`q': invalid symbolic mode character".to_owned())
        );
        assert_eq!(
            parse_symbolic("u", 0o755),
            Err("`': invalid symbolic mode operator".to_owned())
        );
    }
}
