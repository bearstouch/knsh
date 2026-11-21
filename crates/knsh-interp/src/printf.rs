//! Bash's `printf` format engine (KNSH-102; NFR-COMPAT-02), as `printf.def` in bash 5.2 on macOS formats.
//!
//! - The format is reused while arguments remain, if a pass consumed any; a conversion past the last argument takes
//!   an empty string or zero. `\` escapes in the format are bash's (`\n`, `\0nn` and `\nnn` octal, `\xHH`, `\uHHHH`,
//!   `\UHHHHHHHH`, `\"`, `\'`, `\?`); `%%` is `%`.
//! - Conversions: `d i o u x X` (64-bit, numbers read as `strtoimax` with base 0 reads them: `0x1f`, `010`, a
//!   leading `'` or `"` giving the next character's code), `e E f F g G a A` (a `double`, as `long double` is on
//!   Apple silicon), `c`, `s`, `b` (an argument with `echo -e`-style escapes; `\c` stops all output), `q` and `Q`
//!   (quoted for reuse as shell input), `(format)T` (a time through `strftime`), and `n` (the byte count so far into
//!   a variable). Flags `-+ #0`, a width and a precision (numbers or `*`), and the length modifiers `hjlLtz`
//!   (skipped) are read as bash reads them. Numbers are formatted as the C library does, `%s` and `%c` padded with
//!   zeros under `0` as macOS's `printf` pads them, `%b`, `%q` and `%T` with spaces as bash's own `printstr` does.
//! - An argument that is not a whole number is reported (`printf: 12abc: invalid number`), the number read up to
//!   there is used, and the status becomes 1; a number out of range is a warning and is clamped. An invalid or
//!   missing conversion character is reported and stops the output there, with status 1.
//!
//! The engine is pure: what needs the shell (the clock and time zone for `%(…)T`, the variable `%n` sets, the
//! locale) goes through [`Host`]. Its output is bounded ([`MAX_OUTPUT`], [`MAX_FIELD`]) instead of growing without
//! limit on a hostile width.

use std::fmt::Write as _;

use crate::error::Unsupported;

/// Largest width or precision honoured: one field may not exceed it (bash has none; a field this large is refused
/// with an error rather than allocated).
pub(crate) const MAX_FIELD: usize = 1 << 20;

/// Largest output of one `printf`: past it the command is refused with an error rather than buffered without
/// limit (64 MiB).
pub(crate) const MAX_OUTPUT: usize = 64 << 20;

/// What the engine needs from the shell.
pub(crate) trait Host {
    /// `strftime(format)` of `localtime(seconds)`, or of the current time (`None`, the argument `-1`) or the shell's
    /// start (`Some(-2)` is passed as `-2`): bash's 128-byte result.
    ///
    /// # Errors
    ///
    /// The feature the interpreter refuses (no clock given, a `TZ` it cannot convert in).
    fn time(&mut self, format: &str, seconds: i64) -> Result<Vec<u8>, Refusal>;
    /// Assigns `count` to variable `name` (`%n`); `Err` with bash's message for a name that is not an identifier
    /// or a variable that cannot be assigned.
    ///
    /// # Errors
    ///
    /// The message, or a refusal.
    fn assign_count(&mut self, name: &str, count: usize) -> Result<(), CountError>;
    /// Whether the character locale is multibyte (UTF-8): `%q` leaves non-ASCII characters as they are, `'é` is the
    /// character's code.
    fn multibyte(&self) -> bool;
    /// Whether numbers are formatted as in the C locale: `.` as the decimal point, no grouping (`%'d`). `grouping`:
    /// the `'` flag is used.
    fn plain_numbers(&self, grouping: bool) -> bool;
}

/// Why `printf` cannot run as bash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A feature the interpreter refuses.
    Unsupported(Unsupported),
    /// A field or the output past the engine's bounds.
    Limit(&'static str, usize),
}

/// Why `%n` could not assign.
pub(crate) enum CountError {
    /// Bash's message; `printf` stops with status 1.
    Message(String),
    /// A refusal.
    Refused(Refusal),
}

/// What one `printf` produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Output {
    /// The bytes written.
    pub(crate) bytes: Vec<u8>,
    /// Bash's messages, without the `printf: ` prefix, in order.
    pub(crate) messages: Vec<String>,
    /// Whether the status is 1 (a conversion error, a bad conversion character, `%n` failing).
    pub(crate) failed: bool,
}

/// A conversion's flags, width and precision.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // One per flag character, as the C library reads them.
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    grouping: bool,
    width: usize,
    precision: Option<usize>,
}

/// Formats `format` with `args`.
///
/// # Errors
///
/// A [`Refusal`] when a conversion needs what the interpreter refuses, or the output grows past its bounds.
pub(crate) fn format(format: &str, args: &[String], host: &mut dyn Host) -> Result<Output, Refusal> {
    let mut engine = Engine {
        format: format.as_bytes(),
        args,
        next: 0,
        out: Output::default(),
        host,
        pass_start: 0,
    };
    engine.run()?;
    Ok(engine.out)
}

struct Engine<'a> {
    format: &'a [u8],
    args: &'a [String],
    /// The next argument.
    next: usize,
    out: Output,
    host: &'a mut dyn Host,
    /// Where the current pass of the format started writing (`%n` counts from there, as bash's `tw`).
    pass_start: usize,
}

/// How a pass of the format ended.
enum Pass {
    /// It reached the end of the format.
    Done,
    /// Output stops here (`\c` in `%b`, a bad conversion): no more passes.
    Stop,
}

impl Engine<'_> {
    fn run(&mut self) -> Result<(), Refusal> {
        loop {
            self.pass_start = self.out.bytes.len();
            if let Pass::Stop = self.pass()? {
                return Ok(());
            }
            // Bash reuses the format while arguments remain and the last pass consumed some.
            if self.next >= self.args.len() || self.next == 0 {
                return Ok(());
            }
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        if self.out.bytes.len() + bytes.len() > MAX_OUTPUT {
            return Err(Refusal::Limit("printf output bytes", MAX_OUTPUT));
        }
        self.out.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn message(&mut self, text: String) {
        self.out.messages.push(text);
    }

    /// The next argument, if any, consumed.
    fn take(&mut self) -> Option<&str> {
        let arg = self.args.get(self.next)?;
        self.next += 1;
        Some(arg)
    }

    fn pass(&mut self) -> Result<Pass, Refusal> {
        let mut at = 0;
        let format = self.format;
        while at < format.len() {
            let byte = format[at];
            if byte == b'\\' {
                let (decoded, used) = format_escape(format, at + 1, &mut self.out.messages);
                self.emit(&decoded)?;
                at = at + 1 + used;
                continue;
            }
            if byte != b'%' {
                let run = format[at..]
                    .iter()
                    .position(|&b| b == b'\\' || b == b'%')
                    .unwrap_or(format.len() - at);
                self.emit(&format[at..at + run])?;
                at += run;
                continue;
            }
            let start = at;
            at += 1;
            if format.get(at) == Some(&b'%') {
                self.emit(b"%")?;
                at += 1;
                continue;
            }
            match self.conversion(start, &mut at)? {
                Some(Pass::Stop) => return Ok(Pass::Stop),
                Some(Pass::Done) | None => {}
            }
        }
        Ok(Pass::Done)
    }

    /// The conversion starting at `start` (its `%`); `at` is just past the `%` and ends past the conversion.
    #[allow(clippy::too_many_lines)]
    fn conversion(&mut self, start: usize, at: &mut usize) -> Result<Option<Pass>, Refusal> {
        let format = self.format;
        let mut spec = Spec::default();
        while let Some(&flag) = format.get(*at) {
            match flag {
                b'-' => spec.left = true,
                b'+' => spec.plus = true,
                b' ' => spec.space = true,
                b'#' => spec.alternate = true,
                b'0' => spec.zero = true,
                b'\'' => spec.grouping = true,
                _ => break,
            }
            *at += 1;
        }
        if format.get(*at) == Some(&b'*') {
            *at += 1;
            let width = self.int_argument();
            if width < 0 {
                spec.left = true;
            }
            spec.width = bounded(usize::try_from(width.unsigned_abs()).unwrap_or(usize::MAX))?;
        } else {
            spec.width = bounded(read_digits(format, at))?;
        }
        if format.get(*at) == Some(&b'.') {
            *at += 1;
            if format.get(*at) == Some(&b'*') {
                *at += 1;
                let precision = self.int_argument();
                spec.precision = match usize::try_from(precision) {
                    Ok(precision) => Some(bounded(precision)?),
                    // A negative precision is as if none were given.
                    Err(_) => None,
                };
            } else {
                let negative = format.get(*at) == Some(&b'-');
                if negative {
                    *at += 1;
                }
                let digits = read_digits(format, at);
                spec.precision = if negative { None } else { Some(bounded(digits)?) };
            }
        }
        while format.get(*at).is_some_and(|byte| b"hjlLtz".contains(byte)) {
            *at += 1;
        }
        let Some(&conversion) = format.get(*at) else {
            let written = String::from_utf8_lossy(&format[start..]).into_owned();
            self.message(format!("`{written}': missing format character"));
            self.out.failed = true;
            return Ok(Some(Pass::Stop));
        };
        *at += 1;
        let numeric = b"diouxXeEfFgGaA".contains(&conversion);
        if numeric && spec.grouping && !self.host.plain_numbers(true) {
            return Err(Refusal::Unsupported(Unsupported::PrintfLocale));
        }
        match conversion {
            b'c' => {
                let arg = self.take().unwrap_or("");
                let first = arg
                    .as_bytes()
                    .first()
                    .map(std::slice::from_ref)
                    .unwrap_or_default()
                    .to_vec();
                // The C library's `%c` ignores a precision.
                self.libc_string(
                    &first,
                    Spec {
                        precision: None,
                        ..spec
                    },
                )?;
            }
            b's' => {
                let arg = self.take().unwrap_or("").as_bytes().to_vec();
                self.libc_string(&arg, spec)?;
            }
            b'b' => {
                let arg = self.take().unwrap_or("").to_owned();
                let mut expanded = Vec::new();
                let stop = argument_escapes(&arg, &mut expanded, &mut self.out.messages);
                self.bash_string(&expanded, spec)?;
                if stop {
                    return Ok(Some(Pass::Stop));
                }
            }
            b'q' | b'Q' => {
                let mut arg = self.take().unwrap_or("").to_owned();
                if conversion == b'Q'
                    && let Some(precision) = spec.precision.take()
                {
                    // `%Q` applies the precision to the argument before quoting it (bash 5.2).
                    let mut cut = precision.min(arg.len());
                    while !arg.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    arg.truncate(cut);
                }
                let quoted = shell_quote(&arg, self.host.multibyte());
                self.bash_string(quoted.as_bytes(), spec)?;
            }
            b'(' => return self.time_conversion(start, at, spec),
            b'n' => {
                let name = self.take().unwrap_or("").to_owned();
                if !name.is_empty() {
                    let count = self.out.bytes.len() - self.pass_start;
                    match self.host.assign_count(&name, count) {
                        Ok(()) => {}
                        Err(CountError::Message(message)) => {
                            self.message(message);
                            self.out.failed = true;
                            return Ok(Some(Pass::Stop));
                        }
                        Err(CountError::Refused(refusal)) => return Err(refusal),
                    }
                }
            }
            b'd' | b'i' => {
                let value = self.int_argument();
                let negative = value < 0;
                let digits = value.unsigned_abs().to_string();
                self.integer(&digits, negative, spec, "")?;
            }
            b'o' | b'u' | b'x' | b'X' => {
                let value = self.uint_argument();
                let (digits, prefix) = match conversion {
                    b'o' => (format!("{value:o}"), ""),
                    b'u' => (value.to_string(), ""),
                    b'x' => (format!("{value:x}"), if value == 0 { "" } else { "0x" }),
                    _ => (format!("{value:X}"), if value == 0 { "" } else { "0X" }),
                };
                let mut spec = spec;
                if conversion == b'o' && spec.alternate && !digits.starts_with('0') {
                    // `#o` makes the first digit a 0, raising the precision if needed.
                    spec.precision = Some(spec.precision.unwrap_or(0).max(digits.len() + 1));
                }
                let prefix = if spec.alternate { prefix } else { "" };
                self.integer(
                    &digits,
                    false,
                    Spec {
                        plus: false,
                        space: false,
                        ..spec
                    },
                    prefix,
                )?;
            }
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                if !self.host.plain_numbers(false) {
                    return Err(Refusal::Unsupported(Unsupported::PrintfLocale));
                }
                let value = self.float_argument();
                let text = format_float(value, conversion, spec);
                self.emit(text.as_bytes())?;
            }
            other => {
                let shown = String::from_utf8_lossy(&format[*at - 1..])
                    .chars()
                    .next()
                    .unwrap_or(char::from(other));
                self.message(format!("`{shown}': invalid format character"));
                self.out.failed = true;
                return Ok(Some(Pass::Stop));
            }
        }
        Ok(Some(Pass::Done))
    }

    /// `%(format)T`: the time format up to the `)` that closes the `(` (nested ones counted), then `T`.
    fn time_conversion(&mut self, start: usize, at: &mut usize, spec: Spec) -> Result<Option<Pass>, Refusal> {
        let format = self.format;
        let mut depth = 1_usize;
        let open = *at;
        while let Some(&byte) = format.get(*at) {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            *at += 1;
        }
        let time_format = String::from_utf8_lossy(&format[open..(*at).min(format.len())]).into_owned();
        *at += 1;
        if format.get(*at) != Some(&b'T') {
            // Bash warns and prints the `%` alone, then reads on after it.
            let shown = format.get(*at).map_or('\0', |&byte| char::from(byte));
            self.message(format!("warning: `{shown}': invalid time format specification"));
            *at = start + 1;
            self.emit(b"%")?;
            return Ok(Some(Pass::Done));
        }
        *at += 1;
        let time_format = if time_format.is_empty() {
            "%X".to_owned()
        } else {
            time_format
        };
        let seconds = if self.next < self.args.len() {
            self.int_argument()
        } else {
            -1
        };
        let text = self.host.time(&time_format, seconds)?;
        self.bash_string(&text, spec)?;
        Ok(Some(Pass::Done))
    }

    /// A string formatted as the C library's `%s` (and `%c`): precision cuts it, the width pads it, with zeros
    /// under `0` as macOS pads.
    fn libc_string(&mut self, text: &[u8], spec: Spec) -> Result<(), Refusal> {
        let text = spec
            .precision
            .map_or(text, |precision| &text[..precision.min(text.len())]);
        let fill = if spec.zero && !spec.left { b'0' } else { b' ' };
        self.padded(text, spec, fill)
    }

    /// A string formatted as bash's `printstr` (`%b`, `%q`, `%T`): as [`Engine::libc_string`], always padded with
    /// spaces.
    fn bash_string(&mut self, text: &[u8], spec: Spec) -> Result<(), Refusal> {
        let text = spec
            .precision
            .map_or(text, |precision| &text[..precision.min(text.len())]);
        self.padded(text, spec, b' ')
    }

    fn padded(&mut self, text: &[u8], spec: Spec, fill: u8) -> Result<(), Refusal> {
        let pad = spec.width.saturating_sub(text.len());
        if spec.left {
            self.emit(text)?;
            self.emit(&vec![b' '; pad])
        } else {
            self.emit(&vec![fill; pad])?;
            self.emit(text)
        }
    }

    /// An integer's `digits` (without sign), `negative`, with `prefix` (`0x`) as `%d` and `%x` format it.
    fn integer(&mut self, digits: &str, negative: bool, spec: Spec, prefix: &str) -> Result<(), Refusal> {
        let digits = match spec.precision {
            Some(0) if digits == "0" => String::new(),
            Some(precision) if precision > digits.len() => format!("{}{digits}", "0".repeat(precision - digits.len())),
            _ => digits.to_owned(),
        };
        let sign = if negative {
            "-"
        } else if spec.plus {
            "+"
        } else if spec.space {
            " "
        } else {
            ""
        };
        let body_len = sign.len() + prefix.len() + digits.len();
        let pad = spec.width.saturating_sub(body_len);
        let mut text = String::with_capacity(body_len + pad);
        if spec.left {
            text.push_str(sign);
            text.push_str(prefix);
            text.push_str(&digits);
            text.push_str(&" ".repeat(pad));
        } else if spec.zero && spec.precision.is_none() {
            text.push_str(sign);
            text.push_str(prefix);
            text.push_str(&"0".repeat(pad));
            text.push_str(&digits);
        } else {
            text.push_str(&" ".repeat(pad));
            text.push_str(sign);
            text.push_str(prefix);
            text.push_str(&digits);
        }
        self.emit(text.as_bytes())
    }

    /// The next argument as `getintmax` reads it (0 without one), reporting a bad or out-of-range number: an
    /// out-of-range one is clamped, as `strtoimax` clamps it.
    fn int_argument(&mut self) -> i64 {
        let Some(arg) = self.take().map(str::to_owned) else {
            return 0;
        };
        if let Some(code) = character_code(&arg, self.host.multibyte()) {
            return code;
        }
        let parsed = parse_integer(&arg);
        let limit: u128 = if parsed.negative { 1 << 63 } else { (1 << 63) - 1 };
        let overflow = parsed.magnitude > limit;
        self.number_errors(&arg, parsed.complete, overflow);
        let magnitude = parsed.magnitude.min(limit);
        let value = i128::try_from(magnitude).unwrap_or(i128::MAX);
        let value = if parsed.negative { -value } else { value };
        i64::try_from(value).unwrap_or(if parsed.negative { i64::MIN } else { i64::MAX })
    }

    /// The next argument as `getuintmax` reads it: a negative number wraps, as `strtoumax` does; an out-of-range
    /// one is clamped to the largest.
    fn uint_argument(&mut self) -> u64 {
        let Some(arg) = self.take().map(str::to_owned) else {
            return 0;
        };
        if let Some(code) = character_code(&arg, self.host.multibyte()) {
            return code.cast_unsigned();
        }
        let parsed = parse_integer(&arg);
        let overflow = parsed.magnitude > u128::from(u64::MAX);
        self.number_errors(&arg, parsed.complete, overflow);
        if overflow {
            return u64::MAX;
        }
        let magnitude = u64::try_from(parsed.magnitude).unwrap_or(u64::MAX);
        if parsed.negative {
            magnitude.wrapping_neg()
        } else {
            magnitude
        }
    }

    /// The next argument as `getfloatmax` reads it (`strtold`).
    fn float_argument(&mut self) -> f64 {
        let Some(arg) = self.take().map(str::to_owned) else {
            return 0.0;
        };
        if let Some(code) = character_code(&arg, self.host.multibyte()) {
            #[allow(clippy::cast_precision_loss)] // A character code is far below 2^53.
            return code as f64;
        }
        let (value, used) = parse_float(&arg);
        self.number_errors(&arg, used == arg.len(), value.is_infinite() && !is_infinity_text(&arg));
        value
    }

    /// Bash's reports for argument `arg`: `invalid number` (and status 1) unless `complete`, `Result too large`
    /// when `overflow`.
    fn number_errors(&mut self, arg: &str, complete: bool, overflow: bool) {
        if !complete {
            let bytes = arg.as_bytes();
            let kind = if bytes.first() == Some(&b'0') && bytes.get(1).is_some_and(u8::is_ascii_digit) {
                "invalid octal number"
            } else if bytes.first() == Some(&b'0') && bytes.get(1) == Some(&b'x') {
                "invalid hex number"
            } else {
                "invalid number"
            };
            self.message(format!("{arg}: {kind}"));
            self.out.failed = true;
        } else if overflow {
            self.message(format!("warning: {arg}: Result too large"));
        }
    }
}

/// `n` clamped to [`MAX_FIELD`], or the refusal past it.
fn bounded(n: usize) -> Result<usize, Refusal> {
    if n > MAX_FIELD {
        Err(Refusal::Limit("printf field width or precision", MAX_FIELD))
    } else {
        Ok(n)
    }
}

/// The decimal number at `at` in `format` (saturating), advancing past it.
fn read_digits(format: &[u8], at: &mut usize) -> usize {
    let mut value = 0_usize;
    while let Some(&byte) = format.get(*at).filter(|byte| byte.is_ascii_digit()) {
        value = value.saturating_mul(10).saturating_add(usize::from(byte - b'0'));
        *at += 1;
    }
    value
}

/// An argument starting with `'` or `"`: the code of the character after it (0 if none), as bash's `asciicode`:
/// the character's code point in a multibyte locale, its first byte as a signed `char` otherwise.
fn character_code(arg: &str, multibyte: bool) -> Option<i64> {
    let rest = arg.strip_prefix(['\'', '"'])?;
    if multibyte {
        return Some(rest.chars().next().map_or(0, |ch| i64::from(u32::from(ch))));
    }
    Some(rest.bytes().next().map_or(0, |byte| i64::from(byte.cast_signed())))
}

/// What `strtoimax(text, &end, 0)` read.
struct ParsedInteger {
    /// The digits' value, at most `u64::MAX + 1` (anything larger is out of range for every caller).
    magnitude: u128,
    negative: bool,
    /// The whole text was the number (`*end == '\0'`).
    complete: bool,
}

/// `strtoimax` with base 0: blanks, a sign, then `0x` hexadecimal, `0` octal or decimal digits. An empty text is 0
/// and complete; text without digits is 0 and incomplete.
fn parse_integer(text: &str) -> ParsedInteger {
    let bytes = text.as_bytes();
    let mut at = 0;
    while bytes.get(at).is_some_and(|byte| b" \t\n\x0b\x0c\r".contains(byte)) {
        at += 1;
    }
    let mut negative = false;
    if let Some(&sign @ (b'+' | b'-')) = bytes.get(at) {
        negative = sign == b'-';
        at += 1;
    }
    let mut radix = 10;
    if bytes.get(at) == Some(&b'0') {
        if matches!(bytes.get(at + 1), Some(b'x' | b'X')) && bytes.get(at + 2).is_some_and(u8::is_ascii_hexdigit) {
            radix = 16;
            at += 2;
        } else {
            radix = 8;
        }
    }
    let digits_start = at;
    let ceiling = u128::from(u64::MAX) + 1;
    let mut magnitude: u128 = 0;
    while let Some(digit) = bytes.get(at).and_then(|&byte| char::from(byte).to_digit(radix)) {
        magnitude = (magnitude * u128::from(radix) + u128::from(digit)).min(ceiling);
        at += 1;
    }
    // Without digits `strtoimax` reads nothing at all: only the empty text is then complete.
    let complete = if at == digits_start {
        text.is_empty()
    } else {
        at == bytes.len()
    };
    ParsedInteger {
        magnitude,
        negative,
        complete,
    }
}

/// Whether `text` spells an infinity `strtold` reads (so an infinite value is no overflow).
fn is_infinity_text(text: &str) -> bool {
    let trimmed = text.trim_start().trim_start_matches(['+', '-']);
    trimmed.len() >= 3 && trimmed[..3].eq_ignore_ascii_case("inf")
}

/// `strtold`'s reading of `text`: the value and how many bytes it used (0 when it read nothing).
fn parse_float(text: &str) -> (f64, usize) {
    let bytes = text.as_bytes();
    let mut at = 0;
    while bytes.get(at).is_some_and(|byte| b" \t\n\x0b\x0c\r".contains(byte)) {
        at += 1;
    }
    let sign_at = at;
    let negative = bytes.get(at) == Some(&b'-');
    if matches!(bytes.get(at), Some(b'+' | b'-')) {
        at += 1;
    }
    let signed = |value: f64| if negative { -value } else { value };
    let rest = &text[at..];
    let lower = rest.to_ascii_lowercase();
    if lower.starts_with("infinity") {
        return (signed(f64::INFINITY), at + 8);
    }
    if lower.starts_with("inf") {
        return (signed(f64::INFINITY), at + 3);
    }
    if lower.starts_with("nan") {
        let mut used = at + 3;
        if bytes.get(used) == Some(&b'(')
            && let Some(close) = text[used..].find(')')
            && text[used + 1..used + close]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            used += close + 1;
        }
        return (f64::NAN, used);
    }
    if lower.starts_with("0x") && lower[2..].starts_with(|ch: char| ch.is_ascii_hexdigit() || ch == '.') {
        return hex_float(text, at + 2, negative).unwrap_or((0.0, sign_at.max(at + 1)));
    }
    let start = at;
    let mut end = at;
    let mut digits = 0;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
        digits += 1;
    }
    if bytes.get(end) == Some(&b'.') {
        end += 1;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return (0.0, 0);
    }
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        let mut exponent = end + 1;
        if matches!(bytes.get(exponent), Some(b'+' | b'-')) {
            exponent += 1;
        }
        if bytes.get(exponent).is_some_and(u8::is_ascii_digit) {
            while bytes.get(exponent).is_some_and(u8::is_ascii_digit) {
                exponent += 1;
            }
            end = exponent;
        }
    }
    let value: f64 = text[start..end].parse().unwrap_or(0.0);
    (signed(value), end)
}

/// A hexadecimal float (`0x1.8p3`) whose digits start at `from`.
fn hex_float(text: &str, from: usize, negative: bool) -> Option<(f64, usize)> {
    let bytes = text.as_bytes();
    let mut at = from;
    let mut mantissa: f64 = 0.0;
    let mut scale: i32 = 0;
    let mut digits = 0;
    while let Some(digit) = bytes.get(at).and_then(|&b| char::from(b).to_digit(16)) {
        mantissa = mantissa * 16.0 + f64::from(digit);
        at += 1;
        digits += 1;
    }
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        while let Some(digit) = bytes.get(at).and_then(|&b| char::from(b).to_digit(16)) {
            mantissa = mantissa * 16.0 + f64::from(digit);
            scale -= 4;
            at += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    if matches!(bytes.get(at), Some(b'p' | b'P')) {
        let mut exponent_at = at + 1;
        let exponent_negative = bytes.get(exponent_at) == Some(&b'-');
        if matches!(bytes.get(exponent_at), Some(b'+' | b'-')) {
            exponent_at += 1;
        }
        if bytes.get(exponent_at).is_some_and(u8::is_ascii_digit) {
            let mut exponent: i32 = 0;
            while let Some(&digit) = bytes.get(exponent_at).filter(|b| b.is_ascii_digit()) {
                exponent = exponent.saturating_mul(10).saturating_add(i32::from(digit - b'0'));
                exponent_at += 1;
            }
            scale = scale.saturating_add(if exponent_negative { -exponent } else { exponent });
            at = exponent_at;
        }
    }
    let value = mantissa * 2_f64.powi(scale);
    Some((if negative { -value } else { value }, at))
}

/// A float formatted as the C library's `%e`, `%f`, `%g` or `%a` (uppercase for `E`, `F`, `G`, `A`).
fn format_float(value: f64, conversion: u8, spec: Spec) -> String {
    let upper = conversion.is_ascii_uppercase();
    let negative = value.is_sign_negative() && !value.is_nan();
    let magnitude = value.abs();
    let body = if value.is_nan() {
        "nan".to_owned()
    } else if value.is_infinite() {
        "inf".to_owned()
    } else {
        match conversion.to_ascii_lowercase() {
            b'f' => fixed(magnitude, spec.precision.unwrap_or(6), spec.alternate),
            b'e' => exponential(magnitude, spec.precision.unwrap_or(6), spec.alternate),
            b'g' => general(magnitude, spec.precision.unwrap_or(6), spec.alternate),
            _ => hexadecimal(magnitude, spec.precision, spec.alternate),
        }
    };
    let body = if upper { body.to_ascii_uppercase() } else { body };
    let sign = if negative {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let finite = value.is_finite();
    let len = sign.len() + body.len();
    let pad = spec.width.saturating_sub(len);
    if spec.left {
        format!("{sign}{body}{}", " ".repeat(pad))
    } else if spec.zero && finite {
        // Zeros go after the sign and a `0x` prefix.
        let (prefix, digits) = if body.starts_with("0x") || body.starts_with("0X") {
            body.split_at(2)
        } else {
            ("", body.as_str())
        };
        format!("{sign}{prefix}{}{digits}", "0".repeat(pad))
    } else {
        format!("{}{sign}{body}", " ".repeat(pad))
    }
}

/// `%f`: `precision` digits after the point (none and no point for 0, unless `alternate`).
fn fixed(magnitude: f64, precision: usize, alternate: bool) -> String {
    let mut text = format!("{magnitude:.precision$}");
    if precision == 0 && alternate {
        text.push('.');
    }
    text
}

/// `%e`: one digit, the point, `precision` digits, `e`, a sign and at least two exponent digits.
fn exponential(magnitude: f64, precision: usize, alternate: bool) -> String {
    let text = format!("{magnitude:.precision$e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let point = if precision == 0 && alternate { "." } else { "" };
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("{mantissa}{point}e{sign}{:02}", exponent.unsigned_abs())
}

/// `%g`: `%e` or `%f` by the exponent, trailing zeros removed unless `alternate`.
fn general(magnitude: f64, precision: usize, alternate: bool) -> String {
    let precision = precision.max(1);
    let exponent = if magnitude == 0.0 {
        0
    } else {
        let text = format!("{magnitude:.*e}", precision - 1);
        text.split_once('e')
            .and_then(|(_, e)| e.parse::<i64>().ok())
            .unwrap_or(0)
    };
    let mut text = if exponent < -4 || exponent >= i64::try_from(precision).unwrap_or(i64::MAX) {
        exponential(magnitude, precision - 1, alternate)
    } else {
        let decimals = usize::try_from(i64::try_from(precision).unwrap_or(0) - 1 - exponent).unwrap_or(0);
        fixed(magnitude, decimals, alternate)
    };
    if !alternate {
        let (number, exponent) = match text.find('e') {
            Some(at) => (text[..at].to_owned(), text[at..].to_owned()),
            None => (text.clone(), String::new()),
        };
        let number = if number.contains('.') {
            number.trim_end_matches('0').trim_end_matches('.').to_owned()
        } else {
            number
        };
        text = number + &exponent;
    } else if !text.contains('.') {
        // `#g` keeps the point even with no digits after it.
        match text.find('e') {
            Some(at) => text.insert(at, '.'),
            None => text.push('.'),
        }
    }
    text
}

/// `%a`: `0x1.<hex>p<sign><exponent>`, the shortest exact digits without a precision, as macOS formats a `double`.
fn hexadecimal(magnitude: f64, precision: Option<usize>, alternate: bool) -> String {
    if magnitude == 0.0 {
        let digits = precision.map_or(String::new(), |p| "0".repeat(p));
        let point = if digits.is_empty() && !alternate { "" } else { "." };
        return format!("0x0{point}{digits}p+0");
    }
    let bits = magnitude.to_bits();
    let raw_exponent = i64::try_from((bits >> 52) & 0x7ff).unwrap_or(0);
    let mut fraction = bits & ((1 << 52) - 1);
    let mut exponent = raw_exponent - 1023;
    let mut lead: u64 = 1;
    if raw_exponent == 0 {
        // A subnormal: normalise it, as macOS prints `0x1…p-1074`.
        let shift = fraction.leading_zeros() - 11;
        fraction = (fraction << shift) & ((1 << 52) - 1);
        exponent = -1022 - i64::from(shift);
    }
    let mut digits = format!("{fraction:013x}");
    match precision {
        None => {
            let trimmed = digits.trim_end_matches('0').len();
            digits.truncate(trimmed);
        }
        Some(precision) if precision < 13 => {
            // Round to nearest, ties to even, on the dropped bits.
            let dropped = 52 - 4 * precision;
            let kept = fraction >> dropped;
            let rest = fraction & ((1 << dropped) - 1);
            let half = 1 << (dropped - 1);
            let mut kept = kept;
            if rest > half || (rest == half && kept & 1 == 1) {
                kept += 1;
            }
            if precision == 0 {
                lead += kept;
                digits = String::new();
            } else if kept >> (4 * precision) != 0 {
                lead += 1;
                digits = format!("{:0width$x}", kept & ((1 << (4 * precision)) - 1), width = precision);
            } else {
                digits = format!("{kept:0precision$x}");
            }
        }
        Some(precision) => digits.push_str(&"0".repeat(precision - 13)),
    }
    let point = if digits.is_empty() && !alternate { "" } else { "." };
    let sign = if exponent < 0 { '-' } else { '+' };
    format!("0x{lead}{point}{digits}p{sign}{}", exponent.unsigned_abs())
}

/// A `\` escape of the format at `at` (just past the backslash), as bash's `tescape` without `%b`'s rules: the
/// bytes it stands for and how many bytes of the format it used.
fn format_escape(format: &[u8], at: usize, messages: &mut Vec<String>) -> (Vec<u8>, usize) {
    escape(format, at, false, messages).map_or((b"\\".to_vec(), 0), |(bytes, used, _)| (bytes, used))
}

/// Expands `%b`'s argument into `out`, as bash's `bexpand`; `true` when `\c` stops all output.
fn argument_escapes(arg: &str, out: &mut Vec<u8>, messages: &mut Vec<String>) -> bool {
    let bytes = arg.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' || at + 1 == bytes.len() {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        match escape(bytes, at + 1, true, messages) {
            Some((_, _, true)) => return true,
            Some((decoded, used, false)) => {
                out.extend_from_slice(&decoded);
                at += 1 + used;
            }
            None => {
                out.push(b'\\');
                at += 1;
            }
        }
    }
    false
}

/// Bash's `tescape` at `at` (just past a backslash): the bytes, the bytes used and whether it is `%b`'s `\c`, or
/// `None` when the backslash stands for itself (the next character then read normally). `argument`: `%b`'s rules
/// (`\0` takes three more octal digits, `\c` stops, `\'` `\"` `\?` keep their backslash).
fn escape(text: &[u8], at: usize, argument: bool, messages: &mut Vec<String>) -> Option<(Vec<u8>, usize, bool)> {
    let &first = text.get(at)?;
    let simple = |byte: u8| Some((vec![byte], 1, false));
    match first {
        b'a' => simple(0x07),
        b'b' => simple(0x08),
        b'e' | b'E' => simple(0x1b),
        b'f' => simple(0x0c),
        b'n' => simple(b'\n'),
        b'r' => simple(b'\r'),
        b't' => simple(b'\t'),
        b'v' => simple(0x0b),
        b'\\' => simple(b'\\'),
        b'0'..=b'7' => {
            let mut value = u32::from(first - b'0');
            let mut more = if value == 0 && argument { 3 } else { 2 };
            let mut used = 1;
            while more > 0 && text.get(at + used).is_some_and(|b| (b'0'..=b'7').contains(b)) {
                value = value * 8 + u32::from(text[at + used] - b'0');
                used += 1;
                more -= 1;
            }
            Some((vec![u8::try_from(value & 0xff).unwrap_or(0)], used, false))
        }
        b'x' => {
            let mut value = 0_u32;
            let mut used = 1;
            while used <= 2 && text.get(at + used).is_some_and(u8::is_ascii_hexdigit) {
                value = value * 16 + char::from(text[at + used]).to_digit(16).unwrap_or(0);
                used += 1;
            }
            if used == 1 {
                messages.push("missing hex digit for \\x".to_owned());
                return None;
            }
            Some((vec![u8::try_from(value & 0xff).unwrap_or(0)], used, false))
        }
        b'u' | b'U' => {
            let most = if first == b'u' { 4 } else { 8 };
            let mut value = 0_u32;
            let mut used = 1;
            while used <= most && text.get(at + used).is_some_and(u8::is_ascii_hexdigit) {
                value = value
                    .wrapping_mul(16)
                    .wrapping_add(char::from(text[at + used]).to_digit(16).unwrap_or(0));
                used += 1;
            }
            if used == 1 {
                messages.push(format!("missing unicode digit for \\{}", char::from(first)));
                return None;
            }
            let bytes = match char::from_u32(value) {
                Some(ch) => ch.to_string().into_bytes(),
                // Bash's `u32cconv` writes a value that is no character as the escape.
                None => format!("\\u{value:04X}").into_bytes(),
            };
            Some((bytes, used, false))
        }
        b'\'' | b'"' | b'?' if !argument => simple(first),
        b'c' if argument => Some((Vec::new(), 1, true)),
        _ => None,
    }
}

/// Bash 5.2's quoting for `%q`: `''` for an empty string, `$'…'` (`ansic_quote`) when a character is not printable,
/// otherwise each character special to the shell backslash-escaped (`sh_backslash_quote` with tildes quoted), with
/// a leading `#` and a `~` at the start or after `:` or `=`.
pub(crate) fn shell_quote(text: &str, multibyte: bool) -> String {
    if text.is_empty() {
        return "''".to_owned();
    }
    let printable = |ch: char| {
        if ch.is_ascii() {
            !ch.is_ascii_control()
        } else {
            multibyte && !ch.is_control()
        }
    };
    if !text.chars().all(printable) {
        return ansi_c_quote(text, multibyte);
    }
    let mut out = String::with_capacity(text.len() * 2);
    let mut previous: Option<char> = None;
    for (index, ch) in text.chars().enumerate() {
        let special = " \t\n!\"$&'()*,;<>?[\\]^`{|}".contains(ch)
            || (ch == '#' && index == 0)
            || (ch == '~' && (index == 0 || matches!(previous, Some(':' | '='))));
        if special {
            out.push('\\');
        }
        out.push(ch);
        previous = Some(ch);
    }
    out
}

/// Bash's `ansic_quote`: `$'…'` with C escapes, `\'` and `\\`, other unprintable bytes as three octal digits.
fn ansi_c_quote(text: &str, multibyte: bool) -> String {
    let mut out = String::from("$'");
    for ch in text.chars() {
        match ch {
            '\x1b' => out.push_str("\\E"),
            '\x07' => out.push_str("\\a"),
            '\x0b' => out.push_str("\\v"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' | '\'' => {
                out.push('\\');
                out.push(ch);
            }
            _ if ch.is_ascii() && !ch.is_ascii_control() => out.push(ch),
            _ if !ch.is_ascii() && multibyte && !ch.is_control() => out.push(ch),
            _ => {
                let mut buffer = [0; 4];
                for byte in ch.encode_utf8(&mut buffer).bytes() {
                    let _ = write!(out, "\\{byte:03o}");
                }
            }
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests;
