//! Reading the text inside `${…}`, `$((…))`, `(( … ))` and arithmetic `for` into word parts (KNSH-097).
//!
//! The parser keeps those bodies whole (their spans are known, their insides are not split into segments), as bash
//! does: bash reads them again when it expands them. So does this module, for the words inside a parameter expansion
//! (`${x:-"a b"$y}`) and the expressions of arithmetic. It finds the same extents the `knsh-bash` lexer found: an
//! escape, a quote or a nested expansion is skipped as a whole, so its characters never end the enclosing body.
//!
//! The result is a list of [`Part`]s, the same form parser segments are turned into, so one engine expands both.
//! Command substitutions cannot occur in `${…}` and `$((…))`: the parser refuses them there (KNSH-031). Inside
//! `[[ … ]]` and `(( … ))`, which the parser keeps opaque, one is refused rather than read, as is a stray one
//! anywhere: only the parser delimits a substitution's body (KNSH-105 runs those it read, [`Part::Subst`]).

use knsh_bash::Span;

use crate::error::{InterpError, Unsupported};
use crate::expand::decode_ansi_c;

/// One piece of a word, after the quoting structure has been read and before anything is expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    /// Unquoted text: subject to tilde expansion at the start of a word, and to pattern matching in a pattern.
    Text(String),
    /// Quoted text (single quotes, a backslash escape, the literal text of double quotes). An empty one still makes
    /// the word a quoted empty string (`''`).
    Quoted(String),
    /// `"…"`: what is inside, all quoted.
    Double(Vec<Part>),
    /// `$name`, `$1` or a special parameter such as `$@` (`name` is what follows the `$`).
    Param {
        /// The name or special character.
        name: String,
        /// The whole `$…`.
        span: Span,
    },
    /// `${…}`.
    Brace {
        /// Between the braces.
        body: Span,
        /// The whole `${…}`.
        span: Span,
    },
    /// `$((…))` or `$[…]`.
    Arith {
        /// The expression.
        body: Span,
        /// The whole expansion.
        span: Span,
    },
    /// `$(…)`, `` `…` ``, `<(…)` or `>(…)` (KNSH-105): run when expanded, its body parsed again as bash does.
    Subst(Subst),
}

/// A command or process substitution in a word (KNSH-105).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Subst {
    /// Which form.
    pub(crate) kind: SubstKind,
    /// Between the delimiters, as written.
    pub(crate) body: Span,
    /// The whole substitution.
    pub(crate) span: Span,
}

/// The forms of [`Subst`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubstKind {
    /// `$(…)`.
    Command,
    /// `` `…` ``, inside double quotes or not (which changes how its body is un-escaped).
    Backtick {
        /// Inside `"…"` or `$"…"`, not a here-document body.
        in_double_quotes: bool,
    },
    /// `<(…)`: the body's output, read through `/dev/fd/N`.
    Input,
    /// `>(…)`: the body's input, written through `/dev/fd/N`.
    Output,
}

/// How quotes are read in the text being scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// As in an unquoted word: `'…'`, `"…"` and `\` quote.
    Unquoted,
    /// As inside double quotes: `\` quotes only `$`, `` ` ``, `"`, `\` and newline, and `'` is an ordinary
    /// character. A nested `"…"` still groups (bash reads `"${x:-"a b"}"` that way). Arithmetic expressions are read
    /// this way too.
    Double,
    /// As [`Mode::Double`], but `'…'` quotes too: a pattern inside a double-quoted `${x#pattern}`, where bash 5.2
    /// honours single quotes.
    DoublePattern,
}

/// The parts of the text `span` covers in `source`, read in `mode`.
///
/// # Errors
///
/// [`InterpError::Unsupported`] for a command substitution, and
/// [`InterpError::SourceMismatch`] if `span` does not index `source`.
pub(crate) fn scan(source: &str, span: Span, mode: Mode) -> Result<Vec<Part>, InterpError> {
    let text = span.text(source).ok_or(InterpError::SourceMismatch { span })?;
    let mut scanner = Scanner {
        text,
        base: span.start,
        pos: 0,
    };
    scanner.parts(mode, false)
}

/// The offset, within `text`, of the first `target` byte that is not inside an escape, a quote or a nested
/// expansion (and, with `parens`, not inside parentheses either), or `None`.
pub(crate) fn find_top_level(text: &str, target: u8, parens: bool) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == target && depth == 0 {
            return Some(i);
        }
        if let Some(after) = skip(bytes, i) {
            i = after;
            continue;
        }
        if parens && byte == b'(' {
            depth += 1;
        } else if parens && byte == b')' {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    None
}

/// Where the subscript in `text` (the text after a `[`) ends: the offset of its matching `]`, nested brackets
/// counted and quotes and expansions skipped, as bash's `skipsubscript` reads it (KNSH-103).
pub(crate) fn subscript_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if let Some(after) = skip(bytes, i) {
            i = after;
            continue;
        }
        match byte {
            b'[' => depth += 1,
            b']' if depth == 0 => return Some(i),
            b']' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

/// The three expressions of `for (( init; test; update ))`, whose header spans `span` in `source`: split at the
/// top-level `;`, or `None` unless there are exactly three.
pub(crate) fn arithmetic_for_header(source: &str, span: Span) -> Option<[Span; 3]> {
    let text = span.text(source)?;
    let first = find_top_level(text, b';', true)?;
    let rest = text.get(first + 1..)?;
    let second = first + 1 + find_top_level(rest, b';', true)?;
    if find_top_level(text.get(second + 1..)?, b';', true).is_some() {
        return None;
    }
    let at = |start: usize, end: usize| Span::new(span.start + start, span.start + end);
    Some([at(0, first), at(first + 1, second), at(second + 1, text.len())])
}

/// If an escape, a quote or a `$` expansion starts at `i`, the offset just past it; otherwise `None`. Mirrors the
/// lexer's `skip_quoted_or_expansion`: single quotes count wherever they are. An unclosed construct runs to the end.
fn skip(bytes: &[u8], i: usize) -> Option<usize> {
    let len = bytes.len();
    match *bytes.get(i)? {
        b'\\' => Some((i + 2).min(len)),
        b'\'' => Some(find_byte(bytes, i + 1, b'\'').map_or(len, |close| close + 1)),
        b'"' => Some(double_end(bytes, i + 1)),
        b'`' => Some(backtick_end(bytes, i + 1)),
        b'$' => match bytes.get(i + 1) {
            Some(b'{') => Some(close_of(bytes, i + 2, None, b'}').map_or(len, |close| close + 1)),
            Some(b'(') => Some(close_of(bytes, i + 2, Some(b'('), b')').map_or(len, |close| close + 1)),
            Some(b'[') => Some(close_of(bytes, i + 2, Some(b'['), b']').map_or(len, |close| close + 1)),
            _ => None,
        },
        _ => None,
    }
}

fn find_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    bytes.get(from..)?.iter().position(|&b| b == target).map(|at| from + at)
}

/// Just past the `"` closing a double-quoted string whose body starts at `from`.
fn double_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'"' => return i + 1,
            b'\\' => i += 2,
            b'$' | b'`' => i = skip(bytes, i).unwrap_or(i + 1),
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Just past the backtick closing a substitution whose body starts at `from`.
fn backtick_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'`' => return i + 1,
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// The offset of the `close` byte ending a body that starts at `from`, where each `open` byte (if any) nests.
fn close_of(bytes: &[u8], from: usize, open: Option<u8>, close: u8) -> Option<usize> {
    let mut nested = 0_usize;
    let mut i = from;
    while let Some(&byte) = bytes.get(i) {
        if Some(byte) == open {
            nested += 1;
        } else if byte == close {
            if nested == 0 {
                return Some(i);
            }
            nested -= 1;
        } else if let Some(after) = skip(bytes, i) {
            i = after;
            continue;
        }
        i += 1;
    }
    None
}

/// The reading position in one body.
struct Scanner<'a> {
    text: &'a str,
    /// Where `text` starts in the source.
    base: usize,
    pos: usize,
}

impl Scanner<'_> {
    fn span(&self, start: usize, end: usize) -> Span {
        Span::new(self.base + start, self.base + end)
    }

    fn refuse(&self, feature: Unsupported, start: usize) -> InterpError {
        InterpError::Unsupported {
            feature,
            span: self.span(start, self.text.len()),
        }
    }

    /// The text from `start` to `end` (within `text`), or empty.
    fn slice(&self, start: usize, end: usize) -> &str {
        self.text.get(start..end).unwrap_or("")
    }

    /// Reads parts until the end, or (when `in_double`) until the `"` that ends the double-quoted string being
    /// read, which is consumed.
    fn parts(&mut self, mode: Mode, in_double: bool) -> Result<Vec<Part>, InterpError> {
        let bytes = self.text.as_bytes();
        let quoted = mode != Mode::Unquoted || in_double;
        let mut out = Vec::new();
        let mut literal = String::new();
        let flush = |literal: &mut String, out: &mut Vec<Part>| {
            if !literal.is_empty() {
                let text = std::mem::take(literal);
                out.push(if quoted { Part::Quoted(text) } else { Part::Text(text) });
            }
        };
        while let Some(&byte) = bytes.get(self.pos) {
            let start = self.pos;
            match byte {
                b'"' if in_double => {
                    self.pos += 1;
                    flush(&mut literal, &mut out);
                    return Ok(out);
                }
                b'"' => {
                    flush(&mut literal, &mut out);
                    self.pos += 1;
                    let inner = self.parts(if mode == Mode::Unquoted { Mode::Double } else { mode }, true)?;
                    out.push(Part::Double(inner));
                }
                b'\\' => {
                    let next = self.text.get(start + 1..).and_then(|rest| rest.chars().next());
                    match next {
                        // A line continuation: removed, as bash removes it before reading.
                        Some('\n') => self.pos += 2,
                        Some(ch) if !quoted || matches!(ch, '$' | '`' | '"' | '\\') => {
                            flush(&mut literal, &mut out);
                            out.push(Part::Quoted(ch.to_string()));
                            self.pos += 1 + ch.len_utf8();
                        }
                        // Inside double quotes a backslash that escapes nothing is kept.
                        Some(_) | None => {
                            literal.push('\\');
                            self.pos += 1;
                        }
                    }
                }
                b'\'' if mode == Mode::Unquoted || (mode == Mode::DoublePattern && !in_double) => {
                    flush(&mut literal, &mut out);
                    let close = find_byte(bytes, start + 1, b'\'').unwrap_or(bytes.len());
                    out.push(Part::Quoted(self.slice(start + 1, close).to_owned()));
                    self.pos = (close + 1).min(bytes.len());
                }
                b'`' => return Err(self.refuse(Unsupported::CommandSubstitution, start)),
                b'$' => {
                    if let Some(part) = self.dollar(mode, in_double)? {
                        flush(&mut literal, &mut out);
                        out.push(part);
                    } else {
                        literal.push('$');
                        self.pos += 1;
                    }
                }
                _ => {
                    let ch = self
                        .text
                        .get(start..)
                        .and_then(|rest| rest.chars().next())
                        .unwrap_or('\u{fffd}');
                    literal.push(ch);
                    self.pos += ch.len_utf8().max(1);
                }
            }
        }
        flush(&mut literal, &mut out);
        Ok(out)
    }

    /// The expansion starting with the `$` at `pos`, consumed; or `None` (nothing consumed) when the `$` is literal.
    fn dollar(&mut self, mode: Mode, in_double: bool) -> Result<Option<Part>, InterpError> {
        let bytes = self.text.as_bytes();
        let start = self.pos;
        let Some(&next) = bytes.get(start + 1) else {
            return Ok(None);
        };
        let unquoted = mode == Mode::Unquoted && !in_double;
        let part = match next {
            b'{' => {
                let close = close_of(bytes, start + 2, None, b'}').ok_or(InterpError::SourceMismatch {
                    span: self.span(start, bytes.len()),
                })?;
                self.pos = close + 1;
                Part::Brace {
                    body: self.span(start + 2, close),
                    span: self.span(start, close + 1),
                }
            }
            b'(' if bytes.get(start + 2) == Some(&b'(') => {
                // `$((…))` only if the parenthesis matching the second `(` is followed by `)`.
                match close_of(bytes, start + 3, Some(b'('), b')') {
                    Some(close) if bytes.get(close + 1) == Some(&b')') => {
                        self.pos = close + 2;
                        Part::Arith {
                            body: self.span(start + 3, close),
                            span: self.span(start, close + 2),
                        }
                    }
                    Some(_) | None => return Err(self.refuse(Unsupported::CommandSubstitution, start)),
                }
            }
            b'(' => return Err(self.refuse(Unsupported::CommandSubstitution, start)),
            b'[' => {
                let close = close_of(bytes, start + 2, Some(b'['), b']').ok_or(InterpError::SourceMismatch {
                    span: self.span(start, bytes.len()),
                })?;
                self.pos = close + 1;
                Part::Arith {
                    body: self.span(start + 2, close),
                    span: self.span(start, close + 1),
                }
            }
            b'\'' if unquoted => {
                // `$'…'`: up to the first `'` not escaped by a backslash, its escapes decoded.
                let mut end = start + 2;
                while let Some(&byte) = bytes.get(end) {
                    match byte {
                        b'\\' => end += 2,
                        b'\'' => break,
                        _ => end += 1,
                    }
                }
                let end = end.min(bytes.len());
                self.pos = (end + 1).min(bytes.len());
                Part::Quoted(decode_ansi_c(self.slice(start + 2, end)))
            }
            b'"' if unquoted => {
                // `$"…"`: in the C locale, plain double quotes.
                self.pos = start + 2;
                Part::Double(self.parts(Mode::Double, true)?)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let mut end = start + 2;
                while bytes.get(end).is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_') {
                    end += 1;
                }
                self.pos = end;
                Part::Param {
                    name: self.slice(start + 1, end).to_owned(),
                    span: self.span(start, end),
                }
            }
            b'0'..=b'9' | b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!' => {
                self.pos = start + 2;
                Part::Param {
                    name: char::from(next).to_string(),
                    span: self.span(start, start + 2),
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(part))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(text: &str, mode: Mode) -> Vec<Part> {
        scan(text, Span::new(0, text.len()), mode).unwrap()
    }

    fn text(s: &str) -> Part {
        Part::Text(s.to_owned())
    }

    fn quoted(s: &str) -> Part {
        Part::Quoted(s.to_owned())
    }

    #[test]
    fn reads_quotes_and_escapes_like_an_unquoted_word() {
        assert_eq!(
            parts(r#"a 'b c'"d\"e"\f\$g"#, Mode::Unquoted),
            [
                text("a "),
                quoted("b c"),
                Part::Double(vec![quoted("d"), quoted("\""), quoted("e")]),
                quoted("f"),
                quoted("$"),
                text("g"),
            ]
        );
    }

    #[test]
    fn reads_like_double_quotes() {
        assert_eq!(
            parts(r#"a'b\c\$"d""#, Mode::Double),
            [quoted("a'b\\c"), quoted("$"), Part::Double(vec![quoted("d")])]
        );
        assert_eq!(parts("'a'", Mode::DoublePattern), [quoted("a")]);
    }

    #[test]
    fn finds_nested_expansions_and_their_extents() {
        let input = "$x${y:-}}$((1+(2)))$[3]$1$@ $";
        let found = parts(input, Mode::Unquoted);
        assert_eq!(
            found,
            [
                Part::Param {
                    name: "x".into(),
                    span: Span::new(0, 2)
                },
                Part::Brace {
                    body: Span::new(4, 7),
                    span: Span::new(2, 8)
                },
                text("}"),
                Part::Arith {
                    body: Span::new(12, 17),
                    span: Span::new(9, 19)
                },
                Part::Arith {
                    body: Span::new(21, 22),
                    span: Span::new(19, 23)
                },
                Part::Param {
                    name: "1".into(),
                    span: Span::new(23, 25)
                },
                Part::Param {
                    name: "@".into(),
                    span: Span::new(25, 27)
                },
                text(" $"),
            ]
        );
    }

    #[test]
    fn a_brace_inside_quotes_or_a_nested_expansion_does_not_close() {
        let input = r#"${a:-"}"${b}}"#;
        assert_eq!(
            parts(input, Mode::Unquoted),
            [Part::Brace {
                body: Span::new(2, input.len() - 1),
                span: Span::new(0, input.len())
            }]
        );
    }

    #[test]
    fn refuses_command_substitution_and_decodes_ansi_c_quotes() {
        for input in ["$(ls)", "`ls`", "$( (a) )"] {
            assert!(matches!(
                scan(input, Span::new(0, input.len()), Mode::Unquoted),
                Err(InterpError::Unsupported {
                    feature: Unsupported::CommandSubstitution,
                    ..
                })
            ));
        }
        // `$'…'` is quoted text with its escapes decoded (KNSH-098).
        assert_eq!(parts(r"$'a\tb\'c'd", Mode::Unquoted), [quoted("a\tb'c"), text("d")]);
        // Inside double quotes `$'` is a literal dollar and quote.
        assert_eq!(parts("$'a'", Mode::Double), [quoted("$'a'")]);
    }

    #[test]
    fn removes_line_continuations() {
        assert_eq!(parts("a\\\nb", Mode::Unquoted), [text("ab")]);
        assert_eq!(parts("1 +\\\n 2", Mode::Double), [quoted("1 + 2")]);
    }

    #[test]
    fn splits_the_arithmetic_for_header() {
        let header = "i = 0; i < (3); i++";
        let [init, condition, update] = arithmetic_for_header(header, Span::new(0, header.len())).unwrap();
        assert_eq!(init.text(header), Some("i = 0"));
        assert_eq!(condition.text(header), Some(" i < (3)"));
        assert_eq!(update.text(header), Some(" i++"));
        assert!(arithmetic_for_header(";;", Span::new(0, 2)).is_some());
        for bad in ["i = 0; i < 3", "a;b;c;d", ""] {
            assert_eq!(arithmetic_for_header(bad, Span::new(0, bad.len())), None, "{bad}");
        }
    }

    #[test]
    fn finds_top_level_separators() {
        assert_eq!(find_top_level(r"a\/b/c", b'/', false), Some(4));
        assert_eq!(find_top_level(r#""a/b"/c"#, b'/', false), Some(5));
        assert_eq!(find_top_level("${x/a/b}/c", b'/', false), Some(8));
        assert_eq!(find_top_level("(a?1:2):3", b':', true), Some(7));
        assert_eq!(find_top_level("abc", b'/', false), None);
    }
}
