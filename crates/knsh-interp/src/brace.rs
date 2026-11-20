//! Brace expansion (KNSH-098; NFR-COMPAT-02): the first expansion bash applies to a word, before tilde, parameter
//! and arithmetic expansion. A port of bash 5.2's `braces.c`.
//!
//! Bash brace-expands the text of the word as written, where quotes, escapes and `${…}` are skipped as wholes. So
//! does this module: a word is a sequence of unquoted literal characters (which braces act on) and opaque pieces
//! (quotes, escapes, expansions), each piece keeping the text it was written as, since bash's rules look at that
//! text in three places: whether a `{` stands between blanks, whether the text inside the braces holds a comma
//! anywhere, and whether it is a sequence expression (`{1..3}` is one, `{1..$n}` and `{'1'..3}` are not).
//!
//! - `{a,b}`: one word per comma-separated element, each brace-expanded again; the text before and after is added
//!   to each (`x{a,b}y` is `xay xby`), and later braces multiply (`{a,b}{1,2}` is four words).
//! - `{x..y}` and `{x..y..step}`: integers (zero-padded to the widest end written with a leading zero) or single
//!   letters, upwards or downwards; the step's sign is ignored and 0 means 1.
//! - Anything else (`{}`, `{a}`, a `{` with no matching `}`, an invalid sequence) is left as written.
//!
//! The words produced and their total size are bounded ([`MAX_WORDS`], [`MAX_BYTES`]) and so is the work spent
//! looking for braces ([`MAX_SCAN`]): past a limit the word fails with [`InterpError::ExpansionLimit`] rather than
//! exhausting memory or time on untrusted input. Braces nested deeper than
//! [`MAX_EXPANSION_DEPTH`](crate::expand::MAX_EXPANSION_DEPTH) fail with [`InterpError::DepthExceeded`].

use knsh_bash::Span;

use crate::error::{InterpError, Unsupported};
use crate::expand::MAX_EXPANSION_DEPTH;
use crate::scan::Part;
use crate::word::Piece;

/// Most words one word may brace-expand into.
pub const MAX_WORDS: usize = 1 << 20;

/// Most characters the words one word brace-expands into may hold together (64 Mi).
pub const MAX_BYTES: usize = 64 << 20;

/// Most characters examined while looking for braces in one word, a bound on the quadratic worst case of bash's
/// search (each candidate `{` is followed to the end of the word).
pub const MAX_SCAN: usize = 1 << 26;

/// One unit of a word being brace-expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    /// An unquoted literal character.
    Char(char),
    /// An opaque piece, by index.
    Piece(usize),
}

/// The words `pieces` (a word spanning `span`) brace-expand into, each as parts ready for the other expansions. A
/// word without a brace expansion comes back as its single word, unchanged.
///
/// Bash reads each word brace expansion produces afresh, so pieces brought together can form a parameter: `$a{1,2}`
/// is `$a1 $a2`, and `x{$,y}z` holds `x$z`. Those are read as bash reads them. One that would form `${…}`, `$(…)`
/// or `$[…]` out of separate pieces is refused ([`Unsupported::BraceBuiltExpansion`]).
///
/// # Errors
///
/// [`InterpError::ExpansionLimit`] past [`MAX_WORDS`], [`MAX_BYTES`] or [`MAX_SCAN`]; [`InterpError::DepthExceeded`]
/// for braces nested deeper than [`MAX_EXPANSION_DEPTH`]; [`InterpError::Unsupported`] as above.
pub(crate) fn expand(pieces: &[Piece], span: Span) -> Result<Vec<Vec<Part>>, InterpError> {
    let parts = || pieces.iter().map(|piece| piece.part.clone()).collect::<Vec<_>>();
    // Only literal text can hold a brace expansion, and it needs both braces.
    let literal_has = |brace: char| {
        pieces
            .iter()
            .any(|piece| matches!(&piece.part, Part::Text(text) if text.contains(brace)))
    };
    if !literal_has('{') || !literal_has('}') {
        return Ok(vec![parts()]);
    }
    let mut toks = Vec::new();
    for (index, piece) in pieces.iter().enumerate() {
        match &piece.part {
            Part::Text(text) => toks.extend(text.chars().map(Tok::Char)),
            Part::Quoted(_) | Part::Double(_) | Part::Param { .. } | Part::Brace { .. } | Part::Arith { .. } => {
                toks.push(Tok::Piece(index));
            }
        }
    }
    let mut expander = Braces { pieces, scanned: 0 };
    let words = expander.expand(&toks, 0)?;
    words.iter().map(|word| assemble(word, pieces, span)).collect()
}

/// The parts of a brace-expanded word, read again as bash reads it: runs of literal characters joined into text, a
/// `$` in that text starting the parameter it now spells, and a variable name continued by the text after it.
fn assemble(word: &[Tok], pieces: &[Piece], span: Span) -> Result<Vec<Part>, InterpError> {
    let mut out = Vec::new();
    let mut text = String::new();
    for tok in word {
        match *tok {
            Tok::Char(ch) => text.push(ch),
            Tok::Piece(index) => {
                reread(&std::mem::take(&mut text), span, &mut out)?;
                if let Some(piece) = pieces.get(index) {
                    out.push(piece.part.clone());
                }
            }
        }
    }
    reread(&text, span, &mut out)?;
    Ok(out)
}

/// Appends literal `text` to `out` as bash would read it: a variable name before it (`$a` then `1`) takes the name
/// characters it starts with, and each `$` followed by a name, a digit or a special parameter is that parameter.
/// In a word as the parser wrote it neither can happen (the lexer would have read them), so only brace expansion
/// brings them about.
fn reread(text: &str, span: Span, out: &mut Vec<Part>) -> Result<(), InterpError> {
    if text.is_empty() {
        return Ok(());
    }
    let mut rest = text;
    if let Some(Part::Param { name, .. }) = out.last_mut()
        && name.starts_with(is_name_start)
    {
        let len = rest.find(|ch: char| !is_name_char(ch)).unwrap_or(rest.len());
        name.push_str(&rest[..len]);
        rest = &rest[len..];
    }
    let mut literal = String::new();
    let mut chars = rest.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let next = chars.peek().map(|&(_, next)| next);
        if ch != '$' || next.is_none() {
            literal.push(ch);
            continue;
        }
        let after = &rest[at + 1..];
        let name_len = match next {
            Some(first) if is_name_start(first) => after.find(|c: char| !is_name_char(c)).unwrap_or(after.len()),
            Some('0'..='9' | '@' | '*' | '#' | '?' | '-' | '$' | '!') => 1,
            Some('{' | '(' | '[') => {
                return Err(InterpError::Unsupported {
                    feature: Unsupported::BraceBuiltExpansion,
                    span,
                });
            }
            Some(_) | None => {
                literal.push(ch);
                continue;
            }
        };
        if !literal.is_empty() {
            out.push(Part::Text(std::mem::take(&mut literal)));
        }
        out.push(Part::Param {
            name: after[..name_len].to_owned(),
            span,
        });
        for _ in 0..after[..name_len].chars().count() {
            chars.next();
        }
    }
    if !literal.is_empty() {
        out.push(Part::Text(literal));
    }
    Ok(())
}

fn is_name_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// The expansion of one word.
struct Braces<'a> {
    pieces: &'a [Piece],
    /// Characters examined so far, against [`MAX_SCAN`].
    scanned: usize,
}

/// Bash's `brace_whitespace`.
fn is_blank(ch: Option<char>) -> bool {
    matches!(ch, Some(' ' | '\t' | '\n'))
}

impl Braces<'_> {
    fn limit(what: &'static str, limit: usize) -> InterpError {
        InterpError::ExpansionLimit { what, limit }
    }

    /// The last character `tok` was written with.
    fn last_char(&self, tok: Tok) -> Option<char> {
        match tok {
            Tok::Char(ch) => Some(ch),
            Tok::Piece(index) => self.pieces.get(index)?.raw.chars().next_back(),
        }
    }

    /// The first character `tok` was written with.
    fn first_char(&self, tok: Tok) -> Option<char> {
        match tok {
            Tok::Char(ch) => Some(ch),
            Tok::Piece(index) => self.pieces.get(index)?.raw.chars().next(),
        }
    }

    /// The text `toks` were written as.
    fn raw(&self, toks: &[Tok]) -> String {
        let mut out = String::new();
        for tok in toks {
            match *tok {
                Tok::Char(ch) => out.push(ch),
                Tok::Piece(index) => {
                    if let Some(piece) = self.pieces.get(index) {
                        out.push_str(&piece.raw);
                    }
                }
            }
        }
        out
    }

    /// Bash's `brace_gobbler`: from `from`, the index of the first unquoted `satisfy` at the top level, or `None`.
    /// Looking for `}`, one is accepted only after a top-level `,` or `..` (not right before the `}`); looking for
    /// `{`, one standing between blanks (or before a `}`) is skipped.
    fn gobble(&mut self, toks: &[Tok], from: usize, satisfy: char) -> Result<Option<usize>, InterpError> {
        let mut level = 0_usize;
        let mut commas = usize::from(satisfy != '}');
        let mut i = from;
        while let Some(&tok) = toks.get(i) {
            self.scanned += 1;
            if self.scanned > MAX_SCAN {
                return Err(Self::limit("brace expansion scan", MAX_SCAN));
            }
            let Tok::Char(ch) = tok else {
                i += 1;
                continue;
            };
            if ch == satisfy && level == 0 && commas > 0 {
                let before = if i == 0 { None } else { self.last_char(toks[i - 1]) };
                let after = toks.get(i + 1).and_then(|&next| self.first_char(next));
                let blank_before = i == 0 || is_blank(before);
                if ch == '{' && blank_before && (is_blank(after) || toks.get(i + 1) == Some(&Tok::Char('}'))) {
                    i += 1;
                    continue;
                }
                return Ok(Some(i));
            }
            if ch == '{' {
                level += 1;
            } else if ch == '}' && level > 0 {
                level -= 1;
            } else if satisfy == '}' && level == 0 {
                let sequence = ch == '.'
                    && toks.get(i + 1) == Some(&Tok::Char('.'))
                    && toks.get(i + 2) != Some(&Tok::Char(satisfy));
                if ch == ',' || sequence {
                    commas += 1;
                }
            }
            i += 1;
        }
        Ok(None)
    }

    /// Bash's `brace_expand`, with the text after each expansion handled in a loop rather than by recursion.
    fn expand(&mut self, toks: &[Tok], depth: usize) -> Result<Vec<Vec<Tok>>, InterpError> {
        if depth > MAX_EXPANSION_DEPTH {
            return Err(InterpError::DepthExceeded {
                limit: MAX_EXPANSION_DEPTH,
            });
        }
        let mut result: Vec<Vec<Tok>> = vec![Vec::new()];
        let mut rest = toks;
        loop {
            let Some((open, close)) = self.find(rest)? else {
                append(&mut result, &[rest.to_vec()])?;
                return Ok(result);
            };
            let amble = &rest[open + 1..close];
            let postamble = &rest[close + 1..];
            let tack = if self.raw_has_comma(amble) {
                self.amble(amble, depth)?
            } else if let Some(sequence) = sequence(&self.raw(amble))? {
                sequence
            } else if !postamble.is_empty() {
                // An invalid sequence stays as written, braces included; the rest may still expand.
                vec![rest[open..=close].to_vec()]
            } else {
                append(&mut result, &[rest.to_vec()])?;
                return Ok(result);
            };
            append(&mut result, &[rest[..open].to_vec()])?;
            append(&mut result, &tack)?;
            rest = postamble;
            if rest.is_empty() {
                return Ok(result);
            }
        }
    }

    /// The first `{` that starts a brace expansion and its matching `}`.
    fn find(&mut self, toks: &[Tok]) -> Result<Option<(usize, usize)>, InterpError> {
        let mut from = 0;
        loop {
            let Some(open) = self.gobble(toks, from, '{')? else {
                return Ok(None);
            };
            if let Some(close) = self.gobble(toks, open + 1, '}')? {
                return Ok(Some((open, close)));
            }
            from = open + 1;
        }
    }

    /// Whether the text inside the braces holds a `,` not escaped by a backslash, anywhere (bash's test, which looks
    /// inside quotes too).
    fn raw_has_comma(&self, amble: &[Tok]) -> bool {
        let raw = self.raw(amble);
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    chars.next();
                }
                ',' => return true,
                _ => {}
            }
        }
        false
    }

    /// Bash's `expand_amble`: each top-level comma-separated element of `amble`, brace-expanded, one after another.
    fn amble(&mut self, amble: &[Tok], depth: usize) -> Result<Vec<Vec<Tok>>, InterpError> {
        let mut out: Vec<Vec<Tok>> = Vec::new();
        // Characters held by `out`: each element is bounded on its own, and so must be all of them together.
        let mut size = 0_usize;
        let mut start = 0;
        loop {
            let end = self.gobble(amble, start, ',')?;
            let element = &amble[start..end.unwrap_or(amble.len())];
            let words = self.expand(element, depth + 1)?;
            if out.len().saturating_add(words.len()) > MAX_WORDS {
                return Err(Self::limit("brace expansion words", MAX_WORDS));
            }
            size = words.iter().fold(size, |sum, word| sum.saturating_add(word.len()));
            if size > MAX_BYTES {
                return Err(Self::limit("brace expansion size", MAX_BYTES));
            }
            out.extend(words);
            match end {
                Some(comma) => start = comma + 1,
                None => return Ok(out),
            }
        }
    }
}

/// `result` with each of its words followed by each of `tack` in turn (bash's `array_concat`), within the limits.
fn append(result: &mut Vec<Vec<Tok>>, tack: &[Vec<Tok>]) -> Result<(), InterpError> {
    // The size of the product, checked before anything is allocated (CLAUDE.md "Untrusted input"): each word of
    // `result` appears once per tail, and each tail once per word.
    let result_size = result.iter().fold(0_usize, |sum, word| sum.saturating_add(word.len()));
    let tack_size = tack.iter().fold(0_usize, |sum, tail| sum.saturating_add(tail.len()));
    let size = result_size
        .saturating_mul(tack.len())
        .saturating_add(tack_size.saturating_mul(result.len()));
    if size > MAX_BYTES {
        return Err(InterpError::ExpansionLimit {
            what: "brace expansion size",
            limit: MAX_BYTES,
        });
    }
    if tack.len() == 1 {
        for word in result.iter_mut() {
            word.extend_from_slice(&tack[0]);
        }
    } else {
        let count = result.len().saturating_mul(tack.len());
        if count > MAX_WORDS {
            return Err(InterpError::ExpansionLimit {
                what: "brace expansion words",
                limit: MAX_WORDS,
            });
        }
        let mut product = Vec::with_capacity(count);
        for word in result.iter() {
            for tail in tack {
                let mut joined = Vec::with_capacity(word.len() + tail.len());
                joined.extend_from_slice(word);
                joined.extend_from_slice(tail);
                product.push(joined);
            }
        }
        *result = product;
    }
    Ok(())
}

/// What a side of a sequence expression is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Term {
    Int(i64),
    Letter(char),
}

/// Bash's `expand_seqterm`: the words of the sequence expression `text` (`x..y` or `x..y..step`), or `None` when it
/// is not one.
///
/// # Errors
///
/// [`InterpError::ExpansionLimit`] when the sequence would have more than [`MAX_WORDS`] words.
fn sequence(text: &str) -> Result<Option<Vec<Vec<Tok>>>, InterpError> {
    let Some(dots) = text.find("..") else {
        return Ok(None);
    };
    let (lhs, rhs) = (&text[..dots], &text[dots + 2..]);
    if lhs.is_empty() || rhs.is_empty() {
        return Ok(None);
    }
    let left = match legal_number(lhs) {
        Some(value) => Term::Int(value),
        None => match single_letter(lhs) {
            Some(letter) => Term::Letter(letter),
            None => return Ok(None),
        },
    };
    // The right side: a number or a letter, then optionally `..` and an integer step.
    let (right, right_len, after) = if rhs.starts_with(|ch: char| ch.is_ascii_digit())
        || (rhs.starts_with(['+', '-']) && rhs[1..].starts_with(|ch: char| ch.is_ascii_digit()))
    {
        let len = rhs
            .char_indices()
            .skip(1)
            .find(|(_, ch)| !ch.is_ascii_digit())
            .map_or(rhs.len(), |(at, _)| at);
        let Ok(value) = rhs[..len].parse::<i64>() else {
            return Ok(None);
        };
        (Term::Int(value), len, &rhs[len..])
    } else if let Some(letter) = rhs.chars().next().filter(char::is_ascii_alphabetic) {
        (Term::Letter(letter), 1, &rhs[1..])
    } else {
        return Ok(None);
    };
    let step = if after.is_empty() {
        1
    } else {
        // `..` and a step as `strtoimax` reads one: blanks, a sign, digits, and nothing after.
        let Some(step) = after.strip_prefix("..").filter(|step| !step.is_empty()) else {
            return Ok(None);
        };
        match strtoimax(step) {
            Some(step) => step,
            None => return Ok(None),
        }
    };
    let words = match (left, right) {
        (Term::Int(start), Term::Int(end)) => {
            let width = pad_width(lhs, &rhs[..right_len]);
            seq(start, end, step, |n| match width {
                // Bash formats with `%0*d` of an `int`.
                Some(width) => format!("{:0width$}", truncate_to_int(n)),
                None => n.to_string(),
            })?
        }
        (Term::Letter(start), Term::Letter(end)) => {
            seq(i64::from(u32::from(start)), i64::from(u32::from(end)), step, |n| {
                u32::try_from(n)
                    .ok()
                    .and_then(char::from_u32)
                    .map(String::from)
                    .unwrap_or_default()
            })?
        }
        (Term::Int(_), Term::Letter(_)) | (Term::Letter(_), Term::Int(_)) => return Ok(None),
    };
    Ok(words.map(|words| {
        words
            .into_iter()
            .map(|word| word.chars().map(Tok::Char).collect())
            .collect()
    }))
}

/// Bash's `legal_number`: optional blanks, an optional sign, decimal digits, optional blanks, nothing else, within
/// 64 bits.
fn legal_number(text: &str) -> Option<i64> {
    let trimmed = text.trim_matches([' ', '\t', '\n']);
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse().ok()
}

/// A single ASCII letter.
fn single_letter(text: &str) -> Option<char> {
    let mut chars = text.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    chars.next().is_none().then_some(letter)
}

/// `strtoimax` of a whole step: leading blanks, a sign, digits, and nothing after; `None` otherwise or on overflow.
fn strtoimax(text: &str) -> Option<i64> {
    let trimmed = text.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        // `strtoimax` reads no digits as 0 with the rest left over, which bash rejects unless nothing is left.
        return None;
    }
    trimmed.parse().ok()
}

/// The width integers are zero-padded to: the length of either end written with a leading zero (after a `-`), the
/// widest of the two when one is; `None` without padding.
fn pad_width(lhs: &str, rhs: &str) -> Option<usize> {
    let padded = |side: &str| (side.len() > 1 && side.starts_with('0')) || (side.len() > 2 && side.starts_with("-0"));
    (padded(lhs) || padded(rhs)).then(|| lhs.len().max(rhs.len()))
}

/// `n` as the `int` bash formats a padded term as (it truncates).
fn truncate_to_int(n: i64) -> i32 {
    // Truncation is bash's behaviour here: `arg = n` assigns an `intmax_t` to an `int`.
    #[allow(clippy::cast_possible_truncation)]
    let truncated = n as i32;
    truncated
}

/// Bash's `mkseq`: from `start` towards `end` by `step` (its sign set by the direction, 0 read as 1), each value
/// formatted by `format`; `None` when bash refuses the range (its length overflows).
///
/// # Errors
///
/// [`InterpError::ExpansionLimit`] past [`MAX_WORDS`] words.
fn seq(start: i64, end: i64, step: i64, format: impl Fn(i64) -> String) -> Result<Option<Vec<String>>, InterpError> {
    let step = if step == 0 { 1 } else { step };
    let step = if (start > end && step > 0) || (start < end && step < 0) {
        step.checked_neg().unwrap_or(i64::MAX)
    } else {
        step
    };
    let Some(span) = end.checked_sub(start).map(i64::unsigned_abs) else {
        return Ok(None);
    };
    let count = span / step.unsigned_abs() + 1;
    if count > u64::try_from(MAX_WORDS).unwrap_or(u64::MAX) {
        return Err(InterpError::ExpansionLimit {
            what: "brace expansion words",
            limit: MAX_WORDS,
        });
    }
    let mut out = Vec::new();
    let mut n = start;
    loop {
        out.push(format(n));
        let Some(next) = n.checked_add(step) else {
            break;
        };
        n = next;
        if (step < 0 && n < end) || (step > 0 && n > end) {
            break;
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use knsh_bash::{Command, parse};

    use super::*;
    use crate::word;

    /// The words the single word of `echo <word>` brace-expands into, as they would print after quote removal of
    /// literal text (quoted pieces shown as written, to see what stayed opaque).
    fn braces(text: &str) -> Vec<String> {
        try_braces(text).unwrap_or_else(|error| panic!("{text}: {error:?}"))
    }

    fn try_braces(text: &str) -> Result<Vec<String>, InterpError> {
        let line = format!("echo {text}");
        let script = parse(&line).unwrap_or_else(|e| panic!("{line}: {e:?}"));
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!("not a simple command");
        };
        let pieces = word::pieces(&simple.words[1].word.segments, &line, 0)?;
        let raw: Vec<String> = pieces.iter().map(|piece| piece.raw.clone()).collect();
        Ok(expand(&pieces, simple.words[1].span)?
            .into_iter()
            .map(|parts| {
                parts
                    .iter()
                    .map(|part| match part {
                        Part::Text(text) => text.clone(),
                        Part::Param { name, .. } if !pieces.iter().any(|piece| &piece.part == part) => {
                            format!("${name}")
                        }
                        other => pieces
                            .iter()
                            .zip(&raw)
                            .find(|(piece, _)| &piece.part == other)
                            .map(|(_, raw)| raw.clone())
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .collect())
    }

    // Every expected value below is bash 5.2's output.
    #[test]
    fn brace_lists_expand_with_preamble_and_postamble() {
        let cases: &[(&str, &[&str])] = &[
            ("{a,b,c}", &["a", "b", "c"]),
            ("x{a,b}y", &["xay", "xby"]),
            ("{a,b}{1,2}", &["a1", "a2", "b1", "b2"]),
            ("{a,{b,c}d}e", &["ae", "bde", "cde"]),
            ("{,a}", &["", "a"]),
            ("{a,}", &["a", ""]),
            ("{a}", &["{a}"]),
            ("{}", &["{}"]),
            ("{", &["{"]),
            ("a}", &["a}"]),
            ("{a,b", &["{a,b"]),
            ("{a}{b,c}", &["{a}b", "{a}c"]),
            ("{}{a,b}", &["{}a", "{}b"]),
            ("'{a,b}'", &["'{a,b}'"]),
            (r"\{a,b}", &[r"\{a,b}"]),
            (r"{a\,b}", &[r"{a\,b}"]),
            ("{'a,b',c}", &["'a,b'", "c"]),
            ("{$x,b}", &["$x", "b"]),
            ("${x}{a,b}", &["${x}a", "${x}b"]),
            ("a={b,c}", &["a=b", "a=c"]),
            ("{a,b}{", &["a{", "b{"]),
        ];
        for (text, expected) in cases {
            assert_eq!(braces(text), *expected, "{text}");
        }
    }

    // KNSH-098 unit test named by the story.
    #[test]
    fn brace_sequence_with_step_and_padding() {
        let cases: &[(&str, &[&str])] = &[
            ("{1..5}", &["1", "2", "3", "4", "5"]),
            ("{5..1}", &["5", "4", "3", "2", "1"]),
            ("{1..10..3}", &["1", "4", "7", "10"]),
            ("{10..1..3}", &["10", "7", "4", "1"]),
            ("{1..10..-3}", &["1", "4", "7", "10"]),
            ("{1..3..0}", &["1", "2", "3"]),
            ("{3..3}", &["3"]),
            ("{-2..2}", &["-2", "-1", "0", "1", "2"]),
            ("{01..03}", &["01", "02", "03"]),
            ("{1..010..4}", &["001", "005", "009"]),
            ("{8..010}", &["008", "009", "010"]),
            ("{-05..3..4}", &["-05", "-01", "003"]),
            ("{a..e}", &["a", "b", "c", "d", "e"]),
            ("{e..a..2}", &["e", "c", "a"]),
            // The characters between the letters, `\\` included, as `braces.c` produces them (bash 3.2 then removes
            // that backslash as a quote; checking bash 5.2 is pending, KNSH-109).
            ("{Y..b}", &["Y", "Z", "[", "\\", "]", "^", "_", "`", "a", "b"]),
            ("x{1..2}y{a..b}", &["x1ya", "x1yb", "x2ya", "x2yb"]),
        ];
        for (text, expected) in cases {
            assert_eq!(braces(text), *expected, "{text}");
        }
        // Not sequences: left as written.
        for text in [
            "{1..}",
            "{..3}",
            "{1..a}",
            "{a..3}",
            "{ab..c}",
            "{1..3..}",
            "{1..3..x}",
            "{1...3}",
            "{1..$n}",
        ] {
            assert_eq!(braces(text), [text], "{text}");
        }
        // An invalid sequence followed by more text: kept, and the rest still expands.
        assert_eq!(braces("{1..a}{x,y}"), ["{1..a}x", "{1..a}y"]);
        // A comma anywhere inside makes it a list, even inside quotes (bash's test).
        assert_eq!(braces("{1..3,x}"), ["1..3", "x"]);
    }

    // Bash reads each produced word again: pieces brought together form the parameter they now spell.
    #[test]
    fn produced_words_are_read_again() {
        assert_eq!(braces("$a{1,2}"), ["$a1", "$a2"]);
        assert_eq!(braces("x{$,y}z"), ["x$z", "xyz"]);
        assert_eq!(braces("{$,y}1"), ["$1", "y1"]);
        assert_eq!(braces("$1{0,1}"), ["$10", "$11"]);
        assert_eq!(braces("{a,$}"), ["a", "$"]);
        // A word whose pieces would form `${…}` is refused rather than read differently.
        assert!(matches!(
            try_braces("{$,}{a}"),
            Err(InterpError::Unsupported {
                feature: Unsupported::BraceBuiltExpansion,
                ..
            })
        ));
        let line = "echo $a{1,2}";
        let script = parse(line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!()
        };
        let pieces = word::pieces(&simple.words[1].word.segments, line, 0).unwrap();
        let words = expand(&pieces, simple.words[1].span).unwrap();
        assert!(matches!(&words[0][..], [Part::Param { name, .. }] if name == "a1"));
        let pieces = word::pieces(&parse_word("$1{0,1}"), "echo $1{0,1}", 0).unwrap();
        let words = expand(&pieces, Span::new(5, 12)).unwrap();
        assert!(matches!(&words[0][..], [Part::Param { name, .. }, Part::Text(text)] if name == "1" && text == "0"));
    }

    fn parse_word(text: &str) -> Vec<knsh_bash::Segment> {
        let line = format!("echo {text}");
        let script = parse(&line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!()
        };
        simple.words[1].word.segments.clone()
    }

    // CLAUDE.md "Untrusted input": the size of the result is bounded.
    #[test]
    fn huge_expansions_fail_with_a_limit() {
        assert!(matches!(
            try_braces("{1..9999999999}"),
            Err(InterpError::ExpansionLimit { .. })
        ));
        let product = "{a,b}".repeat(21);
        assert!(matches!(try_braces(&product), Err(InterpError::ExpansionLimit { .. })));
        assert_eq!(braces(&"{a,b}".repeat(3)).len(), 8);
        // The size is checked before the words are built: a million words then a long tail would otherwise hold
        // gigabytes before the check.
        let tail = "{a,b}".repeat(20) + &"x".repeat(100);
        assert!(matches!(
            try_braces(&tail),
            Err(InterpError::ExpansionLimit {
                what: "brace expansion size",
                ..
            })
        ));
        // The elements of a list are bounded together, not only one by one.
        let element = "{a,b}".repeat(12) + &"y".repeat(1_000);
        let list = format!("{{{}}}", vec![element; 20].join(","));
        assert!(matches!(
            try_braces(&list),
            Err(InterpError::ExpansionLimit {
                what: "brace expansion size",
                ..
            })
        ));
        // Many braces that never expand finish quickly.
        let opens = "{".repeat(3_000) + "}";
        assert!(matches!(
            try_braces(&opens),
            Ok(_) | Err(InterpError::ExpansionLimit { .. })
        ));
    }
}
