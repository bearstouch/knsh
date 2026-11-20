//! Words as the expansion engine reads them (KNSH-096, KNSH-097, KNSH-098): the parser's segments turned into
//! [`Part`]s (with their source text, which brace expansion reads), and the characters an expansion produces
//! ([`WordChar`]).

use knsh_bash::{Segment, SegmentKind, Span};

use crate::error::{InterpError, Unsupported};
use crate::expand::decode_ansi_c;
use crate::scan::Part;
use crate::state::is_name;

/// One character of a word after expansion, with what bash needs to know about it later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WordChar {
    /// The character.
    pub(crate) ch: char,
    /// Whether it was quoted (inside quotes, escaped by a backslash, or the result of an expansion inside double
    /// quotes). Patterns need the difference: a quoted `*` matches only itself.
    pub(crate) quoted: bool,
    /// Whether it came from an expansion: bash splits the unquoted ones on `IFS`, never the literal text.
    pub(crate) expanded: bool,
}

/// Where a word is read, which decides the expansions bash applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Context {
    /// A command word or a `for` item: every expansion, then word splitting and pathname expansion.
    Argument,
    /// A `case` subject or a `for` variable: no splitting, no pathname expansion.
    Plain,
    /// A `case` pattern: as [`Context::Plain`]; the unquoted characters are pattern characters.
    Pattern,
}

/// One top-level piece of a word: its part, and the text it was written as, which brace expansion reads as bash
/// does (bash brace-expands the word's text before anything else).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Piece {
    /// What it is.
    pub(crate) part: Part,
    /// How it was written.
    pub(crate) raw: String,
}

/// The parts of a word made of `segments`, skipping text before `from` (the name and `=` of an assignment, which
/// share its first literal segment).
///
/// # Errors
///
/// As [`pieces`].
pub(crate) fn parts(segments: &[Segment], source: &str, from: usize) -> Result<Vec<Part>, InterpError> {
    Ok(pieces(segments, source, from)?
        .into_iter()
        .map(|piece| piece.part)
        .collect())
}

/// The pieces of a word made of `segments`, skipping text before `from`. Line continuations are dropped, as bash
/// removes them before reading the line.
///
/// # Errors
///
/// [`InterpError::Unsupported`] for a command or process substitution; [`InterpError::SourceMismatch`] if a span
/// does not index `source`.
pub(crate) fn pieces(segments: &[Segment], source: &str, from: usize) -> Result<Vec<Piece>, InterpError> {
    let mut out = Vec::new();
    for segment in segments.iter().filter(|segment| segment.span.end > from) {
        let span = Span::new(segment.span.start.max(from), segment.span.end);
        let Some(part) = segment_part(segment, source, from)? else {
            continue;
        };
        out.push(Piece {
            part,
            raw: text(span, source)?.to_owned(),
        });
    }
    Ok(out)
}

/// The part one segment is, or `None` for a line continuation.
fn segment_part(segment: &Segment, source: &str, from: usize) -> Result<Option<Part>, InterpError> {
    let refuse = |feature| {
        Err(InterpError::Unsupported {
            feature,
            span: segment.span,
        })
    };
    Ok(Some(match &segment.kind {
        SegmentKind::Literal => {
            let span = Span::new(segment.span.start.max(from), segment.span.end);
            Part::Text(text(span, source)?.to_owned())
        }
        SegmentKind::Escape => match text(segment.body, source)? {
            // A backslash at the very end of the input quotes nothing and stays, as in bash.
            "" => Part::Quoted("\\".to_owned()),
            escaped => Part::Quoted(escaped.to_owned()),
        },
        SegmentKind::LineContinuation => return Ok(None),
        SegmentKind::SingleQuoted => Part::Quoted(text(segment.body, source)?.to_owned()),
        // In the C locale `$"…"` is plain double quoting; translation catalogues are not supported by design.
        SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => {
            Part::Double(quoted_parts(parts(inner, source, from)?))
        }
        SegmentKind::AnsiC => Part::Quoted(decode_ansi_c(text(segment.body, source)?)),
        SegmentKind::Parameter => Part::Param {
            name: text(segment.body, source)?.to_owned(),
            span: segment.span,
        },
        SegmentKind::ParameterExpansion => Part::Brace {
            body: segment.body,
            span: segment.span,
        },
        SegmentKind::Arithmetic => Part::Arith {
            body: segment.body,
            span: segment.span,
        },
        SegmentKind::CommandSubstitution | SegmentKind::Backtick => {
            return refuse(Unsupported::CommandSubstitution);
        }
        SegmentKind::InputProcessSubstitution | SegmentKind::OutputProcessSubstitution => {
            return refuse(Unsupported::ProcessSubstitution);
        }
    }))
}

/// Inside double quotes, literal text is quoted.
fn quoted_parts(parts: Vec<Part>) -> Vec<Part> {
    parts
        .into_iter()
        .map(|part| match part {
            Part::Text(text) => Part::Quoted(text),
            other @ (Part::Quoted(_)
            | Part::Double(_)
            | Part::Param { .. }
            | Part::Brace { .. }
            | Part::Arith { .. }) => other,
        })
        .collect()
}

/// The text `span` indexes in `source`.
pub(crate) fn text(span: Span, source: &str) -> Result<&str, InterpError> {
    span.text(source).ok_or(InterpError::SourceMismatch { span })
}

/// The word `parts` spell when they hold no expansion at all, after quote removal.
pub(crate) fn literal(parts: &[Part]) -> Option<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Text(text) | Part::Quoted(text) => out.push_str(text),
            Part::Double(inner) => out.push_str(&literal(inner)?),
            Part::Param { .. } | Part::Brace { .. } | Part::Arith { .. } => return None,
        }
    }
    Some(out)
}

/// Where the value starts in unquoted text spelled like an assignment (`NAME=…` or `NAME+=…`), which bash outside
/// posix mode treats as one for tilde expansion wherever the word appears; `None` for any other text.
pub(crate) fn assignment_value_start(text: &str) -> Option<usize> {
    let equals = text.find('=')?;
    let name = text.get(..equals)?;
    let name = name.strip_suffix('+').unwrap_or(name);
    is_name(name).then_some(equals + 1)
}

#[cfg(test)]
mod tests {
    use knsh_bash::{Command, CommandWord, parse};

    use super::*;

    /// The words of the single simple command `line`.
    fn words(line: &str) -> Vec<CommandWord> {
        let script = parse(line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!("not a simple command: {line}");
        };
        simple.words.clone()
    }

    fn word_parts(line: &str, index: usize) -> Result<Vec<Part>, InterpError> {
        parts(&words(line)[index].word.segments, line, 0)
    }

    fn refused(line: &str, index: usize) -> Unsupported {
        match word_parts(line, index) {
            Err(InterpError::Unsupported { feature, .. }) => feature,
            other => panic!("{line}: {other:?}"),
        }
    }

    #[test]
    fn reads_quotes_escapes_and_line_continuations() {
        let line = r#"echo 'a b' "c\"d" e\ f g\
h "" $"loc""#;
        let literals: Vec<_> = (1..7)
            .map(|i| literal(&word_parts(line, i).unwrap()).unwrap())
            .collect();
        assert_eq!(literals, ["a b", "c\"d", "e f", "gh", "", "loc"]);
        assert_eq!(literal(&word_parts(r#"echo "a\b""#, 1).unwrap()).unwrap(), r"a\b");
    }

    #[test]
    fn expansions_become_parts() {
        let line = r#"echo a$x"${y}$((1))""#;
        let found = word_parts(line, 1).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(found[0], Part::Text("a".into()));
        assert!(matches!(&found[1], Part::Param { name, .. } if name == "x"));
        let Part::Double(inner) = &found[2] else {
            panic!("{found:?}")
        };
        assert!(matches!(inner[0], Part::Brace { .. }));
        assert!(matches!(inner[1], Part::Arith { .. }));
        assert_eq!(literal(&found), None);
    }

    #[test]
    fn refuses_substitutions_and_ansi_c_quotes() {
        assert_eq!(refused("echo $(ls)", 1), Unsupported::CommandSubstitution);
        assert_eq!(refused("echo `ls`", 1), Unsupported::CommandSubstitution);
        assert_eq!(refused(r#"echo "$(ls)""#, 1), Unsupported::CommandSubstitution);
        assert_eq!(refused("cat <(ls)", 1), Unsupported::ProcessSubstitution);
    }

    // KNSH-098: `$'…'` is quoted text with its escapes decoded, cut at a NUL as bash keeps strings.
    #[test]
    fn ansi_c_quotes_decode_their_escapes() {
        let decoded = |line: &str| literal(&word_parts(line, 1).unwrap()).unwrap();
        assert_eq!(decoded(r"echo $'a\tb\n'"), "a\tb\n");
        assert_eq!(decoded(r"echo $'it\'s'"), "it's");
        assert_eq!(decoded(r"echo $'\x41\101\u00e9'"), "AAé");
        assert_eq!(decoded(r"echo $'a\0b'"), "a");
        assert_eq!(decoded(r"echo $'\c?\cA'"), "\x7f\x01");
        assert_eq!(word_parts(r"echo $'*'", 1).unwrap(), [Part::Quoted("*".into())]);
    }

    // Brace expansion reads the text each piece was written as.
    #[test]
    fn pieces_keep_their_source_text() {
        let line = r#"echo a\,'b'"c$x"${y}$((1))"#;
        let found = pieces(&words(line)[1].word.segments, line, 0).unwrap();
        let raw: Vec<&str> = found.iter().map(|piece| piece.raw.as_str()).collect();
        assert_eq!(raw, ["a", "\\,", "'b'", "\"c$x\"", "${y}", "$((1))"]);
    }

    #[test]
    fn assignment_shaped_text() {
        assert_eq!(assignment_value_start("a=~"), Some(2));
        assert_eq!(assignment_value_start("_b+=x"), Some(4));
        assert_eq!(assignment_value_start("1a=~"), None);
        assert_eq!(assignment_value_start("host:~"), None);
        assert_eq!(assignment_value_start("=x"), None);
    }

    #[test]
    fn a_span_outside_the_source_is_a_mismatch() {
        let word = &words("echo hello")[1];
        assert!(matches!(
            parts(&word.word.segments, "echo", 0),
            Err(InterpError::SourceMismatch { .. })
        ));
    }
}
