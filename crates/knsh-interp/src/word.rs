//! Words as the expansion engine reads them (KNSH-096, KNSH-097, KNSH-098): the parser's segments turned into
//! [`Part`]s (with their source text, which brace expansion reads), and the characters an expansion produces
//! ([`WordChar`]).

use knsh_bash::{Segment, SegmentKind, Span};

use knsh_bash::HereDocument;

use crate::error::InterpError;
use crate::expand::decode_ansi_c;
use crate::scan::{Part, Subst, SubstKind};
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
/// [`InterpError::SourceMismatch`] if a span does not index `source`.
pub(crate) fn pieces(segments: &[Segment], source: &str, from: usize) -> Result<Vec<Piece>, InterpError> {
    pieces_in(segments, source, from, false)
}

/// [`pieces`], inside double quotes when `in_double_quotes` (which changes how a backtick body is un-escaped).
fn pieces_in(
    segments: &[Segment],
    source: &str,
    from: usize,
    in_double_quotes: bool,
) -> Result<Vec<Piece>, InterpError> {
    let mut out = Vec::new();
    for segment in segments.iter().filter(|segment| segment.span.end > from) {
        let span = Span::new(segment.span.start.max(from), segment.span.end);
        let Some(part) = segment_part(segment, source, from, in_double_quotes)? else {
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
fn segment_part(
    segment: &Segment,
    source: &str,
    from: usize,
    in_double_quotes: bool,
) -> Result<Option<Part>, InterpError> {
    let substitution = |kind| {
        Part::Subst(Subst {
            kind,
            body: segment.body,
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
            let inner = pieces_in(inner, source, from, true)?
                .into_iter()
                .map(|piece| piece.part)
                .collect();
            Part::Double(quoted_parts(inner))
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
        SegmentKind::CommandSubstitution => substitution(SubstKind::Command),
        SegmentKind::Backtick => substitution(SubstKind::Backtick { in_double_quotes }),
        SegmentKind::InputProcessSubstitution => substitution(SubstKind::Input),
        SegmentKind::OutputProcessSubstitution => substitution(SubstKind::Output),
    }))
}

/// The parts of here-document `document`'s body (KNSH-105), as one double-quoted part: a quoted body is its text;
/// an unquoted one is read like the inside of double quotes (`"` is literal, `\` escapes only `$`, `` ` ``, `\` and
/// newline), so it is expanded but never split or matched against file names. For `<<-`, the tabs at the start of
/// each line are removed first: each physical line of a quoted body, each line after line continuations are joined
/// in an unquoted one, as bash strips them while it reads the lines.
///
/// # Errors
///
/// [`InterpError::SourceMismatch`] if a span does not index `source`.
pub(crate) fn here_document_parts(document: &HereDocument, source: &str) -> Result<Part, InterpError> {
    if document.quoted {
        let body = text(document.body, source)?;
        let body = if document.strip_tabs {
            strip_leading_tabs(body, &mut true)
        } else {
            body.to_owned()
        };
        return Ok(Part::Double(vec![Part::Quoted(body)]));
    }
    let mut out = Vec::new();
    // Whether the text read so far ends a line (or the body starts): its leading tabs are stripped.
    let mut line_start = true;
    for segment in &document.segments {
        match &segment.kind {
            SegmentKind::Literal if document.strip_tabs => {
                let body = strip_leading_tabs(text(segment.span, source)?, &mut line_start);
                out.push(Part::Text(body));
                continue;
            }
            // A continuation joins two lines into one: the next line's tabs are not at a line's start.
            SegmentKind::LineContinuation => continue,
            _ => {}
        }
        line_start = false;
        if let Some(part) = segment_part(segment, source, 0, false)? {
            out.push(part);
        }
    }
    Ok(Part::Double(quoted_parts(out)))
}

/// `text` without the tabs at the start of each line, `line_start` telling whether it starts at a line's start and
/// left telling whether it ends at one.
fn strip_leading_tabs(text: &str, line_start: &mut bool) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if *line_start && ch == '\t' {
            continue;
        }
        *line_start = ch == '\n';
        out.push(ch);
    }
    out
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
            | Part::Arith { .. }
            | Part::Subst(_)) => other,
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
            Part::Param { .. } | Part::Brace { .. } | Part::Arith { .. } | Part::Subst(_) => return None,
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

    /// The kind of the substitution `line`'s word `index` is (alone, or alone in double quotes).
    fn substitution(line: &str, index: usize) -> SubstKind {
        match word_parts(line, index).unwrap().as_slice() {
            [Part::Subst(subst)] => subst.kind,
            [Part::Double(inner)] => match inner.as_slice() {
                [Part::Subst(subst)] => subst.kind,
                other => panic!("{line}: {other:?}"),
            },
            other => panic!("{line}: {other:?}"),
        }
    }

    /// The text `line`'s first here-document expands from, as parts.
    fn here_document(line: &str) -> Part {
        let script = knsh_bash::parse(line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!("not a simple command: {line}");
        };
        here_document_parts(simple.redirections[0].here_document.as_ref().unwrap(), line).unwrap()
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

    // KNSH-105: substitutions are parts, a backtick knowing whether it is inside double quotes.
    #[test]
    fn substitutions_become_parts() {
        assert_eq!(substitution("echo $(ls)", 1), SubstKind::Command);
        assert_eq!(
            substitution("echo `ls`", 1),
            SubstKind::Backtick {
                in_double_quotes: false
            }
        );
        assert_eq!(
            substitution(r#"echo "`ls`""#, 1),
            SubstKind::Backtick { in_double_quotes: true }
        );
        assert_eq!(substitution(r#"echo "$(ls)""#, 1), SubstKind::Command);
        assert_eq!(substitution("cat <(ls)", 1), SubstKind::Input);
        assert_eq!(substitution("tee >(ls)", 1), SubstKind::Output);
        assert_eq!(literal(&word_parts("echo $(ls)", 1).unwrap()), None);
    }

    // KNSH-105: `<<-` strips the tabs starting each line; an unquoted body's continuation joins lines first.
    #[test]
    fn here_document_bodies_strip_tabs_like_bash() {
        let Part::Double(parts) = here_document("cat <<-'E'\n\ta\n\t\tb\\\n\tc\n\tE\n") else {
            panic!()
        };
        assert_eq!(parts, [Part::Quoted("a\nb\\\nc\n".into())]);
        let Part::Double(parts) = here_document("cat <<-E\n\ta $x\n\tb\\\n\tc\nE\n") else {
            panic!()
        };
        let text: String = parts
            .iter()
            .map(|part| match part {
                Part::Quoted(text) => text.clone(),
                Part::Param { name, .. } => format!("<{name}>"),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(text, "a <x>\nb\tc\n");
        let Part::Double(parts) = here_document("cat <<E\n\ta\nE\n") else {
            panic!()
        };
        assert_eq!(parts, [Part::Quoted("\ta\n".into())]);
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
