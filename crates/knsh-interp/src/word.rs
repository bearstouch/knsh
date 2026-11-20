//! Words as the expansion engine reads them (KNSH-096, KNSH-097): the parser's segments turned into [`Part`]s, the
//! characters an expansion produces ([`WordChar`]), and the checks for expansions later stories implement.
//!
//! Brace expansion and pathname expansion (KNSH-098) are still refused. Brace expansion only ever applies to the
//! literal text of a word, so a word that could hold one is refused before anything runs. Pathname expansion also
//! applies to the unquoted result of an expansion, so it is refused before anything runs for literal text, and when
//! the expansion happens for anything else.

use knsh_bash::{Segment, SegmentKind, Span};

use crate::error::{InterpError, Unsupported};
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

/// The parts of a word made of `segments`, skipping text before `from` (the name and `=` of an assignment, which
/// share its first literal segment).
///
/// # Errors
///
/// [`InterpError::Unsupported`] for a command or process substitution or `$'…'`; [`InterpError::SourceMismatch`] if
/// a span does not index `source`.
pub(crate) fn parts(segments: &[Segment], source: &str, from: usize) -> Result<Vec<Part>, InterpError> {
    let mut out = Vec::new();
    for segment in segments.iter().filter(|segment| segment.span.end > from) {
        let refuse = |feature| {
            Err(InterpError::Unsupported {
                feature,
                span: segment.span,
            })
        };
        let part = match &segment.kind {
            SegmentKind::Literal => {
                let span = Span::new(segment.span.start.max(from), segment.span.end);
                Part::Text(text(span, source)?.to_owned())
            }
            SegmentKind::Escape => match text(segment.body, source)? {
                // A backslash at the very end of the input quotes nothing and stays, as in bash.
                "" => Part::Quoted("\\".to_owned()),
                escaped => Part::Quoted(escaped.to_owned()),
            },
            SegmentKind::LineContinuation => continue,
            SegmentKind::SingleQuoted => Part::Quoted(text(segment.body, source)?.to_owned()),
            // In the C locale `$"…"` is plain double quoting; translation catalogues are not supported by design.
            SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => {
                Part::Double(quoted_parts(parts(inner, source, from)?))
            }
            SegmentKind::AnsiC => return refuse(Unsupported::AnsiCQuoting),
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
        };
        out.push(part);
    }
    Ok(out)
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

/// The characters of `parts` as far as they are known before expansion: literal text as written, and one quoted
/// placeholder for each expansion. Enough to find brace and pathname expansion in literal text.
pub(crate) fn literal_view(parts: &[Part]) -> Vec<WordChar> {
    let mut out = Vec::new();
    for part in parts {
        match part {
            Part::Text(text) => out.extend(text.chars().map(|ch| WordChar {
                ch,
                quoted: false,
                expanded: false,
            })),
            Part::Quoted(text) => out.extend(text.chars().map(|ch| WordChar {
                ch,
                quoted: true,
                expanded: false,
            })),
            Part::Double(inner) => out.extend(literal_view(inner).into_iter().map(|c| WordChar { quoted: true, ..c })),
            Part::Param { .. } | Part::Brace { .. } | Part::Arith { .. } => out.push(WordChar {
                ch: '\0',
                quoted: true,
                expanded: true,
            }),
        }
    }
    out
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

/// Whether bash could match the word against file names: an unquoted `*` or `?`, or an unquoted `[` with an unquoted
/// `]` after it. Conservative: a word that matches nothing would stay as written in bash too, but which words match
/// depends on the filesystem, so any candidate is refused.
pub(crate) fn has_glob(chars: &[WordChar]) -> bool {
    let mut open = false;
    for c in chars.iter().filter(|c| !c.quoted) {
        match c.ch {
            '*' | '?' => return true,
            '[' => open = true,
            ']' if open => return true,
            _ => {}
        }
    }
    false
}

/// Whether the word could hold a brace expansion: an unquoted `{` followed by an unquoted `,` or `..` and then an
/// unquoted `}`. Conservative, like [`has_glob`]: `{}` and `{x}` stay as written, as in bash.
pub(crate) fn has_brace_expansion(chars: &[WordChar]) -> bool {
    let unquoted: Vec<char> = chars.iter().filter(|c| !c.quoted).map(|c| c.ch).collect();
    let Some(open) = unquoted.iter().position(|&ch| ch == '{') else {
        return false;
    };
    let rest = &unquoted[open + 1..];
    let Some(close) = rest.iter().rposition(|&ch| ch == '}') else {
        return false;
    };
    let inside = &rest[..close];
    inside.contains(&',') || inside.windows(2).any(|pair| pair == ['.', '.'])
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
        assert_eq!(refused("echo $'a'", 1), Unsupported::AnsiCQuoting);
    }

    #[test]
    fn literal_view_finds_globs_and_braces_only_in_literal_text() {
        let view = |line: &str| literal_view(&word_parts(line, 1).unwrap());
        for line in ["ls *.rs", "ls a?", "ls [ab]", "ls $x*"] {
            assert!(has_glob(&view(line)), "{line}");
        }
        for line in ["ls '*'", "ls \\[a]", "ls $x", r#"ls "${x}*""#, "ls a]"] {
            assert!(!has_glob(&view(line)), "{line}");
        }
        for line in ["echo {a,b}", "echo {1..3}", "echo {$x,b}"] {
            assert!(has_brace_expansion(&view(line)), "{line}");
        }
        for line in ["echo {}", "echo {x}", "echo '{a,b}'", "echo ${x}"] {
            assert!(!has_brace_expansion(&view(line)), "{line}");
        }
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
