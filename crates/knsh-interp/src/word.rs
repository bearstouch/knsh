//! Reading words: quote removal over words made only of literal text and quotes (KNSH-096).
//!
//! Expansions arrive with KNSH-097 and KNSH-098. Until then a word holding one is refused with the exact span of the
//! segment, and so is a word bash would change by tilde, brace or pathname expansion, decided from its unquoted
//! characters: running such a word unexpanded would run something other than what bash runs.

use knsh_bash::{Assignment, CommandWord, Segment, SegmentKind, Span};

use crate::error::{InterpError, Unsupported};
use crate::state::is_name;

/// One character of a word after quote removal, with whether it was quoted. Patterns need the difference: a quoted
/// `*` matches only itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WordChar {
    /// The character.
    pub(crate) ch: char,
    /// Whether it was quoted (inside quotes or escaped by a backslash).
    pub(crate) quoted: bool,
}

/// Where a word is read, which decides the expansions bash applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Context {
    /// A command word or a `for` item: tilde, brace and pathname expansion.
    Argument,
    /// A `case` subject or a `for` variable: tilde expansion only.
    Plain,
    /// A `case` pattern: tilde expansion; the unquoted characters are pattern characters.
    Pattern,
}

/// `word` after quote removal, in `context`.
///
/// # Errors
///
/// [`InterpError::Unsupported`] for an expansion bash would perform; [`InterpError::SourceMismatch`] if a span does
/// not index `source`.
pub(crate) fn expand(word: &CommandWord, source: &str, context: Context) -> Result<String, InterpError> {
    Ok(characters(word, source, context)?.into_iter().map(|c| c.ch).collect())
}

/// `word` after quote removal, each character with whether it was quoted, in `context`.
///
/// # Errors
///
/// As [`expand`].
pub(crate) fn characters(word: &CommandWord, source: &str, context: Context) -> Result<Vec<WordChar>, InterpError> {
    let mut out = Vec::new();
    read_segments(&word.word.segments, source, false, 0, &mut out)?;
    let refuse = |feature| {
        Err(InterpError::Unsupported {
            feature,
            span: word.span,
        })
    };
    // Outside posix mode bash also expands a tilde after the `=` of any word that looks like an assignment
    // (`env A=~ cmd`, `echo a=x:~`), wherever the word appears.
    let assignment_tilde = assignment_value_start(&out).is_some_and(|start| has_assignment_tilde(&out, start));
    if starts_with_tilde(&out) || assignment_tilde {
        return refuse(Unsupported::TildeExpansion);
    }
    if context == Context::Argument {
        if has_brace_expansion(&out) {
            return refuse(Unsupported::BraceExpansion);
        }
        if has_glob(&out) {
            return refuse(Unsupported::PathnameExpansion);
        }
    }
    Ok(out)
}

/// The value of `assignment` after quote removal. Bash applies no brace, pathname or word-splitting expansion to it,
/// but does expand a `~` at its start or after an unquoted `:`.
///
/// # Errors
///
/// As [`expand`].
pub(crate) fn assignment_value(assignment: &Assignment, source: &str) -> Result<String, InterpError> {
    let mut out = Vec::new();
    read_segments(
        &assignment.word.segments,
        source,
        false,
        assignment.value.start,
        &mut out,
    )?;
    if has_assignment_tilde(&out, 0) {
        return Err(InterpError::Unsupported {
            feature: Unsupported::TildeExpansion,
            span: assignment.span,
        });
    }
    Ok(out.into_iter().map(|c| c.ch).collect())
}

/// An unquoted `ch`.
const fn unquoted(ch: char) -> WordChar {
    WordChar { ch, quoted: false }
}

/// Appends the characters of `segments` after quote removal, skipping text before `from` (the name and `=` of an
/// assignment, which share its first literal segment).
fn read_segments(
    segments: &[Segment],
    source: &str,
    quoted: bool,
    from: usize,
    out: &mut Vec<WordChar>,
) -> Result<(), InterpError> {
    for segment in segments.iter().filter(|segment| segment.span.end > from) {
        let refuse = |feature| {
            Err(InterpError::Unsupported {
                feature,
                span: segment.span,
            })
        };
        match &segment.kind {
            SegmentKind::Literal => {
                let span = Span::new(segment.span.start.max(from), segment.span.end);
                push(text(span, source)?, quoted, out);
            }
            SegmentKind::Escape => match text(segment.body, source)? {
                // A backslash at the very end of the input quotes nothing and stays, as in bash.
                "" => push("\\", true, out),
                escaped => push(escaped, true, out),
            },
            SegmentKind::LineContinuation => {}
            SegmentKind::SingleQuoted => push(text(segment.body, source)?, true, out),
            // In the C locale `$"…"` is plain double quoting; translation catalogues are not supported by design.
            SegmentKind::DoubleQuoted(inner) | SegmentKind::Locale(inner) => {
                read_segments(inner, source, true, from, out)?;
            }
            SegmentKind::AnsiC => return refuse(Unsupported::AnsiCQuoting),
            SegmentKind::Parameter | SegmentKind::ParameterExpansion => {
                return refuse(Unsupported::ParameterExpansion);
            }
            SegmentKind::Arithmetic => return refuse(Unsupported::ArithmeticExpansion),
            SegmentKind::CommandSubstitution | SegmentKind::Backtick => {
                return refuse(Unsupported::CommandSubstitution);
            }
            SegmentKind::InputProcessSubstitution | SegmentKind::OutputProcessSubstitution => {
                return refuse(Unsupported::ProcessSubstitution);
            }
        }
    }
    Ok(())
}

/// The text `span` indexes in `source`.
fn text(span: Span, source: &str) -> Result<&str, InterpError> {
    span.text(source).ok_or(InterpError::SourceMismatch { span })
}

fn push(text: &str, quoted: bool, out: &mut Vec<WordChar>) {
    out.extend(text.chars().map(|ch| WordChar { ch, quoted }));
}

/// Whether the word starts with an unquoted `~`, which bash replaces by a home directory.
fn starts_with_tilde(chars: &[WordChar]) -> bool {
    chars.first() == Some(&unquoted('~'))
}

/// Whether the assignment value starting at `value_start` in `chars` holds a tilde bash expands: an unquoted `~` at
/// its start or right after an unquoted `:` in it.
fn has_assignment_tilde(chars: &[WordChar], value_start: usize) -> bool {
    let Some(value) = chars.get(value_start..) else {
        return false;
    };
    starts_with_tilde(value)
        || value
            .windows(2)
            .any(|pair| pair[0] == unquoted(':') && pair[1] == unquoted('~'))
}

/// Where the value starts in a word spelled like an assignment (`NAME=…` or `NAME+=…`, with the name and the `=`
/// unquoted), which bash marks as one even when it is not in assignment position; `None` for any other word.
fn assignment_value_start(chars: &[WordChar]) -> Option<usize> {
    let equals = chars.iter().position(|c| c.ch == '=')?;
    let before = chars.get(..equals)?;
    let name = match before.split_last() {
        Some((last, name)) if *last == unquoted('+') => name,
        _ => before,
    };
    let unquoted_name = !chars.get(equals)?.quoted && name.iter().all(|c| !c.quoted);
    let text: String = name.iter().map(|c| c.ch).collect();
    (unquoted_name && is_name(&text)).then_some(equals + 1)
}

/// Whether bash could match the word against file names: an unquoted `*` or `?`, or an unquoted `[` with an unquoted
/// `]` after it. Conservative: a word that matches nothing would stay as written in bash too, but which words match
/// depends on the filesystem, so any candidate is refused.
fn has_glob(chars: &[WordChar]) -> bool {
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
fn has_brace_expansion(chars: &[WordChar]) -> bool {
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
    use knsh_bash::{Command, parse};

    use super::*;

    /// The words of the single simple command `line`.
    fn words(line: &str) -> Vec<CommandWord> {
        let script = parse(line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!("not a simple command: {line}");
        };
        simple.words.clone()
    }

    fn expand_all(line: &str) -> Result<Vec<String>, InterpError> {
        words(line)
            .iter()
            .map(|word| expand(word, line, Context::Argument))
            .collect()
    }

    fn refused(line: &str) -> Unsupported {
        match expand_all(line) {
            Err(InterpError::Unsupported { feature, .. }) => feature,
            other => panic!("{line}: {other:?}"),
        }
    }

    #[test]
    fn removes_quotes_escapes_and_line_continuations() {
        assert_eq!(
            expand_all(
                r#"echo 'a b' "c\"d" e\ f g\
h "" $"loc""#
            )
            .unwrap(),
            ["echo", "a b", "c\"d", "e f", "gh", "", "loc"]
        );
    }

    #[test]
    fn keeps_a_backslash_inside_double_quotes_that_escapes_nothing() {
        assert_eq!(expand_all(r#"echo "a\b""#).unwrap(), ["echo", r"a\b"]);
    }

    #[test]
    fn refuses_expansions_until_their_stories() {
        assert_eq!(refused("echo $x"), Unsupported::ParameterExpansion);
        assert_eq!(refused(r#"echo "${x}""#), Unsupported::ParameterExpansion);
        assert_eq!(refused("echo $((1+1))"), Unsupported::ArithmeticExpansion);
        assert_eq!(refused("echo $(ls)"), Unsupported::CommandSubstitution);
        assert_eq!(refused("echo `ls`"), Unsupported::CommandSubstitution);
        assert_eq!(refused("cat <(ls)"), Unsupported::ProcessSubstitution);
        assert_eq!(refused("echo $'a'"), Unsupported::AnsiCQuoting);
        assert_eq!(refused("ls ~"), Unsupported::TildeExpansion);
        assert_eq!(refused("ls ~/x"), Unsupported::TildeExpansion);
        assert_eq!(refused("ls *.rs"), Unsupported::PathnameExpansion);
        assert_eq!(refused("ls a?"), Unsupported::PathnameExpansion);
        assert_eq!(refused("ls [ab]"), Unsupported::PathnameExpansion);
        assert_eq!(refused("echo {a,b}"), Unsupported::BraceExpansion);
        assert_eq!(refused("echo {1..3}"), Unsupported::BraceExpansion);
    }

    // Bash (outside posix mode) expands `~` after the `=` of any word spelled like an assignment, and after a `:`
    // in its value; other words keep `=~` and `:~` as written.
    #[test]
    fn refuses_tilde_in_assignment_like_arguments() {
        for line in ["env A=~ cmd", "echo a+=~", "echo a=x:~/bin", "echo _b=c=:~"] {
            assert_eq!(refused(line), Unsupported::TildeExpansion, "{line}");
        }
        assert_eq!(
            expand_all(r#"echo host:~/x "a"=~ 1a=~ a=b=~ a=\~ a="~""#).unwrap(),
            ["echo", "host:~/x", "a=~", "1a=~", "a=b=~", "a=~", "a=~"]
        );
    }

    #[test]
    fn quoted_or_incomplete_special_characters_stay_literal() {
        assert_eq!(
            expand_all(r#"echo '*' "?" \[a] [ ] {} {x} a~ "~" a]"#).unwrap(),
            ["echo", "*", "?", "[a]", "[", "]", "{}", "{x}", "a~", "~", "a]"]
        );
    }

    #[test]
    fn reads_assignment_values_without_glob_but_with_tilde_checks() {
        let line = "A=*.rs B='x y' C=a:~ D=";
        let script = parse(line).unwrap();
        let Command::Simple(simple) = &script.items[0].and_or.first.first else {
            panic!("not simple");
        };
        let values: Vec<_> = simple
            .assignments
            .iter()
            .map(|assignment| assignment_value(assignment, line))
            .collect();
        assert_eq!(values[0], Ok("*.rs".to_owned()));
        assert_eq!(values[1], Ok("x y".to_owned()));
        assert!(matches!(
            values[2],
            Err(InterpError::Unsupported {
                feature: Unsupported::TildeExpansion,
                ..
            })
        ));
        assert_eq!(values[3], Ok(String::new()));
    }

    #[test]
    fn a_span_outside_the_source_is_a_mismatch() {
        let word = &words("echo hello")[1];
        assert!(matches!(
            expand(word, "echo", Context::Argument),
            Err(InterpError::SourceMismatch { .. })
        ));
    }
}
