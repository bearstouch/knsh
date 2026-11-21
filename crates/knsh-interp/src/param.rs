//! Reading the body of `${…}`: which parameter, and which operator with which words (KNSH-097).
//!
//! Follows bash 5.2's `parameter_brace_expand`: `${#name}` is a length unless what follows `#` is no parameter
//! (`${#:-x}` is `$#` with a default); `${!name}` is indirect, `${!prefix*}` and `${!prefix@}` list variable names;
//! a name is an identifier, a number or one special character; the operator is the first character after it. What
//! bash rejects as a "bad substitution" is [`Parsed::Bad`] (an error when expanded, not a refusal), and forms a
//! later story implements (arrays) are [`Parsed::Unsupported`].
//!
//! The words an operator takes are kept as spans of the source, read by [`crate::scan`] only when the expansion runs.

use knsh_bash::Span;

use crate::error::Unsupported;
use crate::scan::find_top_level;
use crate::state::is_name;

/// A parameter named inside `${…}` (or after `$`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Name {
    /// A shell variable.
    Variable(String),
    /// `$0` (0), `$1`, `${10}` …
    Positional(usize),
    /// `@ * # ? - $ !`.
    Special(char),
    /// `${PIPESTATUS[…]}` or `${BASH_REMATCH[…]}`: the arrays the shell maintains itself, which the interpreter
    /// reads before arrays exist (KNSH-100, KNSH-102; arrays are KNSH-103).
    Array(ShellArray, Subscript),
}

/// An array the shell maintains itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellArray {
    /// `PIPESTATUS` (KNSH-100).
    Pipestatus,
    /// `BASH_REMATCH` (KNSH-102).
    BashRematch,
}

impl ShellArray {
    /// The array variable `name` is, if any.
    pub(crate) fn named(name: &str) -> Option<Self> {
        match name {
            crate::state::PIPESTATUS => Some(Self::Pipestatus),
            crate::state::BASH_REMATCH => Some(Self::BashRematch),
            _ => None,
        }
    }

    /// Its name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Pipestatus => crate::state::PIPESTATUS,
            Self::BashRematch => crate::state::BASH_REMATCH,
        }
    }
}

/// The subscript of `${PIPESTATUS[…]}` and `${BASH_REMATCH[…]}`: what the interpreter reads without evaluating an
/// arithmetic expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subscript {
    /// `[@]`, or `[*]` when `star`.
    All {
        /// `[*]`.
        star: bool,
    },
    /// `[n]`, a decimal number, from the end when negative (bash 4.3 and later).
    Index(i64),
}

impl Subscript {
    /// The subscript `text` (between the brackets) spells, or `None` for one that needs arithmetic (`[$i]`,
    /// `[1+1]`), which is refused with the other arrays.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "@" => Some(Self::All { star: false }),
            "*" => Some(Self::All { star: true }),
            _ => {
                let digits = text.strip_prefix('-').unwrap_or(text);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                text.parse().ok().map(Self::Index)
            }
        }
    }
}

/// The array `name` names and the subscript at the start of `rest` (which starts with `[`), with the subscript's
/// length with the brackets, when `name` is one of the shell's own arrays.
fn shell_array_subscript(name: &Name, rest: &str) -> Option<(ShellArray, Subscript, usize)> {
    let Name::Variable(variable) = name else {
        return None;
    };
    let array = ShellArray::named(variable)?;
    let inner = rest.strip_prefix('[')?;
    let close = inner.find(']')?;
    Some((array, Subscript::parse(&inner[..close])?, close + 2))
}

impl Name {
    /// The parameter `text` names: an identifier, a number or one special character.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if is_name(text) {
            return Some(Self::Variable(text.to_owned()));
        }
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            // A number too large to be a position names a parameter that is never set.
            return Some(Self::Positional(text.parse().unwrap_or(usize::MAX)));
        }
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            (Some(ch @ ('@' | '*' | '#' | '?' | '-' | '$' | '!')), None) => Some(Self::Special(ch)),
            _ => None,
        }
    }

    /// Whether this is `$@` or `$*`, which expand to the positional parameters, or `${PIPESTATUS[@]}`.
    pub(crate) const fn is_list(&self) -> bool {
        matches!(self, Self::Special('@' | '*') | Self::Array(_, Subscript::All { .. }))
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Variable(name) => f.write_str(name),
            Self::Positional(n) => write!(f, "{n}"),
            Self::Special(ch) => write!(f, "{ch}"),
            Self::Array(array, Subscript::All { star }) => {
                write!(f, "{}[{}]", array.name(), if *star { '*' } else { '@' })
            }
            Self::Array(array, Subscript::Index(index)) => write!(f, "{}[{index}]", array.name()),
        }
    }
}

/// The body of a `${…}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// `${#name}`: the length of the value (the number of positional parameters for `@` and `*`).
    Length(Name),
    /// `${!prefix*}` (`at` false) or `${!prefix@}` (`at` true): the names of set variables starting with `prefix`.
    Names {
        /// The prefix.
        prefix: String,
        /// `@` rather than `*`.
        at: bool,
    },
    /// `${name…}`, or `${!name…}` when `indirect`.
    Param {
        /// The parameter written.
        name: Name,
        /// Whether its value names the parameter to expand.
        indirect: bool,
        /// What is done with the value.
        op: Op,
    },
    /// What bash reports as a bad substitution.
    Bad,
    /// A form a later story implements.
    Unsupported(Unsupported),
}

/// Which of `-`, `=`, `?` and `+`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefaultKind {
    /// `-`: use the word.
    Use,
    /// `=`: assign the word.
    Assign,
    /// `?`: fail with the word as message.
    Error,
    /// `+`: use the word when set.
    Alternative,
}

/// Where `${x/pattern/replacement}` matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplaceMode {
    /// `/`: the first match.
    First,
    /// `//`: every match.
    All,
    /// `/#`: a match at the start.
    Prefix,
    /// `/%`: a match at the end.
    Suffix,
}

/// Which case modification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseKind {
    /// `^`
    Upper,
    /// `,`
    Lower,
    /// `~` (undocumented in bash, but accepted).
    Toggle,
}

/// The operator of a `${…}`, with the source spans of its words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Op {
    /// `${name}`.
    None,
    /// `${name-word}` and the like; `colon` for `:-`, `:=`, `:?`, `:+`, which also treat empty as unset.
    Default {
        /// Which operator.
        kind: DefaultKind,
        /// Whether a `:` precedes it.
        colon: bool,
        /// The word.
        word: Span,
    },
    /// `${name:offset}` or `${name:offset:length}`.
    Substring {
        /// The offset expression.
        offset: Span,
        /// The length expression.
        length: Option<Span>,
    },
    /// `${name#p}`, `${name##p}`, `${name%p}`, `${name%%p}`.
    Remove {
        /// `%` rather than `#`.
        suffix: bool,
        /// Doubled: the longest match.
        longest: bool,
        /// The pattern.
        pattern: Span,
    },
    /// `${name/p/r}` and its anchored and global forms.
    Replace {
        /// Where it matches.
        mode: ReplaceMode,
        /// The pattern.
        pattern: Span,
        /// The replacement, absent when no `/` follows the pattern.
        replacement: Option<Span>,
    },
    /// `${name^p}`, `${name^^p}`, `${name,p}`, `${name,,p}`, `${name~p}`, `${name~~p}`.
    Case {
        /// Which modification.
        kind: CaseKind,
        /// Doubled: every matching character, not only the first.
        all: bool,
        /// The pattern each character is tested against (empty: any character).
        pattern: Span,
    },
    /// `${name@op}`.
    Transform(char),
}

/// Reads the body `body` of a `${…}`, which spans `span` in the source.
pub(crate) fn parse(body: &str, span: Span) -> Parsed {
    let at = |start: usize, end: usize| Span::new(span.start + start, span.start + end);
    let bytes = body.as_bytes();
    match bytes.first() {
        None => Parsed::Bad,
        Some(b'#') => length_or_hash(body, &at),
        Some(b'!') => indirect(body, &at),
        Some(_) => {
            let Some((name, len)) = leading_name(body) else {
                return Parsed::Bad;
            };
            with_op(name, false, body, len, &at)
        }
    }
}

/// The parameter name at the start of `text` and its length: an identifier, digits, or one special character.
fn leading_name(text: &str) -> Option<(Name, usize)> {
    let bytes = text.as_bytes();
    let first = *bytes.first()?;
    if first.is_ascii_alphabetic() || first == b'_' {
        let len = bytes
            .iter()
            .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))
            .unwrap_or(bytes.len());
        return Some((Name::Variable(text.get(..len)?.to_owned()), len));
    }
    if first.is_ascii_digit() {
        let len = bytes.iter().position(|b| !b.is_ascii_digit()).unwrap_or(bytes.len());
        return Some((Name::parse(text.get(..len)?)?, len));
    }
    Name::parse(text.get(..1)?).map(|name| (name, 1))
}

/// `${#…}`: a length, `$#` itself, or `$#` with an operator.
fn length_or_hash(body: &str, at: &dyn Fn(usize, usize) -> Span) -> Parsed {
    let rest = body.get(1..).unwrap_or("");
    if rest.is_empty() {
        return Parsed::Param {
            name: Name::Special('#'),
            indirect: false,
            op: Op::None,
        };
    }
    let starts_name = rest
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    if starts_name {
        // Bash reads everything after `#name` as part of the name: anything more is a bad substitution.
        return match leading_name(rest) {
            Some((name, len)) if len == rest.len() => Parsed::Length(name),
            Some((name, len)) if rest.as_bytes().get(len) == Some(&b'[') => {
                match shell_array_subscript(&name, &rest[len..]) {
                    Some((array, subscript, taken)) if len + taken == rest.len() => {
                        Parsed::Length(Name::Array(array, subscript))
                    }
                    Some(_) => Parsed::Bad,
                    None => Parsed::Unsupported(Unsupported::Array),
                }
            }
            Some(_) | None => Parsed::Bad,
        };
    }
    if let Some(name) = Name::parse(rest) {
        return Parsed::Length(name);
    }
    // `${#%}`, `${#:}`, `${#=}`, `${#+}` and `${#/}` are errors in bash, not `$#` with an empty word.
    if matches!(rest, "%" | ":" | "=" | "+" | "/") {
        return Parsed::Bad;
    }
    with_op(Name::Special('#'), false, body, 1, at)
}

/// `${!…}`: indirection, a list of names, or `$!`.
fn indirect(body: &str, at: &dyn Fn(usize, usize) -> Span) -> Parsed {
    let rest = body.get(1..).unwrap_or("");
    let Some(&first) = rest.as_bytes().first() else {
        return Parsed::Param {
            name: Name::Special('!'),
            indirect: false,
            op: Op::None,
        };
    };
    let indirect = first.is_ascii_alphanumeric() || matches!(first, b'_' | b'#' | b'?' | b'@' | b'*');
    if !indirect {
        return with_op(Name::Special('!'), false, body, 1, at);
    }
    let Some((name, len)) = leading_name(rest) else {
        return Parsed::Bad;
    };
    let after = rest.get(len..).unwrap_or("");
    if let Name::Variable(prefix) = &name {
        match after {
            "*" | "@" => {
                return Parsed::Names {
                    prefix: prefix.clone(),
                    at: after == "@",
                };
            }
            _ if after.starts_with('[') => return Parsed::Unsupported(Unsupported::Array),
            _ => {}
        }
    }
    with_op(name, true, body, 1 + len, at)
}

/// The operator after the name, which ends at `from` in `body`.
fn with_op(name: Name, indirect: bool, body: &str, from: usize, at: &dyn Fn(usize, usize) -> Span) -> Parsed {
    if body.as_bytes().get(from) == Some(&b'[') {
        let rest = body.get(from..).unwrap_or("");
        return match shell_array_subscript(&name, rest) {
            Some((array, subscript, taken)) if !indirect => match operator(body, from + taken, at) {
                Some(op) => Parsed::Param {
                    name: Name::Array(array, subscript),
                    indirect,
                    op,
                },
                None => Parsed::Bad,
            },
            Some(_) | None => Parsed::Unsupported(Unsupported::Array),
        };
    }
    match operator(body, from, at) {
        Some(op) => Parsed::Param { name, indirect, op },
        None => Parsed::Bad,
    }
}

/// The operator of `body` starting at `from`, or `None` for a bad substitution (an array subscript is refused by
/// the caller seeing `[`, which reaches here only after a name).
fn operator(body: &str, from: usize, at: &dyn Fn(usize, usize) -> Span) -> Option<Op> {
    let rest = body.get(from..).unwrap_or("");
    let end = body.len();
    let Some(&first) = rest.as_bytes().first() else {
        return Some(Op::None);
    };
    let second = rest.as_bytes().get(1).copied();
    Some(match first {
        b':' => match default_kind(second) {
            Some(kind) => Op::Default {
                kind,
                colon: true,
                word: at(from + 2, end),
            },
            None if rest.len() == 1 => return None,
            None => substring(rest, from, end, at),
        },
        b'-' | b'=' | b'?' | b'+' => Op::Default {
            kind: default_kind(Some(first))?,
            colon: false,
            word: at(from + 1, end),
        },
        b'#' | b'%' => {
            let longest = second == Some(first);
            Op::Remove {
                suffix: first == b'%',
                longest,
                pattern: at(from + if longest { 2 } else { 1 }, end),
            }
        }
        b'/' if rest.len() == 1 => return None,
        b'/' => replace(rest, second, from, end, at),
        b'^' | b',' | b'~' => {
            let all = second == Some(first);
            let kind = match first {
                b'^' => CaseKind::Upper,
                b',' => CaseKind::Lower,
                _ => CaseKind::Toggle,
            };
            Op::Case {
                kind,
                all,
                pattern: at(from + if all { 2 } else { 1 }, end),
            }
        }
        b'@' => match (second, rest.len()) {
            (Some(op @ (b'U' | b'u' | b'L' | b'Q' | b'E' | b'P' | b'A' | b'K' | b'a' | b'k')), 2) => {
                Op::Transform(char::from(op))
            }
            _ => return None,
        },
        _ => return None,
    })
}

/// Which of `-`, `=`, `?`, `+` `byte` is.
const fn default_kind(byte: Option<u8>) -> Option<DefaultKind> {
    match byte {
        Some(b'-') => Some(DefaultKind::Use),
        Some(b'=') => Some(DefaultKind::Assign),
        Some(b'?') => Some(DefaultKind::Error),
        Some(b'+') => Some(DefaultKind::Alternative),
        _ => None,
    }
}

/// `:offset` or `:offset:length` (`rest` starts with the `:`, at `from` in a body ending at `end`).
fn substring(rest: &str, from: usize, end: usize, at: &dyn Fn(usize, usize) -> Span) -> Op {
    let expressions = rest.get(1..).unwrap_or("");
    let (offset, length) = match find_top_level(expressions, b':', true) {
        Some(colon) => (at(from + 1, from + 1 + colon), Some(at(from + 2 + colon, end))),
        None => (at(from + 1, end), None),
    };
    Op::Substring { offset, length }
}

/// `/pattern/replacement` and its `//`, `/#` and `/%` forms (`rest` starts with the `/`).
fn replace(rest: &str, second: Option<u8>, from: usize, end: usize, at: &dyn Fn(usize, usize) -> Span) -> Op {
    let (mode, skip) = match second {
        Some(b'/') => (ReplaceMode::All, 2),
        Some(b'#') => (ReplaceMode::Prefix, 2),
        Some(b'%') => (ReplaceMode::Suffix, 2),
        _ => (ReplaceMode::First, 1),
    };
    let words = rest.get(skip..).unwrap_or("");
    let (pattern, replacement) = match find_top_level(words, b'/', false) {
        Some(slash) => (
            at(from + skip, from + skip + slash),
            Some(at(from + skip + slash + 1, end)),
        ),
        None => (at(from + skip, end), None),
    };
    Op::Replace {
        mode,
        pattern,
        replacement,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(body: &str) -> Parsed {
        parse(body, Span::new(0, body.len()))
    }

    fn var(name: &str) -> Name {
        Name::Variable(name.to_owned())
    }

    fn plain(name: Name) -> Parsed {
        Parsed::Param {
            name,
            indirect: false,
            op: Op::None,
        }
    }

    fn op(body: &str) -> Op {
        match parsed(body) {
            Parsed::Param { op, .. } => op,
            other => panic!("{body}: {other:?}"),
        }
    }

    fn span_text(body: &str, span: Span) -> &str {
        span.text(body).unwrap()
    }

    #[test]
    fn names_and_special_parameters() {
        assert_eq!(parsed("x"), plain(var("x")));
        assert_eq!(parsed("_a1"), plain(var("_a1")));
        assert_eq!(parsed("10"), plain(Name::Positional(10)));
        assert_eq!(parsed("0"), plain(Name::Positional(0)));
        for ch in ['@', '*', '#', '?', '-', '$', '!'] {
            assert_eq!(parsed(&ch.to_string()), plain(Name::Special(ch)), "{ch}");
        }
    }

    #[test]
    fn lengths_and_hash_with_operators() {
        assert_eq!(parsed("#x"), Parsed::Length(var("x")));
        assert_eq!(parsed("#1"), Parsed::Length(Name::Positional(1)));
        assert_eq!(parsed("##"), Parsed::Length(Name::Special('#')));
        assert_eq!(parsed("#@"), Parsed::Length(Name::Special('@')));
        assert_eq!(parsed("#-"), Parsed::Length(Name::Special('-')));
        assert!(matches!(
            parsed("#:-x"),
            Parsed::Param {
                name: Name::Special('#'),
                op: Op::Default {
                    kind: DefaultKind::Use,
                    colon: true,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            parsed("##x"),
            Parsed::Param {
                name: Name::Special('#'),
                op: Op::Remove { .. },
                ..
            }
        ));
        for bad in [
            "#x:-y", "#%", "#:", "#/", "", "x!", "1a", ":-x", "x:", "x/", "x@", "x@QQ", "x@Z",
        ] {
            assert_eq!(parsed(bad), Parsed::Bad, "{bad}");
        }
    }

    #[test]
    fn indirection_and_name_lists() {
        assert_eq!(
            parsed("!x"),
            Parsed::Param {
                name: var("x"),
                indirect: true,
                op: Op::None
            }
        );
        assert_eq!(
            parsed("!#"),
            Parsed::Param {
                name: Name::Special('#'),
                indirect: true,
                op: Op::None
            }
        );
        assert_eq!(
            parsed("!pre*"),
            Parsed::Names {
                prefix: "pre".into(),
                at: false
            }
        );
        assert_eq!(
            parsed("!pre@"),
            Parsed::Names {
                prefix: "pre".into(),
                at: true
            }
        );
        assert_eq!(parsed("!"), plain(Name::Special('!')));
    }

    #[test]
    fn operators_and_their_words() {
        let body = "x:-a b";
        let Op::Default { kind, colon, word } = op(body) else {
            panic!()
        };
        assert_eq!((kind, colon, span_text(body, word)), (DefaultKind::Use, true, "a b"));
        let body = "x=y";
        assert!(matches!(
            op(body),
            Op::Default {
                kind: DefaultKind::Assign,
                colon: false,
                ..
            }
        ));
        let body = "x: -1:(a?1:2)";
        let Op::Substring { offset, length } = op(body) else {
            panic!()
        };
        assert_eq!(span_text(body, offset), " -1");
        assert_eq!(span_text(body, length.unwrap()), "(a?1:2)");
        let body = "x##*/";
        let Op::Remove {
            suffix,
            longest,
            pattern,
        } = op(body)
        else {
            panic!()
        };
        assert_eq!((suffix, longest, span_text(body, pattern)), (false, true, "*/"));
        let body = r"x//a\/b/c/d";
        let Op::Replace {
            mode,
            pattern,
            replacement,
        } = op(body)
        else {
            panic!()
        };
        assert_eq!(mode, ReplaceMode::All);
        assert_eq!(span_text(body, pattern), r"a\/b");
        assert_eq!(span_text(body, replacement.unwrap()), "c/d");
        assert!(matches!(
            op("x/#a"),
            Op::Replace {
                mode: ReplaceMode::Prefix,
                replacement: None,
                ..
            }
        ));
        assert!(matches!(
            op("x,,"),
            Op::Case {
                kind: CaseKind::Lower,
                all: true,
                ..
            }
        ));
        assert_eq!(op("x@Q"), Op::Transform('Q'));
    }

    #[test]
    fn arrays_are_refused() {
        for body in ["a[0]", "#a[@]", "!a[@]", "a[1]:-x"] {
            assert_eq!(parsed(body), Parsed::Unsupported(Unsupported::Array), "{body}");
        }
    }
}
