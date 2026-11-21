//! Reading the body of `${…}`: which parameter, and which operator with which words (KNSH-097, KNSH-103).
//!
//! Follows bash 5.2's `parameter_brace_expand`: `${#name}` is a length unless what follows `#` is no parameter
//! (`${#:-x}` is `$#` with a default); `${!name}` is indirect, `${!prefix*}` and `${!prefix@}` list variable names,
//! `${!name[@]}` and `${!name[*]}` an array's keys; a name is an identifier (with a subscript, `name[…]`, read up to
//! its matching `]` as bash's `skipsubscript` does), a number or one special character; the operator is the first
//! character after it. What bash rejects as a "bad substitution" is [`Parsed::Bad`] (an error when expanded, not a
//! refusal).
//!
//! The words an operator takes, and a subscript, are kept as spans of the source, read by [`crate::scan`] only when
//! the expansion runs.

use knsh_bash::Span;

use crate::error::Unsupported;
use crate::scan::{find_top_level, subscript_end};
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
    /// `name[subscript]`: an element of an array, or all of them (KNSH-103).
    Element(String, Subscript),
}

/// The subscript of `name[…]` (KNSH-103).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Subscript {
    /// `[@]`, or `[*]` when `star`: every element.
    All {
        /// `[*]`.
        star: bool,
    },
    /// A subscript written in the source, between the brackets: expanded, then evaluated as an arithmetic
    /// expression for an indexed array or taken as the key of an associative one.
    Source {
        /// Where it is.
        span: Span,
        /// Its text, for messages.
        text: String,
    },
    /// A subscript that came from a value (`x='a[1]'; ${!x}`): not expanded again.
    Text(String),
}

impl Subscript {
    /// The subscript `text` spells, written at `span` (or taken from a value when `span` is `None`).
    fn new(text: &str, span: Option<Span>) -> Self {
        match (text, span) {
            ("@", _) => Self::All { star: false },
            ("*", _) => Self::All { star: true },
            (_, Some(span)) => Self::Source {
                span,
                text: text.to_owned(),
            },
            (_, None) => Self::Text(text.to_owned()),
        }
    }
}

impl Name {
    /// The parameter `text` names: an identifier, a number or one special character, or `name[subscript]` (the
    /// target of an indirection, whose subscript is not expanded again).
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if is_name(text) {
            return Some(Self::Variable(text.to_owned()));
        }
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            // A number too large to be a position names a parameter that is never set.
            return Some(Self::Positional(text.parse().unwrap_or(usize::MAX)));
        }
        if let Some((name, rest)) = text.split_once('[')
            && is_name(name)
            && let Some(close) = subscript_end(rest)
            && close + 1 == rest.len()
            && close > 0
        {
            return Some(Self::Element(name.to_owned(), Subscript::new(&rest[..close], None)));
        }
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            (Some(ch @ ('@' | '*' | '#' | '?' | '-' | '$' | '!')), None) => Some(Self::Special(ch)),
            _ => None,
        }
    }

    /// Whether this is `$@` or `$*`, which expand to the positional parameters.
    pub(crate) const fn is_list(&self) -> bool {
        matches!(self, Self::Special('@' | '*'))
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Variable(name) => f.write_str(name),
            Self::Positional(n) => write!(f, "{n}"),
            Self::Special(ch) => write!(f, "{ch}"),
            Self::Element(name, Subscript::All { star }) => write!(f, "{name}[{}]", if *star { '*' } else { '@' }),
            Self::Element(name, Subscript::Source { text, .. } | Subscript::Text(text)) => {
                write!(f, "{name}[{text}]")
            }
        }
    }
}

/// The body of a `${…}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// `${#name}`: the length of the value (the number of positional parameters for `@` and `*`).
    Length(Name),
    /// `${!name[@]}` or `${!name[*]}` (`star`): the indices or keys of an array (KNSH-103).
    Keys {
        /// The array.
        name: String,
        /// `[*]`.
        star: bool,
    },
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
    #[allow(dead_code)]
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
            Some((Name::Variable(name), len)) if rest.as_bytes().get(len) == Some(&b'[') => {
                match element(&name, rest, len, 1, at) {
                    Some((element, taken)) if len + taken == rest.len() => Parsed::Length(element),
                    Some(_) | None => Parsed::Bad,
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
            _ if after.starts_with('[') => {
                return match element(prefix, rest, len, 1, at) {
                    Some((Name::Element(name, Subscript::All { star }), taken)) if len + taken == rest.len() => {
                        Parsed::Keys { name, star }
                    }
                    Some((element, taken)) => match operator(body, 1 + len + taken, at) {
                        Some(op) => Parsed::Param {
                            name: element,
                            indirect: true,
                            op,
                        },
                        None => Parsed::Bad,
                    },
                    None => Parsed::Bad,
                };
            }
            _ => {}
        }
    }
    with_op(name, true, body, 1 + len, at)
}

/// The operator after the name, which ends at `from` in `body`.
fn with_op(name: Name, indirect: bool, body: &str, from: usize, at: &dyn Fn(usize, usize) -> Span) -> Parsed {
    if body.as_bytes().get(from) == Some(&b'[') {
        let Name::Variable(variable) = &name else {
            return Parsed::Bad;
        };
        return match element(variable, body, from, 0, at) {
            Some((element, taken)) => match operator(body, from + taken, at) {
                Some(op) => Parsed::Param {
                    name: element,
                    indirect,
                    op,
                },
                None => Parsed::Bad,
            },
            None => Parsed::Bad,
        };
    }
    match operator(body, from, at) {
        Some(op) => Parsed::Param { name, indirect, op },
        None => Parsed::Bad,
    }
}

/// `name[…]` with the subscript starting at `text[from]` (a `[`), where `text` starts `offset` bytes into the body:
/// the element and the subscript's length with its brackets, or `None` when the subscript is not closed or empty
/// (bash's bad substitution).
fn element(
    name: &str,
    text: &str,
    from: usize,
    offset: usize,
    at: &dyn Fn(usize, usize) -> Span,
) -> Option<(Name, usize)> {
    let inner = text.get(from + 1..)?;
    let close = subscript_end(inner)?;
    if close == 0 {
        return None;
    }
    let start = offset + from + 1;
    let subscript = Subscript::new(&inner[..close], Some(at(start, start + close)));
    Some((Name::Element(name.to_owned(), subscript), close + 2))
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

    // KNSH-103: subscripts are read to their matching `]`, with the operator after them.
    #[test]
    fn elements_keys_and_lengths() {
        let element = |body: &str| match parsed(body) {
            Parsed::Param {
                name: Name::Element(name, subscript),
                indirect,
                op,
            } => (name, subscript, indirect, op),
            other => panic!("{body}: {other:?}"),
        };
        let (name, subscript, indirect, op) = element("a[i+1]");
        assert_eq!((name.as_str(), indirect, op), ("a", false, Op::None));
        assert!(matches!(subscript, Subscript::Source { text, .. } if text == "i+1"));
        let (_, subscript, _, op) = element("a[@]:-x");
        assert_eq!(subscript, Subscript::All { star: false });
        assert!(matches!(op, Op::Default { .. }));
        let (_, subscript, _, _) = element("a[\"]\"]");
        assert!(matches!(subscript, Subscript::Source { text, .. } if text == "\"]\""));
        let (_, subscript, _, _) = element("a[b[1]]#x");
        assert!(matches!(subscript, Subscript::Source { text, .. } if text == "b[1]"));
        assert!(matches!(
            parsed("#a[@]"),
            Parsed::Length(Name::Element(_, Subscript::All { .. }))
        ));
        assert!(matches!(parsed("#a[2]"), Parsed::Length(Name::Element(..))));
        assert_eq!(
            parsed("!a[*]"),
            Parsed::Keys {
                name: "a".into(),
                star: true
            }
        );
        assert!(matches!(parsed("!a[0]"), Parsed::Param { indirect: true, .. }));
        for bad in ["a[]", "a[1", "#a[1]x", "1[2]", "a[1]x"] {
            assert_eq!(parsed(bad), Parsed::Bad, "{bad}");
        }
        assert_eq!(
            Name::parse("a[$i]"),
            Some(Name::Element("a".into(), Subscript::Text("$i".into())))
        );
        assert_eq!(
            Name::parse("a[@]"),
            Some(Name::Element("a".into(), Subscript::All { star: false }))
        );
    }
}
