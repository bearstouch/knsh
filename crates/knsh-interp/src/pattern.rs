//! Bash pattern matching for `case` (KNSH-096): `*`, `?` and bracket expressions, with quoted characters matching
//! only themselves.
//!
//! The matcher is iterative, with one remembered `*` to backtrack to, so a hostile pattern costs at most
//! `O(pattern × text)` steps and no recursion. `extglob` patterns are not read (that option is off by default and
//! arrives with KNSH-104).

use crate::word::WordChar;

/// Whether `text` matches `pattern` as a whole.
pub(crate) fn matches(pattern: &[WordChar], text: &str) -> bool {
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    // The position after the last `*` seen, and the text position it is currently made to swallow up to.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        // How many pattern characters matched `text[t]`, or `None` if it did not match.
        let step = match pattern.get(p) {
            Some(c) if is_special(*c, '*') => {
                star = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some(c) if is_special(*c, '?') => Some(1),
            Some(c) if is_special(*c, '[') => {
                let (matched, len) = bracket(&pattern[p..], text[t]);
                matched.then_some(len)
            }
            Some(c) => (c.ch == text[t]).then_some(1),
            None => None,
        };
        match (step, star) {
            (Some(len), _) => {
                p += len;
                t += 1;
            }
            // Let the last `*` swallow one more character and try again from just after it.
            (None, Some((after, swallowed))) => {
                p = after;
                t = swallowed + 1;
                star = Some((after, swallowed + 1));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&c| is_special(c, '*'))
}

/// Whether `c` is the unquoted pattern character `special`.
fn is_special(c: WordChar, special: char) -> bool {
    !c.quoted && c.ch == special
}

/// Matches the bracket expression at the start of `pattern` (which starts with an unquoted `[`) against `ch`:
/// whether it matched and how many pattern characters it takes. A `[` that opens no complete expression matches
/// only a literal `[`, as in bash.
fn bracket(pattern: &[WordChar], ch: char) -> (bool, usize) {
    let Some(parsed) = parse_bracket(pattern) else {
        return (ch == '[', 1);
    };
    let mut found = false;
    for item in &parsed.items {
        found |= match *item {
            Item::Char(c) => c == ch,
            Item::Range(low, high) => low <= ch && ch <= high,
            Item::Class(class) => class.contains(ch),
        };
    }
    (found != parsed.negated, parsed.len)
}

/// A bracket expression read from a pattern.
struct Bracket {
    /// `[!…]` or `[^…]`.
    negated: bool,
    /// What it accepts.
    items: Vec<Item>,
    /// Pattern characters it takes, both brackets included.
    len: usize,
}

/// One member of a bracket expression.
#[derive(Clone, Copy)]
enum Item {
    Char(char),
    Range(char, char),
    Class(Class),
}

/// The POSIX character classes `[:name:]`.
#[derive(Clone, Copy)]
enum Class {
    Alnum,
    Alpha,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Word,
    Xdigit,
}

impl Class {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "alnum" => Self::Alnum,
            "alpha" => Self::Alpha,
            "blank" => Self::Blank,
            "cntrl" => Self::Cntrl,
            "digit" => Self::Digit,
            "graph" => Self::Graph,
            "lower" => Self::Lower,
            "print" => Self::Print,
            "punct" => Self::Punct,
            "space" => Self::Space,
            "upper" => Self::Upper,
            "word" => Self::Word,
            "xdigit" => Self::Xdigit,
            _ => return None,
        })
    }

    fn contains(self, ch: char) -> bool {
        match self {
            Self::Alnum => ch.is_alphanumeric(),
            Self::Alpha => ch.is_alphabetic(),
            Self::Blank => ch == ' ' || ch == '\t',
            Self::Cntrl => ch.is_control(),
            Self::Digit => ch.is_ascii_digit(),
            Self::Graph => !ch.is_control() && !ch.is_whitespace(),
            Self::Lower => ch.is_lowercase(),
            Self::Print => !ch.is_control(),
            Self::Punct => ch.is_ascii_punctuation(),
            Self::Space => ch.is_whitespace(),
            Self::Upper => ch.is_uppercase(),
            Self::Word => ch.is_alphanumeric() || ch == '_',
            Self::Xdigit => ch.is_ascii_hexdigit(),
        }
    }
}

/// Reads the bracket expression at the start of `pattern`, or `None` if no unquoted `]` closes it.
fn parse_bracket(pattern: &[WordChar]) -> Option<Bracket> {
    let mut i = 1;
    let negated = pattern
        .get(i)
        .is_some_and(|c| is_special(*c, '!') || is_special(*c, '^'));
    if negated {
        i += 1;
    }
    let mut items = Vec::new();
    let mut first = true;
    loop {
        let c = pattern.get(i)?;
        // A `]` right after `[` or `[!` is a member, not the end.
        if is_special(*c, ']') && !first {
            return Some(Bracket {
                negated,
                items,
                len: i + 1,
            });
        }
        first = false;
        if is_special(*c, '[')
            && pattern.get(i + 1).is_some_and(|next| is_special(*next, ':'))
            && let Some((class, len)) = class_at(&pattern[i..])
        {
            items.push(Item::Class(class));
            i += len;
            continue;
        }
        let is_range = pattern.get(i + 1).is_some_and(|dash| is_special(*dash, '-'))
            && pattern.get(i + 2).is_some_and(|end| !is_special(*end, ']'));
        if is_range && let Some(end) = pattern.get(i + 2) {
            items.push(Item::Range(c.ch, end.ch));
            i += 3;
        } else {
            items.push(Item::Char(c.ch));
            i += 1;
        }
    }
}

/// Reads `[:name:]` at the start of `pattern`: the class and the characters it takes.
fn class_at(pattern: &[WordChar]) -> Option<(Class, usize)> {
    let close = pattern
        .windows(2)
        .skip(2)
        .position(|pair| is_special(pair[0], ':') && is_special(pair[1], ']'))?
        + 2;
    let name: String = pattern[2..close].iter().map(|c| c.ch).collect();
    Some((Class::named(&name)?, close + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pattern with every character unquoted, except those after a backslash.
    fn pattern(text: &str) -> Vec<WordChar> {
        let mut out = Vec::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\'
                && let Some(next) = chars.next()
            {
                out.push(WordChar { ch: next, quoted: true });
            } else {
                out.push(WordChar { ch, quoted: false });
            }
        }
        out
    }

    fn check(p: &str, text: &str) -> bool {
        matches(&pattern(p), text)
    }

    #[test]
    fn literal_patterns_match_only_the_same_text() {
        assert!(check("abc", "abc"));
        assert!(!check("abc", "abcd"));
        assert!(!check("abc", "ab"));
        assert!(check("", ""));
        assert!(!check("", "a"));
    }

    #[test]
    fn star_and_question_mark() {
        assert!(check("*", ""));
        assert!(check("*", "anything"));
        assert!(check("a*c", "abbbc"));
        assert!(check("a*c", "ac"));
        assert!(!check("a*c", "abd"));
        assert!(check("*.rs", "main.rs"));
        assert!(check("?", "x"));
        assert!(!check("?", ""));
        assert!(check("a*b*c", "aXbYbZc"));
        assert!(check("**a", "a"));
    }

    #[test]
    fn quoted_specials_match_only_themselves() {
        assert!(check(r"\*", "*"));
        assert!(!check(r"\*", "x"));
        assert!(check(r"\?", "?"));
        assert!(!check(r"\[a]", "a"));
        assert!(check(r"\[a]", "[a]"));
    }

    #[test]
    fn bracket_expressions() {
        assert!(check("[abc]", "b"));
        assert!(!check("[abc]", "d"));
        assert!(check("[a-c]x", "bx"));
        assert!(check("[!a-c]", "d"));
        assert!(!check("[^a-c]", "a"));
        assert!(check("[]]", "]"));
        assert!(check("[!]]", "a"));
        assert!(check("[a-]", "-"));
        assert!(check("[[:digit:]]*", "7up"));
        assert!(!check("[[:upper:]]", "a"));
        assert!(check("[[:alpha:]_]", "_"));
    }

    #[test]
    fn an_unclosed_bracket_is_a_literal() {
        assert!(check("[ab", "[ab"));
        assert!(!check("[ab", "a"));
    }

    // CLAUDE.md "Untrusted input": a pathological pattern finishes quickly, without recursion.
    #[test]
    fn many_stars_do_not_explode() {
        let p = "*a".repeat(200) + "b";
        let text = "a".repeat(2000);
        assert!(!check(&p, &text));
    }
}
