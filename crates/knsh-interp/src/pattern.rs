//! Bash pattern matching for `case` (KNSH-096), the pattern operators of parameter expansion (KNSH-097) and pathname
//! expansion (KNSH-098): `*`, `?` and bracket expressions, with quoted characters matching only themselves; with
//! `extglob`, the groups `?(…)`, `*(…)`, `+(…)`, `@(…)` and `!(…)`; with `nocaseglob`, letters of either case.
//!
//! A pattern is compiled once ([`Pattern::new`]) and then matched against any number of texts. A pattern without
//! groups is matched iteratively, with one remembered `*` to backtrack to, so a hostile pattern costs at most
//! `O(pattern × text)` steps. A pattern with groups is matched by computing, for each piece of the pattern, the set
//! of text positions it can end at; the sets an alternative of a group reaches from a given start are computed once
//! and remembered, so the cost stays polynomial (no exponential backtracking), and recursion follows only the
//! nesting of groups, which the parser's limits and [`MAX_GROUP_DEPTH`] bound.

use std::collections::HashMap;

use crate::word::WordChar;

/// Deepest nesting of extended glob groups read as groups. Deeper groups are read as literal text, which keeps the
/// matcher's recursion bounded on untrusted input; the parser already stops at 32 levels of nesting.
pub(crate) const MAX_GROUP_DEPTH: usize = 64;

/// Most end positions the matcher for patterns with groups remembers at once (one byte each). The memo is a cache
/// of pure results, so past this bound it is emptied and refilled: memory stays bounded however long the text (a
/// `${x//+(a)/b}` over a long value would otherwise remember a set per alternative and start, quadratic in the text).
const MAX_MEMO_CELLS: usize = 1 << 26;

/// How a pattern is read and matched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Flags {
    /// `shopt -s extglob`: the groups are pattern operators, not literal text.
    pub(crate) extglob: bool,
    /// Letters match regardless of case (`nocaseglob` for file names).
    pub(crate) nocase: bool,
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    nodes: Vec<Node>,
    /// Whether any node is a group, which needs the set-based matcher.
    grouped: bool,
    nocase: bool,
    /// Whether the pattern was written empty.
    empty: bool,
}

/// One element of a compiled pattern.
#[derive(Debug, Clone)]
enum Node {
    /// A character that matches itself.
    Char(char),
    /// `?`.
    Any,
    /// `*`.
    Star,
    /// `[…]`.
    Bracket(Bracket),
    /// An extended glob group and its alternatives, each with the number the matcher remembers it by.
    Group(GroupKind, Vec<(usize, Vec<Node>)>),
}

/// Which extended glob group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupKind {
    /// `?(…)`: zero or one of the alternatives.
    Optional,
    /// `*(…)`: zero or more.
    Any,
    /// `+(…)`: one or more.
    Some,
    /// `@(…)`: exactly one.
    One,
    /// `!(…)`: anything except one of them.
    Not,
}

impl GroupKind {
    fn from_char(ch: char) -> Option<Self> {
        Some(match ch {
            '?' => Self::Optional,
            '*' => Self::Any,
            '+' => Self::Some,
            '@' => Self::One,
            '!' => Self::Not,
            _ => return None,
        })
    }
}

impl Pattern {
    /// Compiles `chars` (quoted characters match only themselves) read with `flags`.
    pub(crate) fn new(chars: &[WordChar], flags: Flags) -> Self {
        let mut compiler = Compiler {
            extglob: flags.extglob,
            alternatives: 0,
        };
        let nodes = compiler.sequence(chars, 0);
        let grouped = nodes.iter().any(|node| matches!(node, Node::Group(..)));
        Self {
            nodes,
            grouped,
            nocase: flags.nocase,
            empty: chars.is_empty(),
        }
    }

    /// Whether the pattern was written empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.empty
    }

    /// Whether `text` matches the pattern as a whole.
    pub(crate) fn matches_str(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        self.matches(&text)
    }

    /// Whether the characters `text` match the pattern as a whole.
    pub(crate) fn matches(&self, text: &[char]) -> bool {
        if !self.grouped {
            return self.matches_simple(text);
        }
        let mut matcher = SetMatcher {
            pattern: self,
            text,
            memo: HashMap::new(),
            cells: 0,
        };
        let ends = matcher.ends(&self.nodes, 0);
        ends.get(text.len()).copied().unwrap_or(false)
    }

    /// Whether `a` (from the text) matches the pattern character `b`.
    fn same(&self, a: char, b: char) -> bool {
        a == b || (self.nocase && fold(a) == fold(b))
    }

    fn bracket_matches(&self, bracket: &Bracket, ch: char) -> bool {
        if !self.nocase {
            return bracket.matches(ch);
        }
        bracket.matches(ch)
            || ch.to_lowercase().any(|c| bracket.matches(c))
            || ch.to_uppercase().any(|c| bracket.matches(c))
    }

    /// Whether `node` (not a group or a star) matches the character `ch`.
    fn single(&self, node: &Node, ch: char) -> bool {
        match node {
            Node::Char(c) => self.same(ch, *c),
            Node::Any => true,
            Node::Bracket(bracket) => self.bracket_matches(bracket, ch),
            Node::Star | Node::Group(..) => false,
        }
    }

    /// The matcher for patterns without groups: iterative, with one remembered `*` to backtrack to.
    fn matches_simple(&self, text: &[char]) -> bool {
        let pattern = &self.nodes;
        let (mut p, mut t) = (0, 0);
        // The position after the last `*` seen, and the text position it is currently made to swallow up to.
        let mut star: Option<(usize, usize)> = None;
        while t < text.len() {
            let step = match pattern.get(p) {
                Some(Node::Star) => {
                    star = Some((p + 1, t));
                    p += 1;
                    continue;
                }
                Some(node) => self.single(node, text[t]),
                None => false,
            };
            match (step, star) {
                (true, _) => {
                    p += 1;
                    t += 1;
                }
                // Let the last `*` swallow one more character and try again from just after it.
                (false, Some((after, swallowed))) => {
                    p = after;
                    t = swallowed + 1;
                    star = Some((after, swallowed + 1));
                }
                (false, None) => return false,
            }
        }
        pattern[p..].iter().all(|node| matches!(node, Node::Star))
    }
}

/// A character folded for case-insensitive comparison.
fn fold(ch: char) -> char {
    ch.to_lowercase().next().unwrap_or(ch)
}

/// Reads pattern characters into nodes.
struct Compiler {
    extglob: bool,
    /// Alternatives numbered so far.
    alternatives: usize,
}

impl Compiler {
    /// The nodes of `chars`, `depth` groups deep.
    fn sequence(&mut self, chars: &[WordChar], depth: usize) -> Vec<Node> {
        let mut nodes = Vec::new();
        let mut i = 0;
        while let Some(&c) = chars.get(i) {
            if self.extglob
                && depth < MAX_GROUP_DEPTH
                && !c.quoted
                && let Some(kind) = GroupKind::from_char(c.ch)
                && chars.get(i + 1).is_some_and(|next| is_special(*next, '('))
                && let Some((alternatives, len)) = group_at(&chars[i + 1..])
            {
                let alternatives = alternatives
                    .into_iter()
                    .map(|alternative| {
                        let id = self.alternatives;
                        self.alternatives += 1;
                        (id, self.sequence(alternative, depth + 1))
                    })
                    .collect();
                nodes.push(Node::Group(kind, alternatives));
                i += 1 + len;
                continue;
            }
            if c.quoted {
                nodes.push(Node::Char(c.ch));
                i += 1;
                continue;
            }
            match c.ch {
                '*' => {
                    // Consecutive stars are one star.
                    if !matches!(nodes.last(), Some(Node::Star)) {
                        nodes.push(Node::Star);
                    }
                    i += 1;
                }
                '?' => {
                    nodes.push(Node::Any);
                    i += 1;
                }
                '[' => {
                    if let Some(bracket) = parse_bracket(&chars[i..]) {
                        i += bracket.len;
                        nodes.push(Node::Bracket(bracket));
                    } else {
                        // A `[` that opens no complete expression matches only a literal `[`, as in bash.
                        nodes.push(Node::Char('['));
                        i += 1;
                    }
                }
                ch => {
                    nodes.push(Node::Char(ch));
                    i += 1;
                }
            }
        }
        nodes
    }
}

/// The alternatives of the group whose `(` starts `chars`, and how many characters it takes up to its `)`; `None`
/// when no unquoted `)` closes it (the text is then literal, as in bash). Bracket expressions and nested groups are
/// skipped as wholes, so a `|` or `)` inside them belongs to them.
fn group_at(chars: &[WordChar]) -> Option<(Vec<&[WordChar]>, usize)> {
    let mut alternatives = Vec::new();
    let mut nested = 0_usize;
    let mut start = 1;
    let mut i = 1;
    while let Some(&c) = chars.get(i) {
        if c.quoted {
            i += 1;
            continue;
        }
        match c.ch {
            '[' => {
                i += parse_bracket(&chars[i..]).map_or(1, |bracket| bracket.len);
                continue;
            }
            '(' => nested += 1,
            ')' if nested == 0 => {
                alternatives.push(&chars[start..i]);
                return Some((alternatives, i + 1));
            }
            ')' => nested -= 1,
            '|' if nested == 0 => {
                alternatives.push(&chars[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The matcher for patterns with groups: for a sequence of nodes and a start, the set of positions it can end at.
struct SetMatcher<'p, 't> {
    pattern: &'p Pattern,
    text: &'t [char],
    /// The end positions of each alternative (by number) from each start.
    memo: HashMap<(usize, usize), Vec<bool>>,
    /// End positions held by `memo`, against [`MAX_MEMO_CELLS`].
    cells: usize,
}

impl SetMatcher<'_, '_> {
    /// The positions (as a set over `0..=text.len()`) where `nodes` can end when started at `start`.
    fn ends(&mut self, nodes: &[Node], start: usize) -> Vec<bool> {
        let n = self.text.len();
        let mut current = vec![false; n + 1];
        current[start] = true;
        for node in nodes {
            let mut next = vec![false; n + 1];
            match node {
                Node::Star => {
                    if let Some(first) = current.iter().position(|&reached| reached) {
                        next[first..].iter_mut().for_each(|slot| *slot = true);
                    }
                }
                Node::Group(kind, alternatives) => {
                    for from in (0..=n).filter(|&p| current[p]) {
                        let reached = self.group(*kind, alternatives, from);
                        for (slot, hit) in next.iter_mut().zip(reached) {
                            *slot |= hit;
                        }
                    }
                }
                single => {
                    for p in (0..n).filter(|&p| current[p]) {
                        if self.pattern.single(single, self.text[p]) {
                            next[p + 1] = true;
                        }
                    }
                }
            }
            if !next.contains(&true) {
                return next;
            }
            current = next;
        }
        current
    }

    /// Where one alternative (number `id`) can end from `start`, computed once.
    fn alternative(&mut self, id: usize, nodes: &[Node], start: usize) -> Vec<bool> {
        if let Some(known) = self.memo.get(&(id, start)) {
            return known.clone();
        }
        let ends = self.ends(nodes, start);
        if self.cells.saturating_add(ends.len()) > MAX_MEMO_CELLS {
            self.memo.clear();
            self.cells = 0;
        }
        self.cells += ends.len();
        self.memo.insert((id, start), ends.clone());
        ends
    }

    /// Where any one of `alternatives` can end from `start`.
    fn one_of(&mut self, alternatives: &[(usize, Vec<Node>)], start: usize) -> Vec<bool> {
        let mut out = vec![false; self.text.len() + 1];
        for (id, nodes) in alternatives {
            let ends = self.alternative(*id, nodes, start);
            for (slot, hit) in out.iter_mut().zip(ends) {
                *slot |= hit;
            }
        }
        out
    }

    /// Where the group can end from `start`.
    fn group(&mut self, kind: GroupKind, alternatives: &[(usize, Vec<Node>)], start: usize) -> Vec<bool> {
        let n = self.text.len();
        match kind {
            GroupKind::One => self.one_of(alternatives, start),
            GroupKind::Optional => {
                let mut out = self.one_of(alternatives, start);
                out[start] = true;
                out
            }
            GroupKind::Any | GroupKind::Some => {
                // Repeat the alternatives from every position reached until nothing new is reached.
                let mut reached = vec![false; n + 1];
                let mut frontier = vec![start];
                let mut seen = vec![false; n + 1];
                seen[start] = true;
                while let Some(from) = frontier.pop() {
                    let ends = self.one_of(alternatives, from);
                    for (end, hit) in ends.into_iter().enumerate() {
                        if hit {
                            reached[end] = true;
                            if !seen[end] {
                                seen[end] = true;
                                frontier.push(end);
                            }
                        }
                    }
                }
                if kind == GroupKind::Any {
                    reached[start] = true;
                }
                reached
            }
            GroupKind::Not => {
                let excluded = self.one_of(alternatives, start);
                (0..=n).map(|end| end >= start && !excluded[end]).collect()
            }
        }
    }
}

/// Whether `c` is the unquoted pattern character `special`.
fn is_special(c: WordChar, special: char) -> bool {
    !c.quoted && c.ch == special
}

/// A bracket expression read from a pattern.
#[derive(Debug, Clone)]
struct Bracket {
    /// `[!…]` or `[^…]`.
    negated: bool,
    /// What it accepts.
    items: Vec<Item>,
    /// Pattern characters it takes, both brackets included.
    len: usize,
}

impl Bracket {
    fn matches(&self, ch: char) -> bool {
        let found = self.items.iter().any(|item| match *item {
            Item::Char(c) => c == ch,
            Item::Range(low, high) => low <= ch && ch <= high,
            Item::Class(class) => class.contains(ch),
        });
        found != self.negated
    }
}

/// One member of a bracket expression.
#[derive(Debug, Clone, Copy)]
enum Item {
    Char(char),
    Range(char, char),
    Class(Class),
}

/// The POSIX character classes `[:name:]`.
#[derive(Debug, Clone, Copy)]
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

/// Reads the bracket expression at the start of `pattern` (an unquoted `[`), or `None` if no unquoted `]` closes it.
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

/// The alternatives of the extended glob group `chars` starts with, when it starts with one: what pathname expansion
/// needs to decide whether a pattern starting with a group can match a name starting with `.`.
pub(crate) fn leading_group(chars: &[WordChar]) -> Option<(GroupKind, Vec<&[WordChar]>)> {
    let first = chars.first()?;
    if first.quoted || !chars.get(1).is_some_and(|next| is_special(*next, '(')) {
        return None;
    }
    let kind = GroupKind::from_char(first.ch)?;
    let (alternatives, _) = group_at(&chars[1..])?;
    Some((kind, alternatives))
}

/// Whether bash would match the word `chars` against file names: an unquoted `*` or `?`, an unquoted `[` with an
/// unquoted `]` after it, or (with `extglob`) an unquoted `+(`, `@(` or `!(` (bash's `unquoted_glob_pattern_p`).
pub(crate) fn has_glob(chars: &[WordChar], extglob: bool) -> bool {
    let mut open = false;
    for (i, c) in chars.iter().enumerate().filter(|(_, c)| !c.quoted) {
        match c.ch {
            '*' | '?' => return true,
            '[' => open = true,
            ']' if open => return true,
            '+' | '@' | '!' if extglob && chars.get(i + 1).is_some_and(|next| is_special(*next, '(')) => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A pattern with every character unquoted, except those after a backslash.
    pub(crate) fn chars(text: &str) -> Vec<WordChar> {
        let mut out = Vec::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\'
                && let Some(next) = chars.next()
            {
                out.push(WordChar {
                    ch: next,
                    quoted: true,
                    expanded: false,
                });
            } else {
                out.push(WordChar {
                    ch,
                    quoted: false,
                    expanded: false,
                });
            }
        }
        out
    }

    fn check(p: &str, text: &str) -> bool {
        Pattern::new(&chars(p), Flags::default()).matches_str(text)
    }

    fn ext(p: &str, text: &str) -> bool {
        Pattern::new(
            &chars(p),
            Flags {
                extglob: true,
                nocase: false,
            },
        )
        .matches_str(text)
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

    // KNSH-098: `nocaseglob` folds letters, in brackets too.
    #[test]
    fn nocase_matches_either_case() {
        let nocase = |p: &str, text: &str| {
            Pattern::new(
                &chars(p),
                Flags {
                    extglob: false,
                    nocase: true,
                },
            )
            .matches_str(text)
        };
        assert!(nocase("readme*", "README.md"));
        assert!(nocase("[a-c]x", "BX"));
        assert!(nocase("[[:lower:]]", "Q"));
        assert!(!nocase("a", "b"));
        assert!(!check("readme*", "README.md"));
    }

    // KNSH-098: the extended glob groups, as bash 5.2 matches them with `extglob` on.
    #[test]
    fn extglob_groups() {
        assert!(ext("@(a|b).rs", "a.rs"));
        assert!(!ext("@(a|b).rs", "ab.rs"));
        assert!(ext("?(x)y", "y"));
        assert!(ext("?(x)y", "xy"));
        assert!(!ext("?(x)y", "xxy"));
        assert!(ext("*(ab)", ""));
        assert!(ext("*(ab)", "ababab"));
        assert!(!ext("*(ab)", "aba"));
        assert!(!ext("+(ab)", ""));
        assert!(ext("+(ab|c)", "abcab"));
        assert!(ext("!(*.o)", "main.c"));
        assert!(!ext("!(*.o)", "main.o"));
        assert!(ext("!(a)", ""));
        assert!(ext("x!(y)z", "xz"));
        assert!(!ext("x!(y)z", "xyz"));
        assert!(ext("@(a|@(b|c))d", "cd"));
        assert!(ext("@([)]|x)", ")"));
        assert!(ext(r"@(a\|b)", "a|b"));
        // Without `extglob`, or unclosed, the characters are what they are.
        assert!(!check("@(a|b)", "a"));
        assert!(check("@(a|b)", "@(a|b)"));
        assert!(ext("@(a", "@(a"));
        assert!(ext("*(a", "x(a"));
    }

    // CLAUDE.md "Untrusted input": nested repetition is polynomial, not exponential.
    #[test]
    fn nested_groups_do_not_explode() {
        let text = "a".repeat(200) + "b";
        assert!(!ext("*(*(*(a|aa)))", &text));
        assert!(ext("*(*(*(a|aa)))b", &text));
        let deep = "@(".repeat(200) + "a" + &")".repeat(200);
        assert!(ext(&deep, "a") || !ext(&deep, "a"));
    }

    // CLAUDE.md "Untrusted input": the memo of the matcher for groups stays bounded on a long text (it would hold
    // a set per start otherwise, quadratic in the text), and emptying it changes no result.
    #[test]
    fn group_memo_stays_bounded_on_long_texts() {
        let pattern = Pattern::new(
            &chars("+(a)"),
            Flags {
                extglob: true,
                nocase: false,
            },
        );
        let text: Vec<char> = "a".repeat(9_000).chars().collect();
        let mut matcher = SetMatcher {
            pattern: &pattern,
            text: &text,
            memo: HashMap::new(),
            cells: 0,
        };
        let ends = matcher.ends(&pattern.nodes, 0);
        assert!(ends[text.len()]);
        assert!(matcher.cells <= MAX_MEMO_CELLS);
        assert!(matcher.memo.values().map(Vec::len).sum::<usize>() <= MAX_MEMO_CELLS);
    }

    #[test]
    fn glob_detection_follows_bash() {
        assert!(has_glob(&chars("*.rs"), false));
        assert!(has_glob(&chars("[ab]"), false));
        assert!(!has_glob(&chars("a]"), false));
        assert!(!has_glob(&chars(r"\*"), false));
        assert!(!has_glob(&chars("@(a)"), false));
        assert!(has_glob(&chars("@(a)"), true));
        assert!(has_glob(&chars("!(a)"), true));
        assert!(!has_glob(&chars(r"@\(a)"), true));
    }
}
