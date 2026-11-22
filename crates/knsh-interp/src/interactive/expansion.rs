//! History expansion (KNSH-107): bash 5.2's `!` forms, applied to each line an interactive shell reads before it
//! is parsed, with `set -H` (`histexpand`).
//!
//! Supported, as bash's `history_expand`:
//!
//! - **Events:** `!!` (the previous line), `!n` (line `n`), `!-n` (`n` lines back), `!string` (the newest line
//!   starting with `string`), `!?string?` (the newest line containing it), `!#` (the line typed so far), and
//!   `^old^new^` at the start of the line (`!!:s^old^new^`).
//! - **Word designators,** after `:` or directly after the event for `^ $ * - %`: `n`, `^`, `$`, `%`, `x-y`,
//!   `-y`, `x-`, `x*`, `*`. Words are split as bash's `history_tokenize`: blanks separate them, quotes and
//!   backslashes keep them together, and the shell's operators are words of their own.
//! - **Modifiers:** `:h :t :r :e :p :q :x :s/old/new/ :&` and `:g` or `:a` before `s` or `&`.
//!
//! Not expanded, as in bash: `!` before a blank, `=`, a newline or the end of the line; `!` inside single quotes;
//! `!` before the closing double quote; `!` after `\`; `[!…]` patterns, `${!…}`, and `!(…)` with `extglob`.
//!
//! Errors are bash's (`!x: event not found`, `:9: bad word specifier`, `:s^a^b: substitution failed`,
//! `:z: unrecognized history modifier`); `:G` is reported as not supported ([`HistoryError::Unsupported`]) rather
//! than expanded differently. A line that fails to expand is not run.

use std::fmt;

use super::history::History;

/// Why a line could not be expanded. Each holds the part of the line bash names in its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryError {
    /// `!x: event not found`.
    EventNotFound(String),
    /// `:9: bad word specifier`.
    BadWordSpecifier(String),
    /// `:s/a/b/: substitution failed`.
    SubstitutionFailed(String),
    /// `:z: unrecognized history modifier`.
    BadModifier(String),
    /// `:&` or an empty `:s` pattern with no earlier substitution: `no previous substitution`.
    NoPreviousSubstitution,
    /// A form bash has that is not supported here.
    Unsupported(String),
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventNotFound(text) => write!(f, "{text}: event not found"),
            Self::BadWordSpecifier(text) => write!(f, "{text}: bad word specifier"),
            Self::SubstitutionFailed(text) => write!(f, "{text}: substitution failed"),
            Self::BadModifier(text) => write!(f, "{text}: unrecognized history modifier"),
            Self::NoPreviousSubstitution => f.write_str("no previous substitution"),
            Self::Unsupported(text) => write!(f, "{text}: history expansion form not supported (KNSH-107)"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// A line after history expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    /// The expanded line.
    pub line: String,
    /// A `:p` modifier was used: the line is shown and saved, not run.
    pub print_only: bool,
}

/// The words of `line` as bash's `history_tokenize` splits them.
#[must_use]
pub fn words(line: &str) -> Vec<&str> {
    const OPERATORS: &[&str] = &[
        ";;&", "&>>", ";;", ";&", "&&", "||", ">>", "<<", ">&", "<&", "&>", ">|", "<>", ";", "&", "|", "(", ")", "<",
        ">",
    ];
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if let Some(operator) = OPERATORS.iter().find(|operator| line[i..].starts_with(**operator)) {
            out.push(&line[i..i + operator.len()]);
            i += operator.len();
            continue;
        }
        let start = i;
        let mut quote: Option<u8> = None;
        while i < bytes.len() {
            let byte = bytes[i];
            match quote {
                Some(open) if byte == open => quote = None,
                Some(b'"') | None if byte == b'\\' => i += 1,
                None if byte == b'\'' || byte == b'"' => quote = Some(byte),
                None if byte.is_ascii_whitespace() || b";&|()<>".contains(&byte) => break,
                Some(_) | None => {}
            }
            i += 1;
        }
        let end = i.min(bytes.len());
        // A backslash at the very end may have stepped past a multi-byte character: back to a boundary.
        let mut end = end;
        while !line.is_char_boundary(end) {
            end += 1;
        }
        out.push(&line[start..end]);
        i = end;
    }
    out
}

/// Characters that end `!string`: blanks, `:` and bash's `history_search_delimiter_chars`.
fn ends_search_string(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, ':' | ';' | '&' | '(' | ')' | '|' | '<' | '>')
}

/// The state of one expansion.
struct Expander<'a> {
    line: &'a str,
    history: &'a History,
    extglob: bool,
    out: String,
    /// The string the last `!?string?` searched for (`%` names the word it matched).
    search: Option<String>,
    /// The word `!?string?` matched in its line.
    search_word: Option<usize>,
    /// The last `:s` pattern and replacement.
    substitution: Option<(String, String)>,
    print_only: bool,
}

/// Expands `line` with `history` (the lines before it); `extglob` keeps `!(…)` as a pattern. `Ok(None)` when the
/// line holds nothing to expand.
///
/// # Errors
///
/// A [`HistoryError`] as bash reports it; the line must then not run.
pub fn expand(line: &str, history: &History, extglob: bool) -> Result<Option<Expansion>, HistoryError> {
    if !line.contains('!') && !line.starts_with('^') {
        return Ok(None);
    }
    // `^old^new^` is `!!:s^old^new^`, as bash rewrites it.
    let quick;
    let line = if line.starts_with('^') {
        quick = format!("!!:s{line}");
        quick.as_str()
    } else {
        line
    };
    let mut expander = Expander {
        line,
        history,
        extglob,
        out: String::with_capacity(line.len()),
        search: None,
        search_word: None,
        substitution: None,
        print_only: false,
    };
    let changed = expander.run()?;
    let Expander { out, print_only, .. } = expander;
    Ok(changed.then_some(Expansion { line: out, print_only }))
}

impl Expander<'_> {
    /// Copies the line to `out`, expanding each `!`: whether anything was expanded.
    fn run(&mut self) -> Result<bool, HistoryError> {
        let line = self.line;
        let mut changed = false;
        let mut double = false;
        let mut chars = line.char_indices().peekable();
        while let Some((i, ch)) = chars.next() {
            match ch {
                '\'' if !double => {
                    // Copied through the closing quote.
                    self.out.push(ch);
                    for (_, inner) in chars.by_ref() {
                        self.out.push(inner);
                        if inner == '\'' {
                            break;
                        }
                    }
                }
                '"' => {
                    double = !double;
                    self.out.push(ch);
                }
                '\\' => {
                    self.out.push(ch);
                    if let Some((_, next)) = chars.next() {
                        self.out.push(next);
                    }
                }
                '!' if self.expands_at(i, double) => {
                    let end = self.event(i + 1, double)?;
                    changed = true;
                    // Skip what the event spanned.
                    while chars.peek().is_some_and(|(at, _)| *at < end) {
                        chars.next();
                    }
                }
                _ => self.out.push(ch),
            }
        }
        Ok(changed)
    }

    /// Whether the `!` at byte `i` starts an expansion (`double`: inside double quotes).
    fn expands_at(&self, i: usize, double: bool) -> bool {
        let line = self.line;
        let next = line[i + 1..].chars().next();
        match next {
            None => return false,
            Some(ch) if ch.is_whitespace() || ch == '=' => return false,
            Some('"') if double => return false,
            Some('(') if self.extglob && line[i + 2..].contains(')') => return false,
            Some(_) => {}
        }
        let before = &line[..i];
        // `[!…]` and `${!…}`, as bash's `bash_history_inhibit_expansion`.
        if before.ends_with('[') && line[i + 1..].contains(']') {
            return false;
        }
        !before.ends_with("${")
    }

    /// Expands the event starting at byte `start` (after `!`), appending its text: the byte after it.
    #[allow(clippy::too_many_lines)] // Events, designators and modifiers in bash's order, as `history_expand_internal`.
    fn event(&mut self, start: usize, double: bool) -> Result<usize, HistoryError> {
        let line = self.line;
        let rest = &line[start..];
        let entries = self.history.entries();
        let previous = || entries.last().map(String::as_str);
        let (text, mut end, spec): (Option<String>, usize, &str) = match rest.chars().next() {
            Some('!') => (previous().map(str::to_owned), start + 1, "!!"),
            Some('#') => (Some(self.out.clone()), start + 1, "!#"),
            Some(':' | '^' | '$' | '*' | '%') => (previous().map(str::to_owned), start, "!"),
            Some(ch) if ch.is_ascii_digit() || (ch == '-' && rest[1..].starts_with(|c: char| c.is_ascii_digit())) => {
                let digits = rest
                    .bytes()
                    .skip(usize::from(ch == '-'))
                    .take_while(u8::is_ascii_digit)
                    .count();
                let len = digits + usize::from(ch == '-');
                let number: usize = rest[usize::from(ch == '-')..len].parse().unwrap_or(usize::MAX);
                let found = if ch == '-' {
                    entries.len().checked_sub(number).and_then(|index| entries.get(index))
                } else {
                    self.history.get(number).map(|_| &entries[number - self.history.base()])
                };
                (found.cloned(), start + len, &line[start - 1..start + len])
            }
            Some('?') => {
                let body = &rest[1..];
                let len = body.find(['?', '\n']).unwrap_or(body.len());
                let needle = &body[..len];
                let closed = body[len..].starts_with('?');
                let end = start + 1 + len + usize::from(closed);
                let found = entries
                    .iter()
                    .rev()
                    .find(|entry| !needle.is_empty() && entry.contains(needle));
                self.search = Some(needle.to_owned());
                self.search_word = found.and_then(|entry| words(entry).iter().position(|word| word.contains(needle)));
                (found.cloned(), end, &line[start - 1..end])
            }
            Some(_) => {
                let len = rest
                    .char_indices()
                    .find(|(_, ch)| ends_search_string(*ch) || (double && *ch == '"'))
                    .map_or(rest.len(), |(at, _)| at);
                let prefix = &rest[..len];
                let found = entries.iter().rev().find(|entry| entry.starts_with(prefix));
                (found.cloned(), start + len, &line[start - 1..start + len])
            }
            None => (None, start, "!"),
        };
        let Some(event) = text else {
            return Err(HistoryError::EventNotFound(spec.to_owned()));
        };
        // Word designators.
        let mut value = event.clone();
        let rest = &line[end..];
        let designated = if let Some(after) = rest.strip_prefix(':') {
            after.starts_with(|ch: char| ch.is_ascii_digit() || matches!(ch, '^' | '$' | '*' | '%' | '-'))
        } else {
            rest.starts_with(['^', '$', '*', '%']) || (rest.starts_with('-') && spec != "!")
        };
        if designated {
            let colon = usize::from(rest.starts_with(':'));
            let (selected, len) = self
                .designate(&event, &rest[colon..])
                .map_err(|len| HistoryError::BadWordSpecifier(line[end..end + colon + len].to_owned()))?;
            value = selected;
            end += colon + len;
        }
        // Modifiers.
        while let Some(after) = line[end..].strip_prefix(':') {
            let modifier_start = end;
            end += 1;
            let mut global = false;
            let mut letter = after.chars().next();
            if matches!(letter, Some('g' | 'a')) {
                global = true;
                end += 1;
                letter = line[end..].chars().next();
            }
            match letter {
                Some('h') => {
                    if let Some(slash) = value.rfind('/') {
                        value.truncate(slash.max(usize::from(slash == 0)));
                    }
                    end += 1;
                }
                Some('t') => {
                    if let Some(slash) = value.rfind('/') {
                        value = value[slash + 1..].to_owned();
                    }
                    end += 1;
                }
                Some('r') => {
                    if let Some(dot) = suffix_dot(&value) {
                        value.truncate(dot);
                    }
                    end += 1;
                }
                Some('e') => {
                    value = suffix_dot(&value).map_or_else(String::new, |dot| value[dot..].to_owned());
                    end += 1;
                }
                Some('p') => {
                    self.print_only = true;
                    end += 1;
                }
                Some('q') => {
                    value = single_quote(&value);
                    end += 1;
                }
                Some('x') => {
                    value = words_of_blanks(&value)
                        .iter()
                        .map(|word| single_quote(word))
                        .collect::<Vec<_>>()
                        .join(" ");
                    end += 1;
                }
                Some('s') => {
                    let (pattern, replacement, len) = parse_substitution(&line[end + 1..]);
                    end += 1 + len;
                    let pattern = if pattern.is_empty() {
                        self.substitution
                            .as_ref()
                            .map(|(old, _)| old.clone())
                            .or_else(|| self.search.clone())
                            .ok_or(HistoryError::NoPreviousSubstitution)?
                    } else {
                        pattern
                    };
                    let replacement = replacement.replace('&', &pattern);
                    self.substitution = Some((pattern.clone(), replacement.clone()));
                    value = substitute(&value, &pattern, &replacement, global)
                        .ok_or_else(|| HistoryError::SubstitutionFailed(line[modifier_start..end].to_owned()))?;
                }
                Some('&') => {
                    end += 1;
                    let (pattern, replacement) =
                        self.substitution.clone().ok_or(HistoryError::NoPreviousSubstitution)?;
                    value = substitute(&value, &pattern, &replacement, global)
                        .ok_or_else(|| HistoryError::SubstitutionFailed(line[modifier_start..end].to_owned()))?;
                }
                Some('G') => {
                    return Err(HistoryError::Unsupported(line[modifier_start..=end].to_owned()));
                }
                Some(other) => {
                    return Err(HistoryError::BadModifier(
                        line[modifier_start..end + other.len_utf8()].to_owned(),
                    ));
                }
                None => return Err(HistoryError::BadModifier(line[modifier_start..end].to_owned())),
            }
        }
        self.out.push_str(&value);
        Ok(end)
    }

    /// The words of `event` that designator `spec` (after any `:`) selects, joined by spaces, and the designator's
    /// length; `Err(length)` for a bad one.
    fn designate(&self, event: &str, spec: &str) -> Result<(String, usize), usize> {
        let all = words(event);
        let last = all.len().saturating_sub(1);
        let number = |text: &str| -> (Option<usize>, usize) {
            let len = text.bytes().take_while(u8::is_ascii_digit).count();
            (text[..len].parse().ok(), len)
        };
        let bound = |at: &str| -> (Option<usize>, usize) {
            match at.chars().next() {
                Some('^') => (Some(1), 1),
                Some('$') => (Some(last), 1),
                Some('%') => (self.search_word, 1),
                Some(ch) if ch.is_ascii_digit() => number(at),
                _ => (None, 0),
            }
        };
        let (first, mut len) = match spec.chars().next() {
            Some('*') => {
                let words = all.get(1..).map(|rest| rest.join(" ")).unwrap_or_default();
                return Ok((words, 1));
            }
            Some('-') => (Some(0), 0),
            _ => bound(spec),
        };
        let first = first.ok_or(len.max(1))?;
        let (from, to) = if spec[len..].starts_with('*') {
            len += 1;
            (first, Some(last))
        } else if spec[len..].starts_with('-') {
            len += 1;
            let (to, to_len) = bound(&spec[len..]);
            len += to_len;
            match to {
                Some(to) => (first, Some(to)),
                // `x-`: up to the word before the last.
                None if to_len == 0 => (first, last.checked_sub(1)),
                None => return Err(len),
            }
        } else {
            (first, Some(first))
        };
        let Some(to) = to else {
            return Err(len);
        };
        if from > to {
            // `x*` past the last word is empty, as in bash; other inverted ranges are errors.
            if spec[..len].ends_with('*') && from == last + 1 {
                return Ok((String::new(), len));
            }
            return Err(len);
        }
        if to > last || all.is_empty() {
            return Err(len);
        }
        Ok((all[from..=to].join(" "), len))
    }
}

/// The offset of the `.` starting a file name's suffix (after the last `/`), as `:r` and `:e` find it.
fn suffix_dot(value: &str) -> Option<usize> {
    let dot = value.rfind('.')?;
    match value.rfind('/') {
        Some(slash) if slash > dot => None,
        _ => Some(dot),
    }
}

/// `value` in single quotes, each `'` written as `'\''` (`:q`).
fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// `value` split at blanks only (`:x`).
fn words_of_blanks(value: &str) -> Vec<&str> {
    value.split_whitespace().collect()
}

/// The pattern and replacement of `:s` written as `/old/new/` (any delimiter, `\` quoting it, the last delimiter
/// optional at the end of the line), and the bytes they took.
fn parse_substitution(text: &str) -> (String, String, usize) {
    let mut chars = text.char_indices();
    let Some((_, delimiter)) = chars.next() else {
        return (String::new(), String::new(), 0);
    };
    let mut parts = [String::new(), String::new()];
    let mut part = 0;
    let mut end = text.len();
    while let Some((at, ch)) = chars.next() {
        if ch == '\\' {
            if let Some((_, next)) = chars.next() {
                if next != delimiter {
                    parts[part].push('\\');
                }
                parts[part].push(next);
            }
            continue;
        }
        if ch == delimiter {
            if part == 1 {
                end = at + ch.len_utf8();
                break;
            }
            part = 1;
            continue;
        }
        if part == 1 && ch == '\n' {
            end = at;
            break;
        }
        parts[part].push(ch);
    }
    let [pattern, replacement] = parts;
    (pattern, replacement, end)
}

/// `value` with the first (every, with `global`) `pattern` replaced: `None` when it is not there.
fn substitute(value: &str, pattern: &str, replacement: &str, global: bool) -> Option<String> {
    if pattern.is_empty() || !value.contains(pattern) {
        return None;
    }
    Some(if global {
        value.replace(pattern, replacement)
    } else {
        value.replacen(pattern, replacement, 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interactive::history::HistControl;

    fn history(lines: &[&str]) -> History {
        let mut history = History::new();
        for line in lines {
            history.add(line, HistControl::default(), None);
        }
        history
    }

    fn expanded(line: &str, lines: &[&str]) -> Result<String, HistoryError> {
        expand(line, &history(lines), false).map(|expansion| expansion.map_or_else(|| line.to_owned(), |e| e.line))
    }

    // KNSH-107: `!!` is the previous line, inside a larger line too.
    #[test]
    fn history_expansion_bang_bang() {
        assert_eq!(expanded("!!", &["echo a b c"]).unwrap(), "echo a b c");
        assert_eq!(expanded("sudo !! | wc", &["ls -l"]).unwrap(), "sudo ls -l | wc");
        assert_eq!(expanded("!!", &[]), Err(HistoryError::EventNotFound("!!".into())));
        assert_eq!(expand("echo plain", &history(&["x"]), false).unwrap(), None);
    }

    // Each case below was checked against bash 3.2 (`bash -i` reading the lines); bash 5.2 agrees.
    #[test]
    fn events_and_words_match_bash() {
        let lines = ["echo a b c", "ls -l /tmp", "echo x"];
        assert_eq!(expanded("!1", &lines).unwrap(), "echo a b c");
        assert_eq!(expanded("!-2", &lines).unwrap(), "ls -l /tmp");
        assert_eq!(expanded("!ls", &lines).unwrap(), "ls -l /tmp");
        assert_eq!(expanded("!?a b?", &lines).unwrap(), "echo a b c");
        assert_eq!(expanded("cat !$", &lines).unwrap(), "cat x");
        assert_eq!(expanded("cat !-2:$", &lines).unwrap(), "cat /tmp");
        assert_eq!(expanded("!1:^", &lines).unwrap(), "a");
        assert_eq!(expanded("!1:*", &lines).unwrap(), "a b c");
        assert_eq!(expanded("!1:2*", &lines).unwrap(), "b c");
        assert_eq!(expanded("!1:0-1", &lines).unwrap(), "echo a");
        assert_eq!(expanded("!1:1-", &lines).unwrap(), "a b");
        assert_eq!(expanded("!1:-2", &lines).unwrap(), "echo a b");
        assert_eq!(expanded("echo !*", &lines).unwrap(), "echo x");
        assert_eq!(
            expanded("echo $((1+2)) !#", &lines).unwrap(),
            "echo $((1+2)) echo $((1+2)) "
        );
        assert_eq!(
            expanded("!!:9", &lines),
            Err(HistoryError::BadWordSpecifier(":9".into()))
        );
        assert_eq!(
            expanded("!nosuch", &lines),
            Err(HistoryError::EventNotFound("!nosuch".into()))
        );
        assert_eq!(expanded("!99", &lines), Err(HistoryError::EventNotFound("!99".into())));
    }

    #[test]
    fn modifiers_match_bash() {
        let lines = ["vi /usr/local/lib/file.tar.gz", "echo \"x\" 'c'"];
        assert_eq!(expanded("!-2:$:h", &lines).unwrap(), "/usr/local/lib");
        assert_eq!(expanded("!-2:$:t", &lines).unwrap(), "file.tar.gz");
        assert_eq!(expanded("!-2:$:r", &lines).unwrap(), "/usr/local/lib/file.tar");
        assert_eq!(expanded("!-2:$:e", &lines).unwrap(), ".gz");
        assert_eq!(expanded("!!:s/x/y/", &lines).unwrap(), "echo \"y\" 'c'");
        assert_eq!(expanded("!!:q", &lines).unwrap(), "'echo \"x\" '\\''c'\\'''");
        assert_eq!(expanded("!-2:x", &lines).unwrap(), "'vi' '/usr/local/lib/file.tar.gz'");
        assert_eq!(expanded("^x^z", &lines).unwrap(), "echo \"z\" 'c'");
        assert_eq!(
            expanded("^q^z", &lines),
            Err(HistoryError::SubstitutionFailed(":s^q^z".into()))
        );
        assert_eq!(expanded("!!:gs/l/L/", &["ls -l"]).unwrap(), "Ls -L");
        assert_eq!(expanded("!!:s/l/L/:&", &["ls -l"]).unwrap(), "Ls -L");
        assert_eq!(expanded("!!:z", &lines), Err(HistoryError::BadModifier(":z".into())));
        assert!(matches!(expanded("!!:G", &lines), Err(HistoryError::Unsupported(_))));
        let print = expand("!!:p", &history(&["ls"]), false).unwrap().unwrap();
        assert!(print.print_only);
        assert_eq!(print.line, "ls");
    }

    #[test]
    fn quoted_and_literal_bangs_are_kept() {
        let lines = ["ls"];
        for line in [
            "echo '!!'",
            "echo \\!!",
            "echo ! x",
            "echo !",
            "a!=b",
            "echo \"hi!\"",
            "echo [!a]",
            "echo ${!PS*}",
        ] {
            assert_eq!(expanded(line, &lines).unwrap(), line, "{line}");
        }
        assert_eq!(expand("echo !(a)", &history(&lines), true).unwrap(), None);
        assert_eq!(expanded("echo \"!!\"", &lines).unwrap(), "echo \"ls\"");
    }

    #[test]
    fn words_split_like_history_tokenize() {
        assert_eq!(
            words("echo 'a b' c\\ d>out;x&&y"),
            ["echo", "'a b'", "c\\ d", ">", "out", ";", "x", "&&", "y"]
        );
        assert_eq!(words("  "), Vec::<&str>::new());
        assert_eq!(words("é \\"), ["é", "\\"]);
    }

    #[test]
    fn errors_name_what_bash_names() {
        assert_eq!(
            HistoryError::EventNotFound("!x".into()).to_string(),
            "!x: event not found"
        );
        assert_eq!(
            HistoryError::BadWordSpecifier(":9".into()).to_string(),
            ":9: bad word specifier"
        );
        assert_eq!(
            HistoryError::SubstitutionFailed(":s^x^z".into()).to_string(),
            ":s^x^z: substitution failed"
        );
    }
}
