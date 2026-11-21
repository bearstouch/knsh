//! Bash's quoting of values in the output of builtins (KNSH-101): `declare -p` and `export -p` (`sh_double_quote`,
//! or `ansic_quote` for a value with a control character), `alias` (`sh_single_quote`).

/// Bash's `sh_single_quote`: `'…'`, each `'` written as `'\''`.
pub(crate) fn single(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Bash's `sh_quote_reusable` for a word: as it is unless it holds a character the shell reads specially, then
/// [`single`]-quoted (`$'…'` for a control character).
pub(crate) fn reusable(text: &str) -> String {
    if text.is_empty() {
        return "''".to_owned();
    }
    if text.chars().any(char::is_control) {
        return ansi_c(text);
    }
    let special = |ch: char| " \t\n'\"\\|&;()<>!{}*[?]^$`~#=%".contains(ch);
    if text.chars().any(special) {
        single(text)
    } else {
        text.to_owned()
    }
}

/// A value as `declare -p` prints it: `$'…'` (bash's `ansic_quote`) when it holds a character that is not
/// printable, otherwise `"…"` with `"`, `$`, `` ` `` and `\` escaped (bash's `sh_double_quote`).
pub(crate) fn declare_value(text: &str) -> String {
    if text.chars().any(char::is_control) {
        return ansi_c(text);
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        if matches!(ch, '"' | '$' | '`' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Bash's `ansic_quote`: `$'…'` with the C escapes, `\'` and `\\`, and other control characters in octal.
fn ansi_c(text: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(text.len() + 3);
    out.push_str("$'");
    for ch in text.chars() {
        match ch {
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            '\x1b' => out.push_str("\\E"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            ch if ch.is_control() => {
                let mut bytes = [0; 4];
                for byte in ch.encode_utf8(&mut bytes).bytes() {
                    // Writing to a String cannot fail.
                    let _ = write!(out, "\\{byte:03o}");
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quotes_like_sh_single_quote() {
        assert_eq!(single("ls -l"), "'ls -l'");
        assert_eq!(single("it's"), "'it'\\''s'");
        assert_eq!(single(""), "''");
    }

    // KNSH-101: `declare -p` output, checked against bash (`declare -x y="a\"b\$c"`).
    #[test]
    fn declare_values_are_double_quoted_or_ansi_c_quoted() {
        assert_eq!(declare_value("1"), "\"1\"");
        assert_eq!(declare_value("a\"b$c`d\\"), "\"a\\\"b\\$c\\`d\\\\\"");
        assert_eq!(declare_value("a\nb'"), "$'a\\nb\\''");
        assert_eq!(declare_value("\x01"), "$'\\001'");
    }
}
