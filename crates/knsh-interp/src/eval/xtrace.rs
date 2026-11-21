//! `set -x` (KNSH-104; NFR-COMPAT-02): each command written to the shell's standard error after its expansion, after
//! `PS4`, as bash 5.2's `print_cmd.c` writes it.
//!
//! - `PS4` is decoded as a prompt (`\\`, `\a`, `\e`, `\n`, `\r` and octal escapes; the escapes that need the user,
//!   host, time or history are refused) and expanded as inside double quotes (its own double quotes kept, as bash's
//!   `expand_prompt_string` does). Its first character is repeated once more for each `eval` or `source` being run
//!   (bash's `indirection_level`). An empty or unset `PS4` writes no prefix.
//! - A simple command writes each assignment (`name=value`) on a line of its own, then its words; a word is quoted
//!   as bash's `xtrace_print_word_list` quotes it. `for` and `case` write their heads as written (bash 5.2 does not
//!   quote the words of a `for` head); `(( … ))` and each expression of an arithmetic `for` its expanded text;
//!   `[[ … ]]` each term it evaluates, with a pattern's quoted characters backslash-escaped.
//! - Forms whose trace bash 3.2 and 5.2 write differently, or that are not reproduced, are refused while `set -x` is
//!   on: a list assignment (`a=(…)`, `declare -a a=(…)`), an element assignment whose value holds an expansion.

use std::ffi::OsStr;

use knsh_bash::{Assignment, ForCommand, Span};

use super::{Flow, Interpreter, Run, unsupported};
use crate::error::Unsupported;
use crate::expand::Expander;
use crate::quote;
use crate::word;

/// The prompt escapes bash expands from the shell's environment or history, which are not reproduced in `PS4`.
const REFUSED_ESCAPES: &str = "dtT@AuhHwWsvV!#$jlD[]";

/// `PS4` decoded as bash's `decode_prompt_string` does, written back for an expansion as inside double quotes (an
/// escaped backslash stays escaped, so the expansion leaves one).
///
/// # Errors
///
/// [`Unsupported::PromptExpansion`] for an escape that needs the user, host, time, directory or history.
fn decode_prompt(text: &str) -> Result<String, Unsupported> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            None => out.push('\\'),
            Some('\\') => out.push_str("\\\\"),
            Some('a') => out.push('\x07'),
            Some('e') => out.push('\x1b'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(first @ '0'..='7') => {
                let mut value = first.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.peek().and_then(|next| next.to_digit(8)) {
                        Some(digit) => {
                            value = value * 8 + digit;
                            chars.next();
                        }
                        None => break,
                    }
                }
                let decoded = char::from_u32(value & 0xff).unwrap_or('\0');
                if matches!(decoded, '$' | '`' | '"' | '\\') {
                    out.push('\\');
                }
                out.push(decoded);
            }
            Some(escape) if REFUSED_ESCAPES.contains(escape) => return Err(Unsupported::PromptExpansion),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Ok(out)
}

impl Interpreter {
    /// The prefix of a trace line: `PS4` decoded and expanded, its first character repeated for each `eval` or
    /// `source` level.
    fn trace_prefix(&mut self, span: Span, run: &Run<'_>) -> Flow<String> {
        let Some(ps4) = self.state.variable("PS4") else {
            return Ok(String::new());
        };
        let Some(ps4) = ps4.to_str().map(str::to_owned) else {
            return Err(unsupported(Unsupported::NonUtf8Value, span).into());
        };
        if ps4.is_empty() {
            return Ok(String::new());
        }
        let decoded = decode_prompt(&ps4).map_err(|feature| unsupported(feature, span))?;
        let result = Expander::new(
            &mut self.state,
            &*self.homes,
            &*self.fs,
            &*self.collation,
            &decoded,
            &[],
        )
        .prompt_string(Span::new(0, decoded.len()));
        let expanded = self.expanded(result, span, run)?;
        let mut chars = expanded.chars();
        let Some(first) = chars.next() else {
            return Ok(String::new());
        };
        let mut prefix: String = std::iter::repeat_n(first, self.trace_level + 1).collect();
        prefix.push_str(chars.as_str());
        Ok(prefix)
    }

    /// Writes `body` as one trace line, under `set -x`.
    pub(super) fn trace(&mut self, body: &str, span: Span, run: &Run<'_>) -> Flow<()> {
        if !self.state.options().xtrace {
            return Ok(());
        }
        let mut line = self.trace_prefix(span, run)?;
        line.push_str(body);
        line.push('\n');
        self.write_shell(2, line.as_bytes());
        Ok(())
    }

    /// The words of a simple command, quoted as bash's trace quotes them. `lists`: a declaration builtin's argument
    /// held a list (`declare -a x=(…)`), whose trace is not reproduced.
    pub(super) fn trace_words(&mut self, words: &[String], lists: bool, span: Span, run: &Run<'_>) -> Flow<()> {
        if !self.state.options().xtrace {
            return Ok(());
        }
        if lists {
            return Err(unsupported(Unsupported::Trap, span).into());
        }
        let body: Vec<String> = words.iter().map(|word| quote::trace_word(word)).collect();
        self.trace(&body.join(" "), span, run)
    }

    /// An assignment of `value` to a variable: `name=value` or `name+=value`.
    pub(super) fn trace_assignment(&mut self, assignment: &Assignment, value: &OsStr, run: &Run<'_>) -> Flow<()> {
        if !self.state.options().xtrace {
            return Ok(());
        }
        let Some(value) = value.to_str() else {
            return Err(unsupported(Unsupported::NonUtf8Value, assignment.span).into());
        };
        let operator = if assignment.append { "+=" } else { "=" };
        let body = format!("{}{operator}{}", assignment.name, quote::trace_value(value));
        self.trace(&body, assignment.span, run)
    }

    /// An element assignment (`a[i]=v`, its subscript as written, as bash writes it) or a list assignment, refused:
    /// bash 3.2 and 5.2 write a list differently, and an element's value is written here only when it needs no
    /// expansion.
    pub(super) fn trace_array_assignment(&mut self, assignment: &Assignment, run: &Run<'_>) -> Flow<()> {
        if !self.state.options().xtrace {
            return Ok(());
        }
        let refused = || unsupported(Unsupported::Trap, assignment.span).into();
        let (None, Some(subscript)) = (&assignment.array, assignment.subscript) else {
            return Err(refused());
        };
        let parts = word::parts(&assignment.word.segments, run.source, assignment.value.start)?;
        let literal = word::literal(&parts).filter(|_| {
            !matches!(parts.first(), Some(crate::scan::Part::Text(text)) if text.starts_with('~'))
                && !parts
                    .iter()
                    .any(|part| matches!(part, crate::scan::Part::Text(text) if text.contains(":~")))
        });
        let Some(value) = literal else {
            return Err(refused());
        };
        let subscript = subscript.text(run.source).unwrap_or_default();
        let operator = if assignment.append { "+=" } else { "=" };
        let body = format!(
            "{}[{subscript}]{operator}{}",
            assignment.name,
            quote::trace_value(&value)
        );
        self.trace(&body, assignment.span, run)
    }

    /// The head of `for` as its trace writes it: `for name in words`, the words as written (`"$@"` without `in`).
    pub(super) fn for_head(command: &ForCommand, run: &Run<'_>) -> String {
        let name = command.variable.span.text(run.source).unwrap_or_default();
        let words = match &command.items {
            Some(items) => items
                .words
                .iter()
                .map(|item| item.span.text(run.source).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(" "),
            None => "\"$@\"".to_owned(),
        };
        format!("for {name} in {words}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-104: `PS4` is decoded as bash decodes a prompt; escapes needing the environment are refused.
    #[test]
    fn prompts_decode_like_bash() {
        assert_eq!(decode_prompt("+ "), Ok("+ ".to_owned()));
        assert_eq!(decode_prompt("++\\\\ "), Ok("++\\\\ ".to_owned()));
        assert_eq!(decode_prompt("\\n\\a"), Ok("\n\x07".to_owned()));
        assert_eq!(decode_prompt("\\044x"), Ok("\\$x".to_owned()));
        assert_eq!(decode_prompt("\\101"), Ok("A".to_owned()));
        assert_eq!(decode_prompt("\\q\\$"), Err(Unsupported::PromptExpansion));
        assert_eq!(decode_prompt("\\q"), Ok("\\q".to_owned()));
        assert_eq!(decode_prompt("\\w "), Err(Unsupported::PromptExpansion));
        assert_eq!(decode_prompt("x\\"), Ok("x\\".to_owned()));
    }
}
