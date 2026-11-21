//! Evaluating `[[ … ]]` (KNSH-102; NFR-COMPAT-02), as bash 5.2's `execute_cond_node` does.
//!
//! - Each word is expanded without word splitting or pathname expansion (tilde, parameter and arithmetic expansion,
//!   quote removal), and only when it is reached: `&&` and `||` short-circuit.
//! - `==`, `=` and `!=` match the right side as a pattern (extended-glob groups always read, as bash 4.1 and later
//!   do inside `[[`), its quoted characters matching themselves.
//! - `=~` matches the right side as a POSIX extended regular expression with the system's `regcomp` and `regexec`
//!   ([`knsh_platform::regex_match`], in the shell's `LC_ALL`, `LC_CTYPE` or `LANG` locale). Quoted characters
//!   match themselves (bash backslash-escapes them outside bracket expressions). The match and each subexpression
//!   go to `BASH_REMATCH` (empty when it fails); an invalid expression is status 2, without a message, as in bash.
//! - `-eq`, `-ne`, `-lt`, `-le`, `-gt` and `-ge` evaluate both sides as arithmetic expressions; an error there is
//!   reported (`[[: …`) and the test is false.
//! - `<` and `>` compare in the locale's collation; the other operators are `test`'s.
//!
//! The status is 0 when the expression is true, 1 when false, 2 for an invalid regular expression.

use knsh_bash::{Span, UnsupportedCommand};

use super::test::{compare_integers, is_arithmetic_operator};
use super::{Flow, Interpreter, Run, Stop, trailing_redirection, unsupported};
use crate::cond::{self, Expr, Operand, OperandKind};
use crate::error::Unsupported;
use crate::pattern::{Flags, Pattern};
use crate::scan::{self, Mode};
use crate::status::Status;
use crate::word::WordChar;

/// How a conditional expression ended.
enum Truth {
    /// It is true or false.
    Is(bool),
    /// A regular expression in it is invalid: status 2.
    BadRegex,
}

/// The characters special to a POSIX extended regular expression outside a bracket expression.
const REGEX_SPECIALS: &str = ".[]()*+?{}|^$\\";

/// The regular expression `chars` spell: quoted characters escaped where the system would read them specially, as
/// bash's `quote_string_for_globbing` with `QGLOB_REGEXP` does (inside a bracket expression a backslash is literal,
/// so a quoted character there is left as it is).
fn regex_text(chars: &[WordChar]) -> String {
    let mut out = String::with_capacity(chars.len() * 2);
    let mut in_bracket = false;
    // Characters since the bracket opened, for a `]` that is literal as the first one (`[]a]`, `[^]a]`).
    let mut bracket_len = 0_usize;
    for (index, c) in chars.iter().enumerate() {
        if in_bracket {
            let literal_close = bracket_len == 0
                || (bracket_len == 1 && chars.get(index - 1).is_some_and(|prev| prev.ch == '^' && !prev.quoted));
            if c.ch == ']' && !c.quoted && !literal_close {
                in_bracket = false;
            }
            bracket_len += 1;
            out.push(c.ch);
            continue;
        }
        if c.quoted {
            if REGEX_SPECIALS.contains(c.ch) {
                out.push('\\');
            }
            out.push(c.ch);
            continue;
        }
        if c.ch == '[' {
            in_bracket = true;
            bracket_len = 0;
        }
        out.push(c.ch);
    }
    out
}

impl Interpreter {
    /// `[[ … ]]` spanning `construct`.
    pub(super) fn conditional_command(&mut self, construct: &UnsupportedCommand, run: &Run<'_>) -> Flow<Status> {
        let conditional = cond::parse(run.source, construct.span)?;
        if let Some(redirect) = trailing_redirection(run.source, conditional.close.end, construct.span) {
            return Err(unsupported(Unsupported::Conditional, redirect).into());
        }
        // KNSH-104: the `DEBUG` trap runs before any word is expanded.
        self.debug_trap(construct.span, run)?;
        Ok(match self.condition(&conditional.expr, false, construct.span, run)? {
            Truth::Is(true) => Status::SUCCESS,
            Truth::Is(false) => Status::FAILURE,
            Truth::BadRegex => Status::new(2),
        })
    }

    /// Bash's `execute_cond_node`: `!`, `&&` and `||` look only at whether a status is 0, so an invalid regular
    /// expression's 2 is false to them (`! a =~ (` is 0, `a =~ ( || b` runs `b`), and stays 2 only when it is the
    /// status the expression ends with.
    ///
    /// `inverted`: an odd number of `!` stand directly before this node, which `set -x` writes before a term, as
    /// bash's parser marks the term itself (KNSH-104).
    fn condition(&mut self, expr: &Expr, inverted: bool, span: Span, run: &Run<'_>) -> Flow<Truth> {
        Ok(match expr {
            Expr::Not(inner) => match self.condition(inner, !inverted, span, run)? {
                Truth::Is(value) => Truth::Is(!value),
                Truth::BadRegex => Truth::Is(true),
            },
            Expr::And(left, right) => match self.condition(left, false, span, run)? {
                Truth::Is(true) => self.condition(right, false, span, run)?,
                other @ (Truth::Is(false) | Truth::BadRegex) => other,
            },
            Expr::Or(left, right) => match self.condition(left, false, span, run)? {
                Truth::Is(false) | Truth::BadRegex => self.condition(right, false, span, run)?,
                Truth::Is(true) => Truth::Is(true),
            },
            Expr::Unary { op, operand } => {
                let value = self.operand_string(*operand, run)?;
                let bang = if inverted { "! " } else { "" };
                self.trace(&format!("[[ {bang}{op} {} ]]", or_empty(&value)), span, run)?;
                Truth::Is(self.unary_test(op, &value, operand.span, run)?)
            }
            Expr::Binary { op, left, right } => self.binary_condition(op, *left, *right, inverted, span, run)?,
        })
    }

    /// Writes a binary term under `set -x`: `[[ left op right ]]`, an empty side as `''`.
    fn trace_binary(
        &mut self,
        inverted: bool,
        left: &str,
        op: &str,
        right: &str,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<()> {
        let bang = if inverted { "! " } else { "" };
        self.trace(
            &format!("[[ {bang}{} {op} {} ]]", or_empty(left), or_empty(right)),
            span,
            run,
        )
    }

    fn binary_condition(
        &mut self,
        op: &str,
        left: Operand,
        right: Operand,
        inverted: bool,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Truth> {
        let subject = self.operand_string(left, run)?;
        match right.kind {
            OperandKind::Regex => {
                if self.state.options().xtrace {
                    let chars = self.operand_chars(right, run)?;
                    if chars.iter().any(|c| c.quoted) {
                        // Bash 3.2 and 5.2 write a regular expression's quoted characters differently.
                        return Err(unsupported(Unsupported::Trap, span).into());
                    }
                    let text: String = chars.iter().map(|c| c.ch).collect();
                    self.trace_binary(inverted, &subject, op, &text, span, run)?;
                }
                return self.regex_condition(&subject, right, run);
            }
            OperandKind::Pattern => {
                let chars = self.operand_chars(right, run)?;
                if self.state.options().xtrace {
                    // Bash writes the pattern with each quoted character backslash-escaped.
                    let mut text = String::with_capacity(chars.len());
                    for c in &chars {
                        if c.quoted {
                            text.push('\\');
                        }
                        text.push(c.ch);
                    }
                    self.trace_binary(inverted, &subject, op, &text, span, run)?;
                }
                let flags = Flags {
                    extglob: true,
                    nocase: false,
                };
                let matched = Pattern::new(&chars, flags).matches_str(&subject);
                return Ok(Truth::Is(matched == (op != "!=")));
            }
            OperandKind::String => {}
        }
        let other = self.operand_string(right, run)?;
        self.trace_binary(inverted, &subject, op, &other, span, run)?;
        if is_arithmetic_operator(op) {
            let Some(first) = self.arithmetic(&subject, "[[", span, run)? else {
                return Ok(Truth::Is(false));
            };
            let Some(second) = self.arithmetic(&other, "[[", span, run)? else {
                return Ok(Truth::Is(false));
            };
            return Ok(Truth::Is(compare_integers(op, first, second)));
        }
        Ok(Truth::Is(self.string_or_file_test(op, &subject, &other, true, span)?))
    }

    /// `subject =~ regex`, setting `BASH_REMATCH`.
    fn regex_condition(&mut self, subject: &str, operand: Operand, run: &Run<'_>) -> Flow<Truth> {
        let chars = self.operand_chars(operand, run)?;
        let pattern = regex_text(&chars);
        let locale = self.locale_for(&["LC_ALL", "LC_CTYPE", "LANG"], operand.span)?;
        // `nocasematch` (`REG_ICASE`) is a `shopt` option, which cannot be on yet (KNSH-104).
        let outcome = knsh_platform::regex_match(&pattern, subject, &locale, false)?;
        Ok(match outcome {
            knsh_platform::RegexOutcome::Invalid => Truth::BadRegex,
            knsh_platform::RegexOutcome::NoMatch => {
                self.state.set_bash_rematch(Vec::new());
                Truth::Is(false)
            }
            knsh_platform::RegexOutcome::Match(groups) => {
                let mut matched = Vec::with_capacity(groups.len());
                for group in groups {
                    let text = match group {
                        None => String::new(),
                        // A byte range that splits a character (the C locale over UTF-8 text) cannot be held as the
                        // shell's text: refused rather than altered.
                        Some((start, end)) => subject
                            .get(start..end)
                            .ok_or_else(|| Stop::Error(unsupported(Unsupported::RegexText, operand.span)))?
                            .to_owned(),
                    };
                    matched.push(text);
                }
                self.state.set_bash_rematch(matched);
                Truth::Is(true)
            }
        })
    }

    /// An operand expanded to one string.
    fn operand_string(&mut self, operand: Operand, run: &Run<'_>) -> Flow<String> {
        let parts = scan::scan(run.source, operand.span, Mode::Unquoted)?;
        let result = self.expander(run, &[]).string(&parts, operand.span);
        self.expanded(result, operand.span, run)
    }

    /// An operand expanded to characters, quoted ones marked (a pattern or regular expression).
    fn operand_chars(&mut self, operand: Operand, run: &Run<'_>) -> Flow<Vec<WordChar>> {
        let parts = scan::scan(run.source, operand.span, Mode::Unquoted)?;
        let result = self.expander(run, &[]).pattern(&parts, operand.span);
        self.expanded(result, operand.span, run)
    }
}

/// `text`, or `''` when it is empty, as bash's `xtrace_print_cond_term` writes an operand.
fn or_empty(text: &str) -> &str {
    if text.is_empty() { "''" } else { text }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(spec: &[(&str, bool)]) -> Vec<WordChar> {
        spec.iter()
            .flat_map(|(text, quoted)| {
                text.chars().map(move |ch| WordChar {
                    ch,
                    quoted: *quoted,
                    expanded: false,
                })
            })
            .collect()
    }

    // KNSH-102: quoted text matches itself; inside a bracket expression it is left alone.
    #[test]
    fn quoted_characters_are_escaped_outside_brackets() {
        assert_eq!(
            regex_text(&chars(&[("^", false), ("a.c", true), ("$", false)])),
            "^a\\.c$"
        );
        assert_eq!(regex_text(&chars(&[("[", false), (".", true), ("]", false)])), "[.]");
        assert_eq!(
            regex_text(&chars(&[("[]", false), ("*", true), ("]x", false), ("+", true)])),
            "[]*]x\\+"
        );
        assert_eq!(regex_text(&chars(&[("a b", true)])), "a b");
    }
}
