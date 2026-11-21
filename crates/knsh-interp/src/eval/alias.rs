//! Aliases: `alias`, `unalias` and alias expansion (KNSH-101; NFR-COMPAT-02), following bash 5.2's `alias.def`.
//!
//! Bash expands aliases while it reads a line, and only with `expand_aliases` on (off in a script, on in an
//! interactive shell). The interpreter reads a whole script before running it, so it expands when a simple command
//! runs, with the aliases as they were when the command's line started ([`Interpreter::visible_aliases`]): an alias
//! defined on a line is not expanded on that same line, as in bash. The first word of a simple command, when it is
//! unquoted literal text naming an alias, is replaced by the alias's text (and the next word too while the text
//! ends with a blank); the command's text with that replacement is then parsed and run in its place. An alias is
//! not expanded again inside its own text.
//!
//! Text that needs the words around the command to be read again (`alias x='if true; then'`) cannot be expanded
//! this way: the script would not have parsed. Inside a pipeline an alias must expand to a single simple command,
//! which the pipeline then runs as its stage; anything else there is refused.

use knsh_bash::{Command, CommandWord, ListItem, SegmentKind, SimpleCommand, Span};

use super::{Flow, Interpreter, Run, Sink, unsupported};
use crate::error::Unsupported;
use crate::quote;
use crate::status::Status;

/// Most aliases expanded for one simple command, counting those its own text came from (each alias text may start
/// with another): a bound on input that defines aliases in a loop, far above any real chain, which also bounds how
/// deep alias texts nest.
const MAX_ALIAS_CHAIN: usize = 64;

/// Bash's `legal_alias_name`: no blank, quote, `/`, `$`, backquote, `=` or character that ends a word.
fn legal_alias_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|ch| " \t\n()<>;&|\"'`\\$/=".contains(ch))
}

/// The text of `word` if it is unquoted literal text only (what bash checks for an alias), from `source`.
pub(super) fn literal_text<'a>(word: &CommandWord, source: &'a str) -> Option<&'a str> {
    word.word
        .segments
        .iter()
        .all(|segment| matches!(segment.kind, SegmentKind::Literal))
        .then(|| word.span.text(source))
        .flatten()
}

/// Whether `items` is one simple command: what a pipeline stage may expand an alias into.
fn single_simple(items: &[ListItem]) -> Option<&SimpleCommand> {
    let [item] = items else {
        return None;
    };
    let pipeline = &item.and_or.first;
    if item.is_background() || !item.and_or.rest.is_empty() || !pipeline.rest.is_empty() {
        return None;
    }
    if pipeline.negation.is_some() || pipeline.time.is_some() {
        return None;
    }
    match &pipeline.first {
        Command::Simple(simple) => Some(simple),
        Command::Compound(_) | Command::FunctionDefinition(_) | Command::Unsupported(_) => None,
    }
}

impl Interpreter {
    /// Runs `simple` with its alias expanded, if its first word names one and aliases are expanded: `None` when
    /// it does not, and the command runs as written.
    pub(super) fn alias_command(&mut self, simple: &SimpleCommand, run: &Run<'_>) -> Option<Flow<Status>> {
        if !self.state.options().expand_aliases || self.visible_aliases.is_empty() {
            return None;
        }
        let mut text = run
            .source
            .get(simple.span.start..simple.words.first()?.span.start)?
            .to_owned();
        let mut expanded = Vec::new();
        let mut rest_from = None;
        for word in &simple.words {
            let alias = literal_text(word, run.source)
                .filter(|name| !self.alias_guard.iter().any(|guarded| guarded == name))
                .and_then(|name| {
                    self.visible_aliases
                        .get(name)
                        .map(|value| (name.to_owned(), value.clone()))
                });
            let Some((name, value)) = alias else {
                rest_from = Some(word.span.start);
                break;
            };
            // Counted with the aliases whose text this command came from, so a chain of aliases each starting with
            // the next (expanded one inside another, without a depth check of their own) stays bounded.
            if self.alias_guard.len() + expanded.len() >= MAX_ALIAS_CHAIN {
                return Some(Err(unsupported(Unsupported::Alias, simple.span).into()));
            }
            text.push_str(&value);
            expanded.push(name);
            rest_from = Some(word.span.end);
            // Bash checks the next word only after a text ending with a blank.
            if !value.ends_with([' ', '\t']) {
                break;
            }
            rest_from = None;
        }
        if expanded.is_empty() {
            return None;
        }
        let rest = match rest_from {
            Some(start) => run.source.get(start..simple.span.end)?,
            None => run.source.get(simple.words.last()?.span.end..simple.span.end)?,
        };
        text.push_str(rest);
        Some(self.run_alias_text(&text, expanded, simple.span, run))
    }

    /// Parses and runs `text`, a simple command with aliases `expanded`, in place of the command at `span`.
    fn run_alias_text(&mut self, text: &str, expanded: Vec<String>, span: Span, run: &Run<'_>) -> Flow<Status> {
        self.holding_nested(text.len(), |shell| shell.run_alias_parsed(text, expanded, span, run))
    }

    /// [`Interpreter::run_alias_text`] once its text is counted.
    fn run_alias_parsed(&mut self, text: &str, expanded: Vec<String>, span: Span, run: &Run<'_>) -> Flow<Status> {
        let Ok(script) = knsh_bash::parse_with(text, self.parse_options()) else {
            return Err(unsupported(Unsupported::Alias, span).into());
        };
        let budget = self.max_depth.saturating_sub(self.depth);
        self.check_nested(&script.items, text, budget)?;
        let nested = Run::nested(text, run.origin, run.line(span).saturating_sub(1));
        let guarded = self.alias_guard.len();
        self.alias_guard.extend(expanded);
        let result = if self.sink == Sink::Off {
            self.list(&script.items, &nested)
        } else {
            // A pipeline stage runs one command, whose program the pipeline waits for.
            match single_simple(&script.items) {
                Some(simple) => self.simple(simple, &nested),
                None => Err(unsupported(Unsupported::Alias, span).into()),
            }
        };
        self.alias_guard.truncate(guarded);
        result
    }

    /// `alias [-p] [name[=value] …]`.
    pub(super) fn alias_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let (options, operands) = match self.options("alias", "[-p] [name[=value] ... ]", "p", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return status,
        };
        let mut status = Status::SUCCESS;
        if operands.is_empty() || options.contains('p') {
            // `-p` always lists reusably; without it POSIX mode leaves `alias ` out (KNSH-106).
            let reusable = options.contains('p') || !self.state.options().posix();
            let listing: String = self
                .state
                .aliases()
                .iter()
                .map(|(name, value)| alias_line(name, value, reusable))
                .collect();
            status = self.print("alias", listing.as_bytes(), span, run);
            if operands.is_empty() {
                return status;
            }
        }
        let reusable = options.contains('p') || !self.state.options().posix();
        for operand in operands {
            if let Some((name, value)) = operand.split_once('=').filter(|(name, _)| !name.is_empty()) {
                if legal_alias_name(name) {
                    self.state.set_alias(name, value.to_owned());
                } else {
                    self.report(span, run, format_args!("alias: `{name}': invalid alias name"));
                    status = Status::FAILURE;
                }
            } else if let Some(line) = self
                .state
                .alias(operand)
                .map(|value| alias_line(operand, value, reusable))
            {
                if self.print("alias", line.as_bytes(), span, run) != Status::SUCCESS {
                    status = Status::FAILURE;
                }
            } else {
                self.report(span, run, format_args!("alias: {operand}: not found"));
                status = Status::FAILURE;
            }
        }
        status
    }

    /// `unalias [-a] name …`.
    pub(super) fn unalias_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        const USAGE: &str = "[-a] name [name ...]";
        let (options, names) = match self.options("unalias", USAGE, "a", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return status,
        };
        if options.contains('a') {
            self.state.clear_aliases();
            return Status::SUCCESS;
        }
        if names.is_empty() {
            self.report_plain(format_args!("unalias: usage: unalias {USAGE}"));
            return Status::new(2);
        }
        let mut status = Status::SUCCESS;
        for name in names {
            if !self.state.remove_alias(name) {
                self.report(span, run, format_args!("unalias: {name}: not found"));
                status = Status::FAILURE;
            }
        }
        status
    }
}

/// One alias as `alias` prints it: `alias name='value'`, or without `reusable` (POSIX mode, bash's `AL_REUSABLE`
/// unset) `name='value'`.
fn alias_line(name: &str, value: &str, reusable: bool) -> String {
    if !reusable {
        return format!("{name}={}\n", quote::single(value));
    }
    // Bash puts `-- ` before a name that starts with `-`, so the line can be read back.
    let guard = if name.starts_with('-') { "-- " } else { "" };
    format!("alias {guard}{name}={}\n", quote::single(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_names_follow_bash() {
        for name in ["ll", "g.st", "-x", "a-b"] {
            assert!(legal_alias_name(name), "{name}");
        }
        for name in ["", "a/b", "a b", "a$", "a=b", "a'b", "a;b"] {
            assert!(!legal_alias_name(name), "{name}");
        }
        assert_eq!(alias_line("q", "it's", true), "alias q='it'\\''s'\n");
        // KNSH-106: POSIX mode without `-p`.
        assert_eq!(alias_line("ll", "ls -l", false), "ll='ls -l'\n");
    }
}
