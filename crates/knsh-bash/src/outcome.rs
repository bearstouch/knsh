//! The single fail-closed fallback of the parser (KNSH-032; decision 6; FR-LC-05).
//!
//! [`parse_line`] is the one entry point the classifier uses. It never fails: every line becomes a [`ParseOutcome`],
//! either [`Exact`] (the whole line was read and nothing in it is dynamic code) or [`Dynamic`], which lists each
//! dynamic part of the line with a machine-readable [`DynamicReason`] and its span.
//!
//! A line is dynamic as a whole, with no script, when [`parse`] rejects it: over a limit ([`MAX_INPUT_LEN`],
//! [`MAX_TOKENS`], [`MAX_NESTING_DEPTH`]), a syntax error, a construct bash versions read differently, or valid bash
//! the parser cannot delimit (`coproc` among them). A line that parses is dynamic in parts, with its script kept so
//! the exact parts can still be decided (FR-LC-09), when it holds:
//!
//! - a [`Command::Unsupported`] node (`select`, `[[ … ]]`, `(( … ))`), whose contents are opaque;
//! - `eval`, `source` or `.` as a command name;
//! - a command name built from an expansion (`$CMD args`, `$(which x)`, `~/bin/x`, `l?`, `{ls,-la}`, `$'…'`);
//! - a here-document or here-string read by a shell or interpreter ([`Redirect::feeds_interpreter`]).
//!
//! Commands inside substitutions, compound commands and function bodies are checked like those at the top level.
//!
//! # Why there is no path from an error to `Exact`
//!
//! [`Exact`] and [`Dynamic`] have private fields, so code outside this crate cannot build a [`ParseOutcome`] at all:
//! the only way to get one is [`parse_line`], and a classifier that accepts only a `ParseOutcome` can only see what it
//! returned. Inside, the error branch returns [`Dynamic`] before any [`Exact`] is built, and the mapping from
//! [`ParseError`] to [`DynamicReason`] is an exhaustive `match` with no catch-all, so a new error variant cannot
//! compile without being given a reason.
//!
//! Wrappers that run a command given as arguments (`command eval`, `env $CMD`) and interpreters with `-c` or `-e` are
//! classified by [`classify`](crate::classify) (KNSH-036), which starts from this outcome and adds its own reasons;
//! this module marks only what the parser itself decides. `source` and `.` are marked here whatever file they read;
//! the classifier keeps the mark only for a file that is agent-writable or not resolved. A parser result is an intent
//! filter, never a security boundary.

use std::fmt;

use crate::ast::{Command, DeepCommand, Redirect, Script, SimpleCommand};
use crate::error::{CompoundStart, LexError, ParseError, UnsupportedConstruct};
use crate::parse::parse;
use crate::token::{ReservedWord, SegmentKind, Span, Word};

#[cfg(doc)]
use crate::limits::{MAX_INPUT_LEN, MAX_NESTING_DEPTH, MAX_TOKENS};

/// What the parser made of a whole command line: exact, or dynamic in at least one part. Only [`parse_line`] builds
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// The whole line was read and no part of it is dynamic code.
    Exact(Exact),
    /// At least one part of the line is dynamic code, or the line could not be read at all.
    Dynamic(Dynamic),
}

impl ParseOutcome {
    /// Whether the whole line was read and nothing in it is dynamic.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        match self {
            Self::Exact(_) => true,
            Self::Dynamic(_) => false,
        }
    }

    /// The parsed line, when it could be read: always for [`Exact`], and for a [`Dynamic`] line that parsed but holds
    /// dynamic parts.
    #[must_use]
    pub const fn script(&self) -> Option<&Script> {
        match self {
            Self::Exact(exact) => Some(&exact.script),
            Self::Dynamic(dynamic) => dynamic.script.as_ref(),
        }
    }

    /// The dynamic parts of the line, in source order; empty for an [`Exact`] line.
    #[must_use]
    pub fn dynamic_parts(&self) -> &[DynamicPart] {
        match self {
            Self::Exact(_) => &[],
            Self::Dynamic(dynamic) => &dynamic.parts,
        }
    }
}

/// A line read exactly: the parser read all of it, and it holds no dynamic code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exact {
    /// Private, so only [`parse_line`] can vouch that a script is exact.
    script: Script,
}

impl Exact {
    /// The parsed line.
    #[must_use]
    pub const fn script(&self) -> &Script {
        &self.script
    }

    /// The parsed line, by value.
    #[must_use]
    pub fn into_script(self) -> Script {
        self.script
    }
}

/// A line with dynamic code in it. Never has an empty list of parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamic {
    /// The parsed line, or `None` when it could not be read; then the whole line is dynamic and
    /// [`parts`](Self::parts) holds exactly one part, the reason it was not read.
    script: Option<Script>,
    /// The dynamic parts, in source order, at least one.
    parts: Vec<DynamicPart>,
}

impl Dynamic {
    /// The parsed line, or `None` when the parser could not read it, which makes the whole line dynamic.
    #[must_use]
    pub const fn script(&self) -> Option<&Script> {
        self.script.as_ref()
    }

    /// Whether the whole line is dynamic because the parser could not read it.
    #[must_use]
    pub const fn is_whole_line(&self) -> bool {
        self.script.is_none()
    }

    /// The dynamic parts in source order; never empty. For a line the parser could not read, the single part points
    /// at the cause (or covers the whole line when the cause has no place, as for an oversized line).
    #[must_use]
    pub fn parts(&self) -> &[DynamicPart] {
        &self.parts
    }
}

/// One dynamic part of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicPart {
    /// Why it is dynamic.
    pub reason: DynamicReason,
    /// Where it is, as offsets into the line. Inside a backtick substitution whose body bash un-escapes before
    /// reading it, this is the span of that substitution on the line.
    pub span: Span,
}

/// Why part of a line is dynamic code: a closed set, each with a stable [`code`](Self::code) for records and the
/// authority (FR-LC-05, decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicReason {
    /// The line is longer than [`MAX_INPUT_LEN`]; nothing of it was read.
    InputTooLarge,
    /// The line has more than [`MAX_TOKENS`] tokens.
    TooManyTokens,
    /// Quotes, substitutions or commands nest deeper than [`MAX_NESTING_DEPTH`].
    NestingTooDeep,
    /// Bash would reject the line (an unterminated quote, a missing command, an unexpected token, an unclosed
    /// compound command, a here-document with no body or no end).
    SyntaxError,
    /// Bash versions read the line differently (a here-document or comment inside a substitution), so either reading
    /// could hide a command the other runs.
    AmbiguousSyntax,
    /// A here-document delimiter holding an expansion or an ANSI-C or locale quote, whose body's end the parser
    /// does not guess.
    HereDocumentDelimiter,
    /// Valid bash outside decision 6's exact list, either refusing the whole line or kept whole as a
    /// [`Command::Unsupported`] node.
    Unsupported(UnsupportedConstruct),
    /// `coproc`, dynamic by decision 6.
    Coproc,
    /// `eval`, which runs its arguments as code. The classifier gives it too to the builtins that store code for bash
    /// to run later: `trap` with an action, `mapfile -C` and `alias` with a value (KNSH-036).
    Eval,
    /// `source` or `.`, which runs a file as code in the current shell. [`parse_line`] marks every one; the
    /// classifier keeps the mark only when the file is agent-writable (under the session's write roots) or cannot be
    /// resolved (KNSH-036).
    Source,
    /// A command name built from an expansion: a parameter, a substitution, arithmetic, a tilde, a glob, a brace
    /// expansion or an ANSI-C or locale quote. What runs is not known from the line.
    ExpandedCommandName,
    /// A here-document or here-string read by a shell or interpreter as code (KNSH-031).
    InterpreterInput,
    /// A shell or interpreter given its program on the command line: `sh -c`, `python3 -c`, `node -e`, `deno eval`
    /// (KNSH-036). Only the classifier gives this reason.
    InterpreterCode,
    /// A shell or interpreter given no script, so it reads its program from standard input (`curl … | bash`,
    /// `bash -s`) or from arguments supplied at run time (`xargs bash`) (KNSH-036). Only the classifier gives this
    /// reason.
    InterpreterStdin,
    /// A wrapper's option or operand, or an interpreter's argument before its script, built from an expansion: it may
    /// split into several words or be a code option, so what runs is not known from the line (KNSH-036). Only the
    /// classifier gives this reason.
    ExpandedArgument,
    /// A wrapper option outside the wrapper's grammar (`env -S …`, `env -P dir`), which is not guessed at (KNSH-036).
    /// Only the classifier gives this reason.
    UnknownWrapperOption,
    /// A variable whose value a shell or program runs as code (`BASH_ENV`, `PS4`, `NODE_OPTIONS`, `GIT_PAGER`, …),
    /// set for a command, as an `env` operand or by `export` and its kin (KNSH-036). Only the classifier gives this
    /// reason.
    CodeVariable,
}

impl DynamicReason {
    /// A stable, machine-readable name for the reason (`snake_case`), for records, events and the authority.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::TooManyTokens => "too_many_tokens",
            Self::NestingTooDeep => "nesting_too_deep",
            Self::SyntaxError => "syntax_error",
            Self::AmbiguousSyntax => "ambiguous_syntax",
            Self::HereDocumentDelimiter => "here_document_delimiter",
            Self::Unsupported(_) => "unsupported",
            Self::Coproc => "coproc",
            Self::Eval => "eval",
            Self::Source => "source",
            Self::ExpandedCommandName => "expanded_command_name",
            Self::InterpreterInput => "interpreter_input",
            Self::InterpreterCode => "interpreter_code",
            Self::InterpreterStdin => "interpreter_stdin",
            Self::ExpandedArgument => "expanded_argument",
            Self::UnknownWrapperOption => "unknown_wrapper_option",
            Self::CodeVariable => "code_variable",
        }
    }
}

impl fmt::Display for DynamicReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("command line over the size limit"),
            Self::TooManyTokens => f.write_str("command line over the token limit"),
            Self::NestingTooDeep => f.write_str("nesting over the depth limit"),
            Self::SyntaxError => f.write_str("syntax error"),
            Self::AmbiguousSyntax => f.write_str("read differently by bash versions"),
            Self::HereDocumentDelimiter => f.write_str("here-document delimiter with an expansion"),
            Self::Unsupported(construct) => write!(f, "unsupported {construct}"),
            Self::Coproc => f.write_str("`coproc`"),
            Self::Eval => f.write_str("`eval`"),
            Self::Source => f.write_str("`source` or `.`"),
            Self::ExpandedCommandName => f.write_str("command name built from an expansion"),
            Self::InterpreterInput => f.write_str("here-document or here-string read by an interpreter"),
            Self::InterpreterCode => f.write_str("interpreter given code on the command line"),
            Self::InterpreterStdin => f.write_str("interpreter reading its program from standard input"),
            Self::ExpandedArgument => f.write_str("wrapper or interpreter argument built from an expansion"),
            Self::UnknownWrapperOption => f.write_str("wrapper option outside its grammar"),
            Self::CodeVariable => f.write_str("variable whose value a shell or program runs as code"),
        }
    }
}

impl From<&ParseError> for DynamicReason {
    /// The reason a line the parser rejected is dynamic. Exhaustive on purpose: every error, present and future, must
    /// be given a reason, and every reason is dynamic (no error leads to [`Exact`]).
    fn from(error: &ParseError) -> Self {
        match error {
            ParseError::Lex(LexError::InputTooLarge { .. }) => Self::InputTooLarge,
            ParseError::Lex(LexError::TooManyTokens { .. }) => Self::TooManyTokens,
            ParseError::Lex(LexError::NestingTooDeep { .. }) | ParseError::NestingTooDeep { .. } => {
                Self::NestingTooDeep
            }
            ParseError::Lex(LexError::Unterminated { .. })
            | ParseError::MissingCommand { .. }
            | ParseError::MissingRedirectionTarget { .. }
            | ParseError::UnexpectedToken { .. }
            | ParseError::MissingHereDocumentBody { .. }
            | ParseError::Unclosed { .. } => Self::SyntaxError,
            ParseError::Lex(LexError::AmbiguousHereDocument { .. } | LexError::AmbiguousComment { .. }) => {
                Self::AmbiguousSyntax
            }
            ParseError::Lex(LexError::HereDocumentDelimiter { .. }) => Self::HereDocumentDelimiter,
            ParseError::Unsupported {
                construct: UnsupportedConstruct::Compound(CompoundStart::ReservedWord(ReservedWord::Coproc)),
                ..
            } => Self::Coproc,
            ParseError::Unsupported { construct, .. } => Self::Unsupported(*construct),
        }
    }
}

/// Reads a whole command line and decides which parts of it are dynamic code (KNSH-032; FR-LC-05; decision 6).
///
/// Never fails and never panics: anything the parser cannot read becomes [`ParseOutcome::Dynamic`], never an error
/// a caller could mistake for an allow. Pure: the same line always gives the same outcome.
///
/// # Example
///
/// ```
/// use knsh_bash::{DynamicReason, ParseOutcome, parse_line};
///
/// assert!(parse_line("git status && cargo test").is_exact());
///
/// // The exact part is still there to decide; the dynamic part is named and placed.
/// let line = "ls; $CMD --force";
/// let outcome = parse_line(line);
/// assert!(outcome.script().is_some());
/// let part = outcome.dynamic_parts()[0];
/// assert_eq!(part.reason, DynamicReason::ExpandedCommandName);
/// assert_eq!(&line[part.span.range()], "$CMD");
///
/// // A line bash rejects is dynamic as a whole.
/// let ParseOutcome::Dynamic(dynamic) = parse_line("echo 'unterminated") else { panic!() };
/// assert!(dynamic.is_whole_line());
/// assert_eq!(dynamic.parts()[0].reason.code(), "syntax_error");
/// ```
#[must_use]
pub fn parse_line(input: &str) -> ParseOutcome {
    // `parse` checks the size before reading anything, so an oversized line is refused here without being lexed.
    let script = match parse(input) {
        Ok(script) => script,
        Err(error) => {
            // The only exit from the error branch: dynamic, with no script.
            let part = DynamicPart {
                reason: DynamicReason::from(&error),
                span: error.span().unwrap_or(Span::new(0, input.len())),
            };
            return ParseOutcome::Dynamic(Dynamic {
                script: None,
                parts: vec![part],
            });
        }
    };
    let parts = dynamic_parts(&script, input);
    if parts.is_empty() {
        ParseOutcome::Exact(Exact { script })
    } else {
        ParseOutcome::Dynamic(Dynamic {
            script: Some(script),
            parts,
        })
    }
}

/// The dynamic parts of a parsed line, in source order without duplicates (two commands inside one un-escaped
/// backtick substitution share its span on the line).
fn dynamic_parts(script: &Script, input: &str) -> Vec<DynamicPart> {
    let mut parts = Vec::new();
    for deep in script.deep_commands(input) {
        let mut add = |reason, span| {
            parts.push(DynamicPart {
                reason,
                span: deep.on_line(span),
            });
        };
        match deep.command {
            Command::Simple(simple) => {
                if let Some((reason, span)) = simple_command_reason(simple, &deep) {
                    add(reason, span);
                }
                interpreter_inputs(&simple.redirections, &mut add);
            }
            Command::Compound(compound) => interpreter_inputs(&compound.redirections, &mut add),
            Command::FunctionDefinition(definition) => interpreter_inputs(&definition.body.redirections, &mut add),
            Command::Unsupported(unsupported) => {
                add(DynamicReason::Unsupported(unsupported.construct), unsupported.span);
            }
        }
    }
    parts.sort_by_key(|part| (part.span.start, part.span.end));
    parts.dedup();
    parts
}

/// Calls `add` for each here-document or here-string in `redirections` that a shell or interpreter reads as code.
fn interpreter_inputs(redirections: &[Redirect], add: &mut impl FnMut(DynamicReason, Span)) {
    for redirect in redirections.iter().filter(|redirect| redirect.feeds_interpreter) {
        add(DynamicReason::InterpreterInput, redirect.span);
    }
}

/// Why a simple command is dynamic by its name, with the span to report, if it is. A function of the line named like
/// a builtin (`eval() { …; }; eval x`) is still reported: erring towards dynamic is always safe.
fn simple_command_reason(simple: &SimpleCommand, deep: &DeepCommand<'_>) -> Option<(DynamicReason, Span)> {
    let name = simple.name()?;
    let Some(text) = command_name_text(&name.word, deep.source) else {
        return Some((DynamicReason::ExpandedCommandName, name.span));
    };
    match text.as_str() {
        "eval" => Some((DynamicReason::Eval, simple.span)),
        "source" | "." => Some((DynamicReason::Source, simple.span)),
        _ => None,
    }
}

/// The text of a command name after quote removal, or `None` when bash would expand it, so what runs is not known
/// from the line. Quotes and escapes are removed (`e"va"l` and `\eval` are `eval`). Any parameter, substitution or
/// arithmetic makes the name expanded, and so do these in unquoted text: a leading `~` (tilde expansion), `*` or `?`
/// (globs), `{` (brace expansion: `{ls,-la}` runs `ls -la`) and `[` (a glob bracket), except the name `[` itself,
/// which is the `test` builtin. ANSI-C and locale quotes are not decoded, so they count as expanded too.
pub(crate) fn command_name_text(word: &Word, source: &str) -> Option<String> {
    let mut text = String::new();
    let mut bracket = false;
    for (index, segment) in word.segments.iter().enumerate() {
        match &segment.kind {
            SegmentKind::Literal => {
                let literal = segment.span.text(source)?;
                if (index == 0 && literal.starts_with('~')) || literal.contains(['*', '?', '{']) {
                    return None;
                }
                bracket |= literal.contains('[');
                text.push_str(literal);
            }
            SegmentKind::Escape | SegmentKind::SingleQuoted => text.push_str(segment.body.text(source)?),
            SegmentKind::LineContinuation => {}
            SegmentKind::DoubleQuoted(inner) => {
                for part in inner {
                    match part.kind {
                        // Inside double quotes globs, braces and tildes are literal.
                        SegmentKind::Literal => text.push_str(part.span.text(source)?),
                        SegmentKind::Escape => text.push_str(part.body.text(source)?),
                        SegmentKind::LineContinuation => {}
                        SegmentKind::SingleQuoted
                        | SegmentKind::AnsiC
                        | SegmentKind::DoubleQuoted(_)
                        | SegmentKind::Locale(_)
                        | SegmentKind::Parameter
                        | SegmentKind::ParameterExpansion
                        | SegmentKind::CommandSubstitution
                        | SegmentKind::Backtick
                        | SegmentKind::Arithmetic
                        | SegmentKind::InputProcessSubstitution
                        | SegmentKind::OutputProcessSubstitution => return None,
                    }
                }
            }
            SegmentKind::AnsiC
            | SegmentKind::Locale(_)
            | SegmentKind::Parameter
            | SegmentKind::ParameterExpansion
            | SegmentKind::CommandSubstitution
            | SegmentKind::Backtick
            | SegmentKind::Arithmetic
            | SegmentKind::InputProcessSubstitution
            | SegmentKind::OutputProcessSubstitution => return None,
        }
    }
    // `[` alone is the `test` builtin; any other name with an unquoted `[` may be a glob.
    if bracket && !(word.segments.len() == 1 && text == "[") {
        return None;
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{MAX_INPUT_LEN, MAX_NESTING_DEPTH, MAX_TOKENS};

    /// The dynamic parts of `line` as (reason, text on the line).
    fn parts(line: &str) -> Vec<(DynamicReason, &str)> {
        parse_line(line)
            .dynamic_parts()
            .iter()
            .map(|part| (part.reason, &line[part.span.range()]))
            .collect()
    }

    /// Asserts that `line` is dynamic as a whole (no script) for `reason`.
    fn assert_whole_line(line: &str, reason: DynamicReason) {
        let ParseOutcome::Dynamic(dynamic) = parse_line(line) else {
            panic!("{line:?} is exact");
        };
        assert!(dynamic.is_whole_line(), "{line:?} kept a script");
        assert_eq!(dynamic.parts().len(), 1, "{line:?}");
        assert_eq!(dynamic.parts()[0].reason, reason, "{line:?}");
    }

    // decision 6, NFR-SEC-05: the depth limit + 1 makes the line dynamic; at the limit it is still read.
    #[test]
    fn deeply_nested_substitution_becomes_dynamic() {
        let nested = |depth: usize| format!("{}x{}", "$(".repeat(depth), ")".repeat(depth));
        assert!(parse_line(&nested(MAX_NESTING_DEPTH)).script().is_some());
        assert_whole_line(&nested(MAX_NESTING_DEPTH + 1), DynamicReason::NestingTooDeep);
        // Command lists nested in subshells reach the parser's limit the same way.
        // Spaced, since `((` would start an arithmetic command.
        let subshells = |depth: usize| format!("{}x{}", "( ".repeat(depth), " )".repeat(depth));
        assert!(parse_line(&subshells(MAX_NESTING_DEPTH)).is_exact());
        assert_whole_line(&subshells(MAX_NESTING_DEPTH + 1), DynamicReason::NestingTooDeep);
    }

    // NFR-SEC-05: the size is checked before anything is read. The line starts with a syntax error that any lexing
    // would find; the reason is still the size, and the part covers the whole line.
    #[test]
    fn oversized_line_becomes_dynamic_without_parsing() {
        let line = format!(")'{}", "a".repeat(MAX_INPUT_LEN));
        assert_whole_line(&line, DynamicReason::InputTooLarge);
        assert_eq!(parse_line(&line).dynamic_parts()[0].span, Span::new(0, line.len()));
        assert!(parse_line(&"a".repeat(MAX_INPUT_LEN)).is_exact());
    }

    // decision 6: a line bash rejects is dynamic code, never an error a caller could treat as an allow.
    #[test]
    fn syntax_error_becomes_dynamic_not_error_allow() {
        for line in [
            "echo 'open",
            "echo \"$(open",
            "a &&",
            "a |",
            "cmd >",
            "; a",
            "if a; then b",
            "{ a;",
            "a ;; b",
            "fi",
            "cat <<EOF",
            "cat <<EOF\nno end",
        ] {
            assert!(parse(line).is_err(), "{line:?} parses");
            assert_whole_line(line, DynamicReason::SyntaxError);
        }
    }

    // decision 6: `coproc` is dynamic, even before a simple command.
    #[test]
    fn coproc_is_dynamic() {
        assert_whole_line("coproc cat", DynamicReason::Coproc);
        assert_whole_line("ls; coproc worker { sleep 1; }", DynamicReason::Coproc);
        assert_eq!(DynamicReason::Coproc.code(), "coproc");
    }

    // decision 6, FR-LC-05: `eval` runs its arguments as code, wherever it stands.
    #[test]
    fn eval_is_dynamic() {
        assert_eq!(parts("eval \"$x\""), [(DynamicReason::Eval, "eval \"$x\"")]);
        assert_eq!(parts("ls && X=1 eval echo"), [(DynamicReason::Eval, "X=1 eval echo")]);
        // Quoting does not hide the name: bash removes the quotes before looking it up.
        assert_eq!(parts("e'va'l x")[0].0, DynamicReason::Eval);
        assert_eq!(parts("\\eval x")[0].0, DynamicReason::Eval);
        assert_eq!(parts("\"eval\" x")[0].0, DynamicReason::Eval);
        // Nested in a compound command, a function body or a substitution.
        assert_eq!(parts("if true; then eval x; fi")[0], (DynamicReason::Eval, "eval x"));
        assert_eq!(parts("f() { eval x; }")[0], (DynamicReason::Eval, "eval x"));
        assert_eq!(parts("echo $(eval x)")[0], (DynamicReason::Eval, "eval x"));
        // A function named `eval` is still reported: erring towards dynamic is safe.
        assert_eq!(parts("eval() { :; }; eval x"), [(DynamicReason::Eval, "eval x")]);
        // As an argument it is only a word.
        assert!(parse_line("echo eval").is_exact());
    }

    // decision 6, FR-LC-05: `source` and `.` run a file as code in the current shell.
    #[test]
    fn source_is_dynamic() {
        assert_eq!(parts("source ./env.sh"), [(DynamicReason::Source, "source ./env.sh")]);
        assert_eq!(parts(". ~/.profile && make"), [(DynamicReason::Source, ". ~/.profile")]);
        assert_eq!(parts("cd x; s\"ource\" y")[0].0, DynamicReason::Source);
        assert!(parse_line("echo source .").is_exact());
        assert!(parse_line("./build.sh").is_exact());
    }

    // decision 6, FR-LC-05: a name taken from a variable is unknown until it runs.
    #[test]
    fn command_name_from_variable_is_dynamic() {
        assert_eq!(parts("$CMD args"), [(DynamicReason::ExpandedCommandName, "$CMD")]);
        // The exact parts are kept to decide.
        let outcome = parse_line("git status; ${TOOL:-rm} -rf x");
        assert_eq!(outcome.script().unwrap().simple_commands().count(), 2);
        assert_eq!(
            parts("git status; ${TOOL:-rm} -rf x"),
            [(DynamicReason::ExpandedCommandName, "${TOOL:-rm}")]
        );
        for line in [
            "\"$CMD\" x",
            "/usr/bin/$X",
            "$(which python) -V",
            "`which python` -V",
            "$((1)) x",
            "~/bin/tool",
            "/bin/s?",
            "/bin/l*",
            "/bin/[l]s",
            "{ls,-la}",
            "$'\\x65val' x",
            "$\"ls\"",
        ] {
            assert_eq!(parts(line)[0].0, DynamicReason::ExpandedCommandName, "{line:?}");
        }
        // Quoted or escaped specials are literal; `[` is the test builtin; an argument may expand.
        for line in [
            "'l*' x",
            "\"~/x\"",
            "\\~/x",
            "[ -f x ]",
            "echo $HOME",
            "X=$Y cmd",
            "./a~b",
            "a\\*",
        ] {
            assert!(parse_line(line).is_exact(), "{line:?}");
        }
    }

    // NFR-SEC-05: a line at the token limit is read; one token more is dynamic.
    #[test]
    fn too_many_tokens_becomes_dynamic() {
        // Each `a ` is a word and a blank: two tokens.
        let at_limit = "a ".repeat(MAX_TOKENS / 2);
        assert!(parse_line(&at_limit).is_exact());
        assert_whole_line(&format!("{at_limit}a"), DynamicReason::TooManyTokens);
        // The budget is shared with substitution bodies, which are lexed again when parsed: neither part alone is
        // over the limit, but the line is.
        let half = "a ".repeat(MAX_TOKENS / 4 + 1);
        assert!(parse_line(&format!("{half}$(true)")).is_exact());
        assert_whole_line(&format!("{half}$({half})"), DynamicReason::TooManyTokens);
        // The same over nested substitutions and backtick bodies, read in place or un-escaped first (`\$` makes bash
        // un-escape the body, which is then lexed from a copy); the part still lies on the line.
        let quarter = "a ".repeat(MAX_TOKENS / 8 + 1);
        assert_whole_line(&format!("{half}$({quarter}$({quarter}))"), DynamicReason::TooManyTokens);
        assert_whole_line(&format!("{half}`{half}`"), DynamicReason::TooManyTokens);
        let line = format!("{half}`{half}\\$x`");
        assert_whole_line(&line, DynamicReason::TooManyTokens);
        let span = parse_line(&line).dynamic_parts()[0].span;
        assert!(span.start > half.len() && span.end < line.len(), "{span:?}");
    }

    // decision 6: a construct outside the exact list is dynamic, and the rest of the line is still read.
    #[test]
    fn unsupported_node_is_dynamic_in_part() {
        let line = "[[ -f x ]] && make";
        assert_eq!(
            parts(line),
            [(
                DynamicReason::Unsupported(UnsupportedConstruct::Compound(CompoundStart::ReservedWord(
                    ReservedWord::DoubleLeftBracket
                ))),
                "[[ -f x ]]"
            )]
        );
        assert!(parse_line(line).script().is_some());
        assert_eq!(parts("(( x++ ))")[0].0.code(), "unsupported");
        // Refused outright when the parser cannot delimit it.
        assert_whole_line(
            "a=(1 2)",
            DynamicReason::Unsupported(UnsupportedConstruct::ArrayAssignment),
        );
    }

    // decision 6 (KNSH-031): a here-document or here-string fed to an interpreter is code.
    #[test]
    fn here_document_fed_to_interpreter_is_dynamic() {
        assert_eq!(
            parts("bash <<EOF\nrm -rf x\nEOF\n"),
            [(DynamicReason::InterpreterInput, "<<EOF")]
        );
        assert_eq!(parts("python3 <<< 'print(1)'")[0].0, DynamicReason::InterpreterInput);
        assert_eq!(
            parts("{ cat; sh; } <<EOF\nx\nEOF\n")[0].0,
            DynamicReason::InterpreterInput
        );
        assert!(parse_line("cat <<EOF\nhello\nEOF\n").is_exact());
    }

    // KNSH-038 fuzz regression: a `~` inside a command name is literal in bash, so `a~` reading a here-document is
    // not an unknown program; a leading `~` (tilde expansion) still is, and functions keep their names.
    #[test]
    fn tilde_inside_a_command_name_is_not_an_expansion_for_here_documents() {
        assert!(parse_line("a~ <<X\nX\n").is_exact());
        assert!(parse_line("cat <$(ca~ <<X\n\tX\nX\n)\n").is_exact());
        assert!(
            parts("~/bin/x <<X\nX\n")
                .iter()
                .any(|(reason, _)| *reason == DynamicReason::InterpreterInput)
        );
        assert_eq!(
            parts("a~() { bash; }; a~ <<X\nX\n")[0].0,
            DynamicReason::InterpreterInput
        );
    }

    // Lexer refusals that are not syntax errors keep their own reasons.
    #[test]
    fn ambiguous_and_delimiter_refusals_are_dynamic() {
        assert_whole_line("echo $(a;#) b\n)", DynamicReason::AmbiguousSyntax);
        assert_whole_line("cat <<$E\nx\n$E\n", DynamicReason::HereDocumentDelimiter);
    }

    // A command inside an un-escaped backtick body has spans in that body; its part is placed on the line at the
    // backtick substitution, so the span always indexes the line.
    #[test]
    fn part_inside_unescaped_backticks_points_at_the_substitution() {
        let line = "echo `eval \\`x\\``";
        let found = parts(line);
        assert_eq!(found, [(DynamicReason::Eval, "`eval \\`x\\``")]);
        // In a body read as written, the command's own span is used.
        assert_eq!(parts("echo `eval x`"), [(DynamicReason::Eval, "eval x")]);
    }

    // No path from a parser error to `Exact`: every line `parse` rejects is dynamic as a whole, and every exact line
    // parses.
    #[test]
    fn every_parse_error_is_dynamic_and_every_exact_line_parses() {
        let lines = [
            "",
            "ls -l | wc -l",
            "a && b || c; d &",
            "for f in *; do echo \"$f\"; done",
            "case $x in a) b;; esac",
            "f() { g; }; f",
            "echo $(date) `id`",
            "coproc x",
            "time ls",
            "echo ${x:-$(rm f)}",
            "{x}>f",
            "a[1]=x",
            "echo \"",
            "((",
            "select x in a; do b; done",
            "cat <<'EOF'\nbody\nEOF\n",
            "echo $(cat <<EOF)\nx\nEOF\n",
        ];
        for line in lines {
            let outcome = parse_line(line);
            assert_eq!(outcome, parse_line(line), "not deterministic: {line:?}");
            match (parse(line), &outcome) {
                (Err(error), ParseOutcome::Dynamic(dynamic)) => {
                    assert!(dynamic.is_whole_line(), "{line:?}");
                    assert_eq!(
                        dynamic.parts(),
                        [DynamicPart {
                            reason: DynamicReason::from(&error),
                            span: error.span().unwrap_or(Span::new(0, line.len())),
                        }]
                    );
                }
                (Err(_), ParseOutcome::Exact(_)) => panic!("parser error became exact: {line:?}"),
                (Ok(script), ParseOutcome::Exact(exact)) => assert_eq!(exact.script(), &script),
                (Ok(script), ParseOutcome::Dynamic(dynamic)) => {
                    assert_eq!(dynamic.script(), Some(&script));
                    assert_ne!(dynamic.parts(), []);
                }
            }
        }
    }

    #[test]
    fn reason_codes_are_distinct_snake_case() {
        let reasons = [
            DynamicReason::InputTooLarge,
            DynamicReason::TooManyTokens,
            DynamicReason::NestingTooDeep,
            DynamicReason::SyntaxError,
            DynamicReason::AmbiguousSyntax,
            DynamicReason::HereDocumentDelimiter,
            DynamicReason::Unsupported(UnsupportedConstruct::ArrayAssignment),
            DynamicReason::Coproc,
            DynamicReason::Eval,
            DynamicReason::Source,
            DynamicReason::ExpandedCommandName,
            DynamicReason::InterpreterInput,
            DynamicReason::InterpreterCode,
            DynamicReason::InterpreterStdin,
            DynamicReason::ExpandedArgument,
            DynamicReason::UnknownWrapperOption,
            DynamicReason::CodeVariable,
        ];
        let mut codes: Vec<&str> = reasons.iter().map(|reason| reason.code()).collect();
        assert!(
            codes
                .iter()
                .all(|code| code.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
        );
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), reasons.len());
    }
}
