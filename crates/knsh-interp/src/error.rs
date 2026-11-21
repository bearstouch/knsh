//! The crate's single error type.
//!
//! An error stops the whole run: nothing after it is evaluated. Constructs later stories implement are refused by a
//! check of the whole script before its first command runs, so a script this story cannot evaluate runs nothing at
//! all rather than part of itself. What only an expansion's value reveals (a command name that turns out to be a
//! builtin, a variable reached through indirection, a file name that is not UTF-8) is refused when it is found,
//! which stops the script there (KNSH-097, KNSH-098).
//!
//! Bash's own expansion errors (a bad substitution, division by zero, an unset variable under `set -u`) are not
//! errors of this type: they are reported on the diagnostics writer and change the exit status, as in bash.

use std::fmt;

use knsh_bash::{Span, UnsupportedConstruct};
use knsh_platform::PlatformError;

/// Every way evaluating a script can fail, as opposed to a command in it failing (which is an exit [`Status`]).
///
/// [`Status`]: crate::Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpError {
    /// The script uses something the interpreter does not evaluate yet. Found before anything runs.
    Unsupported {
        /// What it is.
        feature: Unsupported,
        /// Where it is, in the source the script was parsed from.
        span: Span,
    },
    /// Evaluation nested deeper than the interpreter's limit ([`MAX_EVAL_DEPTH`](crate::MAX_EVAL_DEPTH) unless set
    /// otherwise): an explicit error rather than a stack overflow.
    DepthExceeded {
        /// The limit that was reached.
        limit: usize,
    },
    /// A span of the script does not index the source text it was given: the script was parsed from other text.
    SourceMismatch {
        /// The span.
        span: Span,
    },
    /// A brace or pathname expansion grew past one of the interpreter's bounds (words or bytes produced, work spent
    /// looking for braces, entries of one directory or of one word's walk): an explicit error rather than unbounded
    /// memory or time on untrusted input (KNSH-098).
    ExpansionLimit {
        /// What was bounded.
        what: &'static str,
        /// The bound that was reached.
        limit: usize,
    },
    /// The working directory given to the shell state is not absolute.
    RelativeWorkingDirectory,
    /// Starting or waiting for a command failed for a reason that is not the command's (no process could be
    /// created, waiting failed).
    Platform(PlatformError),
    /// The evaluation thread could not be started, or ended without a result.
    EvaluationThread,
}

impl fmt::Display for InterpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { feature, span } => write!(
                f,
                "{feature} is not supported by the native interpreter yet (bytes {}..{})",
                span.start, span.end
            ),
            Self::DepthExceeded { limit } => write!(f, "maximum evaluation depth exceeded ({limit})"),
            Self::ExpansionLimit { what, limit } => write!(f, "expansion limit exceeded: {what} (limit {limit})"),
            Self::SourceMismatch { span } => {
                write!(
                    f,
                    "span {}..{} does not index the script's source",
                    span.start, span.end
                )
            }
            Self::RelativeWorkingDirectory => f.write_str("the working directory must be absolute"),
            Self::Platform(error) => write!(f, "running a command failed: {error}"),
            Self::EvaluationThread => f.write_str("the evaluation thread failed"),
        }
    }
}

impl std::error::Error for InterpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::Unsupported { .. }
            | Self::DepthExceeded { .. }
            | Self::ExpansionLimit { .. }
            | Self::SourceMismatch { .. }
            | Self::RelativeWorkingDirectory
            | Self::EvaluationThread => None,
        }
    }
}

impl From<PlatformError> for InterpError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

/// Bash features the interpreter refuses until the story that implements them, which each variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unsupported {
    /// `$(…)`, `` `…` `` (KNSH-105, which runs them in a child shell and captures their output).
    CommandSubstitution,
    /// `<(…)`, `>(…)` (KNSH-105).
    ProcessSubstitution,
    /// An unquoted `$*` or `$@` of several parameters where bash does not split (an assignment, a `case` word, the
    /// word of `${x:=…}`), with an `IFS` whose first character is not a space: bash joins the parameters there with
    /// a separator that depends on the context and its version, which is not emulated (KNSH-109 settles it against
    /// bash 5.2).
    UnsplitJoin,
    /// A brace expansion whose pieces, brought together, would form `${…}`, `$(…)` or `$[…]` (`{$,}{a}`), which bash
    /// would then expand. Not emulated: such a word is refused rather than read differently.
    BraceBuiltExpansion,
    /// An array: `${a[0]}`, `${a[@]}`, `${!a[@]}`, `a[1]` in arithmetic (KNSH-103).
    Array,
    /// A variable bash maintains itself (`RANDOM`, `LINENO`, `BASH_VERSION`, `$_` …), which the interpreter does not
    /// emulate yet, so reading it would give a value bash never gives (KNSH-101).
    ShellVariable,
    /// `${x@P}`, which expands the value as a prompt string (KNSH-107).
    PromptExpansion,
    /// `~N`, `~+N`, `~-N` and `~-`: the directory stack and `OLDPWD` (KNSH-101).
    DirectoryStack,
    /// A variable whose value is not UTF-8, used in an expansion. Passing it on unchanged needs byte-level words.
    NonUtf8Value,
    /// A file name that is not UTF-8, matched by pathname expansion. Passing it on unchanged needs byte-level words.
    NonUtf8FileName,
    /// A redirection after `(( … ))` or `for (( … ))`, which the parser keeps opaque, so its redirections are not
    /// read.
    Redirection,
    /// A here-document, `<<` or `<<-` (KNSH-105).
    HereDocument,
    /// `$!` after a background job whose last command the shell runs itself (`{ …; } &`, `a && b &`): bash's value
    /// is a forked subshell's process id, which does not exist here, and any number given instead could name another
    /// process.
    InShellProcessId,
    /// The `time` keyword in an interpreter given no clocks ([`Interpreter::with_times`](crate::Interpreter::with_times)).
    Time,
    /// A function definition (KNSH-103).
    FunctionDefinition,
    /// A bash builtin other than `let` and the few whose external program behaves the same (KNSH-101, KNSH-102).
    Builtin,
    /// A construct the parser keeps opaque: `[[ … ]]`, `select`, an arithmetic `for` whose header is not three
    /// expressions.
    Construct(UnsupportedConstruct),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandSubstitution => f.write_str("command substitution (KNSH-105)"),
            Self::ProcessSubstitution => f.write_str("process substitution (KNSH-105)"),
            Self::BraceBuiltExpansion => f.write_str("an expansion formed by brace expansion"),
            Self::UnsplitJoin => {
                f.write_str("joining $* or $@ with a non-space IFS where bash does not split (KNSH-109)")
            }
            Self::Array => f.write_str("arrays (KNSH-103)"),
            Self::ShellVariable => f.write_str("a variable bash maintains itself (KNSH-101)"),
            Self::PromptExpansion => f.write_str("prompt expansion (KNSH-107)"),
            Self::DirectoryStack => f.write_str("the directory stack and OLDPWD (KNSH-101)"),
            Self::NonUtf8Value => f.write_str("a variable value that is not UTF-8"),
            Self::NonUtf8FileName => f.write_str("a file name that is not UTF-8"),
            Self::Redirection => f.write_str("a redirection of an arithmetic command"),
            Self::HereDocument => f.write_str("here-document (KNSH-105)"),
            Self::InShellProcessId => f.write_str("$! of a background job the shell runs itself"),
            Self::Time => f.write_str("the time keyword without clocks"),
            Self::FunctionDefinition => f.write_str("function definition (KNSH-103)"),
            Self::Builtin => f.write_str("this builtin (KNSH-101, KNSH-102)"),
            Self::Construct(construct) => write!(f, "{construct}"),
        }
    }
}
