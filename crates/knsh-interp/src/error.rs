//! The crate's single error type.
//!
//! An error stops the whole run: nothing after it is evaluated. Constructs later stories implement are refused by a
//! check of the whole script before its first command runs, so a script this story cannot evaluate runs nothing at
//! all rather than part of itself.

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
    /// `$name`, `${…}` (KNSH-097).
    ParameterExpansion,
    /// `$((…))`, `$[…]` (KNSH-097).
    ArithmeticExpansion,
    /// `$(…)`, `` `…` `` (KNSH-097, run in a child shell from KNSH-100).
    CommandSubstitution,
    /// `<(…)`, `>(…)` (KNSH-105).
    ProcessSubstitution,
    /// `~` and `~user` at the start of a word, or after `=` or `:` in an assignment (KNSH-097).
    TildeExpansion,
    /// An unquoted `*`, `?` or `[…]` in a word that bash would match against file names (KNSH-098).
    PathnameExpansion,
    /// An unquoted `{a,b}` or `{1..3}` (KNSH-098).
    BraceExpansion,
    /// `$'…'` quoting, whose escapes are decoded (KNSH-098).
    AnsiCQuoting,
    /// A redirection, on a simple or compound command (KNSH-099).
    Redirection,
    /// A pipeline of more than one command (KNSH-100).
    Pipeline,
    /// A list run in the background with `&` (KNSH-100).
    Background,
    /// A subshell `( … )` (KNSH-100).
    Subshell,
    /// The `time` keyword (KNSH-100).
    Time,
    /// A function definition (KNSH-103).
    FunctionDefinition,
    /// A bash builtin other than the few whose external program behaves the same (KNSH-101, KNSH-102).
    Builtin,
    /// A construct the parser keeps opaque: `[[ … ]]`, `(( … ))`, `for (( … ))`, `select`.
    Construct(UnsupportedConstruct),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParameterExpansion => f.write_str("parameter expansion (KNSH-097)"),
            Self::ArithmeticExpansion => f.write_str("arithmetic expansion (KNSH-097)"),
            Self::CommandSubstitution => f.write_str("command substitution (KNSH-097)"),
            Self::ProcessSubstitution => f.write_str("process substitution (KNSH-105)"),
            Self::TildeExpansion => f.write_str("tilde expansion (KNSH-097)"),
            Self::PathnameExpansion => f.write_str("pathname expansion (KNSH-098)"),
            Self::BraceExpansion => f.write_str("brace expansion (KNSH-098)"),
            Self::AnsiCQuoting => f.write_str("ANSI-C quoting (KNSH-098)"),
            Self::Redirection => f.write_str("redirection (KNSH-099)"),
            Self::Pipeline => f.write_str("pipeline (KNSH-100)"),
            Self::Background => f.write_str("background list (KNSH-100)"),
            Self::Subshell => f.write_str("subshell (KNSH-100)"),
            Self::Time => f.write_str("the time keyword (KNSH-100)"),
            Self::FunctionDefinition => f.write_str("function definition (KNSH-103)"),
            Self::Builtin => f.write_str("this builtin (KNSH-101, KNSH-102)"),
            Self::Construct(construct) => write!(f, "{construct}"),
        }
    }
}
