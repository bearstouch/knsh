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
    /// `$(…)` or `` `…` `` where the interpreter does not run it (KNSH-105): inside `[[ … ]]`, `(( … ))`, `$(( … ))`
    /// or `${…}`, whose text it reads again without the parser, or in a prompt string (`PS4`).
    CommandSubstitution,
    /// `<(…)` or `>(…)` where the interpreter does not run it, as for [`Unsupported::CommandSubstitution`].
    ProcessSubstitution,
    /// A `coproc` the interpreter does not run as bash does (KNSH-105): not a pipeline of its own (in a pipeline, a
    /// `!` or `time` pipeline, or started with `&`), a name that is not an identifier, or one whose array cannot be
    /// assigned.
    Coproc,
    /// An unquoted `$*` or `$@` of several parameters where bash does not split (an assignment, a `case` word, the
    /// word of `${x:=…}`), with an `IFS` whose first character is not a space: bash joins the parameters there with
    /// a separator that depends on the context and its version, which is not emulated (KNSH-109 settles it against
    /// bash 5.2).
    UnsplitJoin,
    /// A brace expansion whose pieces, brought together, would form `${…}`, `$(…)` or `$[…]` (`{$,}{a}`), which bash
    /// would then expand. Not emulated: such a word is refused rather than read differently.
    BraceBuiltExpansion,
    /// An array form the interpreter does not evaluate as bash does (KNSH-103): `${a[@]@A}` and `${a[@]@K}`, an
    /// assignment to every element (`${a[@]:=x}`), an element assignment before a command (`a[1]=x cmd`), an
    /// associative array assigned as an indexed one or the reverse, an associative list mixing `[key]=value` and
    /// plain words, a bad subscript where bash's message is not reproduced.
    Array,
    /// A variable bash maintains itself (`RANDOM`, `LINENO`, `BASH_VERSION`, `$_` …), which the interpreter does not
    /// emulate, so reading or changing it would give a value bash never gives; also a builtin's listing that would
    /// include such variables (`declare -p` without names, `readonly -p`).
    ShellVariable,
    /// `${x@P}`, which expands the value as a prompt string (KNSH-107).
    PromptExpansion,
    /// `~N`, `~+N` and `~-N`: entries of the directory stack (`pushd`, `popd` and `dirs`, not scheduled yet).
    DirectoryStack,
    /// A variable whose value is not UTF-8, used in an expansion. Passing it on unchanged needs byte-level words.
    NonUtf8Value,
    /// A file name that is not UTF-8, matched by pathname expansion. Passing it on unchanged needs byte-level words.
    NonUtf8FileName,
    /// A redirection after `(( … ))` or `for (( … ))`, which the parser keeps opaque, so its redirections are not
    /// read.
    Redirection,
    /// A here-document whose body the parser did not attach to its redirection (never produced by
    /// [`knsh_bash::parse`], which refuses such a line).
    HereDocument,
    /// `$!` after a background job whose last command the shell runs itself (`{ …; } &`, `a && b &`): bash's value
    /// is a forked subshell's process id, which does not exist here, and any number given instead could name another
    /// process.
    InShellProcessId,
    /// The `time` keyword in an interpreter given no clocks ([`Interpreter::with_times`](crate::Interpreter::with_times)).
    Time,
    /// Printing a function's definition (`declare -f name`, `type name`, `command -V name`), which bash re-formats
    /// with its own pretty-printer, not reproduced (KNSH-103); also `export -f`, which passes functions in the
    /// environment in bash's own encoding.
    FunctionPrint,
    /// A pipeline stage that is not the last calling a function through a name an expansion produced
    /// (`$cmd | wc`): the function must run beside the other stages, which is decided before the stage starts, from
    /// the name as written (KNSH-103).
    PipelineFunction,
    /// A bash builtin the interpreter does not run yet (`getopts`, `kill`, `ulimit`, …), or a form of one it runs
    /// that it does not reproduce.
    Builtin,
    /// Changing a `set -o` or `shopt` option the interpreter does not implement (`set -a`, `set -o posix`,
    /// `shopt -s nocasematch`), or reading a line-editing or history option of an interactive shell (KNSH-107)
    /// (KNSH-104).
    ShellOption,
    /// A `trap` form whose behaviour the interpreter does not reproduce (KNSH-104): a `SIGCHLD` trap with a command
    /// (bash runs it as each child ends), a listing bash 3.2 and 5.2 print differently (a subshell's reset traps,
    /// signals ignored at entry), a function changing a trap it did not inherit, or `set -x` tracing a form whose
    /// trace bash prints differently by version.
    Trap,
    /// A name reference the interpreter does not follow as bash does (KNSH-103): to an array element, more than
    /// eight references deep, circular inside a function, or assigned through a circular chain.
    Nameref,
    /// An alias whose text cannot be run in place of the command it starts: text that does not parse alone, a
    /// pipeline stage whose alias is not a single simple command, or a chain of aliases past the interpreter's
    /// bound (KNSH-101).
    Alias,
    /// `source` of one of the shell's own descriptors (`. /dev/stdin`, `. /dev/fd/3`), which the interpreter does
    /// not read as files.
    SourceDescriptor,
    /// A sourced file that is not UTF-8.
    NonUtf8Script,
    /// `umask` printing the mask, or changing it with a symbolic mode, when the host never said what the process's
    /// umask is ([`ShellState::with_umask`](crate::ShellState::with_umask)): the interpreter never reads it itself.
    UnknownUmask,
    /// `eval` or `source` text with a syntax error bash would report differently from what the parser can tell
    /// (an unterminated quote, a construct the parser does not read), or before which bash would have run commands
    /// the parser cannot separate (KNSH-101).
    Unparsed,
    /// One of the shell's standard descriptors read, stat'ed or tested as a terminal (`read` from standard input,
    /// `test -t 1`, `[ -p /dev/stdin ]`) by an interpreter the host gave no standard descriptors
    /// ([`Interpreter::with_standard_descriptors`](crate::Interpreter::with_standard_descriptors)), KNSH-102.
    StandardDescriptor,
    /// A `[[ … ]]` whose words the interpreter cannot read as bash's parser does (a syntax error bash would report
    /// before running anything, a regular expression with an unbalanced parenthesis), or a redirection after it,
    /// which the parser keeps opaque (KNSH-102).
    Conditional,
    /// A `read` option that needs what a later story adds: `-e` on a terminal (line editing, KNSH-107) (KNSH-102).
    ReadOption,
    /// `printf %(…)T` in an interpreter given no local time
    /// ([`Interpreter::with_local_time`](crate::Interpreter::with_local_time)), or with a `TZ` the host's conversion
    /// does not use; and number formatting in a locale whose grouping or decimal point the interpreter does not
    /// reproduce (KNSH-102).
    PrintfLocale,
    /// `[[ … =~ … ]]` on text the system's regular expression engine would match in bytes while bash matches in
    /// characters, or the reverse: a capture that does not end on a character boundary (KNSH-102).
    RegexText,
    /// A construct the parser keeps opaque: `select`, an arithmetic `for` whose header is not three expressions.
    Construct(UnsupportedConstruct),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandSubstitution => f.write_str("command substitution in this context"),
            Self::ProcessSubstitution => f.write_str("process substitution in this context"),
            Self::Coproc => f.write_str("this coproc form"),
            Self::BraceBuiltExpansion => f.write_str("an expansion formed by brace expansion"),
            Self::UnsplitJoin => {
                f.write_str("joining $* or $@ with a non-space IFS where bash does not split (KNSH-109)")
            }
            Self::Array => f.write_str("this array form (KNSH-103)"),
            Self::ShellVariable => f.write_str("a variable bash maintains itself"),
            Self::PromptExpansion => f.write_str("prompt expansion (KNSH-107)"),
            Self::DirectoryStack => f.write_str("the directory stack"),
            Self::NonUtf8Value => f.write_str("a variable value that is not UTF-8"),
            Self::NonUtf8FileName => f.write_str("a file name that is not UTF-8"),
            Self::Redirection => f.write_str("a redirection of an arithmetic command"),
            Self::HereDocument => f.write_str("a here-document without its body"),
            Self::InShellProcessId => f.write_str("$! of a background job the shell runs itself"),
            Self::Time => f.write_str("the time keyword without clocks"),
            Self::FunctionPrint => f.write_str("printing a function definition (KNSH-103)"),
            Self::PipelineFunction => f.write_str("a function named by an expansion in a pipeline stage (KNSH-103)"),
            Self::Builtin => f.write_str("this builtin or builtin form"),
            Self::ShellOption => f.write_str("this shell option (KNSH-104)"),
            Self::Trap => f.write_str("this trap or trace form (KNSH-104)"),
            Self::Nameref => f.write_str("this name reference (KNSH-103)"),
            Self::Alias => f.write_str("this alias's text in place of its command"),
            Self::SourceDescriptor => f.write_str("source of one of the shell's descriptors"),
            Self::NonUtf8Script => f.write_str("a sourced file that is not UTF-8"),
            Self::UnknownUmask => f.write_str("the umask, which the host did not give"),
            Self::Unparsed => f.write_str("eval or source text the parser cannot report as bash would"),
            Self::StandardDescriptor => f.write_str("a standard descriptor the host did not give"),
            Self::Conditional => f.write_str("this [[ … ]] form"),
            Self::ReadOption => f.write_str("this read option (KNSH-107)"),
            Self::PrintfLocale => f.write_str("this printf conversion in the shell's locale or time zone"),
            Self::RegexText => f.write_str("a regular expression match bash would split differently"),
            Self::Construct(construct) => write!(f, "{construct}"),
        }
    }
}
