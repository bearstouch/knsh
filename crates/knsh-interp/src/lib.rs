//! Native bash interpreter: evaluates the syntax tree [`knsh_bash::parse`] builds (phase 4, KNSH-096).
//!
//! Phase 4 replaces "one stock interpreter per line" with `knsh`'s own bash-compatible interpreter, so the supervisor
//! can decide on every simple command, including inside scripts (`specs/00-stories/README.md`, phase 4). This crate
//! is its execution engine. KNSH-096 is the core: shell state ([`ShellState`]: variables, positional parameters,
//! `$?`, an options placeholder, the working directory) and an evaluator ([`Interpreter`]) for simple commands that
//! run external programs, `;` and newline lists, `&&`, `||`, `!`, `if`, `for`, `while`, `until`, `case` and `{ }`
//! groups, with bash's exit statuses ([`Status`]). KNSH-097 adds tilde, parameter and arithmetic expansion (every
//! `${…}` operator of bash 5.2 but arrays and `@P`), `(( ))`, arithmetic `for` and `let`, and `set -u`
//! ([`ShellOptions::nounset`]); [`evaluate_arithmetic`] evaluates one arithmetic expression on its own. KNSH-098
//! adds brace expansion, `IFS` word splitting, pathname expansion (with `set -f` and the `dotglob`, `nullglob`,
//! `failglob`, `nocaseglob`, `globstar` and `extglob` options of [`ShellOptions`]), `$'…'` and quote removal, in
//! bash's order. KNSH-099 adds every redirection but here-documents (`< > >> >| <> <& >& &> &>> <<<`, numbered and
//! `{name}` descriptors, closing with `-`, moving with `n-`, `set -C` as [`ShellOptions::noclobber`]), applied left to
//! right on the shell's own descriptor table and undone after each command, `exec` with redirections only (kept for
//! the shell's life) and `:`; `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` name the shell's
//! descriptors, and `/dev/tcp` and `/dev/udp` are refused (FR-NET-08). KNSH-100 adds pipelines (`|`, `|&`,
//! `PIPESTATUS`, `pipefail` and `lastpipe` as [`ShellOptions`]), `( … )` subshells, background jobs (`&`, `$!`), the
//! job builtins `wait` (with `-n`), `jobs`, `fg`, `bg` and `disown`, the `time` keyword, and job control (`set -m`
//! as [`ShellOptions::monitor`]; an interactive shell with its terminal through [`Interpreter::with_job_control`],
//! and [`JobSignals`] for the supervisor's pause, FR-SES-10). KNSH-101 adds the core builtins: `cd` (with `CDPATH`,
//! `-L`, `-P` and `OLDPWD`; the host is told of each change through a [`DirectoryObserver`], [`Osc7`] writing
//! OSC 7), `pwd`, `export`, `unset`, `readonly`, `declare` and `typeset` (variable attributes but arrays), `local`
//! (an error outside a function until KNSH-103), `shift`, `set` for the positional parameters, `exit`, `return`,
//! `break`, `continue`, `true`, `false`, `:`, `echo` (with [`ShellOptions::xpg_echo`]), `eval`, `source` and `.`,
//! `command`, `builtin`, `type`, `hash` (bash's command hash table), `alias` and `unalias` (expanded with
//! [`ShellOptions::expand_aliases`]), `umask` (passed to every command and redirection) and `exec` with a command.
//!
//! # Boundaries
//!
//! - The tree is consumed unchanged: there is no second parser of commands. Words are expanded from the parser's
//!   segments; only the bodies the parser keeps whole (`${…}`, `$((…))`, `(( … ))`) are read again, as bash reads
//!   them when it expands them. `case` patterns, the pattern operators and pathname expansion match with bash's
//!   `*`, `?`, bracket and (with `extglob`) group rules. A script using `extglob` groups in its own text is parsed
//!   with [`knsh_bash::parse_with`]; so is a script using `{name}>file` (with
//!   [`knsh_bash::ParseOptions::redirection_variables`], as bash 4.1 and later read it).
//! - Every effect goes through an injected trait from `knsh-platform`: commands are looked up and directories read
//!   for pathname expansion through [`knsh_platform::Fs`], file names sorted through [`knsh_platform::Collation`]
//!   (bash's `strcoll` order), redirection files opened through [`knsh_platform::Descriptors`], and commands run
//!   through [`knsh_platform::CommandSpawner`] with exactly the shell's descriptor table, so tests run without
//!   processes or a real filesystem and no descriptor of the interpreter's own process reaches a command. That spawner is where KNSH-108 inserts a decision before each command.
//! - A subshell is a copy of the interpreter, never a forked process (the process is multithreaded, and every program
//!   must start through the spawner): pipeline stages and background lists that the shell runs itself run on threads
//!   of their own (decision 19). Children are known by handle, waited for by one thread each, and a job's process
//!   group is signalled only while one of its members is held unreaped.
//! - What later stories implement (command substitution, here-documents, functions, arrays, `read`, `trap`, `set`
//!   options) is refused with [`InterpError::Unsupported`] by a check of the whole script before anything runs, or,
//!   when only an expansion's value reveals it (or `eval` and `source` text), when it is reached. Builtins whose
//!   external program behaves the same for literal arguments (`printf`, `test`, `[`) run as that program until
//!   KNSH-102.
//! - `eval`, `source` and alias text are parsed, checked and evaluated by the same parser and evaluator as the
//!   script, so every program in them starts through the same spawner (KNSH-108). `cd` changes the interpreter's
//!   working directory, never the process's, and `exec cmd` runs the program and then ends the shell (decision 20).
//! - Nesting is bounded by an explicit, documented limit ([`MAX_EVAL_DEPTH`]) that fails with
//!   [`InterpError::DepthExceeded`], on an evaluation thread whose stack ([`EVAL_STACK_SIZE`]) holds that many
//!   levels. Loops have no iteration limit, as in bash. Brace and pathname expansion are bounded in words, size and
//!   directory entries read, failing with [`InterpError::ExpansionLimit`].
//! - No `unsafe`, no I/O of its own beyond the injected traits and the diagnostics and output writers, no
//!   third-party crates.
//!
//! # Specification
//!
//! - `specs/00-stories/KNSH-096-interpreter-core-and-ast-evaluator.md`
//! - `specs/00-stories/KNSH-099-redirections-and-descriptor-management.md`, `specs/09-reference/decisions.md`
//!   (decision 18: network redirections refused)
//! - `specs/04-non-functional-requirements/compatibility.md` (NFR-COMPAT-01: bash semantics; NFR-COMPAT-02: corpus
//!   behaviour; NFR-COMPAT-09: 126 and 127)
//! - `specs/00-stories/KNSH-097-parameter-variable-and-arithmetic-expansion.md`
//! - `specs/04-non-functional-requirements/compatibility.md` (NFR-COMPAT-05: the bash 3.2 and 5.2 differences)
//! - `specs/00-stories/KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md`
//! - `specs/00-stories/KNSH-100-pipelines-subshells-and-job-control.md`, FR-SES-10 (pause of every job's group),
//!   `specs/09-reference/decisions.md` (decision 19: subshells are copies)
//! - `specs/00-stories/KNSH-101-core-builtins.md`, NFR-COMPAT-10 (OSC 7), `specs/09-reference/decisions.md`
//!   (decision 20: `exec` runs, then ends the shell)
//! - `specs/09-reference/defaults-and-limits.md` (the evaluation, arithmetic and expansion depth limits, and the
//!   brace and pathname expansion bounds)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod arith;
mod brace;
mod check;
mod error;
mod eval;
mod expand;
mod glob;
mod jobs;
mod lookup;
mod observer;
mod param;
mod pattern;
mod quote;
mod scan;
mod state;
mod status;
mod word;

pub use arith::{Failure as ArithmeticError, MAX_ARITH_DEPTH, evaluate_arithmetic};
pub use error::{InterpError, Unsupported};
pub use eval::{EVAL_STACK_SIZE, Interpreter, MAX_EVAL_DEPTH};
pub use jobs::{JobSignals, MAX_REMEMBERED_JOBS};
pub use observer::{DirectoryObserver, Osc7, osc7};
pub use state::{ShellOptions, ShellState};
pub use status::Status;
