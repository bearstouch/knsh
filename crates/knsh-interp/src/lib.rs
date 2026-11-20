//! Native bash interpreter: evaluates the syntax tree [`knsh_bash::parse`] builds (phase 4, KNSH-096).
//!
//! Phase 4 replaces "one stock interpreter per line" with `knsh`'s own bash-compatible interpreter, so the supervisor
//! can decide on every simple command, including inside scripts (`specs/00-stories/README.md`, phase 4). This crate
//! is its execution engine. KNSH-096 is the core: shell state ([`ShellState`]: variables, positional parameters,
//! `$?`, an options placeholder, the working directory) and an evaluator ([`Interpreter`]) for simple commands that
//! run external programs, `;` and newline lists, `&&`, `||`, `!`, `if`, `for`, `while`, `until`, `case` and `{ }`
//! groups, with bash's exit statuses ([`Status`]).
//!
//! # Boundaries
//!
//! - The tree is consumed unchanged: there is no second parser. Words are read from the parser's segments (quote
//!   removal only, until KNSH-097 and KNSH-098 add expansions); `case` patterns are matched with bash's `*`, `?` and
//!   bracket rules.
//! - Every effect goes through an injected trait from `knsh-platform`: commands are looked up through
//!   [`knsh_platform::Fs`] and run through [`knsh_platform::CommandSpawner`], so tests run without processes. That
//!   spawner is where KNSH-108 inserts a decision before each command.
//! - What later stories implement (expansions, redirections, pipelines and subshells, functions, most builtins) is
//!   refused with [`InterpError::Unsupported`] by a check of the whole script before anything runs. Builtins whose
//!   external program behaves the same for literal arguments (`echo`, `printf`, `true`, `false`, `test`, `[`) run as
//!   that program until KNSH-101 and KNSH-102.
//! - Nesting is bounded by an explicit, documented limit ([`MAX_EVAL_DEPTH`]) that fails with
//!   [`InterpError::DepthExceeded`], on an evaluation thread whose stack ([`EVAL_STACK_SIZE`]) holds that many
//!   levels. Loops have no iteration limit, as in bash.
//! - No `unsafe`, no I/O of its own beyond the injected traits and the diagnostics writer, no third-party crates.
//!
//! # Specification
//!
//! - `specs/00-stories/KNSH-096-interpreter-core-and-ast-evaluator.md`
//! - `specs/04-non-functional-requirements/compatibility.md` (NFR-COMPAT-01: bash semantics; NFR-COMPAT-02: corpus
//!   behaviour; NFR-COMPAT-09: 126 and 127)
//! - `specs/09-reference/defaults-and-limits.md` (the evaluation depth limit)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod check;
mod error;
mod eval;
mod lookup;
mod pattern;
mod state;
mod status;
mod word;

pub use error::{InterpError, Unsupported};
pub use eval::{EVAL_STACK_SIZE, Interpreter, MAX_EVAL_DEPTH};
pub use state::{ShellOptions, ShellState};
pub use status::Status;
