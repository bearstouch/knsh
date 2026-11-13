//! Parser for the TOML subset used by policy and configuration files.
//!
//! [`parse`] reads exactly the TOML that the policy profile and hook configuration use into a tree of [`Table`],
//! [`Array`] and [`Value`] whose every [`Item`] carries its source [`Position`]. Anything outside the subset is
//! rejected with a typed [`TomlError`] naming line and column, never guessed at. Policy semantics (which keys
//! exist, what they mean) are not this crate's concern: they belong to the policy loader (KNSH-039).
//!
//! # The subset
//!
//! Accepted, with TOML 1.0 semantics:
//!
//! - Comments (`# …`), blank lines, `\n` or `\r\n` line ends; spaces and tabs as whitespace.
//! - Keys: bare (`A-Z a-z 0-9 _ -`), basic-quoted (`"…"`) and literal-quoted (`'…'`), and dotted keys made of them
//!   (`a."b".c`), with optional whitespace around the dots.
//! - Tables: `[table]`, `[a.b]` and arrays of tables `[[name]]`.
//! - Values:
//!   - single-line basic strings with the TOML 1.0 escapes (`\b \t \n \f \r \" \\ \uXXXX \UXXXXXXXX`);
//!   - single-line literal strings;
//!   - decimal integers in the `i64` range, with optional sign and single underscores between digits;
//!   - booleans `true` and `false`;
//!   - arrays, possibly spanning lines, with comments between elements and an optional trailing comma;
//!   - inline tables, on one line, without a trailing comma.
//!
//! Rejected as [`Reason::OutsideSubset`]: dates and times, floats (including `inf` and `nan`), multi-line strings
//! and hexadecimal, octal or binary integers. Everything that is not valid TOML 1.0 is rejected with its own
//! [`Reason`]: among others duplicate keys, a table defined twice (by headers, dotted keys or inline), control
//! characters in strings or comments, malformed numbers and escapes. A spec example that needs more TOML extends
//! this subset deliberately, in the spec first (`specs/05-models/policy-profile.md#toml-subset`).
//!
//! # Limits
//!
//! Input above [`MAX_INPUT_LEN`] is refused before it is read; nesting of tables and arrays is bounded by
//! [`MAX_DEPTH`], which also bounds recursion. The parser never panics and has no recovery mode: the first problem
//! ends the parse. Error messages never contain text from the input (NFR-PRIV-02).
//!
//! # Boundaries
//!
//! No workspace or third-party dependencies. Input is untrusted and the parser is fuzzed (`fuzz/`, target
//! `toml_parser`).
//!
//! # Specification
//!
//! - `specs/05-models/policy-profile.md` (example and subset)
//! - `specs/05-models/hook.md` (hook example)
//! - `specs/02-architecture/implementation.md`
//! - `specs/07-testing/fuzzing.md`
//! - NFR-SUP-06

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod error;
mod parse;
mod value;

pub use error::{Construct, Position, Reason, TomlError};
pub use parse::{MAX_DEPTH, MAX_INPUT_LEN, parse};
pub use value::{Array, Item, Iter, Table, Value};
