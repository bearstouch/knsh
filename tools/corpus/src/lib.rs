//! Dev-only pipeline for the agent-command corpus (KNSH-033). Never shipped.
//!
//! The corpus is a set of versioned text files under `tests/corpus/` holding command lines that agents actually run.
//! The parser, the classifier and later the interpreter are measured against it. This crate provides:
//!
//! - [`normalise()`]: replaces home paths, user names, host names, IP addresses and secret-like values with stable
//!   placeholders, so no corpus line carries personal or secret data (decision 7, NFR-PRIV-08);
//! - [`entry`] and [`sources`]: the corpus file format (one entry per line, each with its source ID and licence) and
//!   the source registry with each source's licence;
//! - [`compat`]: detection of bash constructs that bash 3.2 (macOS `/bin/bash`) lacks, for the tags NFR-COMPAT-05
//!   relies on;
//! - [`import`]: turns a raw trace (plain lines or JSON lines from a trajectory) into normalised entries;
//! - [`check`]: the gate that fails CI when a corpus file is malformed, unnormalised, untagged or leaks a raw home
//!   path or token.
//!
//! # Boundaries
//!
//! A dev-only tool with one binary, `knsh-corpus`. It depends only on the in-house `knsh-json` reader, and nothing
//! may depend on it (enforced by `xtask/tests/dependency_policy.rs`), so it adds nothing to shipped crates. It uses
//! no user telemetry: inputs are published trajectories and CI traces only (NFR-PRIV-08).
//!
//! # Specification
//!
//! - `specs/07-testing/agent-command-corpus.md` (format, normalisation, provenance)
//! - `specs/09-reference/decisions.md`, decision 7
//! - `specs/04-non-functional-requirements/privacy.md`, NFR-PRIV-08
//! - `specs/04-non-functional-requirements/compatibility.md`, NFR-COMPAT-05
//! - `specs/00-stories/KNSH-033-agent-command-corpus-pipeline.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod check;
pub mod compat;
pub mod entry;
mod error;
pub mod import;
pub mod normalise;
pub mod sources;

pub use error::{CorpusError, EntryError};
pub use normalise::{Scrub, normalise};
