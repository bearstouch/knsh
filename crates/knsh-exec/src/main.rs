//! Sandbox trampoline.
//!
//! Applies a Seatbelt profile with `sandbox-exec -f`, then execs the agent command.
//!
//! # Boundaries
//!
//! Standard library only, single-threaded, no workspace or third-party dependencies (NFR-SUP-01). One of only two
//! crates allowed to use `unsafe`.
//! Every `unsafe` block needs a `// SAFETY:` comment and every `unsafe fn` a `# Safety` doc section.
//!
//! # Specification
//!
//! - `specs/02-architecture/process-model.md`
//! - `specs/04-non-functional-requirements/supply-chain.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]

/// Entry point. Does nothing until the binary is implemented.
fn main() {}
