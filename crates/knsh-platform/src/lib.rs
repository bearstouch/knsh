//! Platform interface and the macOS backend.
//!
//! Traits for every operating-system effect (clock, filesystem, processes, Keychain, authentication prompt, file
//! events, sockets) and the macOS implementation: XPC, Keychain, `LocalAuthentication`, `FSEvents`, APFS clones, unified
//! logging, `CommonCrypto` and SQLite through direct C calls.
//!
//! # Boundaries
//!
//! One of only two crates allowed to use `unsafe` (with `knsh-exec`): every `unsafe` block needs a `// SAFETY:`
//! comment and every `unsafe fn` a `# Safety` doc section. The only third-party dependency is `libc`, and no other
//! crate may depend on it (NFR-SUP-02).
//!
//! # Specification
//!
//! - `specs/02-architecture/implementation.md`
//! - `specs/02-architecture/platform-support.md`
//! - `specs/08-integrations/macos-services.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
