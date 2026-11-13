//! Per-command network proxy.
//!
//! HTTP CONNECT and SOCKS proxy, TLS server-name reader, and host and address checks.
//!
//! # Boundaries
//!
//! Reads the TLS server name without decrypting. Depends on `knsh-core` and `knsh-platform`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/network-proxy.md`
//! - `specs/02-architecture/enforcement-model.md`
//!
//! Skeleton created by KNSH-001; functionality arrives in later stories.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
