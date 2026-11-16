//! Per-command network proxy (KNSH-059).
//!
//! `knshd` runs one local proxy. Sandbox profiles allow outbound network only to its loopback port (and the
//! profile's own loopback ports), so every connection an envelope or a supervised line makes goes through it, and
//! each one is tied to a command and session by the credentials in its proxy settings (FR-NET-01).
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`credentials`] | Per-line and per-envelope credentials: issue, authenticate (constant time), revoke |
//! | [`http`] | Strict reader for HTTP request heads, with size limits; the fixed responses (`407` challenge) |
//! | [`socks5`] | Strict SOCKS5 handshake reader with username/password authentication (RFC 1928, RFC 1929) |
//! | [`target`] | Destinations of both protocols as one [`Target`]: names normalised, IP literals recognised |
//! | [`gate`] | The [`ConnectionGate`] that decides destinations, and the [`ProxyReport`] for refusals |
//! | [`relay`] | Byte-for-byte tunnels with idle and total timeouts |
//! | `server` | The listener, the kqueue accept loop and one thread per connection ([`Proxy`], macOS) |
//!
//! Built on standard threads and the platform's kqueue, with no third-party crate: every parser of client bytes is
//! hand-written, bounded before it allocates, refuses malformed input instead of repairing it, and is fuzzed
//! (`fuzz/fuzz_targets/proxy_handshake.rs`).
//!
//! # Boundaries
//!
//! The proxy enforces; it does not author rules. Which destinations a command may reach is the [`ConnectionGate`]'s
//! answer (host rules, name resolution and address checks arrive with KNSH-060; until then `knshd` uses
//! [`RefuseAll`]). The TLS server-name check is KNSH-061. The proxy makes no requests of its own (FR-NET-13): it only
//! connects on a client's behalf, after every check passed. Plain-HTTP requests in absolute-URI form are refused
//! (`405`), not forwarded.
//!
//! Depends on `knsh-core` (identifiers, [`knsh_core::Redacted`]) and `knsh-platform` (clock, random source, kqueue).
//! No `unsafe`.
//!
//! # Specification
//!
//! - `specs/03-functional-requirements/network-proxy.md`: FR-NET-01, FR-NET-05, FR-NET-09, FR-NET-13
//! - `specs/09-reference/decisions.md`, decision 14 (credential transport, `407` with Basic, SOCKS5)
//! - `specs/04-non-functional-requirements/security.md`: NFR-SEC-05, NFR-SEC-07
//! - `specs/07-testing/fuzzing.md` (HTTP CONNECT and SOCKS handling)
//! - `specs/09-reference/defaults-and-limits.md` (handshake, connect, idle and total timeouts; connection limit)

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

mod base64;
pub mod credentials;
mod error;
pub mod gate;
pub mod http;
pub mod relay;
#[cfg(target_os = "macos")]
mod server;
pub mod socks5;
pub mod target;

pub use credentials::{Credentials, Issued, MAX_CREDENTIALS, Owner, TOKEN_LEN, USER_PREFIX};
pub use error::ProxyError;
pub use gate::{ConnectionGate, Denial, Protocol, ProxyReport, Refusal, RefuseAll};
#[cfg(target_os = "macos")]
pub use server::{Config, Parts, Proxy};
pub use target::{Host, Target};
