//! The in-envelope agent client: `knsh -c` forwarding and the `sh`, `bash` and `zsh` shims (KNSH-049).
//!
//! Inside an envelope, `$SHELL` is `knsh` and the shim directory is first in `PATH` (FR-AGT-03), so both
//! `$SHELL -c '…'` and `bash -c '…'` start this client. It runs nothing itself: [`forward`] sends the line, the
//! working directory, the environment and the interpreter it was asked for over `agent.sock`, with its stdio passed as
//! descriptors, and exits as the supervisor's line did (FR-AGT-10, FR-LC-31, NFR-COMPAT-09). [`shims`] maps the name
//! `knsh` was started as to that interpreter and installs the shim links. [`socket`] is the real connection (macOS).
//!
//! Requirements: FR-AGT-10, FR-LC-01, FR-LC-14, FR-LC-16 (stripped by `knshd`), FR-LC-31, FR-OUT-03, FR-OUT-04,
//! FR-AGT-31, NFR-COMPAT-09, NFR-REL-01; `specs/03-functional-requirements/agent-integration.md`,
//! `specs/06-api/agent-socket.md#execrun`.

pub mod forward;
pub mod shims;
#[cfg(target_os = "macos")]
pub mod socket;
