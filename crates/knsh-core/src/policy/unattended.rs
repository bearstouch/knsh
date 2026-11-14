//! The built-in `unattended` profile (KNSH-041; FR-AGT-21).
//!
//! A non-interactive `knsh` or `knsh -c` outside any envelope (an agent CLI started with `SHELL=knsh` but not through
//! `knsh agent`) runs under this profile: supervised, sandboxed, and denied anything that needs approval, so a
//! misconfigured setup fails closed. Its contents are documented in
//! `specs/03-functional-requirements/policy.md#the-unattended-profile`: plain read-only commands, writes only to
//! `${TMPDIR}`, no network, and `ask` for everything else.
//!
//! The profile is TOML text compiled into the binary ([`UNATTENDED_PROFILE_TEXT`]), so its integrity is the binary's
//! code signature, and it is read by the same loader as any profile: the engine still never authors policy in code
//! (FR-POL-03). [`load_unattended`] reads it without a profile source, so a file in the policies directory can neither
//! replace it nor be its parent.
//!
//! What makes asks (and allowed dynamic code) into denies is the line verdict ([`evaluate_line`](super::evaluate_line)):
//! any profile named [`UNATTENDED_PROFILE`] can never ask. A pushed or local profile taking that name only loses its
//! asks, which fails closed. Choosing this profile for a session (FR-AGT-21) is the supervisor's (part b of phase 2).

use super::paths::PathContext;
use super::{LookupError, PolicyFs, Profile, ProfileSource, load_profile_text};
use crate::error::ProfileError;
use crate::session::ProfileName;

/// The name of the built-in `unattended` profile.
pub const UNATTENDED_PROFILE: &str = "unattended";

/// The built-in `unattended` profile's text, as compiled into the binary.
pub const UNATTENDED_PROFILE_TEXT: &str = include_str!("builtin/unattended.toml");

/// Loads the built-in `unattended` profile, expanding its paths for `context`.
///
/// # Errors
///
/// [`ProfileError`] if a path variable cannot be resolved (`${TMPDIR}`, `${HOME}` or the start directory does not
/// exist) or a path cannot be canonicalised. The text itself is checked by this crate's tests, so it always parses.
pub fn load_unattended<F: PolicyFs + ?Sized>(context: &PathContext, fs: &F) -> Result<Profile, ProfileError> {
    load_profile_text(UNATTENDED_PROFILE_TEXT.as_bytes(), &BuiltIn, context, fs)
}

/// The profile source of a built-in profile: it has no parents, so nothing on disk can be merged into it.
struct BuiltIn;

impl ProfileSource for BuiltIn {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}
