//! Secret names (KNSH-089, `specs/05-models/secret.md`).
//!
//! A secret is looked up by name: the Keychain item's account under service `knsh`, or the name the authority gave
//! it with `secrets.provide`. Profiles name secrets in `[secrets.env]` with the same rule. Only the name is pure
//! domain: the value never enters this crate, since zeroing its memory needs code outside it (`knsh-platform`).

use std::fmt;

use crate::error::CoreError;
use crate::session::is_valid_name;

/// Largest secret value the engine holds, in bytes (64 KiB): far above any token or key, and small enough that an
/// untrusted size is refused before anything is copied (`specs/09-reference/defaults-and-limits.md`).
pub const MAX_SECRET_VALUE_LEN: usize = 64 * 1024;

/// The name of a secret, for example `npm-token`.
///
/// # Invariants
///
/// 1 to [`MAX_NAME_LEN`](crate::MAX_NAME_LEN) bytes from `[A-Za-z0-9._-]`, the rule profile names follow, so a name
/// is safe in event payloads, error data and the redaction marker `«redacted:<name>»` without escaping. A name is not
/// secret: events and records report it (FR-SEC-06).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SecretName(String);

impl SecretName {
    /// Validates and wraps a secret name.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidSecretName`] if `s` is empty, longer than [`MAX_NAME_LEN`](crate::MAX_NAME_LEN) bytes or
    /// holds a character outside `[A-Za-z0-9._-]`.
    pub fn new(s: &str) -> Result<Self, CoreError> {
        if is_valid_name(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(CoreError::InvalidSecretName)
        }
    }

    /// The name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_NAME_LEN;

    #[test]
    fn accepts_names_profiles_use() {
        for name in [
            "npm-token",
            "a",
            "GITHUB_TOKEN",
            "deploy.key-2",
            &"a".repeat(MAX_NAME_LEN),
        ] {
            assert_eq!(SecretName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_names_outside_the_rule() {
        for name in ["", "a b", "tok/en", "t\u{f6}ken", "a\0", &"a".repeat(MAX_NAME_LEN + 1)] {
            assert_eq!(SecretName::new(name), Err(CoreError::InvalidSecretName), "{name:?}");
        }
    }
}
