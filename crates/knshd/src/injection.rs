//! Secret injection: which secrets an allowed line receives, and why one it needs is missing (KNSH-092; FR-SEC-01 to
//! FR-SEC-06, FR-NET-10; `specs/03-functional-requirements/secrets.md#injection-knsh-092`).
//!
//! # What a line receives
//!
//! The decision already did the policy work (`knsh_core`'s line evaluation): the `[secrets.env]` variables whose
//! `inject_for` patterns certainly match a command of the line, none for dynamic code (FR-SEC-01, FR-SEC-04), each
//! such command asked unless a grant covered it (FR-SEC-02), and the secrets' `hosts`, to which the proxy narrows the
//! line's network (FR-SEC-03, FR-NET-10). [`needed`] turns that into the secrets to look up: each variable with its
//! secret's name. It checks the decision once more: a line holding dynamic code receives nothing, whatever its
//! capabilities say.
//!
//! # Looking them up
//!
//! The supervisor looks the names up through the session's redactors ([`crate::redaction::Redactors::inject`]), so
//! every value a line receives is one its redactor replaces: a line whose secret changed between its decision and its
//! spawn is denied rather than run with a value its output would show. A secret that cannot be had denies the line
//! with a reason naming it ([`denial_reason`]); the line never runs with some of its secrets missing.
//!
//! # Privacy
//!
//! A value lives in a [`SecretValue`] (zeroed when dropped) until it is copied into the spawn request's environment.
//! Events and records carry names only ([`injected_names`], FR-SEC-06).

use knsh_core::{Allowed, Profile, SecretName};
use knsh_platform::SecretValue;

/// Why a secret could not be had. Either way the line that needs it is denied (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// No provided secret is live under the name and the Keychain has no such item.
    NotFound,
    /// The Keychain has the item but it cannot be read (decision 11: not readable by `knshd`, a locked keychain,
    /// tampering), or its value was refused.
    AccessDenied,
}

impl Unavailable {
    /// A fixed phrase for a denial reason.
    const fn phrase(self) -> &'static str {
        match self {
            Self::NotFound => "not found",
            Self::AccessDenied => "access denied",
        }
    }
}

/// A secret a line needs that it cannot have: what its denial names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Missing {
    /// The secret.
    pub(crate) name: SecretName,
    /// Why.
    pub(crate) reason: Unavailable,
}

/// One secret a line is to receive: the environment variable and the secret's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Needed {
    /// The `[secrets.env]` table key: the variable the value is injected as.
    pub(crate) variable: String,
    /// The secret to look up.
    pub(crate) name: SecretName,
}

/// Why an allowed line cannot be given its secrets. Each denies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InjectionError {
    /// A variable the line would receive names a secret that is not a valid secret name, or is not in the profile
    /// the line was decided with.
    InvalidSecret {
        /// The variable.
        variable: String,
    },
    /// A variable the engine sets itself or that must never reach a line (proxy settings, `DYLD_*`): injecting it
    /// would replace the line's proxy credentials or reach the dynamic linker.
    ReservedVariable {
        /// The variable.
        variable: String,
    },
    /// A secret could not be had.
    Unavailable(Missing),
    /// A value holds a NUL byte, which no environment variable can carry.
    NotAnEnvironmentValue {
        /// The secret.
        name: SecretName,
    },
    /// The session's secrets changed between the decision and the injection, so the line's redactor does not hold a
    /// value it would receive.
    NotRedacted,
}

/// One secret given to a line: its variable, its name and its value.
#[derive(Debug)]
pub(crate) struct Injected {
    /// The environment variable.
    pub(crate) variable: String,
    /// The secret's name: what `secret.injected` and the record name.
    pub(crate) name: SecretName,
    /// The value; `Debug` shows only its length.
    pub(crate) value: SecretValue,
}

/// The secrets `allowed` is to receive under `profile`, the session's profile it was decided with (module
/// documentation, "What a line receives"), in variable order. `reserved` says which variables may never be injected.
///
/// # Errors
///
/// [`InjectionError::InvalidSecret`] or [`InjectionError::ReservedVariable`]: the line is denied.
pub(crate) fn needed(
    allowed: &Allowed,
    profile: &Profile,
    reserved: impl Fn(&str) -> bool,
) -> Result<Vec<Needed>, InjectionError> {
    let capabilities = &allowed.profile.capabilities;
    // FR-SEC-04, defence in depth: the decision gives dynamic code no secrets; this holds even if it did.
    if capabilities.dynamic || allowed.classification.is_dynamic() {
        return Ok(Vec::new());
    }
    capabilities
        .secrets
        .iter()
        .map(|variable| {
            let invalid = || InjectionError::InvalidSecret {
                variable: variable.clone(),
            };
            if reserved(variable) {
                return Err(InjectionError::ReservedVariable {
                    variable: variable.clone(),
                });
            }
            let injection = profile.secrets.get(variable).ok_or_else(invalid)?;
            let name = SecretName::new(&injection.secret).map_err(|_| invalid())?;
            Ok(Needed {
                variable: variable.clone(),
                name,
            })
        })
        .collect()
}

/// Pairs each of `needed` with its value from `values` (as the lookup returned them, in the same order).
///
/// # Errors
///
/// [`InjectionError::NotAnEnvironmentValue`] for a value holding a NUL byte; [`InjectionError::NotRedacted`] if a
/// value is missing (the lookup answered for other names).
pub(crate) fn pair(
    needed: Vec<Needed>,
    values: Vec<(SecretName, SecretValue)>,
) -> Result<Vec<Injected>, InjectionError> {
    if needed.len() != values.len() {
        return Err(InjectionError::NotRedacted);
    }
    needed
        .into_iter()
        .zip(values)
        .map(|(needed, (name, value))| {
            if name != needed.name {
                return Err(InjectionError::NotRedacted);
            }
            if value.expose().contains(&0) {
                return Err(InjectionError::NotAnEnvironmentValue { name });
            }
            Ok(Injected {
                variable: needed.variable,
                name,
                value,
            })
        })
        .collect()
}

/// The reason a line denied for `error` is given: it names the secret or variable, never a value.
pub(crate) fn denial_reason(error: &InjectionError) -> String {
    match error {
        InjectionError::InvalidSecret { variable } => format!(
            "the secret injected as {variable} is not a valid secret of the session's profile, so the line was denied"
        ),
        InjectionError::ReservedVariable { variable } => {
            format!("{variable} is set by the engine and cannot receive a secret, so the line was denied")
        }
        InjectionError::Unavailable(Missing { name, reason }) => format!(
            "the secret {name} the line needs is unavailable ({}), so the line was denied (fail closed)",
            reason.phrase()
        ),
        InjectionError::NotAnEnvironmentValue { name } => {
            format!("the secret {name} holds a NUL byte and cannot be an environment variable, so the line was denied")
        }
        InjectionError::NotRedacted => String::from(
            "the session's secrets changed while the line was decided, so it was denied (fail closed); send it again",
        ),
    }
}

/// The record's `secrets_injected`: the names of the secrets in `injected`, each once, sorted (FR-SEC-06,
/// FR-REC-11). Never a value.
pub(crate) fn injected_names(injected: &[Injected]) -> Vec<String> {
    let mut names: Vec<String> = injected.iter().map(|secret| secret.name.as_str().to_owned()).collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests;
