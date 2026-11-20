//! One redactor per session, on every output path (KNSH-091; FR-SEC-11, FR-REC-05, FR-EVT-07, FR-OUT-06,
//! NFR-PRIV-02; `specs/03-functional-requirements/secrets.md#redaction`).
//!
//! # The secret set
//!
//! A session redacts the secrets its profile names under `[secrets.env]` and every secret the authority has provided
//! (`secrets.provide`) and that is still live. Each is read through the secrets broker as injection would read it; one
//! that cannot be had (not found, access denied) is left out, since the engine never holds its value and so can
//! neither inject nor leak it. A human session, which has no profile here, redacts the provided secrets.
//!
//! # One instance per session
//!
//! [`Redactors::for_session`] answers with the session's [`Redactor`]: the cached instance while the session's secret
//! set reads the same, a new one (which then replaces it) as soon as a value is provided, revoked, expires or changes
//! in the Keychain. The supervisor takes it once per line and passes that one instance to every path of the line:
//! the decision pipeline (hooks, the authority, standalone approvals, `command.proposed`), the record (`command`,
//! `rewritten_from`, `argv` names, network hosts), the lifecycle events, the captured output and what `exec.run`
//! returns. So hooks and the authority see exactly the text the record keeps (FR-REC-05).
//!
//! # Failing closed
//!
//! A set the engine cannot redact (a value over the engine's size limits) is an error: an agent line is then denied,
//! and what is recorded of it is [`hidden`] entirely. A human command is still recorded, hidden, never blocked.
//!
//! # Locks
//!
//! One lock over the cache, a leaf: secrets are read and redactors built outside it, and nothing else is locked
//! while it is held.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{CoreError, Profile, REDACTED_MARKER, Redacted, Redactor, SecretName, SessionId};
use knsh_platform::SecretValue;

#[cfg(target_os = "macos")]
use crate::secrets::SecretBroker;

/// Where a session's secret values come from: the secrets broker in `knshd`, a fake in tests.
pub(crate) trait RedactionSecrets: Send + Sync {
    /// The secrets to redact for a session whose profile names `names`: each of them that can be read, and every
    /// live provided secret, each once, in name order. Secrets that cannot be had are left out.
    fn redaction_secrets(&self, names: &[SecretName]) -> Vec<(SecretName, SecretValue)>;
}

#[cfg(target_os = "macos")]
impl RedactionSecrets for SecretBroker {
    fn redaction_secrets(&self, names: &[SecretName]) -> Vec<(SecretName, SecretValue)> {
        self.redaction_set(names)
    }
}

/// A session's cached redactor and the values it was built from, to tell whether it is still current.
struct Cached {
    /// The profile's secret names the redactor was last built for: a later call without the profile (a refusal
    /// before it loads) keeps redacting them rather than replacing the session's redactor with a weaker one.
    names: Vec<SecretName>,
    secrets: Vec<(SecretName, SecretValue)>,
    redactor: Redactor,
}

/// Every session's redactor (module documentation).
pub(crate) struct Redactors {
    /// `None`: no secret source, so nothing to redact (a daemon without a broker, and tests).
    secrets: Option<Arc<dyn RedactionSecrets>>,
    cache: Mutex<HashMap<SessionId, Cached>>,
}

impl Redactors {
    /// Redactors reading each session's secrets from `secrets`.
    pub(crate) fn new(secrets: Arc<dyn RedactionSecrets>) -> Arc<Self> {
        Arc::new(Self {
            secrets: Some(secrets),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Redactors with no secrets: every session's redactor is empty (tests that redact nothing).
    #[cfg(test)]
    pub(crate) fn none() -> Arc<Self> {
        Arc::new(Self {
            secrets: None,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The redactor of `session_id`, whose profile is `profile` (`None` for a human session, or an agent line refused
    /// before its profile was loaded): the same instance as long as its secret set reads the same.
    ///
    /// # Errors
    ///
    /// [`CoreError::EmptySecretValue`] or [`CoreError::RedactionTooLarge`] when the set cannot be redacted; the caller
    /// fails closed (module documentation).
    pub(crate) fn for_session(&self, session_id: SessionId, profile: Option<&Profile>) -> Result<Redactor, CoreError> {
        let Some(source) = &self.secrets else {
            return Ok(Redactor::default());
        };
        // Without the profile, the names the session's redactor was last built for: one session, one secret set.
        let names = match profile {
            Some(profile) => profile_secrets(profile),
            None => self
                .lock()
                .get(&session_id)
                .map(|cached| cached.names.clone())
                .unwrap_or_default(),
        };
        // Read outside the lock: a slow Keychain never holds up another session's line.
        let secrets = source.redaction_secrets(&names);
        if let Some(cached) = self.lock().get(&session_id)
            && cached.names == names
            && same_secrets(&cached.secrets, &secrets)
        {
            return Ok(cached.redactor.clone());
        }
        // Built outside the lock too; a large set takes a while.
        let redactor = build(&secrets)?;
        self.lock().insert(
            session_id,
            Cached {
                names,
                secrets,
                redactor: redactor.clone(),
            },
        );
        Ok(redactor)
    }

    /// The redactor `session_id` uses now: the one its last line took ([`Self::for_session`]), or, before its first
    /// line, one for its provided secrets. For what the engine reports about a session outside a line's own path,
    /// such as the proxy's host names, so it hides what the session's lines hide.
    ///
    /// # Errors
    ///
    /// As [`Self::for_session`], when there is no cached redactor and the provided secrets cannot be redacted.
    pub(crate) fn latest(&self, session_id: SessionId) -> Result<Redactor, CoreError> {
        if let Some(cached) = self.lock().get(&session_id) {
            return Ok(cached.redactor.clone());
        }
        let Some(source) = &self.secrets else {
            return Ok(Redactor::default());
        };
        // Not cached: a report can come for a session that already ended (a leftover process's connection), and
        // caching then would keep its secret values after [`Self::forget`].
        build(&source.redaction_secrets(&[]))
    }

    /// Drops the cached redactor of a session that ended, and with it the values it held.
    pub(crate) fn forget(&self, session_id: SessionId) {
        self.lock().remove(&session_id);
    }

    /// The cache, even if a thread panicked while holding it: each entry is replaced whole.
    fn lock(&self) -> MutexGuard<'_, HashMap<SessionId, Cached>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A redactor for `secrets`.
fn build(secrets: &[(SecretName, SecretValue)]) -> Result<Redactor, CoreError> {
    Redactor::new(
        secrets
            .iter()
            .map(|(name, value)| (name.clone(), Redacted::new(value.expose()))),
    )
}

/// `text` through `redactor`, or entirely [`hidden`] without one (module documentation, "Failing closed").
pub(crate) fn redact_or_hide(redactor: Option<&Redactor>, text: &str) -> Redacted<String> {
    redactor.map_or_else(hidden, |redactor| redactor.redact_text(text))
}

/// What is kept of a text that could not be redacted: the plain marker, nothing of the text.
pub(crate) fn hidden() -> Redacted<String> {
    Redacted::new(REDACTED_MARKER.to_owned())
}

/// The secret names `profile` injects (`[secrets.env]`), each once. A name that is not a valid secret name cannot
/// name a secret, so it has nothing to redact.
fn profile_secrets(profile: &Profile) -> Vec<SecretName> {
    let mut names: Vec<SecretName> = profile
        .secrets
        .values()
        .filter_map(|injection| SecretName::new(&injection.secret).ok())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Whether two secret sets hold the same names with the same values, in the same order.
fn same_secrets(a: &[(SecretName, SecretValue)], b: &[(SecretName, SecretValue)]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|((name_a, value_a), (name_b, value_b))| name_a == name_b && value_a.expose() == value_b.expose())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixed set of secrets: each named one by value, and `provided` ones always.
    #[derive(Default)]
    pub(crate) struct FakeSecrets {
        /// Secrets readable by name (as from the Keychain).
        pub(crate) stored: Mutex<Vec<(&'static str, &'static str)>>,
        /// Secrets the authority provided: always in the set.
        pub(crate) provided: Mutex<Vec<(&'static str, &'static str)>>,
    }

    impl RedactionSecrets for FakeSecrets {
        fn redaction_secrets(&self, names: &[SecretName]) -> Vec<(SecretName, SecretValue)> {
            let mut set: Vec<(SecretName, SecretValue)> = Vec::new();
            for (name, value) in self.provided.lock().unwrap().iter() {
                set.push((
                    SecretName::new(name).unwrap(),
                    SecretValue::from_vec(value.as_bytes().to_vec()),
                ));
            }
            for (name, value) in self.stored.lock().unwrap().iter() {
                let name = SecretName::new(name).unwrap();
                if names.contains(&name) && !set.iter().any(|(other, _)| *other == name) {
                    set.push((name, SecretValue::from_vec(value.as_bytes().to_vec())));
                }
            }
            set.sort_by(|a, b| a.0.cmp(&b.0));
            set
        }
    }

    /// Redactors over a fake holding `provided` as provided secrets.
    pub(crate) fn provided(secrets: &[(&'static str, &'static str)]) -> Arc<Redactors> {
        let fake = FakeSecrets::default();
        fake.provided.lock().unwrap().extend_from_slice(secrets);
        Redactors::new(Arc::new(fake))
    }

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(knsh_core::Ulid::from_u128(n))
    }

    fn profile(text: &str) -> Profile {
        use crate::policy::tests::{fs, loader};
        loader(fs(&[("web", text)]))
            .load(
                &knsh_core::ProfileName::new("web").unwrap(),
                std::path::Path::new("/Users/u/app"),
            )
            .unwrap()
    }

    // KNSH-091: one instance per session while its secrets read the same; a change of value builds a new one.
    #[test]
    fn one_shared_redactor_per_session() {
        let fake = Arc::new(FakeSecrets::default());
        fake.provided.lock().unwrap().push(("api-key", "key-0123456789"));
        let redactors = Redactors::new(fake.clone());
        let first = redactors.for_session(session(1), None).unwrap();
        let again = redactors.for_session(session(1), None).unwrap();
        assert_eq!(first.secrets(), again.secrets());
        assert!(
            format!("{:p}", first.secrets()) == format!("{:p}", again.secrets()),
            "the same instance"
        );
        assert_eq!(
            first.redact_text("x key-0123456789 y").expose(),
            "x «redacted:api-key» y"
        );

        // A new value (a provided secret replaced) is redacted at once, by a new instance.
        fake.provided.lock().unwrap()[0].1 = "key-new-987654";
        let changed = redactors.for_session(session(1), None).unwrap();
        assert_eq!(changed.redact_text("key-new-987654").expose(), "«redacted:api-key»");
        // Forgotten with its session: the next call builds afresh.
        redactors.forget(session(1));
        assert!(redactors.lock().is_empty());
    }

    // KNSH-091: an agent session redacts the secrets its profile injects, and the provided ones; a Keychain secret the
    // profile does not name is not read.
    #[test]
    fn redacts_profile_secrets_and_provided_ones() {
        let fake = Arc::new(FakeSecrets::default());
        fake.stored
            .lock()
            .unwrap()
            .extend([("npm-token", "npm_abcdefgh123"), ("other", "other-secret-1")]);
        fake.provided.lock().unwrap().push(("gh-token", "ghp_zyxwvut987"));
        let redactors = Redactors::new(fake);
        let web = profile(
            "name = \"web\"\n[secrets.env]\nNPM_TOKEN = { secret = \"npm-token\", inject_for = [\"npm publish\"] }\n",
        );
        let redactor = redactors.for_session(session(2), Some(&web)).unwrap();
        let text = redactor.redact_text("npm_abcdefgh123 ghp_zyxwvut987 other-secret-1");
        assert_eq!(text.expose(), "«redacted:npm-token» «redacted:gh-token» other-secret-1");
    }

    // KNSH-091: a call without the profile (a refusal before it loads) keeps the profile's secrets in the session's
    // set rather than replacing its redactor with a weaker one, so the proxy's report still hides them; `latest` for
    // a session with no redactor (one that ended) answers without caching anything.
    #[test]
    fn calls_without_the_profile_keep_its_secrets() {
        let fake = Arc::new(FakeSecrets::default());
        fake.stored.lock().unwrap().push(("npm-token", "npm_abcdefgh123"));
        let redactors = Redactors::new(fake);
        let web = profile(
            "name = \"web\"\n[secrets.env]\nNPM_TOKEN = { secret = \"npm-token\", inject_for = [\"npm publish\"] }\n",
        );
        redactors.for_session(session(4), Some(&web)).unwrap();
        let early = redactors.for_session(session(4), None).unwrap();
        assert_eq!(early.redact_text("npm_abcdefgh123").expose(), "«redacted:npm-token»");
        let latest = redactors.latest(session(4)).unwrap();
        assert_eq!(latest.redact_text("npm_abcdefgh123").expose(), "«redacted:npm-token»");

        redactors.forget(session(4));
        redactors.latest(session(4)).unwrap();
        assert!(redactors.lock().is_empty(), "nothing cached for an ended session");
    }

    // KNSH-091, fail closed: a set that cannot be redacted is an error, never an empty redactor.
    #[test]
    fn unredactable_set_is_an_error() {
        static BIG: std::sync::LazyLock<&'static str> =
            std::sync::LazyLock::new(|| Box::leak("x".repeat(knsh_core::MAX_SECRET_VALUE_LEN + 1).into_boxed_str()));
        let fake = FakeSecrets::default();
        fake.provided.lock().unwrap().push(("huge", *BIG));
        let redactors = Redactors::new(Arc::new(fake));
        assert_eq!(
            redactors.for_session(session(3), None).err(),
            Some(CoreError::RedactionTooLarge)
        );
        assert_eq!(redact_or_hide(None, "anything").expose(), REDACTED_MARKER);
    }
}
