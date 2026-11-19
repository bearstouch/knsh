//! Named secrets in memory (KNSH-089).

use std::collections::BTreeMap;
use std::sync::Mutex;

use knsh_core::SecretName;

use super::lock;
use crate::error::PlatformError;
use crate::secret::{SecretStore, SecretValue};

#[derive(Default)]
struct State {
    /// The secrets, by name. Kept as plain bytes: a fake never holds real secrets.
    values: BTreeMap<SecretName, Vec<u8>>,
    /// Names whose read fails with access denied and this `OSStatus`, as an item `knshd` is not trusted to read
    /// would (`-25293`, decision 11).
    denied: BTreeMap<SecretName, i32>,
    reads: usize,
}

/// A [`SecretStore`] in memory: secrets the test adds, names whose read is denied, every read counted. Never touches
/// the real Keychain.
#[derive(Default)]
pub struct MemSecretStore {
    state: Mutex<State>,
}

impl std::fmt::Debug for MemSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemSecretStore").finish_non_exhaustive()
    }
}

impl MemSecretStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the secret `name` with `value`.
    pub fn insert(&self, name: &SecretName, value: &[u8]) {
        let mut state = lock(&self.state);
        state.denied.remove(name);
        state.values.insert(name.clone(), value.to_vec());
    }

    /// Removes the secret `name`, as a user deleting the item would.
    pub fn remove(&self, name: &SecretName) {
        lock(&self.state).values.remove(name);
    }

    /// Makes every later read of `name` fail with access denied and `status`.
    pub fn deny(&self, name: &SecretName, status: i32) {
        lock(&self.state).denied.insert(name.clone(), status);
    }

    /// Reads so far.
    #[must_use]
    pub fn reads(&self) -> usize {
        lock(&self.state).reads
    }
}

impl SecretStore for MemSecretStore {
    fn read(&self, name: &SecretName) -> Result<SecretValue, PlatformError> {
        let mut state = lock(&self.state);
        state.reads += 1;
        if let Some(&status) = state.denied.get(name) {
            return Err(PlatformError::SecretAccessDenied { status: Some(status) });
        }
        state
            .values
            .get(name)
            .map(|value| SecretValue::from_vec(value.clone()))
            .ok_or(PlatformError::SecretNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_of(name: &str) -> SecretName {
        SecretName::new(name).unwrap()
    }

    #[test]
    fn missing_secret_returns_not_found() {
        let store = MemSecretStore::new();
        let name = name_of("npm-token");
        assert!(matches!(store.read(&name), Err(PlatformError::SecretNotFound)));
        store.insert(&name, b"v1");
        assert_eq!(store.read(&name).unwrap().expose(), b"v1");
        store.remove(&name);
        assert!(matches!(store.read(&name), Err(PlatformError::SecretNotFound)));
        assert_eq!(store.reads(), 3);
    }

    #[test]
    fn denied_secret_returns_access_denied() {
        let store = MemSecretStore::new();
        let name = name_of("npm-token");
        store.insert(&name, b"v1");
        store.deny(&name, -25293);
        assert!(matches!(
            store.read(&name),
            Err(PlatformError::SecretAccessDenied { status: Some(-25293) })
        ));
    }
}
