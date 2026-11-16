//! In-memory Keychain items: the policy signing key (KNSH-065) and the authority trust record (KNSH-068).

use std::sync::Mutex;

use knsh_core::TrustedAuthority;

use super::lock;
use crate::control::TrustStore;
use crate::error::{Operation, PlatformError};
use crate::presence::Authenticated;
use crate::signing::{SIGNING_KEY_LEN, SigningKey, SigningKeyStore};

#[derive(Debug, Default)]
struct State {
    key: Option<[u8; SIGNING_KEY_LEN]>,
    /// `OSStatus` every read fails with, as a tampered or locked keychain would (decision 11).
    read_failure: Option<i32>,
    /// `OSStatus` every create fails with.
    create_failure: Option<i32>,
    reads: usize,
    creates: usize,
}

/// A [`SigningKeyStore`] in memory: empty or holding a key, with injected read and create failures, counting calls.
/// Never touches the real Keychain.
#[derive(Debug, Default)]
pub struct MemKeyStore {
    state: Mutex<State>,
}

impl MemKeyStore {
    /// An empty store: no key yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store already holding `key`.
    #[must_use]
    pub fn with_key(key: [u8; SIGNING_KEY_LEN]) -> Self {
        let store = Self::new();
        lock(&store.state).key = Some(key);
        store
    }

    /// Makes every later read fail with `status` (for example `-25293`, what an item overwritten by another program
    /// reads as).
    pub fn fail_reads(&self, status: i32) {
        lock(&self.state).read_failure = Some(status);
    }

    /// Lets reads succeed again.
    pub fn allow_reads(&self) {
        lock(&self.state).read_failure = None;
    }

    /// Makes every later create fail with `status` (for example `-25299`, an item that already exists).
    pub fn fail_creates(&self, status: i32) {
        lock(&self.state).create_failure = Some(status);
    }

    /// Reads so far.
    #[must_use]
    pub fn reads(&self) -> usize {
        lock(&self.state).reads
    }

    /// Successful creates so far.
    #[must_use]
    pub fn creates(&self) -> usize {
        lock(&self.state).creates
    }
}

impl SigningKeyStore for MemKeyStore {
    fn read(&self) -> Result<Option<SigningKey>, PlatformError> {
        let mut state = lock(&self.state);
        state.reads += 1;
        if let Some(status) = state.read_failure {
            return Err(PlatformError::Keychain {
                operation: Operation::KeychainRead,
                status,
            });
        }
        Ok(state.key.map(SigningKey::from_bytes))
    }

    fn create(&self, key: &SigningKey) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let duplicate = state.key.is_some().then_some(-25299);
        if let Some(status) = state.create_failure.or(duplicate) {
            return Err(PlatformError::Keychain {
                operation: Operation::KeychainAdd,
                status,
            });
        }
        state.key = Some(*key.bytes());
        state.creates += 1;
        Ok(())
    }
}

/// `errSecItemNotFound`, what an update of a missing item reports.
const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecDuplicateItem`, what a create of an existing item reports.
const DUPLICATE_ITEM: i32 = -25299;

#[derive(Debug, Default)]
struct TrustState {
    record: Option<TrustedAuthority>,
    /// `OSStatus` every read fails with, as a tampered or locked keychain would (decision 11).
    read_failure: Option<i32>,
    /// `OSStatus` every create and replace fails with.
    write_failure: Option<i32>,
    reads: usize,
    writes: usize,
}

/// A [`TrustStore`] in memory: empty or holding a record, with injected read and write failures, counting calls.
/// Never touches the real Keychain. Like the Keychain, a create over an existing record and a replace of a missing
/// one fail and change nothing.
#[derive(Debug, Default)]
pub struct MemTrustStore {
    state: Mutex<TrustState>,
}

impl MemTrustStore {
    /// An empty store: no authority trusted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store already holding `record`.
    #[must_use]
    pub fn with_record(record: TrustedAuthority) -> Self {
        let store = Self::new();
        lock(&store.state).record = Some(record);
        store
    }

    /// The record held now, read without counting or failing: what a test checks after a write.
    #[must_use]
    pub fn record(&self) -> Option<TrustedAuthority> {
        lock(&self.state).record.clone()
    }

    /// Makes every later read fail with `status` (for example `-25293`, what an item overwritten by another program
    /// reads as).
    pub fn fail_reads(&self, status: i32) {
        lock(&self.state).read_failure = Some(status);
    }

    /// Makes every later create and replace fail with `status`.
    pub fn fail_writes(&self, status: i32) {
        lock(&self.state).write_failure = Some(status);
    }

    /// Reads so far.
    #[must_use]
    pub fn reads(&self) -> usize {
        lock(&self.state).reads
    }

    /// Successful creates and replaces so far.
    #[must_use]
    pub fn writes(&self) -> usize {
        lock(&self.state).writes
    }

    /// Stores `record` unless writes fail or `conflict` (given whether a record exists) names the `OSStatus` the
    /// Keychain would report for `operation`; on failure nothing changes.
    fn write(
        &self,
        record: &TrustedAuthority,
        operation: Operation,
        conflict: impl FnOnce(bool) -> Option<i32>,
    ) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        let conflict = conflict(state.record.is_some());
        if let Some(status) = state.write_failure.or(conflict) {
            return Err(PlatformError::Keychain { operation, status });
        }
        state.record = Some(record.clone());
        state.writes += 1;
        Ok(())
    }
}

impl TrustStore for MemTrustStore {
    fn read(&self) -> Result<Option<TrustedAuthority>, PlatformError> {
        let mut state = lock(&self.state);
        state.reads += 1;
        if let Some(status) = state.read_failure {
            return Err(PlatformError::Keychain {
                operation: Operation::KeychainRead,
                status,
            });
        }
        Ok(state.record.clone())
    }

    fn create(&self, record: &TrustedAuthority, _proof: Authenticated) -> Result<(), PlatformError> {
        self.write(record, Operation::KeychainAdd, |existing| {
            existing.then_some(DUPLICATE_ITEM)
        })
    }

    fn replace(&self, record: &TrustedAuthority, _proof: Authenticated) -> Result<(), PlatformError> {
        self.write(record, Operation::KeychainUpdate, |existing| {
            (!existing).then_some(ITEM_NOT_FOUND)
        })
    }
}
