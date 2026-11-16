//! A resolver whose answers the test sets.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::resolver::Resolver;

/// Answers each name with the addresses the test set for it, and fails for any other name. Counts every question,
/// so a test can show a name was resolved exactly once (FR-NET-07: no second resolution between check and connect).
#[derive(Debug, Default)]
pub struct FakeResolver {
    answers: Mutex<HashMap<String, Vec<IpAddr>>>,
    asked: Mutex<Vec<String>>,
}

impl FakeResolver {
    /// A resolver that knows no name.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// From now on, `name` resolves to `addresses` (replacing an earlier answer: a rebinding attack in one line).
    pub fn answer(&self, name: &str, addresses: &[IpAddr]) {
        lock(&self.answers).insert(name.to_owned(), addresses.to_vec());
    }

    /// Every name asked so far, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        lock(&self.asked).clone()
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, PlatformError> {
        lock(&self.asked).push(name.to_owned());
        lock(&self.answers).get(name).cloned().ok_or(PlatformError::Os {
            operation: Operation::Resolve,
            errno: libc::ENOENT,
        })
    }
}
