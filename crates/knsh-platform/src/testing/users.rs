//! A user database the test fills in.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::users::UserHomes;

/// Home directories by user name, plus the current user's; every other name is unknown.
#[derive(Debug, Clone, Default)]
pub struct FakeUserHomes {
    homes: BTreeMap<String, PathBuf>,
    current: Option<PathBuf>,
}

impl FakeUserHomes {
    /// A database with no users and no current user entry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds user `name` with home directory `home`.
    #[must_use]
    pub fn with_user(mut self, name: impl Into<String>, home: impl Into<PathBuf>) -> Self {
        self.homes.insert(name.into(), home.into());
        self
    }

    /// Sets the current user's home directory.
    #[must_use]
    pub fn with_current(mut self, home: impl Into<PathBuf>) -> Self {
        self.current = Some(home.into());
        self
    }
}

impl UserHomes for FakeUserHomes {
    fn home_of(&self, name: &str) -> Option<PathBuf> {
        self.homes.get(name).cloned()
    }

    fn current_home(&self) -> Option<PathBuf> {
        self.current.clone()
    }
}
