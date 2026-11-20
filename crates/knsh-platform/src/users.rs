//! Home directories from the user database, for the native interpreter's tilde expansion (KNSH-097).
//!
//! Bash expands `~name` to the home directory the system's user database gives for `name`, and `~` to the current
//! user's when `HOME` is unset. A name with no entry leaves the word as written, so a lookup that fails for any
//! reason answers `None`: bash makes no distinction either.

use std::path::PathBuf;

/// Looks up home directories in the user database. Object safe: hold it as `Arc<dyn UserHomes>`.
pub trait UserHomes: Send + Sync {
    /// The home directory of the user called `name`, or `None` if the database has no such user (or cannot be
    /// read).
    fn home_of(&self, name: &str) -> Option<PathBuf>;

    /// The home directory of the user running the shell (its real user id, as bash uses), or `None` if the
    /// database has no entry for it.
    fn current_home(&self) -> Option<PathBuf>;
}
