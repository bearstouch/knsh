//! The user database through `getpwnam_r` and `getpwuid_r` (KNSH-097).

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::users::UserHomes;

/// First buffer size for one user database entry; doubled on `ERANGE`.
const FIRST_BUFFER: usize = 1024;

/// Largest buffer tried for one entry. An entry larger than this is treated as missing, so a corrupt database
/// cannot make the lookup allocate without bound.
const MAX_BUFFER: usize = 1 << 20;

/// The system user database (Open Directory on macOS, through the reentrant `getpw*_r` calls).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUserHomes;

impl SystemUserHomes {
    /// The system user database.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Which entry to look up.
enum Key<'a> {
    Name(&'a CStr),
    Uid(libc::uid_t),
}

/// Which text field of an entry to copy.
#[derive(Clone, Copy)]
enum Field {
    /// `pw_dir`.
    Home,
    /// `pw_name`.
    Name,
}

/// The home directory of the entry `key` names.
fn home(key: &Key<'_>) -> Option<PathBuf> {
    field(key, Field::Home).map(|bytes| PathBuf::from(OsStr::from_bytes(&bytes)))
}

/// The login name of user `uid` (`getpwuid`'s `pw_name`): what bash's `\u` prompt escape shows (KNSH-107). `None`
/// when the user database has no entry for it.
#[must_use]
pub fn user_name(uid: u32) -> Option<String> {
    field(&Key::Uid(uid), Field::Name).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Field `wanted` of the entry `key` names, growing the buffer on `ERANGE` up to [`MAX_BUFFER`].
fn field(key: &Key<'_>, wanted: Field) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; FIRST_BUFFER];
    loop {
        // SAFETY: an all-zero `passwd` is a valid value (integers zero, pointers null); the call overwrites it.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let status = match key {
            // SAFETY: `name` is NUL-terminated; `entry`, `buffer` (of `buffer.len()` bytes) and `found` are valid
            // and writable for the whole call, and nothing else uses them meanwhile.
            Key::Name(name) => unsafe {
                libc::getpwnam_r(
                    name.as_ptr(),
                    &raw mut entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &raw mut found,
                )
            },
            // SAFETY: as above.
            Key::Uid(uid) => unsafe {
                libc::getpwuid_r(
                    *uid,
                    &raw mut entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &raw mut found,
                )
            },
        };
        if status == libc::ERANGE && buffer.len() < MAX_BUFFER {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        let pointer = match wanted {
            Field::Home => entry.pw_dir,
            Field::Name => entry.pw_name,
        };
        if status != 0 || found.is_null() || pointer.is_null() {
            return None;
        }
        // SAFETY: on success the field points to a NUL-terminated string inside `buffer`, which is still alive and
        // not written to until the copy below is made.
        let text = unsafe { CStr::from_ptr(pointer) };
        return Some(text.to_bytes().to_vec());
    }
}

impl UserHomes for SystemUserHomes {
    fn home_of(&self, name: &str) -> Option<PathBuf> {
        // A name holding NUL names no user.
        let name = CString::new(name).ok()?;
        home(&Key::Name(&name))
    }

    fn current_home(&self) -> Option<PathBuf> {
        // SAFETY: `getuid` has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        home(&Key::Uid(uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_a_home_and_unknown_users_have_none() {
        let homes = SystemUserHomes::new();
        assert_eq!(homes.home_of("root"), Some(PathBuf::from("/var/root")));
        assert_eq!(homes.home_of("knsh-no-such-user-097"), None);
        assert_eq!(homes.home_of("a\0b"), None);
        assert!(homes.current_home().is_some());
    }

    // KNSH-107: `\u` shows the login name of the user.
    #[test]
    fn user_names_come_from_the_user_database() {
        assert_eq!(user_name(0).as_deref(), Some("root"));
        assert_eq!(user_name(4_000_000_000), None);
    }
}
