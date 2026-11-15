//! Checks on the profile file before it is handed to `sandbox-exec` (KNSH-046, FR-SBX-07).
//!
//! `knshd` writes every compiled profile as a `0600` file of its user in a `0700` engine directory. The trampoline
//! refuses anything else, so a profile that another user (or a group member) could have rewritten is never applied:
//! a weakened profile would be worse than a refused line.

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Permission bits that let anyone but the owner change the file.
const WRITABLE_BY_OTHERS: u32 = 0o022;

/// Why the profile file is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileError {
    /// It cannot be read (missing, or a component cannot be searched). Holds the `errno`.
    Unreadable(Option<i32>),
    /// It is not a regular file (a symlink, a directory, a FIFO, a device or a socket).
    NotRegular,
    /// It belongs to another user.
    WrongOwner,
    /// Its group or others can write it.
    Writable,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(Some(errno)) => {
                write!(f, "profile unreadable: {}", std::io::Error::from_raw_os_error(*errno))
            }
            Self::Unreadable(None) => f.write_str("profile unreadable"),
            Self::NotRegular => f.write_str("profile is not a regular file"),
            Self::WrongOwner => f.write_str("profile belongs to another user"),
            Self::Writable => f.write_str("profile is writable by group or others"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Requires `path` to be a regular file (not a symlink) owned by `uid` and writable by nobody else.
///
/// # Errors
///
/// A [`ProfileError`] naming the first check that failed.
pub(crate) fn check(path: &Path, uid: u32) -> Result<(), ProfileError> {
    // `symlink_metadata`: the final component is not followed, so a link planted in place of the file is refused.
    let metadata = fs::symlink_metadata(path).map_err(|error| ProfileError::Unreadable(error.raw_os_error()))?;
    // `is_file` is true for regular files only, so a symlink, directory, FIFO, device or socket is refused here.
    if !metadata.file_type().is_file() {
        return Err(ProfileError::NotRegular);
    }
    if metadata.uid() != uid {
        return Err(ProfileError::WrongOwner);
    }
    if metadata.mode() & WRITABLE_BY_OTHERS != 0 {
        return Err(ProfileError::Writable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    /// A fresh private directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("knsh-exec-profile-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn own_uid(path: &Path) -> u32 {
        fs::metadata(path).unwrap().uid()
    }

    #[test]
    fn accepts_a_private_regular_file() {
        let dir = scratch("ok");
        let file = dir.join("p.sb");
        fs::write(&file, "(version 1)").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check(&file, own_uid(&dir)), Ok(()));
        // Read-only for others is fine: only writes could weaken it.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(check(&file, own_uid(&dir)), Ok(()));
        fs::remove_dir_all(&dir).unwrap();
    }

    // KNSH-046: a profile that is missing, linked, shared or foreign is never applied.
    #[test]
    fn refuses_unsafe_profiles() {
        let dir = scratch("bad");
        let uid = own_uid(&dir);
        assert!(matches!(
            check(&dir.join("missing.sb"), uid),
            Err(ProfileError::Unreadable(Some(_)))
        ));
        assert_eq!(check(&dir, uid), Err(ProfileError::NotRegular));

        let file = dir.join("p.sb");
        fs::write(&file, "(version 1)").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o620)).unwrap();
        assert_eq!(check(&file, uid), Err(ProfileError::Writable));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o602)).unwrap();
        assert_eq!(check(&file, uid), Err(ProfileError::Writable));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check(&file, uid.wrapping_add(1)), Err(ProfileError::WrongOwner));

        let link = dir.join("link.sb");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(check(&link, uid), Err(ProfileError::NotRegular));
        fs::remove_dir_all(&dir).unwrap();
    }
}
