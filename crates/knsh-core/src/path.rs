//! Canonical absolute paths (FR-POL-11).
//!
//! Policy matches paths only after they are resolved to canonical form with symlinks followed (for example
//! `/private/var/…` rather than `/var/…`). Resolving against the real filesystem is a platform effect and lives in
//! `knsh-platform`; this module defines the type that carries the result and checks the invariants that can be
//! checked without I/O. Any string that still contains `.`, `..`, `//` or is relative was not resolved, so it is
//! refused rather than normalised here: normalising lexically would be wrong where a component is a symlink.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::CoreError;

/// An absolute path that has already been resolved to canonical form.
///
/// # Invariants
///
/// - Non-empty, starts with `/`, and contains no NUL byte.
/// - No component is `.` or `..`, and no component is empty: there is no `//` and no trailing `/` (except for the
///   root `/` itself). So each canonical path has exactly one spelling, and byte equality is path equality.
///   (`Ord` is `PathBuf`'s component-wise order, which differs from byte order: `/a/b < /a-b`.)
/// - Constructed only through [`CanonicalPath::new`]; there is no `From<PathBuf>` or `From<&str>`.
///
/// Holding a `CanonicalPath` proves the shape above, not that the path exists or that symlinks were followed:
/// callers must obtain it from the platform's resolver.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPath(PathBuf);

impl CanonicalPath {
    /// Wraps an already-resolved absolute path after checking the invariants. Does not touch the filesystem.
    ///
    /// # Errors
    ///
    /// Checked in this order:
    /// - [`CoreError::PathEmpty`] for an empty path.
    /// - [`CoreError::PathNul`] if it contains a NUL byte.
    /// - [`CoreError::PathRelative`] unless it starts with `/`.
    /// - [`CoreError::PathDotComponent`] if any component is `.` or `..`.
    /// - [`CoreError::PathEmptyComponent`] for `//` anywhere or a trailing `/` on anything but the root.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, CoreError> {
        let path = path.into();
        validate(path.as_os_str())?;
        Ok(Self(path))
    }

    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consumes the wrapper and returns the path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// Checks the raw bytes rather than `Path::components()`, because `components()` silently drops `.` and repeated
/// separators, which are exactly the signs of an unresolved path.
fn validate(raw: &OsStr) -> Result<(), CoreError> {
    let bytes = raw.as_encoded_bytes();
    if bytes.is_empty() {
        return Err(CoreError::PathEmpty);
    }
    if bytes.contains(&0) {
        return Err(CoreError::PathNul);
    }
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return Err(CoreError::PathRelative);
    };
    // The root alone is canonical; splitting its empty remainder would report an empty component.
    if rest.is_empty() {
        return Ok(());
    }
    // Scan every component before reporting an empty one, so a path such as `/a//..` reports the dot component,
    // which is the more specific sign that the path was never resolved.
    let mut has_empty = false;
    for component in rest.split(|&b| b == b'/') {
        match component {
            b"." | b".." => return Err(CoreError::PathDotComponent),
            b"" => has_empty = true,
            _ => {}
        }
    }
    if has_empty {
        return Err(CoreError::PathEmptyComponent);
    }
    Ok(())
}

impl AsRef<Path> for CanonicalPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl fmt::Debug for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CanonicalPath").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_accepts_resolved_absolute_paths() {
        for ok in [
            "/",
            "/private/var/folders/x",
            "/a",
            "/a/b.c",
            "/a/.hidden",
            "/a/..b",
            "/a/b..",
            "/a/...",
            "/ spaced",
        ] {
            let path = CanonicalPath::new(ok).unwrap();
            assert_eq!(path.as_path(), Path::new(ok));
        }
        assert_eq!(CanonicalPath::new("/x").unwrap().into_path_buf(), PathBuf::from("/x"));
    }

    // FR-POL-11: only resolved, absolute paths reach policy matching.
    #[test]
    fn canonical_path_rejects_relative_and_dot_components() {
        assert_eq!(CanonicalPath::new(""), Err(CoreError::PathEmpty));
        for relative in ["a", "a/b", "./a", "../a", ".", "..", "~/a"] {
            assert_eq!(CanonicalPath::new(relative), Err(CoreError::PathRelative), "{relative}");
        }
        for dotted in [
            "/.", "/..", "/a/.", "/a/..", "/./a", "/../a", "/a/./b", "/a/../b", "/a//..",
        ] {
            assert_eq!(CanonicalPath::new(dotted), Err(CoreError::PathDotComponent), "{dotted}");
        }
        for unnormal in ["//", "//a", "/a//b", "/a/", "/a/b/"] {
            assert_eq!(
                CanonicalPath::new(unnormal),
                Err(CoreError::PathEmptyComponent),
                "{unnormal}"
            );
        }
        assert_eq!(CanonicalPath::new("/a\0b"), Err(CoreError::PathNul));
    }
}
