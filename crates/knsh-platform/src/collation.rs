//! String collation, for the order of the native interpreter's pathname expansion results (KNSH-098).
//!
//! Bash sorts the file names a pattern matches with `strcoll` in the collation of its locale (`LC_ALL`, else
//! `LC_COLLATE`, else `LANG`), ties broken by bytes. In the C and POSIX locales that is byte order; in other locales
//! it is the system's collation tables (on macOS `en_US.UTF-8` puts `_x` before `#h`, `a` before `B`), which only the
//! system can give. A locale the system does not have leaves the C order, as bash's `setlocale` failing does.

use std::cmp::Ordering;

/// Orders strings in a locale's collation. Object safe: hold it as `Arc<dyn Collation>`.
pub trait Collation: Send + Sync {
    /// Sorts `items` as `strcoll` orders them in the collation of `locale` (a locale name such as `en_US.UTF-8`),
    /// equal ones by their bytes. Returns `false`, with `items` sorted by their bytes (the C order), when the
    /// system has no such locale.
    fn sort(&self, locale: &str, items: &mut [String]) -> bool;
}

/// Whether `locale` names the C locale, whose collation is byte order everywhere: `C`, `POSIX` or empty.
#[must_use]
pub fn is_c_locale(locale: &str) -> bool {
    matches!(locale, "" | "C" | "POSIX")
}

/// The C collation only: byte order for every locale. Correct wherever the locale is C, POSIX or a locale whose
/// collation is byte order (macOS's `C.UTF-8`); for any other it reports the locale as missing.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteCollation;

impl Collation for ByteCollation {
    fn sort(&self, locale: &str, items: &mut [String]) -> bool {
        items.sort_unstable();
        is_c_locale(locale)
    }
}

/// Bash's tie-break after `strcoll` (`strvec_posixcmp`): the first bytes, then the whole strings by bytes.
#[must_use]
pub fn tie_break(a: &str, b: &str) -> Ordering {
    a.as_bytes().cmp(b.as_bytes())
}
