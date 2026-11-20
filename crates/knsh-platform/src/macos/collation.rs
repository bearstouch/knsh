//! Collation through `newlocale` and `strcoll_l` (KNSH-098), the calls bash's `strcoll` resolves to in a locale.

use std::ffi::{CStr, CString, c_char, c_int};

use crate::collation::{Collation, is_c_locale, tie_break};

unsafe extern "C" {
    /// `strcoll` in the locale `locale` (`<xlocale.h>`); `libc` has no binding for it on Apple targets.
    fn strcoll_l(s1: *const c_char, s2: *const c_char, locale: libc::locale_t) -> c_int;
}

/// The system's collation tables.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCollation;

impl SystemCollation {
    /// The system's collation tables.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// A locale opened for its collation, freed on drop.
struct Locale(libc::locale_t);

impl Locale {
    /// The collation of `name`, or `None` if the system has no such locale. A name with a `/` or a NUL, or one
    /// starting with `.`, is refused without being looked up: locale names are plain names, and a path must not
    /// make the process load collation tables from wherever it points.
    fn open(name: &str) -> Option<Self> {
        if name.contains('/') || name.starts_with('.') {
            return None;
        }
        let name = CString::new(name).ok()?;
        // The character type is loaded with the collation: without it `strcoll_l` reads UTF-8 as single bytes of the
        // C locale and places `é` next to `a`. Bash takes both from `LANG` too.
        let mask = libc::LC_COLLATE_MASK | libc::LC_CTYPE_MASK;
        // SAFETY: `name` is NUL-terminated and outlives the call; a null base asks for a new locale object.
        let locale = unsafe { libc::newlocale(mask, name.as_ptr(), std::ptr::null_mut()) };
        (!locale.is_null()).then_some(Self(locale))
    }

    fn compare(&self, a: &CStr, b: &CStr) -> std::cmp::Ordering {
        // SAFETY: both strings are NUL-terminated and alive for the call; `self.0` is a live locale object.
        let order = unsafe { strcoll_l(a.as_ptr(), b.as_ptr(), self.0) };
        order.cmp(&0)
    }
}

impl Drop for Locale {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from `newlocale`, is freed once, here, and never used afterwards.
        unsafe {
            libc::freelocale(self.0);
        }
    }
}

impl Collation for SystemCollation {
    fn sort(&self, locale: &str, items: &mut [String]) -> bool {
        items.sort_unstable();
        if is_c_locale(locale) {
            return true;
        }
        let Some(opened) = Locale::open(locale) else {
            return false;
        };
        // A string holding NUL cannot be compared by `strcoll`; such strings (never file names) sort by bytes, as
        // the C order already put them.
        let Some(keys) = items
            .iter()
            .map(|item| CString::new(item.as_str()).ok())
            .collect::<Option<Vec<_>>>()
        else {
            return true;
        };
        let mut order: Vec<usize> = (0..items.len()).collect();
        order.sort_by(|&a, &b| {
            opened
                .compare(&keys[a], &keys[b])
                .then_with(|| tie_break(&items[a], &items[b]))
        });
        let sorted: Vec<String> = order.iter().map(|&index| items[index].clone()).collect();
        items.clone_from_slice(&sorted);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(locale: &str, items: &[&str]) -> (Vec<String>, bool) {
        let mut items: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();
        let found = SystemCollation::new().sort(locale, &mut items);
        (items, found)
    }

    const NAMES: &[&str] = &["B", "a", "_x", "\u{e9}", "Z", "0", "~t", "a b", "Ab", " sp", "#h"];

    #[test]
    fn c_and_c_utf8_sort_by_bytes() {
        let expected = [" sp", "#h", "0", "Ab", "B", "Z", "_x", "a", "a b", "~t", "\u{e9}"];
        assert_eq!(sorted("C", NAMES), (expected.map(String::from).to_vec(), true));
        assert_eq!(sorted("C.UTF-8", NAMES), (expected.map(String::from).to_vec(), true));
    }

    // Observed with `/bin/bash -c 'printf "[%s]" *'` on macOS over files with these names: punctuation first,
    // letters of either case together, an accented letter with its base letter.
    #[test]
    fn en_us_utf8_uses_the_system_tables() {
        let expected = [" sp", "_x", "#h", "~t", "0", "a", "a b", "Ab", "B", "\u{e9}", "Z"];
        assert_eq!(
            sorted("en_US.UTF-8", NAMES),
            (expected.map(String::from).to_vec(), true)
        );
    }

    #[test]
    fn a_missing_or_path_like_locale_leaves_the_c_order() {
        let (items, found) = sorted("xx_NOPE.UTF-8", &["b", "B", "a"]);
        assert!(!found);
        assert_eq!(items, ["B", "a", "b"]);
        assert!(!sorted("../en_US.UTF-8", &["a"]).1);
        assert!(!sorted("/usr/share/locale/en_US.UTF-8", &["a"]).1);
        assert!(!sorted("en_US\0.UTF-8", &["a"]).1);
    }
}
