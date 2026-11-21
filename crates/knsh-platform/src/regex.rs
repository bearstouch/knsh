//! POSIX extended regular expressions through the system's `regcomp` and `regexec`, for the native interpreter's
//! `[[ string =~ regex ]]` (KNSH-102).
//!
//! Bash matches `=~` with the C library's `regcomp(REG_EXTENDED)` and `regexec`, so the system engine is the one
//! that gives bash's answers exactly: the same bracket expressions, character classes, back-references the system
//! allows in an ERE, leftmost-longest matches and subexpression offsets. An in-house engine would have to reproduce
//! all of that and would still differ in corners; the system one needs no new crate (decision recorded in
//! `specs/09-reference/decisions.md`). Linux has the same calls; its `regex_t` layout differs, so this module is
//! built on macOS until the Linux backend declares that one.
//!
//! Bash compiles and matches in its locale (`LC_CTYPE` and `LC_COLLATE`: what `.` and `[^a]` match in UTF-8, what a
//! range covers). This process never calls `setlocale`, so the locale the shell's variables name is installed for
//! the calling thread only (`newlocale` and `uselocale`), around the compile and the match, and the previous one put
//! back: other threads are never affected. A locale the system does not have leaves the C locale, as bash's
//! `setlocale` failing does.

#[cfg(target_os = "macos")]
use std::ffi::CString;

use crate::error::{Operation, PlatformError};

/// What matching a regular expression found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexOutcome {
    /// The pattern is not a valid extended regular expression (`regcomp` failed): bash's status 2.
    Invalid,
    /// The pattern is valid and does not match.
    NoMatch,
    /// It matches: the byte range of the whole match, then of each parenthesised subexpression in order (`None` for
    /// one that took no part in the match), as bash stores them in `BASH_REMATCH`.
    Match(Vec<Option<(usize, usize)>>),
}

/// Not built yet off macOS: the Linux backend declares its own `regex_t` (KNSH-102 records the pending port).
///
/// # Errors
///
/// Always [`PlatformError::Os`] with [`Operation::Regex`] and `ENOSYS`.
#[cfg(not(target_os = "macos"))]
pub fn regex_match(_: &str, _: &str, _: &str, _: bool) -> Result<RegexOutcome, PlatformError> {
    Err(PlatformError::Os {
        operation: Operation::Regex,
        errno: libc::ENOSYS,
    })
}

#[cfg(target_os = "macos")]
/// The thread's locale switched to `name` (for collation and character classes) until dropped.
struct ThreadLocale {
    /// The locale installed, freed on drop.
    installed: libc::locale_t,
    /// What the thread used before, put back on drop.
    previous: libc::locale_t,
}

#[cfg(target_os = "macos")]
impl ThreadLocale {
    /// Installs `name`, or the C locale when the system has no such locale; `None` if neither could be made.
    fn install(name: &str) -> Option<Self> {
        let mask = libc::LC_CTYPE_MASK | libc::LC_COLLATE_MASK;
        let make = |name: &str| {
            let name = CString::new(name).ok()?;
            // SAFETY: `name` is a valid NUL-terminated string for the duration of the call; a null base asks for a
            // new object. A null result means failure and is checked.
            let locale = unsafe { libc::newlocale(mask, name.as_ptr(), std::ptr::null_mut()) };
            (!locale.is_null()).then_some(locale)
        };
        let installed = make(name).or_else(|| make("C"))?;
        // SAFETY: `installed` is a valid locale object made above; `uselocale` only changes this thread's locale and
        // returns the previous one (never null for a valid argument).
        let previous = unsafe { libc::uselocale(installed) };
        Some(Self { installed, previous })
    }
}

#[cfg(target_os = "macos")]
impl Drop for ThreadLocale {
    fn drop(&mut self) {
        // SAFETY: `previous` is the locale this thread used before `install`, still valid; once it is back,
        // `installed` is no longer in use by any thread and can be freed.
        unsafe {
            libc::uselocale(self.previous);
            libc::freelocale(self.installed);
        }
    }
}

#[cfg(target_os = "macos")]
/// macOS's `regex_t` (`<regex.h>`), declared here because the `libc` crate keeps `re_nsub`, the count of
/// subexpressions, private. Its size is checked against `libc`'s below.
#[repr(C)]
#[allow(clippy::struct_field_names)] // The C names.
struct RegexT {
    re_magic: libc::c_int,
    re_nsub: libc::size_t,
    re_endp: *const libc::c_char,
    re_g: *mut libc::c_void,
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<RegexT>() == std::mem::size_of::<libc::regex_t>());

// The system's POSIX regular expression calls, over the layout above (the same symbols `libc` binds).
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn regcomp(preg: *mut RegexT, pattern: *const libc::c_char, cflags: libc::c_int) -> libc::c_int;
    fn regexec(
        preg: *const RegexT,
        string: *const libc::c_char,
        nmatch: libc::size_t,
        pmatch: *mut libc::regmatch_t,
        eflags: libc::c_int,
    ) -> libc::c_int;
    fn regfree(preg: *mut RegexT);
}

#[cfg(target_os = "macos")]
/// A compiled expression, freed on drop.
struct Compiled(RegexT);

#[cfg(target_os = "macos")]
impl Drop for Compiled {
    fn drop(&mut self) {
        // SAFETY: the expression was compiled successfully by `regcomp` and is freed exactly once.
        unsafe { regfree(&raw mut self.0) };
    }
}

#[cfg(target_os = "macos")]
/// Matches `subject` against the extended regular expression `pattern` as bash's `sh_regmatch` does:
/// `regcomp(REG_EXTENDED)` (with `REG_ICASE` when `ignore_case`, bash's `nocasematch`), then `regexec`, in the locale
/// `locale` (the shell's `LC_ALL`, `LC_CTYPE` or `LANG`), on the calling thread only.
///
/// A pattern or subject holding a NUL byte cannot be passed to the C library and is [`RegexOutcome::Invalid`]; shell
/// strings never hold one.
///
/// # Errors
///
/// [`PlatformError::Os`] with [`Operation::Regex`] when no locale object could be made or `regexec` failed for a
/// reason other than not matching (`REG_ESPACE`), with the `regexec` code as the `errno`.
pub fn regex_match(
    pattern: &str,
    subject: &str,
    locale: &str,
    ignore_case: bool,
) -> Result<RegexOutcome, PlatformError> {
    let (Ok(c_pattern), Ok(c_subject)) = (CString::new(pattern), CString::new(subject)) else {
        return Ok(RegexOutcome::Invalid);
    };
    let failure = |errno| PlatformError::Os {
        operation: Operation::Regex,
        errno,
    };
    let _locale = ThreadLocale::install(locale).ok_or_else(|| failure(libc::ENOMEM))?;
    let mut flags = libc::REG_EXTENDED;
    if ignore_case {
        flags |= libc::REG_ICASE;
    }
    let mut raw = RegexT {
        re_magic: 0,
        re_nsub: 0,
        re_endp: std::ptr::null(),
        re_g: std::ptr::null_mut(),
    };
    // SAFETY: `raw` is writable for the duration of the call and `c_pattern` is a valid NUL-terminated string.
    if unsafe { regcomp(&raw mut raw, c_pattern.as_ptr(), flags) } != 0 {
        return Ok(RegexOutcome::Invalid);
    }
    let compiled = Compiled(raw);
    let groups = compiled.0.re_nsub + 1;
    let mut matches = vec![libc::regmatch_t { rm_so: -1, rm_eo: -1 }; groups];
    // SAFETY: `compiled` holds a successfully compiled expression, `c_subject` is a valid NUL-terminated string, and
    // `matches` has room for exactly `groups` entries, the count passed.
    let code = unsafe {
        regexec(
            &raw const compiled.0,
            c_subject.as_ptr(),
            groups,
            matches.as_mut_ptr(),
            0,
        )
    };
    match code {
        0 => Ok(RegexOutcome::Match(
            matches
                .iter()
                .map(|found| {
                    let start = usize::try_from(found.rm_so).ok()?;
                    let end = usize::try_from(found.rm_eo).ok()?;
                    (start <= end && end <= subject.len()).then_some((start, end))
                })
                .collect(),
        )),
        libc::REG_NOMATCH => Ok(RegexOutcome::NoMatch),
        other => Err(failure(other)),
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    fn captures(pattern: &str, subject: &str) -> Vec<Option<&'static str>> {
        let leaked: &'static str = Box::leak(subject.to_owned().into_boxed_str());
        match regex_match(pattern, leaked, "C", false).unwrap() {
            RegexOutcome::Match(groups) => groups
                .into_iter()
                .map(|group| group.map(|(start, end)| &leaked[start..end]))
                .collect(),
            other => panic!("{pattern} on {subject}: {other:?}"),
        }
    }

    // KNSH-102: POSIX ERE semantics, leftmost-longest, with unmatched groups reported as such.
    #[test]
    fn extended_expressions_match_with_subexpressions() {
        assert_eq!(
            captures("^([a-z]+)-([0-9]+)$", "abc-123"),
            [Some("abc-123"), Some("abc"), Some("123")]
        );
        assert_eq!(captures("(x)?b", "ab"), [Some("b"), None]);
        assert_eq!(captures("a|ab", "xab"), [Some("ab")]);
        assert_eq!(captures("[[:digit:]]{2}", "a12b"), [Some("12")]);
        assert_eq!(regex_match("^a$", "b", "C", false).unwrap(), RegexOutcome::NoMatch);
        assert_eq!(regex_match("(", "x", "C", false).unwrap(), RegexOutcome::Invalid);
        assert_eq!(regex_match("a\0", "a", "C", false).unwrap(), RegexOutcome::Invalid);
        assert!(matches!(
            regex_match("^A$", "a", "C", true).unwrap(),
            RegexOutcome::Match(_)
        ));
    }

    // KNSH-102: the shell's locale decides what `.` matches; an unknown locale leaves the C locale.
    #[test]
    fn locale_decides_multibyte_matching() {
        assert!(matches!(
            regex_match("^.$", "é", "en_US.UTF-8", false).unwrap(),
            RegexOutcome::Match(_)
        ));
        assert_eq!(regex_match("^.$", "é", "C", false).unwrap(), RegexOutcome::NoMatch);
        assert_eq!(
            regex_match("^.$", "é", "xx_NOPE", false).unwrap(),
            RegexOutcome::NoMatch
        );
    }
}
