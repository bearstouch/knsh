//! A wrapper that never prints what it holds (NFR-PRIV-02).
//!
//! Secrets, command output and environment values must never reach a log, a record or the wire by accident.
//! `Redacted<T>` makes the accidental path impossible: its `Debug` and `Display` print `«redacted»`, so a stray `{:?}`
//! in a log line, a panic message or a derived `Debug` on a containing struct leaks nothing. Reading the value takes
//! a deliberate, greppable call to [`Redacted::expose`].

use std::fmt;

/// Text printed in place of the inner value by both `Debug` and `Display`.
pub const REDACTED_MARKER: &str = "«redacted»";

/// How every redaction marker starts: [`REDACTED_MARKER`] and the redaction engine's named markers,
/// `«redacted:<name>»` (FR-SEC-10, `specs/05-models/secret.md`).
const MARKER_OPENING: &str = "«redacted";

/// Whether `text` holds a redaction marker: [`REDACTED_MARKER`] or a named one, `«redacted:<name>»` (FR-SEC-10).
///
/// A marker stands for a value that was taken out. Text holding one cannot be told apart from redacted text, so it
/// must never be turned back into something that runs or is kept as if it were real: a rewrite (FR-AUTH-32) or a
/// grant. Matching is deliberately loose: `«redacted` followed by `»` or `:` is a marker, whether or not a named one
/// is well formed, so a malformed marker is never mistaken for plain text.
#[must_use]
pub(crate) fn holds_redaction_marker(text: &str) -> bool {
    text.match_indices(MARKER_OPENING)
        .any(|(at, opening)| matches!(text[at + opening.len()..].chars().next(), Some('»' | ':')))
}

/// Holds a value that must not be printed.
///
/// # Invariants
///
/// - `Debug` and `Display` always print [`REDACTED_MARKER`], whatever `T` is, including with `{:#?}` and width or
///   fill flags.
/// - The value is reachable only through [`expose`](Self::expose) and [`into_inner`](Self::into_inner).
/// - There is no `From<T>` and no `Deref`, so a `Redacted<String>` cannot be passed where a `String` or `&str` is
///   expected, and vice versa.
///
/// `PartialEq` is not implemented on purpose: comparing secrets is a decision that should be explicit (and, for
/// credentials, constant-time), not something `==` does quietly.
#[derive(Clone, Default)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wraps a value so that it can no longer be printed.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the inner value. Every call site is a place where the value can leave the wrapper; keep them few and
    /// make sure the value is not logged, stored or emitted from there.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Unwraps the inner value. The same care applies as for [`expose`](Self::expose).
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "hunter2-AKIAIOSFODNN7EXAMPLE";

    /// A struct that derives `Debug` while holding a secret, as real record types will.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Env {
        name: &'static str,
        value: Redacted<String>,
    }

    // NFR-PRIV-02: nothing formatted from a `Redacted` contains the inner value.
    #[test]
    fn redacted_debug_never_prints_inner_value() {
        let secret = Redacted::new(String::from(SECRET));
        for printed in [
            format!("{secret:?}"),
            format!("{secret:#?}"),
            format!("{secret}"),
            format!("{secret:>40}"),
            format!("{:?}", Some(&secret)),
            format!("{:?}", vec![secret.clone()]),
        ] {
            assert!(!printed.contains("hunter2"), "{printed}");
            assert!(printed.contains(REDACTED_MARKER), "{printed}");
        }
        assert_eq!(format!("{secret:?}"), "«redacted»");
        assert_eq!(format!("{secret}"), "«redacted»");

        // A derived Debug on a containing struct is safe too.
        let env = Env {
            name: "TOKEN",
            value: secret.clone(),
        };
        let printed = format!("{env:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(printed.contains("TOKEN"));

        // Explicit access still works.
        assert_eq!(secret.expose(), SECRET);
        assert_eq!(secret.into_inner(), SECRET);
    }

    // FR-SEC-10, FR-AUTH-32: both the plain and the named markers are found, wherever they are; text that merely
    // mentions the word is not a marker.
    #[test]
    fn finds_plain_and_named_redaction_markers() {
        for text in [
            "«redacted»",
            "npm publish --token «redacted:npm-token»",
            "curl -H 'auth: «redacted:»'",
            "«redacted «redacted:x»",
        ] {
            assert!(holds_redaction_marker(text), "{text}");
        }
        for text in [
            "",
            "echo redacted",
            "«redacted",
            "«redacted »",
            "echo «redactedx»",
            "redacted:npm-token",
        ] {
            assert!(!holds_redaction_marker(text), "{text}");
        }
    }
}

/// Compile-time check that a `Redacted<String>` and a plain `String` cannot be mixed.
///
/// ```compile_fail
/// use knsh_core::Redacted;
/// fn store(_: &str) {}
/// let secret = Redacted::new(String::from("s"));
/// store(&secret);
/// ```
///
/// ```compile_fail
/// use knsh_core::Redacted;
/// fn emit(_: Redacted<String>) {}
/// emit(String::from("raw secret"));
/// ```
#[cfg(doctest)]
pub struct NoImplicitRedactedConversion;
