//! Seatbelt profile text (SBPL) and the one place untrusted text enters it.
//!
//! A compiled profile is bytes: paths are written as their raw bytes, so a path is matched exactly as the kernel
//! sees it, never re-encoded. Every path reaches the text through [`Writer::path`], which writes it as an SBPL string
//! literal with `\` and `"` escaped. Those are the only two bytes with a meaning inside an SBPL string (observed on
//! macOS 26.6.2, KNSH-044: quotes, backslashes, parentheses, `;`, newlines, tabs and non-ASCII letters in a path all
//! match exactly once escaped this way, and an unescaped `"` ends the string and lets the rest of the path be read as
//! profile code). Nothing else in the text comes from input: operations, filters, regexes and tag rule names are
//! constants of this crate, and tags are built from IDs.

use std::fmt;

/// The text of a compiled Seatbelt profile, as `sandbox-exec -f` reads it.
///
/// Built only by [`compile`](crate::compile), so it always holds a complete, balanced profile.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SbplText(Vec<u8>);

impl SbplText {
    /// The profile's bytes, to write to the profile file.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the text and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SbplText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SbplText({:?})", String::from_utf8_lossy(&self.0))
    }
}

/// Builds profile text line by line.
#[derive(Default)]
pub(crate) struct Writer {
    text: Vec<u8>,
}

impl Writer {
    /// Constant text: an operation, a filter name, a regex or a comment, never input.
    pub(crate) fn raw(&mut self, text: &str) -> &mut Self {
        self.text.extend_from_slice(text.as_bytes());
        self
    }

    /// `bytes` as an SBPL string literal (module documentation).
    pub(crate) fn path(&mut self, bytes: &[u8]) -> &mut Self {
        self.text.push(b'"');
        for &byte in bytes {
            if matches!(byte, b'\\' | b'"') {
                self.text.push(b'\\');
            }
            self.text.push(byte);
        }
        self.text.push(b'"');
        self
    }

    /// Ends the current line.
    pub(crate) fn newline(&mut self) -> &mut Self {
        self.text.push(b'\n');
        self
    }

    /// The finished profile.
    pub(crate) fn finish(self) -> SbplText {
        SbplText(self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(bytes: &[u8]) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.path(bytes);
        writer.finish().into_bytes()
    }

    #[test]
    fn escapes_only_backslash_and_quote() {
        assert_eq!(literal(b"/a b/c"), b"\"/a b/c\"");
        assert_eq!(literal(br#"/a"b\c"#), br#""/a\"b\\c""#);
        // Parentheses, `;`, newlines and non-ASCII bytes have no meaning inside a string and are kept as they are.
        assert_eq!(literal("/a)b;\n(é".as_bytes()), "\"/a)b;\n(é\"".as_bytes());
    }
}
