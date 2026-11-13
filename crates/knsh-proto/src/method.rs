//! Method names: `area.verb`, plus the bare handshake name `hello` (`specs/06-api/README.md#envelope`).

use std::fmt;

use crate::error::ProtoError;

/// Longest accepted method name, in bytes. Every name in the spec is far shorter; the bound keeps an untrusted name
/// from being copied around at frame size.
pub const MAX_METHOD_NAME_LEN: usize = 64;

/// The handshake method, the one name without an area (`specs/06-api/handshake.md`).
pub(crate) const HELLO: &str = "hello";

/// The area JSON-RPC 2.0 reserves for its own extensions ("Method names that begin with rpc.").
const RESERVED_AREA: &str = "rpc";

/// A syntactically valid method name.
///
/// # Invariants
///
/// The name is `hello`, or `area.verb`: two segments joined by one dot, each an ASCII lowercase letter followed by
/// lowercase letters, digits or `_`, at most [`MAX_METHOD_NAME_LEN`] bytes in all, with an area other than `rpc`.
/// Validity says nothing about whether the method exists; that is the method catalogue's job (KNSH-014).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodName(String);

impl MethodName {
    /// Checks `name` against the method-name grammar.
    ///
    /// # Errors
    ///
    /// [`ProtoError::MethodNotFound`] if `name` does not follow the grammar: no method can have such a name, so a
    /// request naming one is answered as an unknown method (`-32601`), not as an invalid request.
    pub fn new(name: &str) -> Result<Self, ProtoError> {
        if is_valid(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(ProtoError::MethodNotFound)
        }
    }

    /// The name as sent on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The area (`exec` in `exec.run`), or `None` for `hello`.
    #[must_use]
    pub fn area(&self) -> Option<&str> {
        self.0.split_once('.').map(|(area, _)| area)
    }

    /// The verb (`run` in `exec.run`), or the whole name for `hello`.
    #[must_use]
    pub fn verb(&self) -> &str {
        self.0.split_once('.').map_or(self.0.as_str(), |(_, verb)| verb)
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for MethodName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Whether `name` follows the grammar described on [`MethodName`].
fn is_valid(name: &str) -> bool {
    if name.len() > MAX_METHOD_NAME_LEN {
        return false;
    }
    if name == HELLO {
        return true;
    }
    // `split_once` takes the first dot, so a second dot lands in `verb` and fails the segment check there.
    match name.split_once('.') {
        Some((area, verb)) => area != RESERVED_AREA && is_segment(area) && is_segment(verb),
        None => false,
    }
}

/// A lowercase ASCII letter followed by lowercase letters, digits or `_`.
fn is_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_method_named_in_the_spec() {
        // The method names that appear in specs/06-api (agent-socket, user-socket, control-service, handshake),
        // including notifications sent by the engine.
        for name in [
            "hello",
            "exec.run",
            "exec.start",
            "exec.wait",
            "exec.kill",
            "policy.check",
            "records.query",
            "records.output",
            "events.subscribe",
            "checkpoint.undo",
            "session.start_agent",
            "decision.requested",
            "command.output",
            "a.b",
            "a1.b2_",
        ] {
            let method = MethodName::new(name).unwrap();
            assert_eq!(method.as_str(), name);
        }
    }

    #[test]
    fn rejects_names_outside_the_grammar_as_unknown_methods() {
        let too_long = format!("a.{}", "b".repeat(MAX_METHOD_NAME_LEN - 1));
        for name in [
            "",
            ".",
            "exec",
            "exec.",
            ".run",
            "exec..run",
            "exec.run.now",
            "Exec.run",
            "exec.Run",
            "1exec.run",
            "exec.1run",
            "_exec.run",
            "exec-x.run",
            "exec.run ",
            " exec.run",
            "exec.r\u{fc}n",
            "exec.run\0",
            "rpc.discover",
            "hello.",
            "Hello",
            too_long.as_str(),
        ] {
            assert_eq!(MethodName::new(name), Err(ProtoError::MethodNotFound), "{name:?}");
        }
    }

    #[test]
    fn accepts_name_at_length_limit() {
        let name = format!("a.{}", "b".repeat(MAX_METHOD_NAME_LEN - 2));
        assert_eq!(name.len(), MAX_METHOD_NAME_LEN);
        assert!(MethodName::new(&name).is_ok());
    }

    #[test]
    fn splits_area_and_verb() {
        let method = MethodName::new("session.start_agent").unwrap();
        assert_eq!((method.area(), method.verb()), (Some("session"), "start_agent"));
        let hello = MethodName::new("hello").unwrap();
        assert_eq!((hello.area(), hello.verb()), (None, "hello"));
    }
}
