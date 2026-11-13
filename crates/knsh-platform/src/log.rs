//! The system log (unified logging on macOS, subsystem `knsh`).
//!
//! The API makes it impossible to log command output, environment values or secrets by accident (NFR-PRIV-02):
//! the message is a `&'static str` written in the source, and every field value is typed — numbers, booleans,
//! identifiers, `errno` values and other static strings. There is no variant that accepts a runtime `String`.

use std::fmt;

use knsh_core::Ulid;

/// Severity, mapped to the unified-logging types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Verbose detail, normally not persisted.
    Debug,
    /// Useful but not essential; persisted only when the log configuration asks for it.
    Info,
    /// Normal operation (unified logging's default type; persisted).
    Notice,
    /// A recoverable failure.
    Error,
    /// A bug or a broken invariant in the engine itself.
    Fault,
}

/// A typed field value. Deliberately has no variant for runtime text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Value {
    /// An unsigned number (counts, sizes, durations in milliseconds).
    U64(u64),
    /// A signed number (exit codes, process ids).
    I64(i64),
    /// A flag.
    Bool(bool),
    /// An identifier such as a session or record id.
    Id(Ulid),
    /// An `errno` value; written as its number.
    Errno(i32),
    /// A string fixed at compile time, such as an operation or state name.
    Static(&'static str),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64(value) => write!(f, "{value}"),
            Self::I64(value) => write!(f, "{value}"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Id(value) => write!(f, "{value}"),
            Self::Errno(value) => write!(f, "errno:{value}"),
            Self::Static(value) => f.write_str(value),
        }
    }
}

/// One `name=value` field of a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Field {
    /// Field name, fixed at compile time.
    pub name: &'static str,
    /// Field value.
    pub value: Value,
}

impl Field {
    /// A field named `name` with `value`.
    #[must_use]
    pub const fn new(name: &'static str, value: Value) -> Self {
        Self { name, value }
    }
}

/// Writes to the system log. Object safe: hold it as `Arc<dyn SystemLog>`.
///
/// Logging is best effort (`specs/08-integrations/macos-services.md`): it never fails and
/// never blocks the caller on the log daemon, so it has no `Result`.
pub trait SystemLog: Send + Sync {
    /// Writes one entry: a static message and typed fields.
    fn log(&self, level: Level, message: &'static str, fields: &[Field]);
}

/// Renders an entry as `message name=value name=value`, the text written to the system log.
///
/// Names and static values come from the source code, so no escaping is needed for privacy; control characters in
/// them are still replaced so one entry is always one line.
#[must_use]
pub fn render(message: &'static str, fields: &[Field]) -> String {
    let mut line = String::from(message);
    for field in fields {
        line.push(' ');
        line.push_str(field.name);
        line.push('=');
        line.push_str(&field.value.to_string());
    }
    line.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_writes_message_then_typed_fields() {
        let line = render(
            "command finished",
            &[
                Field::new("exit", Value::I64(-1)),
                Field::new("bytes", Value::U64(7)),
                Field::new("sandboxed", Value::Bool(true)),
                Field::new("cause", Value::Errno(2)),
                Field::new("state", Value::Static("done\n")),
            ],
        );
        assert_eq!(
            line,
            "command finished exit=-1 bytes=7 sandboxed=true cause=errno:2 state=done "
        );
    }
}
