//! A log that keeps entries for assertions.

use std::sync::Mutex;

use super::lock;
use crate::log::{Field, Level, SystemLog};

/// One recorded entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Severity.
    pub level: Level,
    /// The static message.
    pub message: &'static str,
    /// The typed fields, in order.
    pub fields: Vec<Field>,
}

/// Records every entry in memory, in order.
#[derive(Debug, Default)]
pub struct RecordingLog {
    entries: Mutex<Vec<Entry>>,
}

impl RecordingLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every entry written so far.
    #[must_use]
    pub fn entries(&self) -> Vec<Entry> {
        lock(&self.entries).clone()
    }
}

impl SystemLog for RecordingLog {
    fn log(&self, level: Level, message: &'static str, fields: &[Field]) {
        lock(&self.entries).push(Entry {
            level,
            message,
            fields: fields.to_vec(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Value;

    #[test]
    fn records_entries_in_order() {
        let log = RecordingLog::new();
        log.log(Level::Notice, "started", &[]);
        log.log(Level::Error, "failed", &[Field::new("errno", Value::Errno(13))]);
        let entries = log.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].message, "failed");
        assert_eq!(entries[1].fields, [Field::new("errno", Value::Errno(13))]);
    }
}
