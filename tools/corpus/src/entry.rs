//! The corpus file format: one entry per line, each with its source ID, licence, tags and command.
//!
//! A corpus file is `tests/corpus/<source>.txt` (UTF-8):
//!
//! ```text
//! # knsh-corpus 1
//! # source<TAB>licence<TAB>tags<TAB>command
//! knsh-seed<TAB>MIT<TAB>-<TAB>git status --short
//! knsh-seed<TAB>MIT<TAB>b32-missing<TAB>declare -A seen=()
//! ```
//!
//! - The first line is the versioned header [`FILE_HEADER`]. Later lines starting with `#`, and blank lines, are
//!   comments (an entry always starts with its source ID, never with `#`).
//! - `tags` is a comma-separated, sorted, duplicate-free list of [`Tag`]s, or `-` for none, so every entry has
//!   exactly one spelling and diffs stay small.
//! - `command` is the rest of the line. Backslash, newline, tab and carriage return are written `\\`, `\n`, `\t` and
//!   `\r`, so a multi-line command (a here-document, a loop) is still one line. Every other byte is literal; other
//!   control characters are not allowed at all.

use std::fmt;

use crate::error::EntryError;
use crate::sources::{validate_licence, validate_source_id};

/// The first line of every corpus file; the trailing number is the format version.
pub const FILE_HEADER: &str = "# knsh-corpus 1";

/// Longest accepted command, in bytes after unescaping. Agent lines are far shorter; anything longer is a pasted file.
pub const MAX_COMMAND_LEN: usize = 16 * 1024;

/// What an entry is useful for testing. Declared in alphabetical order, which is also the canonical tag order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tag {
    /// Parses in bash 3.2 but behaves differently from bash 5.2 (NFR-COMPAT-05). Tagged by hand.
    B32Differs,
    /// Uses a construct bash 3.2 lacks (NFR-COMPAT-05). Added by the importer; required by the gate.
    B32Missing,
    /// Runs dynamic code: `eval`, `source`, `bash -c`, a here-document fed to an interpreter.
    Dynamic,
    /// Contains a here-document.
    Heredoc,
    /// Is irreversible or destructive (`rm -rf`, `git push --force`, `DROP TABLE`).
    Irreversible,
    /// Spans several lines. Added by the importer; required by the gate.
    Multiline,
    /// Uses the network.
    Network,
    /// Runs another command through a wrapper (`env`, `xargs`, `sudo`, `timeout`, `nohup`).
    Wrapper,
}

impl Tag {
    /// Every tag, in canonical order.
    pub const ALL: [Self; 8] = [
        Self::B32Differs,
        Self::B32Missing,
        Self::Dynamic,
        Self::Heredoc,
        Self::Irreversible,
        Self::Multiline,
        Self::Network,
        Self::Wrapper,
    ];

    /// The tag as written in corpus files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::B32Differs => "b32-differs",
            Self::B32Missing => "b32-missing",
            Self::Dynamic => "dynamic",
            Self::Heredoc => "heredoc",
            Self::Irreversible => "irreversible",
            Self::Multiline => "multiline",
            Self::Network => "network",
            Self::Wrapper => "wrapper",
        }
    }

    /// Parses a tag as written in corpus files.
    ///
    /// # Errors
    ///
    /// [`EntryError::UnknownTag`] for anything that is not exactly one of the tags.
    pub fn parse(s: &str) -> Result<Self, EntryError> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| EntryError::UnknownTag(s.to_owned()))
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One corpus entry.
///
/// Invariant (for values from [`parse_entry`] or [`Entry::new`]): the source ID and licence are valid, the tags are
/// sorted and unique, and the command is non-empty, within [`MAX_COMMAND_LEN`] and free of control characters other
/// than newline, tab and carriage return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The source ID (registered in `sources.tsv`).
    pub source: String,
    /// The SPDX licence of the source.
    pub licence: String,
    /// Tags, sorted and unique.
    pub tags: Vec<Tag>,
    /// The command line, unescaped.
    pub command: String,
}

impl Entry {
    /// Builds an entry, sorting and de-duplicating `tags`.
    ///
    /// # Errors
    ///
    /// [`EntryError::MissingSource`], [`EntryError::InvalidSourceId`], [`EntryError::MissingLicence`],
    /// [`EntryError::LicenceNotAllowed`] or a command error from [`validate_command`].
    pub fn new(source: &str, licence: &str, mut tags: Vec<Tag>, command: String) -> Result<Self, EntryError> {
        validate_source_id(source)?;
        validate_licence(licence)?;
        validate_command(&command)?;
        tags.sort_unstable();
        tags.dedup();
        Ok(Self {
            source: source.to_owned(),
            licence: licence.to_owned(),
            tags,
            command,
        })
    }

    /// True if the entry carries `tag`.
    #[must_use]
    pub fn has(&self, tag: Tag) -> bool {
        self.tags.contains(&tag)
    }

    /// The entry as one corpus file line, without the trailing newline.
    #[must_use]
    pub fn to_line(&self) -> String {
        let tags = if self.tags.is_empty() {
            "-".to_owned()
        } else {
            self.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(",")
        };
        format!("{}\t{}\t{tags}\t{}", self.source, self.licence, escape(&self.command))
    }
}

/// Checks a command: non-empty, within [`MAX_COMMAND_LEN`], and no control characters other than `\n`, `\t`, `\r`.
///
/// # Errors
///
/// [`EntryError::EmptyCommand`], [`EntryError::TooLong`] or [`EntryError::ControlCharacter`].
pub fn validate_command(command: &str) -> Result<(), EntryError> {
    if command.trim().is_empty() {
        return Err(EntryError::EmptyCommand);
    }
    if command.len() > MAX_COMMAND_LEN {
        return Err(EntryError::TooLong {
            len: command.len(),
            limit: MAX_COMMAND_LEN,
        });
    }
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return Err(EntryError::ControlCharacter);
    }
    Ok(())
}

/// Parses one entry line (not a header, comment or blank line).
///
/// # Errors
///
/// An [`EntryError`] for a wrong field count, a missing or invalid source ID, a missing or disallowed licence,
/// unknown or non-canonical tags, an invalid escape, a raw control character, or an empty or over-long command.
/// Whether the source is registered is checked separately ([`crate::sources::Registry::check_entry`]).
pub fn parse_entry(line: &str) -> Result<Entry, EntryError> {
    // The command is the last field and may itself contain no raw tab (tabs are escaped), so exactly four fields.
    let fields: Vec<&str> = line.split('\t').collect();
    let [source, licence, tags, command] = fields[..] else {
        return Err(EntryError::FieldCount {
            expected: 4,
            found: fields.len(),
        });
    };
    validate_source_id(source)?;
    validate_licence(licence)?;
    let tags = parse_tags(tags)?;
    let command = unescape(command)?;
    validate_command(&command)?;
    Ok(Entry {
        source: source.to_owned(),
        licence: licence.to_owned(),
        tags,
        command,
    })
}

/// Parses the tags field, insisting on the canonical spelling.
fn parse_tags(field: &str) -> Result<Vec<Tag>, EntryError> {
    if field == "-" {
        return Ok(Vec::new());
    }
    if field.is_empty() {
        return Err(EntryError::TagsNotCanonical);
    }
    let tags = field.split(',').map(Tag::parse).collect::<Result<Vec<_>, _>>()?;
    // Strictly increasing means sorted and unique.
    if tags.windows(2).any(|w| w[0] >= w[1]) {
        return Err(EntryError::TagsNotCanonical);
    }
    Ok(tags)
}

/// Escapes a command for the last field of an entry line.
#[must_use]
pub fn escape(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    for c in command.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// Reverses [`escape`]. Strict: any other escape or a raw control character is an error, so a hand-edited line
/// cannot carry a byte the format does not allow.
///
/// # Errors
///
/// [`EntryError::InvalidEscape`] or [`EntryError::ControlCharacter`].
pub fn unescape(field: &str) -> Result<String, EntryError> {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                _ => return Err(EntryError::InvalidEscape),
            },
            c if c.is_control() => return Err(EntryError::ControlCharacter),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Parses a whole corpus file into entries, with the 1-based line number of each.
///
/// # Errors
///
/// The 1-based line number and reason for the first invalid line, including a missing or unsupported header.
pub fn parse_file(text: &str) -> Result<Vec<(usize, Entry)>, (usize, EntryError)> {
    let mut lines = text.lines().enumerate().map(|(i, l)| (i + 1, l));
    match lines.next() {
        Some((_, FILE_HEADER)) => {}
        Some((n, header)) if header.starts_with("# knsh-corpus") => {
            return Err((n, EntryError::UnsupportedVersion(header.to_owned())));
        }
        Some((n, _)) => return Err((n, EntryError::MissingHeader)),
        None => return Err((1, EntryError::MissingHeader)),
    }
    lines
        .filter(|(_, line)| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|(n, line)| parse_entry(line).map(|e| (n, e)).map_err(|e| (n, e)))
        .collect()
}

/// Renders entries as a corpus file: header, column comment, one line per entry, trailing newline.
#[must_use]
pub fn render_file(entries: &[Entry]) -> String {
    let mut out = format!("{FILE_HEADER}\n# source\tlicence\ttags\tcommand\n");
    for entry in entries {
        out.push_str(&entry.to_line());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-033: every entry records its source and licence.
    #[test]
    fn rejects_entry_without_source_and_licence() {
        assert_eq!(parse_entry("\tMIT\t-\tls"), Err(EntryError::MissingSource));
        assert_eq!(parse_entry("seed\t\t-\tls"), Err(EntryError::MissingLicence));
        assert_eq!(parse_entry("\t\t-\tls"), Err(EntryError::MissingSource));
        assert_eq!(
            parse_entry("ls -la"),
            Err(EntryError::FieldCount { expected: 4, found: 1 })
        );
        assert_eq!(
            parse_entry("seed\tProprietary\t-\tls"),
            Err(EntryError::LicenceNotAllowed("Proprietary".into()))
        );
        assert_eq!(
            Entry::new("", "MIT", vec![], "ls".into()),
            Err(EntryError::MissingSource)
        );
        assert_eq!(
            Entry::new("seed", "", vec![], "ls".into()),
            Err(EntryError::MissingLicence)
        );
    }

    #[test]
    fn round_trips_entries_with_escapes() {
        let entry = Entry::new(
            "seed",
            "MIT",
            vec![Tag::Multiline, Tag::Heredoc, Tag::Multiline],
            "cat <<'EOF'\n\ta\\b\nEOF".into(),
        )
        .unwrap();
        let line = entry.to_line();
        assert_eq!(line, "seed\tMIT\theredoc,multiline\tcat <<'EOF'\\n\\ta\\\\b\\nEOF");
        assert_eq!(parse_entry(&line).unwrap(), entry);
    }

    #[test]
    fn rejects_malformed_fields() {
        assert_eq!(
            parse_entry("s\tMIT\tnope\tls"),
            Err(EntryError::UnknownTag("nope".into()))
        );
        assert_eq!(
            parse_entry("s\tMIT\twrapper,dynamic\tls"),
            Err(EntryError::TagsNotCanonical)
        );
        assert_eq!(
            parse_entry("s\tMIT\tdynamic,dynamic\tls"),
            Err(EntryError::TagsNotCanonical)
        );
        assert_eq!(parse_entry("s\tMIT\t\tls"), Err(EntryError::TagsNotCanonical));
        assert_eq!(parse_entry("s\tMIT\t-\t  "), Err(EntryError::EmptyCommand));
        assert_eq!(parse_entry("s\tMIT\t-\tls\\x"), Err(EntryError::InvalidEscape));
        assert_eq!(parse_entry("s\tMIT\t-\tls\\"), Err(EntryError::InvalidEscape));
        assert_eq!(parse_entry("s\tMIT\t-\tls\u{1b}[0m"), Err(EntryError::ControlCharacter));
        assert_eq!(
            parse_entry("s\tMIT\t-\ta\tb"),
            Err(EntryError::FieldCount { expected: 4, found: 5 })
        );
        let long = format!("s\tMIT\t-\t{}", "a".repeat(MAX_COMMAND_LEN + 1));
        assert!(matches!(parse_entry(&long), Err(EntryError::TooLong { .. })));
    }

    #[test]
    fn parses_files_with_header_and_comments() {
        let text = "# knsh-corpus 1\n# comment\n\ns\tMIT\t-\tls\n";
        let entries = parse_file(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 4);
        assert_eq!(
            parse_file("s\tMIT\t-\tls\n").unwrap_err(),
            (1, EntryError::MissingHeader)
        );
        assert_eq!(
            parse_file("# knsh-corpus 9\n").unwrap_err(),
            (1, EntryError::UnsupportedVersion("# knsh-corpus 9".into()))
        );
        assert_eq!(parse_file("# knsh-corpus 1\ns\tMIT\t-\t\n").unwrap_err().0, 2);
        let rendered = render_file(&entries.into_iter().map(|(_, e)| e).collect::<Vec<_>>());
        assert_eq!(parse_file(&rendered).unwrap().len(), 1);
    }
}
