//! The importer: turns a raw trace into normalised, tagged entries and merges them into a source's corpus file.
//!
//! Inputs are published agent trajectories and traces of agent CLIs run on open-source repositories in CI, never user
//! telemetry (NFR-PRIV-08). Two input formats are read:
//!
//! - [`InputFormat::Lines`]: one command per line (blank lines skipped);
//! - [`InputFormat::JsonLines`]: one JSON value per line, with commands at a dotted field path. Arrays met on the
//!   path are walked element by element, so `message.content.input.command` reads every tool call of a
//!   stream-JSON transcript line.
//!
//! Each command is normalised ([`crate::normalise()`]), auto-tagged (`b32-missing`, `multiline`, `heredoc`) and
//! checked with the same rules as the CI gate before it is written, so an import can never produce a file that fails
//! the gate. Commands that fail (too long, control characters, or a normaliser gap the leak scan catches) are counted
//! as rejected and left out. The corpus file is replaced atomically; an existing file that does not pass the gate is
//! never overwritten.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use knsh_json::Value;

use crate::check::{MAX_FILE_LEN, check_entry, load_registry, read_bounded};
use crate::compat::missing_in_bash32;
use crate::entry::{Entry, Tag, parse_file, render_file};
use crate::error::{CorpusError, EntryError};
use crate::normalise::{Scrub, normalise};
use crate::sources::Registry;

/// Largest trace file read (trajectory dumps are large, but bounded).
pub const MAX_INPUT_LEN: u64 = 256 * 1024 * 1024;
/// Largest JSON line parsed.
pub const MAX_JSON_LINE: usize = 16 * 1024 * 1024;

/// How commands are laid out in a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFormat {
    /// One command per line.
    Lines,
    /// One JSON value per line; commands are strings at this field path.
    JsonLines {
        /// The path's object keys, outermost first.
        field: Vec<String>,
    },
}

/// What to import and how.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// The registered source the commands come from.
    pub source: String,
    /// The trace's layout.
    pub format: InputFormat,
    /// Known user and host names to scrub besides the pattern rules.
    pub scrub: Scrub,
    /// Tags to add to every imported entry.
    pub tags: Vec<Tag>,
}

/// What an import did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Commands found in the trace.
    pub read: usize,
    /// New entries written.
    pub added: usize,
    /// Commands already in the file (after normalisation) or repeated in the trace.
    pub duplicates: usize,
    /// Commands left out because they failed a check.
    pub rejected: usize,
}

/// Extracts the raw commands of a trace.
///
/// # Errors
///
/// [`CorpusError::Json`] for a JSON line that does not parse: a malformed trace is rejected, not partly imported.
pub fn extract_commands(text: &str, format: &InputFormat, path: &Path) -> Result<Vec<String>, CorpusError> {
    let lines = text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty());
    match format {
        InputFormat::Lines => Ok(lines.map(|(_, l)| l.to_owned()).collect()),
        InputFormat::JsonLines { field } => {
            let mut commands = Vec::new();
            for (i, line) in lines {
                let value = knsh_json::parse(line.as_bytes(), MAX_JSON_LINE).map_err(|source| CorpusError::Json {
                    path: path.to_owned(),
                    line: i + 1,
                    source,
                })?;
                collect_strings(&value, field, &mut commands);
            }
            Ok(commands)
        }
    }
}

/// Collects the strings at `path` below `value`, walking every array met on the way.
fn collect_strings(value: &Value, path: &[String], out: &mut Vec<String>) {
    if let Some(items) = value.as_array() {
        for item in items {
            collect_strings(item, path, out);
        }
        return;
    }
    match path.split_first() {
        None => {
            if let Some(s) = value.as_str() {
                out.push(s.to_owned());
            }
        }
        Some((key, rest)) => {
            if let Some(child) = value.as_object().and_then(|o| o.get(key)) {
                collect_strings(child, rest, out);
            }
        }
    }
}

/// The tags the importer derives from the command text.
fn auto_tags(command: &str) -> Vec<Tag> {
    let mut tags = Vec::new();
    if !missing_in_bash32(command).is_empty() {
        tags.push(Tag::B32Missing);
    }
    if command.contains('\n') {
        tags.push(Tag::Multiline);
    }
    // `<<` and `<<-` start a here-document; `<<<` is a here-string.
    if command
        .match_indices("<<")
        .any(|(i, _)| !command[i + 2..].starts_with('<') && (i == 0 || command.as_bytes()[i - 1] != b'<'))
    {
        tags.push(Tag::Heredoc);
    }
    tags
}

/// Normalises, tags and checks raw commands, then merges them after `existing` (kept first, in order).
///
/// Returns the merged entries and the counts. Pure: no I/O.
#[must_use]
pub fn merge_commands(
    existing: Vec<Entry>,
    commands: &[String],
    registry: &Registry,
    options: &ImportOptions,
    licence: &str,
) -> (Vec<Entry>, ImportSummary) {
    let mut summary = ImportSummary {
        read: commands.len(),
        ..ImportSummary::default()
    };
    let mut seen: BTreeSet<String> = existing.iter().map(|e| e.command.clone()).collect();
    let mut entries = existing;
    for raw in commands {
        // Surrounding whitespace (a trailing newline from a transcript) carries no meaning for the shell.
        let command = normalise(raw.trim(), &options.scrub);
        if seen.contains(&command) {
            summary.duplicates += 1;
            continue;
        }
        let mut tags = options.tags.clone();
        tags.extend(auto_tags(&command));
        // Only an entry that would pass the CI gate is written; anything else is counted and dropped.
        let entry = Entry::new(&options.source, licence, tags, command)
            .and_then(|e| check_entry(&e, registry, &options.source).map(|()| e));
        match entry {
            Ok(entry) => {
                seen.insert(entry.command.clone());
                entries.push(entry);
                summary.added += 1;
            }
            Err(_) => summary.rejected += 1,
        }
    }
    (entries, summary)
}

/// Imports the trace at `input` into `<corpus_dir>/<source>.txt`.
///
/// # Errors
///
/// An unregistered source, an unreadable or malformed trace, an existing corpus file that does not pass the gate
/// (it is left untouched), or a failed write.
pub fn import(corpus_dir: &Path, input: &Path, options: &ImportOptions) -> Result<ImportSummary, CorpusError> {
    let registry = load_registry(corpus_dir)?;
    let licence = registry
        .get(&options.source)
        .ok_or_else(|| CorpusError::Entry(EntryError::UnknownSource(options.source.clone())))?
        .licence
        .clone();
    let target = corpus_dir.join(format!("{}.txt", options.source));

    let existing = if target.exists() {
        let text = read_bounded(&target, MAX_FILE_LEN)?;
        let parsed = parse_file(&text).map_err(|(line, error)| CorpusError::At {
            path: target.clone(),
            line,
            error,
        })?;
        let mut entries = Vec::with_capacity(parsed.len());
        for (line, entry) in parsed {
            check_entry(&entry, &registry, &options.source).map_err(|error| CorpusError::At {
                path: target.clone(),
                line,
                error,
            })?;
            entries.push(entry);
        }
        entries
    } else {
        Vec::new()
    };

    let text = read_bounded(input, MAX_INPUT_LEN)?;
    let commands = extract_commands(&text, &options.format, input)?;
    let (entries, summary) = merge_commands(existing, &commands, &registry, options, &licence);
    if summary.added > 0 {
        write_atomically(&target, render_file(&entries).as_bytes())?;
    }
    Ok(summary)
}

/// Replaces `path` with `contents`: write a temporary file in the same directory, fsync it, rename it over `path`,
/// then fsync the directory. A crash leaves either the old file or the new one, never a partial file.
///
/// # Errors
///
/// [`CorpusError::Io`] for any failed step; the temporary file is removed on failure.
pub fn write_atomically(path: &Path, contents: &[u8]) -> Result<(), CorpusError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp: PathBuf = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let io = |p: &Path| {
        let p = p.to_owned();
        move |source| CorpusError::Io { path: p, source }
    };
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(io(&temp))?;
        file.write_all(contents).map_err(io(&temp))?;
        file.sync_all().map_err(io(&temp))?;
        fs::rename(&temp, path).map_err(io(path))?;
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
    })();
    if result.is_err() {
        // Best effort: the temp file may already be gone (renamed) or never created.
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry::parse("# knsh-corpus sources 1\nseed\tMIT\tx\n").unwrap()
    }

    fn options() -> ImportOptions {
        ImportOptions {
            source: "seed".into(),
            format: InputFormat::Lines,
            scrub: Scrub::default(),
            tags: vec![],
        }
    }

    #[test]
    fn extracts_commands_from_json_lines_through_arrays() {
        let text = concat!(
            r#"{"message":{"content":[{"type":"text","text":"hi"},{"type":"tool_use","input":{"command":"ls -la"}}]}}"#,
            "\n\n",
            r#"{"message":{"content":[{"input":{"command":"git status"}},{"input":{"command":"cargo test"}}]}}"#,
            "\n",
        );
        let format = InputFormat::JsonLines {
            field: vec!["message".into(), "content".into(), "input".into(), "command".into()],
        };
        assert_eq!(
            extract_commands(text, &format, Path::new("t")).unwrap(),
            ["ls -la", "git status", "cargo test"]
        );
        let err = extract_commands("{\"a\":1}\n{bad\n", &format, Path::new("t")).unwrap_err();
        assert!(matches!(err, CorpusError::Json { line: 2, .. }));
    }

    #[test]
    fn merges_normalised_tagged_and_deduplicated_entries() {
        let existing = vec![Entry::new("seed", "MIT", vec![], "git status".into()).unwrap()];
        let commands: Vec<String> = [
            "git status\n",
            "cd /Users/alice/x && ls",
            "cd /Users/bob/x && ls",
            "declare -A seen",
            "cat <<EOF\nhi\nEOF",
            "cat <<< hi",
            "bad\u{7}bell",
        ]
        .map(String::from)
        .to_vec();
        let (entries, summary) = merge_commands(existing, &commands, &registry(), &options(), "MIT");
        assert_eq!(
            summary,
            ImportSummary {
                read: 7,
                added: 4,
                duplicates: 2,
                rejected: 1
            }
        );
        let lines: Vec<String> = entries.iter().map(Entry::to_line).collect();
        assert_eq!(
            lines,
            [
                "seed\tMIT\t-\tgit status",
                "seed\tMIT\t-\tcd /Users/__USER__/x && ls",
                "seed\tMIT\tb32-missing\tdeclare -A seen",
                "seed\tMIT\theredoc,multiline\tcat <<EOF\\nhi\\nEOF",
                "seed\tMIT\t-\tcat <<< hi",
            ]
        );
    }
}
