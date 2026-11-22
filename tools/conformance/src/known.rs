//! Known differences: the lines and cases on which the native interpreter is known not to behave as bash 5.2, each
//! pointing to where the compatibility page documents it (`tests/conformance/known-differences.tsv`).
//!
//! ```text
//! # knsh-conformance known-differences 1
//! corpus<TAB><escaped corpus command><TAB>compatibility.md#<anchor>
//! oils<TAB><file>: <case name><TAB>compatibility.md#<anchor>
//! bash-suite<TAB><driver><TAB>compatibility.md#<anchor>
//! ```
//!
//! A corpus id is the command escaped as in the corpus files, so it does not move when lines are added. The anchor
//! must name a heading of `specs/04-non-functional-requirements/compatibility.md`: "documented in the compatibility
//! page" is checked, not assumed. A corpus line that differs and is not listed fails release runs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ConformanceError;
use crate::report::Suite;

/// The header of the file.
pub const HEADER: &str = "# knsh-conformance known-differences 1";

/// Where an entry's documentation must be: a heading of the compatibility page.
pub const DOC_PREFIX: &str = "compatibility.md#";

/// The known differences, by suite and id, each with its documentation anchor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Known {
    entries: BTreeMap<(Suite, String), String>,
}

impl Known {
    /// Where the difference of `id` in `suite` is documented, if it is known.
    #[must_use]
    pub fn documented(&self, suite: Suite, id: &str) -> Option<&str> {
        self.entries.get(&(suite, id.to_owned())).map(String::as_str)
    }

    /// Every entry.
    pub fn iter(&self) -> impl Iterator<Item = (Suite, &str, &str)> {
        self.entries
            .iter()
            .map(|((suite, id), doc)| (*suite, id.as_str(), doc.as_str()))
    }
}

/// The GitHub anchor of a Markdown heading's text: lower case, spaces to `-`, only letters, digits, `-` and `_`.
#[must_use]
pub fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

/// The anchors of every heading in a Markdown page.
#[must_use]
pub fn anchors(page: &str) -> Vec<String> {
    page.lines()
        .filter_map(|line| {
            line.trim_start_matches('#')
                .strip_prefix(' ')
                .filter(|_| line.starts_with('#'))
        })
        .map(anchor)
        .collect()
}

/// Reads the known differences in `text` (from `path`), checking each anchor against `page_anchors`.
///
/// # Errors
///
/// [`ConformanceError::Format`] for a missing header, a line without three fields, an unknown suite, a duplicate,
/// or documentation that is not a heading of the compatibility page.
pub fn parse(text: &str, path: &Path, page_anchors: &[String]) -> Result<Known, ConformanceError> {
    let error = |line: usize, message: String| ConformanceError::Format {
        path: path.to_owned(),
        line,
        message,
    };
    let mut lines = text.lines().enumerate();
    if lines.next().map(|(_, line)| line) != Some(HEADER) {
        return Err(error(1, format!("the first line must be {HEADER:?}")));
    }
    let mut known = Known::default();
    for (index, line) in lines {
        let number = index + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let [suite, id, doc] = fields[..] else {
            return Err(error(number, "expected suite<TAB>id<TAB>documentation".into()));
        };
        let suite = Suite::from_id(suite).ok_or_else(|| error(number, format!("unknown suite {suite:?}")))?;
        let target = doc
            .strip_prefix(DOC_PREFIX)
            .ok_or_else(|| error(number, format!("documentation must be {DOC_PREFIX}<anchor>")))?;
        if !page_anchors.iter().any(|anchor| anchor == target) {
            return Err(error(
                number,
                format!("the compatibility page has no heading #{target}"),
            ));
        }
        if id.is_empty() || known.entries.insert((suite, id.to_owned()), doc.to_owned()).is_some() {
            return Err(error(number, "an empty or duplicate id".into()));
        }
    }
    Ok(known)
}

/// Reads the known-differences file at `path`, checked against the compatibility page at `page`.
///
/// # Errors
///
/// [`ConformanceError::Io`] when a file cannot be read; [`ConformanceError::Format`] as [`parse`].
pub fn load(path: &Path, page: &Path) -> Result<Known, ConformanceError> {
    let text = fs::read_to_string(path).map_err(|e| ConformanceError::io(path, e))?;
    let page_text = fs::read_to_string(page).map_err(|e| ConformanceError::io(page, e))?;
    parse(&text, path, &anchors(&page_text))
}

/// The default file, relative to the workspace root.
#[must_use]
pub fn default_path() -> PathBuf {
    PathBuf::from("tests/conformance/known-differences.tsv")
}

/// The compatibility page, relative to the workspace root.
#[must_use]
pub fn default_page() -> PathBuf {
    PathBuf::from("specs/04-non-functional-requirements/compatibility.md")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "# Compatibility\n\n## Native mode: known differences\n\n### `set -x` trace format\n";

    #[test]
    fn anchors_follow_github() {
        assert_eq!(
            anchors(PAGE),
            vec!["compatibility", "native-mode-known-differences", "set--x-trace-format"]
        );
    }

    #[test]
    fn reads_entries_and_checks_their_documentation() {
        let anchors = anchors(PAGE);
        let path = Path::new("known.tsv");
        let text = format!("{HEADER}\n# comment\ncorpus\tset -x; true\tcompatibility.md#set--x-trace-format\n");
        let known = parse(&text, path, &anchors).unwrap();
        assert_eq!(
            known.documented(Suite::Corpus, "set -x; true"),
            Some("compatibility.md#set--x-trace-format")
        );
        assert_eq!(known.documented(Suite::Oils, "set -x; true"), None);

        let bad = [
            "corpus\tx\n".to_owned(),
            format!("{HEADER}\ncorpus\tx\n"),
            format!("{HEADER}\nnope\tx\tcompatibility.md#compatibility\n"),
            format!("{HEADER}\ncorpus\tx\tREADME.md#compatibility\n"),
            format!("{HEADER}\ncorpus\tx\tcompatibility.md#no-such-heading\n"),
            format!("{HEADER}\ncorpus\tx\tcompatibility.md#compatibility\ncorpus\tx\tcompatibility.md#compatibility\n"),
        ];
        for text in bad {
            assert!(
                matches!(parse(&text, path, &anchors), Err(ConformanceError::Format { .. })),
                "{text}"
            );
        }
    }
}
