//! `checkpoint.diff` as pure data and computation (KNSH-086): which paths differ between two states of the history
//! tree, how, and a unified text diff of each text file.
//!
//! [`FileDiff`] says what a path was in each state ([`EntryKind`]), how it changed ([`FileChange`]) and either its
//! unified diff ([`TextDiff::Unified`]) or why there is none ([`NoTextDiff`]): a binary file is reported as changed
//! without a text diff, and so is a file too large to diff, one whose version could not be read, one whose name
//! marks it as holding secrets, and anything that is not a regular file.
//!
//! [`unified`] writes the diff: lines as bytes, a shortest edit script by Myers' algorithm on the lines between the
//! common head and tail, hunks with three lines of context. Its input is agent-written, so the work is bounded: at
//! most [`MAX_EDIT_LINES`] differing lines are matched up; beyond that the differing middle is shown as removed and
//! added whole, which is still a correct diff, only not the shortest. Callers give it at most [`MAX_DIFF_FILE`]
//! bytes per side. No I/O.

use std::collections::HashMap;
use std::path::Path;

use crate::history::StateId;
use crate::id::RecordId;
use crate::path::CanonicalPath;
use crate::record::FileChange;

/// The largest version of a file given a text diff, in bytes (1 MiB). A larger one is reported as
/// [`NoTextDiff::TooLarge`]: its diff would not be readable, and its base64 form would not fit one frame.
pub const MAX_DIFF_FILE: u64 = 1 << 20;

/// The most differing lines [`unified`] matches up by Myers' algorithm, whose time and memory grow with the square
/// of this. Beyond it the differing middle is shown as removed and added whole.
pub const MAX_EDIT_LINES: usize = 1_000;

/// The most line comparisons [`unified`] spends following matching lines in Myers' algorithm (16 Mi). The edit
/// bound alone still lets a 1 MiB input of short lines cost about 2,000 diagonals times a million lines; past this
/// budget the differing middle is shown as removed and added whole, as past [`MAX_EDIT_LINES`].
pub const MAX_EDIT_WORK: usize = 16 << 20;

/// Lines of context around each change.
const CONTEXT: usize = 3;

/// What `checkpoint.diff` compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTarget {
    /// The change of a line (`record_id`): the state before it and the state after it. For a line of a concurrent
    /// set, the whole set (FR-CKP-07).
    Record(RecordId),
    /// A state (`state_id`) and the current state: what `checkpoint.restore` to that state would change.
    State(StateId),
}

/// What a path was in one state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// Nothing.
    Absent,
    /// A regular file.
    File,
    /// A folder.
    Folder,
    /// A symbolic link.
    Symlink,
    /// A socket, FIFO or device.
    Other,
    /// Not known: the version was never captured, or its copy is gone.
    Unknown,
}

impl EntryKind {
    /// The wire value: `absent`, `file`, `folder`, `symlink`, `other` or `unknown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::File => "file",
            Self::Folder => "folder",
            Self::Symlink => "symlink",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

/// Why a changed path has no text diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoTextDiff {
    /// A version holds a NUL byte or is not UTF-8.
    Binary,
    /// A version is larger than [`MAX_DIFF_FILE`].
    TooLarge,
    /// A version could not be read: never captured, its copy is gone, or the live file could not be read safely.
    Unavailable,
    /// The file's name marks it as holding secrets (`.env*`, `*.pem`, `*.key`, `id_*`, FR-CKP-33): its contents are
    /// never sent ([`is_sensitive`]).
    Sensitive,
    /// Neither version is a regular file with contents to compare (a folder, a symlink, a special file).
    NotAFile,
}

impl NoTextDiff {
    /// The wire value: `binary`, `too_large`, `unavailable`, `sensitive` or `not_a_file`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::TooLarge => "too_large",
            Self::Unavailable => "unavailable",
            Self::Sensitive => "sensitive",
            Self::NotAFile => "not_a_file",
        }
    }
}

/// A path's text diff, or why it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextDiff {
    /// The unified diff ([`unified`]): UTF-8 text.
    Unified(Vec<u8>),
    /// None, and why.
    Omitted(NoTextDiff),
}

/// One path that differs between the two states of a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    /// The path.
    pub path: CanonicalPath,
    /// Created, modified or deleted, from the first state to the second.
    pub change: FileChange,
    /// What it was in the first state.
    pub before: EntryKind,
    /// What it is in the second state.
    pub after: EntryKind,
    /// Its text diff, or why there is none.
    pub text: TextDiff,
}

/// The paths that differ between two states, sorted by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// The first state.
    pub from: StateId,
    /// The second state.
    pub to: StateId,
    /// Each path that differs.
    pub files: Vec<FileDiff>,
}

/// Whether `bytes` cannot be shown as text: they hold a NUL byte or are not UTF-8.
#[must_use]
pub fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

/// Whether the file at `path` is named like one holding secrets: `.env*`, `*.pem`, `*.key` or `id_*`, the sensitive
/// patterns of FR-CKP-33. Its contents are never put in a diff: a diff is sent to agents, and the record of what a
/// line did must not become a way to read what the sandbox would not let it read.
#[must_use]
pub fn is_sensitive(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
        return false;
    };
    name.starts_with(".env")
        || name.starts_with("id_")
        || Path::new(name.as_ref())
            .extension()
            .is_some_and(|extension| extension == "pem" || extension == "key")
}

/// One line of an edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// In both: the next line of each side.
    Equal,
    /// Only in the old side: its next line.
    Delete,
    /// Only in the new side: its next line.
    Insert,
}

/// The unified diff of `before` and `after` (`None`: the path was absent, shown as `/dev/null`), labelled with
/// `path`. Empty when they hold the same lines. Bounded by [`MAX_EDIT_LINES`] (module documentation).
#[must_use]
pub fn unified(path: &Path, before: Option<&[u8]>, after: Option<&[u8]>) -> Vec<u8> {
    let old = lines(before.unwrap_or_default());
    let new = lines(after.unwrap_or_default());
    let ops = edit_script(&old, &new);
    if ops.iter().all(|op| *op == Op::Equal) {
        return Vec::new();
    }
    let label = label(path);
    let mut out = Vec::new();
    let old_label = if before.is_some() { label.as_str() } else { "/dev/null" };
    let new_label = if after.is_some() { label.as_str() } else { "/dev/null" };
    out.extend_from_slice(format!("--- {old_label}\n+++ {new_label}\n").as_bytes());
    for hunk in hunks(&ops) {
        write_hunk(&mut out, &ops, hunk, &old, &new);
    }
    out
}

/// `path` for a diff header: on one line, whatever its name holds.
fn label(path: &Path) -> String {
    path.to_string_lossy().replace(['\n', '\r'], "?")
}

/// The lines of `bytes`, each with its `\n` (the last may have none).
fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split_inclusive(|byte| *byte == b'\n').collect()
}

/// A shortest edit script turning `old` into `new`, or a correct longer one when more than [`MAX_EDIT_LINES`]
/// lines differ.
fn edit_script<'a>(old: &[&'a [u8]], new: &[&'a [u8]]) -> Vec<Op> {
    // Lines are compared as numbers: each distinct line gets one.
    let mut numbers: HashMap<&'a [u8], u32> = HashMap::new();
    let mut number = |side: &[&'a [u8]]| -> Vec<u32> {
        side.iter()
            .map(|line| {
                let next = u32::try_from(numbers.len()).unwrap_or(u32::MAX);
                *numbers.entry(*line).or_insert(next)
            })
            .collect()
    };
    let old = number(old);
    let new = number(new);
    let head = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
    let tail = old[head..]
        .iter()
        .rev()
        .zip(new[head..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (old_middle, new_middle) = (&old[head..old.len() - tail], &new[head..new.len() - tail]);
    let middle = myers(old_middle, new_middle, MAX_EDIT_LINES, MAX_EDIT_WORK).unwrap_or_else(|| {
        let mut whole = vec![Op::Delete; old_middle.len()];
        whole.resize(old_middle.len() + new_middle.len(), Op::Insert);
        whole
    });
    let mut ops = vec![Op::Equal; head];
    ops.extend(middle);
    ops.resize(ops.len() + tail, Op::Equal);
    ops
}

/// Myers' greedy shortest edit script, or `None` if it needs more than `max` edits or more than `work` steps (each
/// diagonal tried and each matching line followed). Memory is the square of the edits needed, since each round keeps
/// only its own diagonals.
fn myers(old: &[u32], new: &[u32], max: usize, work: usize) -> Option<Vec<Op>> {
    let mut work = work;
    let (n, m) = (old.len(), new.len());
    let limit = max.min(n + m);
    // `trace[d][k + d]`: the furthest `x` on diagonal `k = x - y` after `d` edits.
    let mut trace: Vec<Vec<usize>> = Vec::new();
    for d in 0..=limit {
        let mut row = vec![0usize; 2 * d + 1];
        for index in (0..=2 * d).step_by(2) {
            // `k` runs over -d, -d + 2, ..., d; `index` is `k + d`.
            let mut x = if d == 0 {
                0
            } else {
                let previous = &trace[d - 1];
                // Diagonal k-1 is `previous[index - 2]`, diagonal k+1 is `previous[index]` (their `k + d - 1`):
                // step down (an insert) from k+1, or right (a delete) from k-1, whichever reached further.
                if index == 0 || (index != 2 * d && previous[index - 2] < previous[index]) {
                    previous[index]
                } else {
                    previous[index - 2] + 1
                }
            };
            // y = x - k = x - index + d; never negative on a reachable diagonal.
            let Some(mut y) = (x + d).checked_sub(index) else {
                continue;
            };
            work = work.checked_sub(1)?;
            while x < n && y < m && old[x] == new[y] {
                work = work.checked_sub(1)?;
                x += 1;
                y += 1;
            }
            row[index] = x;
            if x >= n && y >= m {
                trace.push(row);
                return Some(backtrack(&trace, n, m));
            }
        }
        trace.push(row);
    }
    None
}

/// Walks `trace` back from the end to the start, collecting the edit script.
fn backtrack(trace: &[Vec<usize>], n: usize, m: usize) -> Vec<Op> {
    let mut ops = Vec::with_capacity(n + m);
    let (mut x, mut y) = (n, m);
    for d in (1..trace.len()).rev() {
        let previous = &trace[d - 1];
        // `index = k + d` with `k = x - y`.
        let index = (x + d) - y;
        let down = index == 0 || (index != 2 * d && previous[index - 2] < previous[index]);
        let (previous_x, previous_k_index) = if down {
            (previous[index], index)
        } else {
            (previous[index - 2], index - 2)
        };
        // In round d-1, `k + (d - 1)` is `previous_k_index`, so y = x - k = x + (d - 1) - previous_k_index.
        let previous_y = previous_x + (d - 1) - previous_k_index;
        while x > previous_x && y > previous_y {
            ops.push(Op::Equal);
            x -= 1;
            y -= 1;
        }
        if down {
            ops.push(Op::Insert);
            y -= 1;
        } else {
            ops.push(Op::Delete);
            x -= 1;
        }
    }
    // Round 0 is one snake from the start.
    while x > 0 && y > 0 {
        ops.push(Op::Equal);
        x -= 1;
        y -= 1;
    }
    ops.reverse();
    ops
}

/// The ranges of `ops` each hunk shows: every change with up to [`CONTEXT`] equal lines around it, merging changes
/// whose context would touch.
fn hunks(ops: &[Op]) -> Vec<std::ops::Range<usize>> {
    let mut hunks = Vec::new();
    let mut i = 0;
    while i < ops.len() {
        if ops[i] == Op::Equal {
            i += 1;
            continue;
        }
        let start = i.saturating_sub(CONTEXT);
        let mut end = i;
        loop {
            while end < ops.len() && ops[end] != Op::Equal {
                end += 1;
            }
            let run = ops[end..].iter().take_while(|op| **op == Op::Equal).count();
            if end + run < ops.len() && run <= 2 * CONTEXT {
                end += run;
            } else {
                break;
            }
        }
        let stop = (end + CONTEXT).min(ops.len());
        hunks.push(start..stop);
        i = stop;
    }
    hunks
}

/// Writes one hunk: its `@@` header, then each line with ` `, `-` or `+`.
fn write_hunk(out: &mut Vec<u8>, ops: &[Op], hunk: std::ops::Range<usize>, old: &[&[u8]], new: &[&[u8]]) {
    // Where the hunk starts on each side: the lines consumed by the ops before it.
    let old_start = ops[..hunk.start].iter().filter(|op| **op != Op::Insert).count();
    let new_start = ops[..hunk.start].iter().filter(|op| **op != Op::Delete).count();
    let shown = &ops[hunk];
    let old_len = shown.iter().filter(|op| **op != Op::Insert).count();
    let new_len = shown.iter().filter(|op| **op != Op::Delete).count();
    out.extend_from_slice(format!("@@ -{} +{} @@\n", range(old_start, old_len), range(new_start, new_len)).as_bytes());
    let (mut a, mut b) = (old_start, new_start);
    for op in shown {
        let (mark, line) = match op {
            Op::Equal => {
                a += 1;
                b += 1;
                (b' ', old[a - 1])
            }
            Op::Delete => {
                a += 1;
                (b'-', old[a - 1])
            }
            Op::Insert => {
                b += 1;
                (b'+', new[b - 1])
            }
        };
        out.push(mark);
        out.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            out.extend_from_slice(b"\n\\ No newline at end of file\n");
        }
    }
}

/// A hunk range: `start,len` with `start` 1-based, `len` left out when 1, and an empty range named by the line
/// before it (as GNU diff writes them).
fn range(start: usize, len: usize) -> String {
    match len {
        0 => format!("{start},0"),
        1 => format!("{}", start + 1),
        _ => format!("{},{len}", start + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff(before: Option<&str>, after: Option<&str>) -> String {
        String::from_utf8(unified(
            Path::new("/code/app/a.txt"),
            before.map(str::as_bytes),
            after.map(str::as_bytes),
        ))
        .unwrap()
    }

    /// Applies the edit script to `old` and checks it yields `new`: the script is correct whatever its length.
    fn check_script(old: &str, new: &str) -> Vec<Op> {
        let (a, b) = (lines(old.as_bytes()), lines(new.as_bytes()));
        let ops = edit_script(&a, &b);
        let (mut x, mut y) = (0, 0);
        for op in &ops {
            match op {
                Op::Equal => {
                    assert_eq!(a[x], b[y]);
                    x += 1;
                    y += 1;
                }
                Op::Delete => x += 1,
                Op::Insert => y += 1,
            }
        }
        assert_eq!((x, y), (a.len(), b.len()));
        ops
    }

    #[test]
    fn modified_file_has_hunks_with_context() {
        let before = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        let after = "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n";
        assert_eq!(
            diff(Some(before), Some(after)),
            "--- /code/app/a.txt\n+++ /code/app/a.txt\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
        );
    }

    #[test]
    fn created_and_deleted_files_diff_against_dev_null() {
        assert_eq!(
            diff(None, Some("a\nb\n")),
            "--- /dev/null\n+++ /code/app/a.txt\n@@ -0,0 +1,2 @@\n+a\n+b\n"
        );
        assert_eq!(
            diff(Some("a\n"), None),
            "--- /code/app/a.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n"
        );
    }

    #[test]
    fn missing_final_newline_is_marked() {
        assert_eq!(
            diff(Some("a\nb"), Some("a\nc")),
            "--- /code/app/a.txt\n+++ /code/app/a.txt\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
        );
    }

    #[test]
    fn far_apart_changes_get_separate_hunks() {
        let before = (1..=20).map(|n| format!("{n}\n")).collect::<Vec<_>>().concat();
        let after = before.replace("2\n", "two\n").replace("19\n", "nineteen\n");
        let text = diff(Some(&before), Some(&after));
        assert_eq!(text.matches("@@ -").count(), 2, "{text}");
        assert!(text.contains("@@ -1,5 +1,5 @@\n 1\n-2\n+two\n 3\n 4\n 5\n"), "{text}");
    }

    #[test]
    fn same_lines_give_an_empty_diff() {
        assert_eq!(diff(Some("a\n"), Some("a\n")), "");
        assert_eq!(diff(None, Some("")), "", "an empty file has no lines to add");
    }

    #[test]
    fn edit_script_is_correct_and_shortest() {
        let ops = check_script("a\nb\nc\na\nb\nb\na\n", "c\nb\na\nb\na\nc\n");
        // The classic example of Myers' paper: five edits.
        assert_eq!(ops.iter().filter(|op| **op != Op::Equal).count(), 5);
        check_script("", "x\n");
        check_script("x\n", "");
        check_script("a\nb\n", "b\na\n");
    }

    // Agent-written input: a diff beyond the edit bound is still correct, shown as removed and added whole.
    #[test]
    fn many_differences_fall_back_to_whole_replacement() {
        let before = (0..1_500).map(|n| format!("old {n}\n")).collect::<Vec<_>>().concat();
        let after = (0..1_500).map(|n| format!("new {n}\n")).collect::<Vec<_>>().concat();
        let ops = check_script(&before, &after);
        assert_eq!(ops.iter().filter(|op| **op == Op::Delete).count(), 1_500);
        let text = diff(Some(&before), Some(&after));
        assert!(text.starts_with("--- /code/app/a.txt\n+++ /code/app/a.txt\n@@ -1,1500 +1,1500 @@\n-old 0\n"));
    }

    // Agent-written input: long matching runs between few differences cost work, not just edits; past the work
    // budget the diff is still correct.
    #[test]
    fn work_budget_falls_back_to_whole_replacement() {
        let old: Vec<u32> = (0..100).collect();
        let mut new = old.clone();
        new[50] = 1_000;
        assert!(myers(&old, &new, MAX_EDIT_LINES, 10).is_none());
        let ops = myers(&old, &new, MAX_EDIT_LINES, MAX_EDIT_WORK).unwrap();
        assert_eq!(ops.iter().filter(|op| **op != Op::Equal).count(), 2);
    }

    // The edit script is correct and shortest on many small inputs (checked against a longest common subsequence).
    #[test]
    fn edit_script_matches_lcs_on_small_inputs() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2_000 {
            let old: Vec<u32> = (0..next() % 12).map(|_| (next() % 4) as u32).collect();
            let new: Vec<u32> = (0..next() % 12).map(|_| (next() % 4) as u32).collect();
            let ops = myers(&old, &new, MAX_EDIT_LINES, MAX_EDIT_WORK).unwrap();
            let (mut x, mut y) = (0, 0);
            for op in &ops {
                match op {
                    Op::Equal => {
                        assert_eq!(old[x], new[y]);
                        x += 1;
                        y += 1;
                    }
                    Op::Delete => x += 1,
                    Op::Insert => y += 1,
                }
            }
            assert_eq!((x, y), (old.len(), new.len()));
            let mut lcs = vec![vec![0usize; new.len() + 1]; old.len() + 1];
            for i in (0..old.len()).rev() {
                for j in (0..new.len()).rev() {
                    lcs[i][j] = if old[i] == new[j] {
                        lcs[i + 1][j + 1] + 1
                    } else {
                        lcs[i + 1][j].max(lcs[i][j + 1])
                    };
                }
            }
            let equal = ops.iter().filter(|op| **op == Op::Equal).count();
            assert_eq!(equal, lcs[0][0], "{old:?} {new:?}");
        }
    }

    #[test]
    fn binary_and_sensitive_files_are_recognised() {
        assert!(is_binary(b"a\0b"));
        assert!(is_binary(&[0xff, 0xfe]));
        assert!(!is_binary("héllo\n".as_bytes()));
        for name in [".env", ".env.local", "server.pem", "tls.key", "id_ed25519"] {
            assert!(is_sensitive(&Path::new("/code/app").join(name)), "{name}");
        }
        for name in ["env.txt", "main.rs", "keys.rs", "the_id_file"] {
            assert!(!is_sensitive(&Path::new("/code/app").join(name)), "{name}");
        }
    }

    #[test]
    fn wire_values() {
        assert_eq!(EntryKind::Symlink.as_str(), "symlink");
        assert_eq!(NoTextDiff::TooLarge.as_str(), "too_large");
    }
}
