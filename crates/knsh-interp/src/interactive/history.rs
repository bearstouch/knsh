//! The history list (KNSH-107): the lines an interactive shell read, as bash keeps them, with `HISTSIZE`,
//! `HISTFILESIZE`, `HISTCONTROL` and the history file's format.
//!
//! - Entries are numbered from 1; when `HISTSIZE` drops the oldest, numbering goes on (bash's `history_base`), so
//!   `!n` and `history` keep naming the same lines.
//! - `HISTCONTROL` is a colon-separated list: `ignorespace` (a line starting with a blank is not saved),
//!   `ignoredups` (a line equal to the newest entry is not saved), `ignoreboth` (both), `erasedups` (earlier
//!   entries equal to the line are removed before it is saved). Unknown words are ignored, as bash ignores them.
//! - The file holds one line per entry, a multi-line entry as its lines; lines that are bash's time stamps
//!   (`#` followed by digits, written with `HISTTIMEFORMAT`) are skipped when reading, as bash does.
//! - Bounds: the list never holds more than [`MAX_HISTORY_ENTRIES`] (an unlimited or larger `HISTSIZE` stops
//!   there), and a history file larger than [`MAX_HISTORY_FILE`] is read only from its end.

/// Entries kept at most, whatever `HISTSIZE` says (bash has no bound with a negative `HISTSIZE`).
pub const MAX_HISTORY_ENTRIES: usize = 100_000;

/// Bytes of a history file read at most: a larger file is read from its last [`MAX_HISTORY_FILE`] bytes.
pub const MAX_HISTORY_FILE: u64 = 64 * 1024 * 1024;

/// Bash's default `HISTSIZE` and `HISTFILESIZE` for an interactive shell.
pub const DEFAULT_HISTORY_SIZE: usize = 500;

/// What `HISTCONTROL` asks for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Bash's `history_control` bits.
pub struct HistControl {
    /// `ignorespace`.
    pub ignore_space: bool,
    /// `ignoredups`.
    pub ignore_dups: bool,
    /// `erasedups`.
    pub erase_dups: bool,
}

impl HistControl {
    /// `HISTCONTROL`'s value (`None` when unset).
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        let mut control = Self::default();
        for word in value.unwrap_or("").split(':') {
            match word {
                "ignorespace" => control.ignore_space = true,
                "ignoredups" => control.ignore_dups = true,
                "ignoreboth" => {
                    control.ignore_space = true;
                    control.ignore_dups = true;
                }
                "erasedups" => control.erase_dups = true,
                _ => {}
            }
        }
        control
    }
}

/// A history size variable (`HISTSIZE`, `HISTFILESIZE`): `None` for unlimited (unset, negative, or not a number
/// for `HISTSIZE` as bash's `sv_histsize` leaves it), bounded by [`MAX_HISTORY_ENTRIES`].
#[must_use]
pub fn size_limit(value: Option<&str>) -> Option<usize> {
    let value = value?.trim();
    let number: i64 = value.parse().ok()?;
    if number < 0 {
        return None;
    }
    Some(usize::try_from(number).unwrap_or(usize::MAX).min(MAX_HISTORY_ENTRIES))
}

/// The history list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    entries: Vec<String>,
    /// The number of the oldest entry.
    base: usize,
    /// How many of the newest entries were added since the file was last read or written (`history -a`).
    unsaved: usize,
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

impl History {
    /// An empty list, numbering from 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            base: 1,
            unsaved: 0,
        }
    }

    /// The entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// The number of the oldest entry.
    #[must_use]
    pub fn base(&self) -> usize {
        self.base
    }

    /// The number the next entry will have (bash's `\!`).
    #[must_use]
    pub fn next_number(&self) -> usize {
        self.base + self.entries.len()
    }

    /// The entry numbered `number`.
    #[must_use]
    pub fn get(&self, number: usize) -> Option<&str> {
        number
            .checked_sub(self.base)
            .and_then(|index| self.entries.get(index))
            .map(String::as_str)
    }

    /// Whether `line` would be saved under `control`: not blank, not starting with a blank under `ignorespace`,
    /// not equal to the newest entry under `ignoredups`.
    #[must_use]
    pub fn should_save(&self, line: &str, control: HistControl) -> bool {
        if line.trim().is_empty() {
            return false;
        }
        if control.ignore_space && line.starts_with([' ', '\t']) {
            return false;
        }
        !(control.ignore_dups && self.entries.last().is_some_and(|last| last == line))
    }

    /// Saves `line` as `control` says, then keeps at most `limit` entries: `true` when it was saved.
    pub fn add(&mut self, line: &str, control: HistControl, limit: Option<usize>) -> bool {
        if !self.should_save(line, control) {
            return false;
        }
        if control.erase_dups {
            // Bash numbers the remaining entries again from the same base.
            self.entries.retain(|entry| entry != line);
            self.unsaved = self.unsaved.min(self.entries.len());
        }
        self.push(line.to_owned());
        self.stifle(limit);
        true
    }

    /// Adds `line` whatever `HISTCONTROL` says (`history -s`).
    pub fn push(&mut self, line: String) {
        self.entries.push(line);
        self.unsaved += 1;
        self.stifle(Some(MAX_HISTORY_ENTRIES));
    }

    /// Replaces the newest entry with `line` (a command read over several lines, `cmdhist`).
    pub fn replace_last(&mut self, line: String) {
        match self.entries.last_mut() {
            Some(last) => *last = line,
            None => self.push(line),
        }
    }

    /// Removes the newest entry (`history -s` replaces the `history` command itself).
    pub fn pop(&mut self) -> Option<String> {
        let entry = self.entries.pop()?;
        self.unsaved = self.unsaved.saturating_sub(1);
        Some(entry)
    }

    /// Keeps at most `limit` entries (`None`: [`MAX_HISTORY_ENTRIES`]), dropping the oldest (bash's
    /// `stifle_history`).
    pub fn stifle(&mut self, limit: Option<usize>) {
        let limit = limit.unwrap_or(MAX_HISTORY_ENTRIES).min(MAX_HISTORY_ENTRIES);
        if self.entries.len() > limit {
            let dropped = self.entries.len() - limit;
            self.entries.drain(..dropped);
            self.base += dropped;
            self.unsaved = self.unsaved.min(self.entries.len());
        }
    }

    /// Removes every entry (`history -c`).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.unsaved = 0;
    }

    /// Removes entry `number` (`history -d`): `false` when there is none.
    pub fn delete(&mut self, number: usize) -> bool {
        let Some(index) = number
            .checked_sub(self.base)
            .filter(|index| *index < self.entries.len())
        else {
            return false;
        };
        let len = self.entries.len();
        if index >= len - self.unsaved.min(len) {
            self.unsaved -= 1;
        }
        self.entries.remove(index);
        true
    }

    /// The entries added since the file was last read or written, oldest first.
    #[must_use]
    pub fn unsaved(&self) -> &[String] {
        &self.entries[self.entries.len() - self.unsaved.min(self.entries.len())..]
    }

    /// Marks every entry as written to the file.
    pub fn mark_saved(&mut self) {
        self.unsaved = 0;
    }

    /// Adds the entries of history file text `bytes` (`history -r`, and the start of an interactive shell), then
    /// keeps at most `limit`. They count as already in the file.
    pub fn read_file(&mut self, bytes: &[u8], limit: Option<usize>) {
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            if is_time_stamp(line) {
                continue;
            }
            self.entries.push(line.to_owned());
            if self.entries.len() > MAX_HISTORY_ENTRIES {
                self.stifle(Some(MAX_HISTORY_ENTRIES));
            }
        }
        self.stifle(limit);
        self.unsaved = 0;
    }
}

/// Whether `line` is one of bash's time stamps in a history file: `#` and digits.
fn is_time_stamp(line: &str) -> bool {
    line.len() > 1 && line.starts_with('#') && line[1..].bytes().all(|byte| byte.is_ascii_digit())
}

/// The text of a history file holding `entries`, then cut to its last `limit` lines (`HISTFILESIZE`, `None`:
/// no cut), as bash's `history_truncate_file`.
#[must_use]
pub fn file_text<'a>(entries: impl IntoIterator<Item = &'a str>, limit: Option<usize>) -> Vec<u8> {
    let mut lines: Vec<&str> = Vec::new();
    for entry in entries {
        lines.extend(entry.split('\n'));
    }
    if let Some(limit) = limit
        && lines.len() > limit
    {
        lines.drain(..lines.len() - limit);
    }
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: `HISTCONTROL=ignoredups` saves a line equal to the newest entry once.
    #[test]
    fn histcontrol_ignoredups() {
        let control = HistControl::parse(Some("ignoredups"));
        let mut history = History::new();
        assert!(history.add("ls", control, None));
        assert!(!history.add("ls", control, None));
        assert!(history.add("pwd", control, None));
        assert!(history.add("ls", control, None));
        assert_eq!(history.entries(), ["ls", "pwd", "ls"]);
        // Without it, every line is saved.
        assert!(history.add("ls", HistControl::default(), None));
        assert_eq!(history.entries().len(), 4);
    }

    #[test]
    fn histcontrol_other_words() {
        let both = HistControl::parse(Some("ignoreboth"));
        assert!(both.ignore_space && both.ignore_dups && !both.erase_dups);
        let mut history = History::new();
        assert!(!history.add(" secret", both, None));
        assert!(!history.add("   ", HistControl::default(), None));
        let erase = HistControl::parse(Some("bogus:erasedups"));
        for line in ["a", "b", "a", "c", "a"] {
            history.add(line, erase, None);
        }
        assert_eq!(history.entries(), ["b", "c", "a"]);
    }

    #[test]
    fn histsize_drops_the_oldest_and_numbering_goes_on() {
        let mut history = History::new();
        for line in ["one", "two", "three"] {
            history.add(line, HistControl::default(), Some(2));
        }
        assert_eq!(history.entries(), ["two", "three"]);
        assert_eq!((history.base(), history.next_number()), (2, 4));
        assert_eq!(history.get(3), Some("three"));
        assert_eq!(history.get(1), None);
        assert!(history.delete(2));
        assert_eq!(history.entries(), ["three"]);
        assert_eq!(size_limit(Some("-1")), None);
        assert_eq!(size_limit(Some("x")), None);
        assert_eq!(size_limit(Some("10")), Some(10));
        assert_eq!(size_limit(Some("99999999999")), Some(MAX_HISTORY_ENTRIES));
    }

    #[test]
    fn history_file_round_trip() {
        let mut history = History::new();
        history.read_file(b"#1700000000\nls -l\necho a\n", None);
        assert_eq!(history.entries(), ["ls -l", "echo a"]);
        assert_eq!(history.unsaved(), &[] as &[String]);
        history.add("pwd", HistControl::default(), None);
        assert_eq!(history.unsaved(), ["pwd"]);
        let text = file_text(history.entries().iter().map(String::as_str), Some(2));
        assert_eq!(text, b"echo a\npwd\n");
        assert_eq!(file_text(["for x\ndo :\ndone"], None), b"for x\ndo :\ndone\n");
    }
}
