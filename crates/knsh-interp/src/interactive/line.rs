//! The text being edited and the cursor in it (KNSH-107).
//!
//! The cursor is a byte offset that always lies on a character boundary, and never between a character and the
//! zero-width characters (combining marks, joiners) that follow it: moving left or right steps over a character and
//! its zero-width followers together, as readline does with `MB_FIND_NONZERO`, so the cursor never lands inside
//! what the terminal shows as one cell.

use super::width::is_zero_width;

/// Longest line the editor holds: the parser's own input limit ([`knsh_bash::MAX_INPUT_LEN`]). Typing or pasting
/// past it is refused with the bell.
pub const MAX_LINE_LEN: usize = knsh_bash::MAX_INPUT_LEN;

/// A line of text and a cursor in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineBuffer {
    text: String,
    cursor: usize,
}

/// Which characters make up a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordKind {
    /// Letters and digits (emacs `forward-word`, vi `w`).
    Alphanumeric,
    /// Anything but blanks (Ctrl-W `unix-word-rubout`, vi `W`).
    NonBlank,
}

impl WordKind {
    /// Whether `ch` is part of a word of this kind.
    fn contains(self, ch: char) -> bool {
        match self {
            Self::Alphanumeric => ch.is_alphanumeric() || ch == '_',
            Self::NonBlank => !ch.is_whitespace(),
        }
    }
}

impl LineBuffer {
    /// An empty line.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `text` with the cursor at its end.
    #[must_use]
    pub fn with_text(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            cursor: text.len(),
        }
    }

    /// The text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The cursor's byte offset.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the line is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Replaces the text, the cursor at `cursor` (moved onto a cell boundary at or before it).
    pub fn set(&mut self, text: &str, cursor: usize) {
        text.clone_into(&mut self.text);
        self.cursor = self.boundary_at_or_before(cursor.min(self.text.len()));
    }

    /// Moves the cursor to `cursor` (onto a cell boundary at or before it).
    pub fn set_cursor(&mut self, cursor: usize) {
        self.cursor = self.boundary_at_or_before(cursor.min(self.text.len()));
    }

    /// The cell boundary at or before byte `at`.
    fn boundary_at_or_before(&self, mut at: usize) -> usize {
        while at > 0 && !self.text.is_char_boundary(at) {
            at -= 1;
        }
        while at > 0 && self.text[at..].chars().next().is_some_and(is_zero_width) {
            at = self.text[..at].char_indices().next_back().map_or(0, |(index, _)| index);
        }
        at
    }

    /// The cell boundary before byte `at` (a boundary): one character back, then back over the zero-width ones it
    /// follows.
    #[must_use]
    pub fn previous(&self, at: usize) -> usize {
        let Some((index, _)) = self.text[..at].char_indices().next_back() else {
            return 0;
        };
        self.boundary_at_or_before(index)
    }

    /// The cell boundary after byte `at` (a boundary): one character on, then on over the zero-width ones after it.
    #[must_use]
    pub fn next(&self, at: usize) -> usize {
        let mut chars = self.text[at..].char_indices();
        if chars.next().is_none() {
            return at;
        }
        for (offset, ch) in chars {
            if !is_zero_width(ch) {
                return at + offset;
            }
        }
        self.text.len()
    }

    /// Inserts `text` at the cursor and moves the cursor after it: `false` (nothing inserted) past
    /// [`MAX_LINE_LEN`].
    pub fn insert(&mut self, text: &str) -> bool {
        if self.text.len().saturating_add(text.len()) > MAX_LINE_LEN {
            return false;
        }
        self.text.insert_str(self.cursor, text);
        self.cursor += text.len();
        // A combining mark typed after a character joins its cell: the cursor stays after both.
        true
    }

    /// Removes bytes `start..end` (cell boundaries) and returns them; the cursor moves to `start` if it was inside
    /// or after them by their length.
    pub fn remove(&mut self, start: usize, end: usize) -> String {
        let (start, end) = (start.min(end), end.max(start).min(self.text.len()));
        let removed: String = self.text.drain(start..end).collect();
        if self.cursor >= end {
            self.cursor -= end - start;
        } else if self.cursor > start {
            self.cursor = start;
        }
        removed
    }

    /// The start of the word at or before the cursor (emacs `backward-word`): back over non-word characters, then
    /// over word characters.
    #[must_use]
    pub fn word_start_before(&self, at: usize, kind: WordKind) -> usize {
        let mut pos = at;
        while pos > 0 && !self.char_before(pos).is_some_and(|ch| kind.contains(ch)) {
            pos = self.previous(pos);
        }
        while pos > 0 && self.char_before(pos).is_some_and(|ch| kind.contains(ch)) {
            pos = self.previous(pos);
        }
        pos
    }

    /// The end of the word at or after the cursor (emacs `forward-word`): on over non-word characters, then over
    /// word characters.
    #[must_use]
    pub fn word_end_after(&self, at: usize, kind: WordKind) -> usize {
        let mut pos = at;
        while pos < self.text.len() && !self.char_at(pos).is_some_and(|ch| kind.contains(ch)) {
            pos = self.next(pos);
        }
        while pos < self.text.len() && self.char_at(pos).is_some_and(|ch| kind.contains(ch)) {
            pos = self.next(pos);
        }
        pos
    }

    /// The character starting at byte `at`.
    #[must_use]
    pub fn char_at(&self, at: usize) -> Option<char> {
        self.text.get(at..).and_then(|rest| rest.chars().next())
    }

    /// The character ending at byte `at`.
    #[must_use]
    pub fn char_before(&self, at: usize) -> Option<char> {
        self.text.get(..at).and_then(|before| before.chars().next_back())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: the cursor steps over wide characters and over a character with its combining marks at once.
    #[test]
    fn cursor_steps_over_whole_cells() {
        let mut line = LineBuffer::with_text("a日e\u{301}b");
        assert_eq!(line.cursor(), line.text().len());
        let mut stops = vec![line.cursor()];
        while line.cursor() > 0 {
            let previous = line.previous(line.cursor());
            line.set_cursor(previous);
            stops.push(line.cursor());
        }
        // `b` at 7, `e` + U+0301 at 4..7, `日` at 1..4, `a` at 0.
        assert_eq!(stops, [8, 7, 4, 1, 0]);
        assert_eq!(line.next(4), 7);
        line.set_cursor(5);
        assert_eq!(line.cursor(), 4, "never between a character and its combining mark");
    }

    #[test]
    fn words_and_removal() {
        let mut line = LineBuffer::with_text("echo foo-bar  baz");
        assert_eq!(line.word_start_before(line.cursor(), WordKind::Alphanumeric), 14);
        assert_eq!(line.word_start_before(14, WordKind::Alphanumeric), 9);
        assert_eq!(line.word_start_before(14, WordKind::NonBlank), 5);
        assert_eq!(line.word_end_after(0, WordKind::Alphanumeric), 4);
        assert_eq!(line.word_end_after(4, WordKind::Alphanumeric), 8);
        assert_eq!(line.remove(5, 13), "foo-bar ");
        assert_eq!(line.text(), "echo  baz");
        assert_eq!(line.cursor(), 9);
        assert!(!line.insert(&"x".repeat(MAX_LINE_LEN)));
    }
}
