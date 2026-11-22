//! Drawing the prompt and the line on the terminal (KNSH-107): where each character lands when the line wraps,
//! with wide characters, zero-width characters and control characters, and the bytes that redraw it.
//!
//! The renderer keeps no copy of the screen. After each key the editing area is drawn again from the start of the
//! prompt's last line: up to that row, carriage return, clear to the end of the screen (`ESC [ J`), the prompt's
//! last line, the line, then back to the cursor. Rows are counted from the prompt's last line, so the renderer only
//! remembers the row the cursor was left on. A prompt holding newlines is written whole once
//! ([`Prompt::full`]); later redraws write only its last line.
//!
//! As readline, the prompt's invisible parts are marked by bash's `\[` and `\]` (the bytes [`IGNORE_START`] and
//! [`IGNORE_END`] after decoding): what lies between them is written but takes no column. A wide character that
//! does not fit at the end of a row goes to the next row, leaving the last column blank, as terminals place it.
//! Control characters in the line are shown as `^X` (`^?` for DEL), tabs up to the next multiple of 8 columns.

use std::fmt::Write as _;

use super::width::char_width;

/// Readline's `RL_PROMPT_START_IGNORE`: what `\[` in a prompt becomes.
pub const IGNORE_START: char = '\u{1}';

/// Readline's `RL_PROMPT_END_IGNORE`: what `\]` in a prompt becomes.
pub const IGNORE_END: char = '\u{2}';

/// A decoded prompt, split for drawing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// The whole prompt as written to the terminal (markers removed).
    full: String,
    /// Its last line as written (after the last newline), markers removed.
    last_line: String,
    /// The columns the last line takes, invisible parts left out.
    width: usize,
    /// Written after the whole prompt the first time only (OSC 133 `B`), taking no column.
    mark: String,
}

impl Prompt {
    /// The prompt `decoded` (prompt escapes already decoded, so it may hold [`IGNORE_START`] and [`IGNORE_END`]).
    #[must_use]
    pub fn new(decoded: &str) -> Self {
        let mut full = String::with_capacity(decoded.len());
        let mut last_start = 0;
        let mut width = 0;
        let mut invisible = false;
        for ch in decoded.chars() {
            match ch {
                IGNORE_START => invisible = true,
                IGNORE_END => invisible = false,
                '\n' => {
                    full.push(ch);
                    last_start = full.len();
                    width = 0;
                }
                '\r' if !invisible => {
                    full.push(ch);
                    width = 0;
                }
                _ => {
                    full.push(ch);
                    if !invisible {
                        width += char_width(ch);
                    }
                }
            }
        }
        let last_line = full[last_start..].to_owned();
        Self {
            full,
            last_line,
            width,
            mark: String::new(),
        }
    }

    /// The same prompt followed by `mark` (between [`IGNORE_START`] and [`IGNORE_END`], or other bytes that take no
    /// column) the first time it is drawn only.
    #[must_use]
    pub fn with_mark(mut self, mark: &str) -> Self {
        self.mark = mark
            .chars()
            .filter(|ch| *ch != IGNORE_START && *ch != IGNORE_END)
            .collect();
        self
    }

    /// The whole prompt, as written the first time.
    #[must_use]
    pub fn full(&self) -> &str {
        &self.full
    }

    /// The columns its last line takes.
    #[must_use]
    pub fn width(&self) -> usize {
        self.width
    }
}

/// A row and column on the screen, counted from the start of the prompt's last line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Rows below the prompt's last line.
    pub row: usize,
    /// Columns from the left edge.
    pub col: usize,
}

/// How a character of the line is shown: its text and the columns it takes, at column `col`.
fn shown(ch: char, col: usize) -> (String, usize) {
    match ch {
        '\t' => {
            let spaces = 8 - col % 8;
            (" ".repeat(spaces), spaces)
        }
        '\u{7f}' => ("^?".to_owned(), 2),
        _ if u32::from(ch) < 0x20 => {
            let letter = char::from(u8::try_from(u32::from(ch) + 0x40).unwrap_or(b'?'));
            (format!("^{letter}"), 2)
        }
        _ => (ch.to_string(), char_width(ch)),
    }
}

/// Where the next cell of `width` columns lands after `at` on a terminal `columns` wide, and the position after it.
fn place(at: Position, width: usize, columns: usize) -> (Position, Position) {
    let mut start = at;
    if start.col >= columns || (width > 0 && start.col + width > columns) {
        start = Position {
            row: start.row + 1,
            col: 0,
        };
    }
    let end = Position {
        row: start.row,
        col: start.col + width,
    };
    (start, end)
}

/// The text the line `text` is shown as, the position after it and the position of byte `cursor`, starting after
/// a prompt `prompt_width` columns wide on a terminal `columns` wide.
#[must_use]
pub fn layout(prompt_width: usize, text: &str, cursor: usize, columns: usize) -> (String, Position, Position) {
    let columns = columns.max(1);
    let mut at = Position {
        row: prompt_width / columns,
        col: prompt_width % columns,
    };
    if prompt_width > 0 && at.col == 0 {
        // The prompt filled its last row exactly: the terminal waits at the end of that row.
        at = Position {
            row: at.row - 1,
            col: columns,
        };
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor_at = None;
    for (index, ch) in text.char_indices() {
        if index == cursor {
            cursor_at = Some(at);
        }
        let (display, width) = shown(ch, if at.col >= columns { 0 } else { at.col });
        let (start, end) = place(at, width, columns);
        if start.row > at.row && at.col < columns && width > 1 {
            // A wide character pushed to the next row: the terminal leaves the rest of the row blank.
            out.push_str(&" ".repeat(columns - at.col));
        }
        out.push_str(&display);
        at = end;
    }
    let normal = |position: Position| {
        if position.col >= columns {
            Position {
                row: position.row + 1,
                col: 0,
            }
        } else {
            position
        }
    };
    let cursor_at = normal(cursor_at.unwrap_or(at));
    (out, at, cursor_at)
}

/// The renderer's memory of the screen: the row the cursor was left on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Screen {
    cursor_row: usize,
}

impl Screen {
    /// A screen with the cursor on the prompt's last line.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes that draw `prompt` and `text` with the cursor at byte `cursor`, on a terminal `columns` wide:
    /// the whole prompt when `first`, else from the start of the prompt's last line.
    pub fn draw(&mut self, prompt: &Prompt, text: &str, cursor: usize, columns: usize, first: bool) -> String {
        let mut out = String::new();
        if first {
            out.push_str(&prompt.full);
            out.push_str(&prompt.mark);
        } else {
            if self.cursor_row > 0 {
                let _ = write!(out, "\x1b[{}A", self.cursor_row);
            }
            out.push_str("\r\x1b[J");
            out.push_str(&prompt.last_line);
        }
        let (shown, end, target) = layout(prompt.width, text, cursor, columns);
        out.push_str(&shown);
        let mut end = end;
        if end.col >= columns.max(1) {
            // Leave the pending wrap: the cursor really moves to the next row.
            out.push_str("\r\n");
            end = Position {
                row: end.row + 1,
                col: 0,
            };
        }
        if end != target {
            if end.row > target.row {
                let _ = write!(out, "\x1b[{}A", end.row - target.row);
            }
            out.push('\r');
            if target.col > 0 {
                let _ = write!(out, "\x1b[{}C", target.col);
            }
        }
        self.cursor_row = target.row;
        out
    }

    /// The bytes that move the cursor below the line (after drawing `text` with `prompt`), so output that follows
    /// starts on a row of its own; the screen then starts again.
    pub fn finish(&mut self, prompt: &Prompt, text: &str, columns: usize) -> String {
        let (_, end, _) = layout(prompt.width, text, text.len(), columns);
        let mut out = String::new();
        let rows_below = end.row.saturating_sub(self.cursor_row);
        if rows_below > 0 {
            let _ = write!(out, "\x1b[{rows_below}B");
        }
        out.push_str("\r\n");
        self.cursor_row = 0;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: the cursor lands two columns per wide character, never inside one.
    #[test]
    fn cursor_moves_over_wide_characters() {
        let text = "日本語x";
        // After `$ ` (2 columns): the cursor before `本` (byte 3) is at column 4, before `x` (byte 9) at 8.
        assert_eq!(layout(2, text, 3, 80).2, Position { row: 0, col: 4 });
        assert_eq!(layout(2, text, 9, 80).2, Position { row: 0, col: 8 });
        assert_eq!(layout(2, text, text.len(), 80).2, Position { row: 0, col: 9 });
        // A combining mark takes no column.
        assert_eq!(layout(0, "e\u{301}x", 3, 80).2, Position { row: 0, col: 1 });
        // On a 5-column terminal after a 2-column prompt, `本` does not fit in column 4: it moves to row 1, column 4
        // of row 0 stays blank, and the cursor before `語` is at column 2 of row 1.
        let (shown, end, cursor) = layout(2, "日本語", 6, 5);
        assert_eq!(cursor, Position { row: 1, col: 2 });
        assert_eq!(end, Position { row: 1, col: 4 });
        assert_eq!(shown, "日 本語");
    }

    #[test]
    fn prompts_skip_invisible_parts_and_keep_their_last_line() {
        let prompt = Prompt::new("\u{1}\x1b[1m\u{2}user\u{1}\x1b[0m\u{2}\n$ ");
        assert_eq!(prompt.full(), "\x1b[1muser\x1b[0m\n$ ");
        assert_eq!(prompt.width(), 2);
        assert_eq!(prompt.last_line, "$ ");
        assert_eq!(Prompt::new("日> ").width(), 4);
    }

    #[test]
    fn control_characters_show_as_caret_letters() {
        let (shown, end, _) = layout(0, "a\u{1}\u{7f}\tb", 0, 80);
        assert_eq!(shown, "a^A^?   b");
        assert_eq!(end.col, 9);
    }

    #[test]
    fn redraws_return_to_the_prompt_row_and_the_cursor() {
        let prompt = Prompt::new("$ ");
        let mut screen = Screen::new();
        assert_eq!(screen.draw(&prompt, "ls", 2, 80, true), "$ ls");
        assert_eq!(screen.draw(&prompt, "ls", 0, 80, false), "\r\x1b[J$ ls\r\x1b[2C");
        // A line filling the row exactly leaves the pending wrap, and the cursor goes back up.
        let out = screen.draw(&prompt, "abc", 0, 5, false);
        assert_eq!(out, "\r\x1b[J$ abc\r\n\x1b[1A\r\x1b[2C");
        // Wrapped onto a second row with the cursor at the end: the next redraw first goes up one row.
        let out = screen.draw(&prompt, "abcdef", 6, 5, false);
        assert_eq!(out, "\r\x1b[J$ abcdef");
        assert_eq!(screen.cursor_row, 1);
        assert!(screen.draw(&prompt, "", 0, 5, false).starts_with("\x1b[1A\r\x1b[J"));
        assert_eq!(screen.finish(&prompt, "", 5), "\r\n");
    }
}
