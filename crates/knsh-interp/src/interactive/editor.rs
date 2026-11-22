//! The line editor's keymaps (KNSH-107): what each key does to the line, in emacs mode (readline's default
//! bindings) and in vi mode (insert and command modes, the basic motions and operators).
//!
//! The editor is a pure state machine: [`Editor::key`] takes one [`Key`] and the history list and returns what the
//! session must do ([`Action`]); [`Editor::view`] tells what to draw. It never touches the terminal, so every
//! binding is tested without one.
//!
//! Bindings, as readline's (`bind -p` in bash 5.2), for the keys listed:
//!
//! - **emacs:** Ctrl-A/E/B/F, Home, End and the arrows move; Meta-B/F and Ctrl/Alt-arrows move by word;
//!   Backspace, Ctrl-H, Delete and Ctrl-D delete (Ctrl-D on an empty line is end of input); Ctrl-K, Ctrl-U,
//!   Ctrl-W, Meta-D and Meta-Backspace kill into the kill ring, Ctrl-Y yanks and Meta-Y cycles; Ctrl-T transposes;
//!   Meta-U/L/C change case; Ctrl-_ undoes and Meta-R reverts; Ctrl-P/N, Up and Down walk the history, Meta-< and
//!   Meta-> go to its ends; Ctrl-R and Ctrl-S search it incrementally; Meta-. and Meta-_ yank the last argument of
//!   earlier lines; Ctrl-V inserts the next character as typed; Tab completes and Meta-? lists completions;
//!   Ctrl-L clears the screen; Ctrl-C abandons the line; Ctrl-G aborts a search.
//! - **vi insert mode:** characters, Enter, Backspace, Ctrl-W, Ctrl-U, Ctrl-V, Ctrl-D, Ctrl-R, Tab, the arrows;
//!   Escape enters command mode.
//! - **vi command mode:** counts; `h l 0 ^ $ w b e W B E f F t T` and space move; `i a I A` insert; `x X D C S s r
//!   ~ p P u` edit; `d c y` take a motion (`dd cc yy` the whole line); `k -` and `j +` walk the history; Enter
//!   accepts.

use super::expansion;
use super::keys::Key;
use super::line::{LineBuffer, WordKind};

/// Lines kept in the kill ring (readline keeps 10 by default).
const KILL_RING_SIZE: usize = 10;

/// Undo steps kept for one line.
const UNDO_LIMIT: usize = 1000;

/// Which keymap the editor reads keys with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditMode {
    /// Readline's emacs keymap (bash's default).
    Emacs,
    /// Readline's vi keymap, starting each line in insert mode.
    Vi,
}

/// What the session must do after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing but redraw the line.
    Redraw,
    /// The line is finished: run it.
    Accept(String),
    /// End of input (Ctrl-D on an empty line).
    Eof,
    /// Ctrl-C: the line is abandoned.
    Interrupt,
    /// Tab (or Meta-?, `list: true`): complete the word before the cursor; `list` when the possibilities should be
    /// listed (a second Tab in a row, as readline's `show-all-if-ambiguous` off).
    Complete {
        /// List the possibilities instead of only completing.
        list: bool,
    },
    /// Ctrl-L: clear the screen and draw the line again at the top.
    ClearScreen,
    /// Ring the bell: the key did nothing.
    Bell,
}

/// What [`Editor::view`] shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View<'a> {
    /// The text of the line.
    pub text: &'a str,
    /// The cursor's byte offset in it.
    pub cursor: usize,
    /// While searching the history incrementally: the prompt to show instead of the shell's, readline's
    /// ``(reverse-i-search)`query': ``.
    pub search_prompt: Option<String>,
}

/// An incremental search of the history (Ctrl-R, Ctrl-S).
#[derive(Debug, Clone)]
struct Search {
    /// What is searched for.
    query: String,
    /// Searching towards older lines.
    reverse: bool,
    /// The history line shown (`None`: the line being edited), with the offset of the match in it.
    found: Option<(usize, usize)>,
    /// The last search found nothing.
    failed: bool,
    /// The line and cursor before the search, put back by Ctrl-G.
    original: (String, usize),
    /// The history position before the search.
    original_index: Option<usize>,
}

/// A vi operator waiting for its motion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Delete,
    Change,
    Yank,
}

/// A vi command waiting for the character it applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharCommand {
    /// `r`.
    Replace,
    /// `f`, `F`, `t`, `T`: find forward (`forward`), stopping before it (`till`).
    Find { forward: bool, till: bool },
}

/// The vi mode the editor is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViState {
    Insert,
    Command,
}

/// The last command, for commands that act differently when repeated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Last {
    Other,
    /// A kill: the next kill adds to the same kill-ring entry.
    Kill,
    /// A yank of `start..end`: Meta-Y may replace it with an older kill.
    Yank {
        start: usize,
        end: usize,
        ring: usize,
    },
    /// Meta-. inserted `start..end`, the last argument of the line `back` lines before the newest.
    YankedArgument {
        start: usize,
        end: usize,
        back: usize,
    },
    /// A self-inserted character: typing more is one undo step.
    Insert,
    /// Tab: a second one lists the possibilities.
    Tab,
}

/// The line editor: the line, its keymap state, the kill ring, the undo list and the position in the history.
#[derive(Debug, Clone)]
pub struct Editor {
    line: LineBuffer,
    mode: EditMode,
    vi: ViState,
    kill_ring: Vec<String>,
    undo: Vec<(String, usize)>,
    /// What the key being handled does (set by its handler).
    last: Last,
    /// What the key before it did.
    previous: Last,
    /// The history line being edited (`None`: the new line), and the new line as it was when the walk started.
    history_index: Option<usize>,
    saved: (String, usize),
    /// The incremental search running, if any.
    search: Option<Search>,
    quoted_insert: bool,
    count: Option<usize>,
    operator: Option<(Operator, usize)>,
    char_command: Option<(CharCommand, Option<Operator>, usize)>,
}

impl Editor {
    /// An editor with an empty line in `mode`.
    #[must_use]
    pub fn new(mode: EditMode) -> Self {
        Self {
            line: LineBuffer::new(),
            mode,
            vi: ViState::Insert,
            kill_ring: Vec::new(),
            undo: Vec::new(),
            last: Last::Other,
            previous: Last::Other,
            history_index: None,
            saved: (String::new(), 0),
            search: None,
            quoted_insert: false,
            count: None,
            operator: None,
            char_command: None,
        }
    }

    /// Starts a new line in `mode`, keeping the kill ring.
    pub fn begin(&mut self, mode: EditMode) {
        let kill_ring = std::mem::take(&mut self.kill_ring);
        *self = Self::new(mode);
        self.kill_ring = kill_ring;
    }

    /// The keymap in use.
    #[must_use]
    pub fn mode(&self) -> EditMode {
        self.mode
    }

    /// What to draw.
    #[must_use]
    pub fn view(&self) -> View<'_> {
        let search_prompt = self.search.as_ref().map(|search| {
            let failed = if search.failed { "failed " } else { "" };
            let direction = if search.reverse { "reverse" } else { "forward" };
            format!("({failed}{direction}-i-search)`{}': ", search.query)
        });
        View {
            text: self.line.text(),
            cursor: self.line.cursor(),
            search_prompt,
        }
    }

    /// The text and cursor, for completion.
    #[must_use]
    pub fn line(&self) -> &LineBuffer {
        &self.line
    }

    /// Replaces bytes `start..cursor` with `text` (a completion), leaving the cursor after it. One undo step.
    pub fn replace_before_cursor(&mut self, start: usize, text: &str) -> bool {
        let cursor = self.line.cursor();
        if start > cursor || self.line.text().len() - (cursor - start) + text.len() > super::line::MAX_LINE_LEN {
            return false;
        }
        self.snapshot();
        self.line.remove(start, cursor);
        self.line.insert(text);
        // The Tab that asked for it stays the last key, so a second Tab lists what is left.
        true
    }

    /// Records the line before a change, for undo.
    fn snapshot(&mut self) {
        let state = (self.line.text().to_owned(), self.line.cursor());
        if self.undo.last() != Some(&state) {
            if self.undo.len() >= UNDO_LIMIT {
                self.undo.remove(0);
            }
            self.undo.push(state);
        }
    }

    /// Puts back the line before the last change.
    fn undo(&mut self) -> Action {
        match self.undo.pop() {
            Some((text, cursor)) => {
                self.line.set(&text, cursor);
                Action::Redraw
            }
            None => Action::Bell,
        }
    }

    /// Adds `text` to the kill ring: to the newest entry when the key before was a kill too (after it, or before
    /// it with `before`).
    fn kill(&mut self, text: String, before: bool) {
        if text.is_empty() {
            return;
        }
        if self.previous == Last::Kill
            && let Some(newest) = self.kill_ring.last_mut()
        {
            if before {
                newest.insert_str(0, &text);
            } else {
                newest.push_str(&text);
            }
        } else {
            if self.kill_ring.len() >= KILL_RING_SIZE {
                self.kill_ring.remove(0);
            }
            self.kill_ring.push(text);
        }
    }

    /// Kills bytes `start..end`.
    fn kill_range(&mut self, start: usize, end: usize) -> Action {
        if start == end {
            self.last = Last::Kill;
            return Action::Redraw;
        }
        self.snapshot();
        let before = end <= self.line.cursor();
        let text = self.line.remove(start, end);
        self.kill(text, before);
        self.last = Last::Kill;
        Action::Redraw
    }

    /// Handles `key`, with `history` the history list, oldest first.
    pub fn key(&mut self, key: Key, history: &[String]) -> Action {
        if self.quoted_insert {
            self.quoted_insert = false;
            let ch = match key {
                Key::Char(ch) | Key::Meta(ch) => ch,
                Key::Control(letter) => char::from(letter & 0x1F),
                Key::Enter => '\r',
                Key::Tab => '\t',
                Key::Backspace => '\u{7f}',
                Key::Escape => '\u{1b}',
                _ => return Action::Bell,
            };
            return self.self_insert(ch);
        }
        // In vi mode `ESC` is never Meta: an `ESC` that arrived with the next key (typed fast, pasted) is Escape
        // followed by that key, as readline's vi keymaps read it.
        if self.mode == EditMode::Vi && self.search.is_none() {
            let split = match key {
                Key::Meta('\r') => Some(Key::Enter),
                Key::Meta('\t') => Some(Key::Tab),
                Key::Meta(ch) => Some(Key::Char(ch)),
                Key::MetaBackspace => Some(Key::Backspace),
                _ => None,
            };
            if let Some(second) = split {
                self.key(Key::Escape, history);
                return self.key(second, history);
            }
        }
        self.previous = std::mem::replace(&mut self.last, Last::Other);
        if self.search.is_some()
            && let Some(action) = self.search_key(key, history)
        {
            return action;
        }
        match (self.mode, self.vi) {
            (EditMode::Emacs, _) | (EditMode::Vi, ViState::Insert) => self.common_key(key, history),
            (EditMode::Vi, ViState::Command) => self.vi_command(key, history),
        }
    }

    /// Inserts `ch` typed by the user.
    fn self_insert(&mut self, ch: char) -> Action {
        if self.previous != Last::Insert {
            self.snapshot();
        }
        let mut bytes = [0_u8; 4];
        if self.line.insert(ch.encode_utf8(&mut bytes)) {
            self.last = Last::Insert;
            Action::Redraw
        } else {
            Action::Bell
        }
    }

    /// Emacs keys, and the vi insert-mode keys (a subset of them).
    #[allow(clippy::too_many_lines)] // One arm per binding, as readline's keymap table.
    fn common_key(&mut self, key: Key, history: &[String]) -> Action {
        let vi = self.mode == EditMode::Vi;
        let cursor = self.line.cursor();
        let len = self.line.text().len();
        match key {
            Key::Char(ch) => self.self_insert(ch),
            Key::Enter | Key::Control(b'J' | b'M') => self.accept(),
            Key::Tab => self.complete(),
            Key::Control(b'C') => Action::Interrupt,
            Key::Control(b'D') if self.line.is_empty() => Action::Eof,
            Key::Control(b'D') | Key::Delete if !vi || key == Key::Delete => {
                if cursor == len {
                    return Action::Bell;
                }
                self.snapshot();
                let next = self.line.next(cursor);
                self.line.remove(cursor, next);
                Action::Redraw
            }
            Key::Backspace | Key::Control(b'H') => {
                if cursor == 0 {
                    return Action::Bell;
                }
                self.snapshot();
                let previous = self.line.previous(cursor);
                self.line.remove(previous, cursor);
                Action::Redraw
            }
            Key::Control(b'W') => {
                let start = self.line.word_start_before(cursor, WordKind::NonBlank);
                self.kill_range(start, cursor)
            }
            Key::Control(b'U') => self.kill_range(0, cursor),
            Key::Control(b'V') => {
                self.quoted_insert = true;
                Action::Redraw
            }
            Key::Control(b'R') => self.start_search(true),
            Key::Control(b'S') if !vi => self.start_search(false),
            Key::Up | Key::Control(b'P') => self.history_move(history, -1),
            Key::Down | Key::Control(b'N') => self.history_move(history, 1),
            Key::Left | Key::Control(b'B') => self.move_to(self.line.previous(cursor)),
            Key::Right | Key::Control(b'F') => self.move_to(self.line.next(cursor)),
            Key::Home | Key::Control(b'A') => self.move_to(0),
            Key::End | Key::Control(b'E') => self.move_to(len),
            Key::WordLeft => self.move_to(self.line.word_start_before(cursor, WordKind::Alphanumeric)),
            Key::WordRight => self.move_to(self.line.word_end_after(cursor, WordKind::Alphanumeric)),
            Key::Escape if vi => {
                self.vi = ViState::Command;
                self.count = None;
                if cursor > 0 {
                    self.line.set_cursor(self.line.previous(cursor));
                }
                Action::Redraw
            }
            Key::Control(b'L') if !vi => Action::ClearScreen,
            _ if vi => Action::Bell,
            Key::Control(b'K') => self.kill_range(cursor, len),
            Key::Control(b'Y') => self.yank(),
            Key::Control(b'T') => self.transpose(),
            Key::Control(b'_') => self.undo(),
            Key::Meta('b') => self.move_to(self.line.word_start_before(cursor, WordKind::Alphanumeric)),
            Key::Meta('f') => self.move_to(self.line.word_end_after(cursor, WordKind::Alphanumeric)),
            Key::Meta('d') => {
                let end = self.line.word_end_after(cursor, WordKind::Alphanumeric);
                self.kill_range(cursor, end)
            }
            Key::MetaBackspace => {
                let start = self.line.word_start_before(cursor, WordKind::Alphanumeric);
                self.kill_range(start, cursor)
            }
            Key::Meta('y') => self.yank_pop(),
            Key::Meta('.' | '_') => self.yank_last_arg(history),
            Key::Meta('<') => self.history_jump(history, true),
            Key::Meta('>') => self.history_jump(history, false),
            Key::Meta('u') => self.change_case(Case::Upper),
            Key::Meta('l') => self.change_case(Case::Lower),
            Key::Meta('c') => self.change_case(Case::Capital),
            Key::Meta('r') => {
                if let Some((text, cursor)) = self.undo.first().cloned() {
                    self.line.set(&text, cursor);
                    self.undo.clear();
                }
                Action::Redraw
            }
            Key::Meta('?' | '=') => Action::Complete { list: true },
            Key::Meta('\r') => self.accept(),
            Key::Control(_) | Key::Meta(_) | Key::Delete | Key::Escape | Key::Unknown => Action::Bell,
        }
    }

    /// Accepts the line.
    fn accept(&mut self) -> Action {
        self.search = None;
        Action::Accept(self.line.text().to_owned())
    }

    /// Tab: completion, listing on the second one in a row.
    fn complete(&mut self) -> Action {
        let list = self.previous == Last::Tab;
        self.last = Last::Tab;
        Action::Complete { list }
    }

    /// Moves the cursor to `at`.
    fn move_to(&mut self, at: usize) -> Action {
        self.line.set_cursor(at);
        Action::Redraw
    }

    /// Ctrl-Y: inserts the newest kill.
    fn yank(&mut self) -> Action {
        let Some(text) = self.kill_ring.last().cloned() else {
            return Action::Bell;
        };
        self.snapshot();
        let start = self.line.cursor();
        if !self.line.insert(&text) {
            return Action::Bell;
        }
        self.last = Last::Yank {
            start,
            end: self.line.cursor(),
            ring: self.kill_ring.len() - 1,
        };
        Action::Redraw
    }

    /// Meta-Y after a yank: replaces what was yanked with the kill before it.
    fn yank_pop(&mut self) -> Action {
        let Last::Yank { start, end, ring } = self.previous else {
            return Action::Bell;
        };
        if self.kill_ring.is_empty() {
            return Action::Bell;
        }
        let ring = if ring == 0 { self.kill_ring.len() - 1 } else { ring - 1 };
        let text = self.kill_ring[ring].clone();
        self.line.remove(start, end);
        self.line.set_cursor(start);
        self.line.insert(&text);
        self.last = Last::Yank {
            start,
            end: self.line.cursor(),
            ring,
        };
        Action::Redraw
    }

    /// Meta-.: inserts the last word of the previous history line; again, of the line before that.
    fn yank_last_arg(&mut self, history: &[String]) -> Action {
        let (back, replace) = match self.previous {
            Last::YankedArgument { start, end, back } => (back + 1, Some((start, end))),
            _ => (0, None),
        };
        let Some(entry) = history.len().checked_sub(back + 1).and_then(|index| history.get(index)) else {
            return Action::Bell;
        };
        let words = expansion::words(entry);
        let Some(word) = words.last() else {
            return Action::Bell;
        };
        self.snapshot();
        if let Some((start, end)) = replace {
            self.line.remove(start, end);
            self.line.set_cursor(start);
        }
        let start = self.line.cursor();
        if !self.line.insert(word) {
            return Action::Bell;
        }
        self.last = Last::YankedArgument {
            start,
            end: self.line.cursor(),
            back,
        };
        Action::Redraw
    }

    /// Ctrl-T: swaps the characters before and at the cursor (the two before it at the end of the line), moving
    /// the cursor on.
    fn transpose(&mut self) -> Action {
        let len = self.line.text().len();
        let mut cursor = self.line.cursor();
        if cursor == 0 || len == 0 {
            return Action::Bell;
        }
        if cursor == len {
            cursor = self.line.previous(cursor);
        }
        let start = self.line.previous(cursor);
        if start == cursor {
            return Action::Bell;
        }
        let end = self.line.next(cursor);
        self.snapshot();
        let first = self.line.text()[start..cursor].to_owned();
        let second = self.line.text()[cursor..end].to_owned();
        self.line.remove(start, end);
        self.line.set_cursor(start);
        self.line.insert(&(second + &first));
        Action::Redraw
    }

    /// Meta-U, Meta-L, Meta-C: the word after the cursor in upper, lower or capitalised case.
    fn change_case(&mut self, case: Case) -> Action {
        let cursor = self.line.cursor();
        let end = self.line.word_end_after(cursor, WordKind::Alphanumeric);
        if end == cursor {
            return Action::Redraw;
        }
        self.snapshot();
        let word = self.line.text()[cursor..end].to_owned();
        let changed = match case {
            Case::Upper => word.to_uppercase(),
            Case::Lower => word.to_lowercase(),
            Case::Capital => {
                let mut out = String::with_capacity(word.len());
                let mut first = true;
                for ch in word.chars() {
                    if first && ch.is_alphanumeric() {
                        out.extend(ch.to_uppercase());
                        first = false;
                    } else {
                        out.extend(ch.to_lowercase());
                    }
                }
                out
            }
        };
        self.line.remove(cursor, end);
        self.line.set_cursor(cursor);
        self.line.insert(&changed);
        Action::Redraw
    }

    /// Up (`step` −1) or down (+1) in the history.
    fn history_move(&mut self, history: &[String], step: isize) -> Action {
        let target = match (self.history_index, step) {
            (None, -1) if !history.is_empty() => Some(history.len() - 1),
            (Some(0), -1) | (None, _) => return Action::Bell,
            (Some(index), -1) => Some(index - 1),
            (Some(index), _) if index + 1 < history.len() => Some(index + 1),
            (Some(_), _) => None,
        };
        self.go_to_history(history, target)
    }

    /// Meta-< (`first`) and Meta->: the oldest line, or the line being written.
    fn history_jump(&mut self, history: &[String], first: bool) -> Action {
        if first {
            if history.is_empty() {
                return Action::Bell;
            }
            self.go_to_history(history, Some(0))
        } else {
            self.go_to_history(history, None)
        }
    }

    /// Shows history line `target` (`None`: the line being written), cursor at its end.
    fn go_to_history(&mut self, history: &[String], target: Option<usize>) -> Action {
        if self.history_index.is_none() {
            self.saved = (self.line.text().to_owned(), self.line.cursor());
        }
        self.history_index = target;
        self.line = match target.and_then(|index| history.get(index)) {
            Some(entry) => LineBuffer::with_text(entry),
            None => LineBuffer::with_text(&self.saved.0),
        };
        self.undo.clear();
        if self.mode == EditMode::Vi && self.vi == ViState::Command {
            self.line.set_cursor(0);
        }
        Action::Redraw
    }

    // ---- Incremental search ----

    /// Ctrl-R (`reverse`) or Ctrl-S.
    fn start_search(&mut self, reverse: bool) -> Action {
        self.search = Some(Search {
            query: String::new(),
            reverse,
            found: None,
            failed: false,
            original: (self.line.text().to_owned(), self.line.cursor()),
            original_index: self.history_index,
        });
        Action::Redraw
    }

    /// A key while searching: `None` when it ends the search and must be handled as usual.
    fn search_key(&mut self, key: Key, history: &[String]) -> Option<Action> {
        let search = self.search.as_mut()?;
        match key {
            Key::Char(ch) => {
                search.query.push(ch);
                Some(self.search_step(history, false))
            }
            Key::Backspace | Key::Control(b'H') => {
                search.query.pop();
                search.found = None;
                Some(self.search_step(history, false))
            }
            Key::Control(b'R') => {
                search.reverse = true;
                Some(self.search_step(history, true))
            }
            Key::Control(b'S') => {
                search.reverse = false;
                Some(self.search_step(history, true))
            }
            Key::Control(b'G') => {
                let (text, cursor) = search.original.clone();
                self.history_index = search.original_index;
                self.line.set(&text, cursor);
                self.search = None;
                Some(Action::Bell)
            }
            Key::Control(b'C') => {
                self.search = None;
                Some(Action::Interrupt)
            }
            Key::Enter => Some(self.accept()),
            _ => {
                // Any other key ends the search on the line found, then does what it does.
                if let Some((index, _)) = search.found {
                    self.history_index = Some(index);
                }
                self.search = None;
                if key == Key::Escape {
                    return Some(Action::Redraw);
                }
                None
            }
        }
    }

    /// Searches for the query from the line shown (`skip`: past it, Ctrl-R again).
    fn search_step(&mut self, history: &[String], skip: bool) -> Action {
        let Some(search) = self.search.as_mut() else {
            return Action::Redraw;
        };
        if search.query.is_empty() {
            search.failed = false;
            return Action::Redraw;
        }
        let candidates: Vec<usize> = match (search.found, search.reverse) {
            (Some((index, _)), true) => {
                let from = if skip { index } else { index + 1 };
                (0..from.min(history.len())).rev().collect()
            }
            (None, true) => (0..history.len()).rev().collect(),
            (Some((index, _)), false) => {
                let from = if skip { index + 1 } else { index };
                (from..history.len()).collect()
            }
            (None, false) => Vec::new(),
        };
        let hit = candidates.into_iter().find_map(|index| {
            let entry = history.get(index)?;
            let at = if search.reverse {
                entry.rfind(search.query.as_str())
            } else {
                entry.find(search.query.as_str())
            }?;
            Some((index, at))
        });
        if let Some((index, at)) = hit {
            search.found = Some((index, at));
            search.failed = false;
            let entry = history.get(index).map_or("", String::as_str);
            self.line.set(entry, at);
            Action::Redraw
        } else {
            search.failed = true;
            Action::Bell
        }
    }

    // ---- vi command mode ----

    /// The count typed before a command, 1 by default.
    fn take_count(&mut self) -> usize {
        self.count.take().unwrap_or(1)
    }

    /// Enters insert mode.
    fn insert_mode(&mut self) -> Action {
        self.vi = ViState::Insert;
        self.last = Last::Other;
        Action::Redraw
    }

    /// The cursor kept on a character in command mode (never after the last one).
    fn clamp_command_cursor(&mut self) {
        let len = self.line.text().len();
        if len > 0 && self.line.cursor() >= len {
            let last = self.line.previous(len);
            self.line.set_cursor(last);
        }
    }

    /// A key in vi command mode.
    #[allow(clippy::too_many_lines)] // One arm per command, as readline's vi keymap.
    fn vi_command(&mut self, key: Key, history: &[String]) -> Action {
        if let Some((command, operator, count)) = self.char_command.take() {
            let Key::Char(target) = key else {
                return Action::Bell;
            };
            return self.vi_char_command(command, operator, count, target);
        }
        let ch = match key {
            Key::Char(ch) => ch,
            Key::Enter | Key::Control(b'J' | b'M') => return self.accept(),
            Key::Control(b'C') => return Action::Interrupt,
            Key::Control(b'D') if self.line.is_empty() => return Action::Eof,
            Key::Control(b'L') => return Action::ClearScreen,
            Key::Control(b'R') => return self.start_search(true),
            Key::Escape => {
                self.count = None;
                self.operator = None;
                return Action::Redraw;
            }
            Key::Left | Key::Backspace => 'h',
            Key::Right => 'l',
            Key::Up => 'k',
            Key::Down => 'j',
            Key::Home => '0',
            Key::End => '$',
            Key::Tab => return self.complete(),
            _ => return Action::Bell,
        };
        if ch.is_ascii_digit() && (ch != '0' || self.count.is_some()) {
            let digit = usize::from(u8::try_from(ch).unwrap_or(b'0') - b'0');
            self.count = Some(
                self.count
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit)
                    .min(9999),
            );
            return Action::Redraw;
        }
        let count = self.take_count();
        let pending = self.operator;
        let total = count
            .saturating_mul(pending.map_or(1, |(_, op_count)| op_count))
            .min(9999);
        if let Some(motion) = self.vi_motion(ch, total, pending.map(|(operator, _)| operator)) {
            self.operator = None;
            if let Some((operator, _)) = pending {
                let (start, end) = self.motion_range(ch, motion);
                return self.apply_operator(operator, start, end);
            }
            self.line.set_cursor(motion);
            self.clamp_command_cursor();
            return Action::Redraw;
        }
        let cursor = self.line.cursor();
        let len = self.line.text().len();
        match ch {
            'f' | 'F' | 't' | 'T' => {
                let operator = self
                    .operator
                    .take()
                    .map(|(operator, op_count)| (operator, op_count * count));
                self.char_command = Some((
                    CharCommand::Find {
                        forward: ch.is_ascii_lowercase(),
                        till: matches!(ch, 't' | 'T'),
                    },
                    operator.map(|(operator, _)| operator),
                    operator.map_or(count, |(_, count)| count),
                ));
                Action::Redraw
            }
            'd' | 'c' | 'y' => {
                let operator = match ch {
                    'd' => Operator::Delete,
                    'c' => Operator::Change,
                    _ => Operator::Yank,
                };
                match self.operator.take() {
                    // `dd`, `cc`, `yy`: the whole line.
                    Some((pending, _)) if pending == operator => self.apply_operator(operator, 0, len),
                    Some(_) => Action::Bell,
                    None => {
                        self.operator = Some((operator, count));
                        Action::Redraw
                    }
                }
            }
            _ if self.operator.take().is_some() => Action::Bell,
            'i' => self.insert_mode(),
            'a' => {
                self.line.set_cursor(self.line.next(cursor));
                self.insert_mode()
            }
            'I' => {
                self.line.set_cursor(0);
                self.insert_mode()
            }
            'A' => {
                self.line.set_cursor(len);
                self.insert_mode()
            }
            'x' => {
                let mut end = cursor;
                for _ in 0..count {
                    end = self.line.next(end);
                }
                let action = self.apply_operator(Operator::Delete, cursor, end);
                self.clamp_command_cursor();
                action
            }
            'X' => {
                let mut start = cursor;
                for _ in 0..count {
                    start = self.line.previous(start);
                }
                self.apply_operator(Operator::Delete, start, cursor)
            }
            'D' => {
                let action = self.apply_operator(Operator::Delete, cursor, len);
                self.clamp_command_cursor();
                action
            }
            'C' => self.apply_operator(Operator::Change, cursor, len),
            'S' => self.apply_operator(Operator::Change, 0, len),
            's' => {
                let mut end = cursor;
                for _ in 0..count {
                    end = self.line.next(end);
                }
                self.apply_operator(Operator::Change, cursor, end)
            }
            'r' => {
                self.char_command = Some((CharCommand::Replace, None, count));
                Action::Redraw
            }
            '~' => {
                if len == 0 {
                    return Action::Bell;
                }
                self.snapshot();
                let mut at = cursor;
                for _ in 0..count {
                    let Some(ch) = self.line.char_at(at) else { break };
                    let next = self.line.next(at);
                    let swapped: String = if ch.is_uppercase() {
                        ch.to_lowercase().collect()
                    } else {
                        ch.to_uppercase().collect()
                    };
                    let tail = self.line.text()[at + ch.len_utf8()..next].to_owned();
                    self.line.remove(at, next);
                    self.line.set_cursor(at);
                    self.line.insert(&(swapped + &tail));
                    at = self.line.cursor();
                }
                self.line.set_cursor(at);
                self.clamp_command_cursor();
                Action::Redraw
            }
            'p' | 'P' => {
                let Some(text) = self.kill_ring.last().cloned() else {
                    return Action::Bell;
                };
                self.snapshot();
                if ch == 'p' && len > 0 {
                    self.line.set_cursor(self.line.next(cursor));
                }
                for _ in 0..count {
                    if !self.line.insert(&text) {
                        return Action::Bell;
                    }
                }
                let end = self.line.cursor();
                self.line.set_cursor(self.line.previous(end));
                Action::Redraw
            }
            'u' => {
                let action = self.undo();
                self.clamp_command_cursor();
                action
            }
            'k' | '-' => {
                let mut action = Action::Bell;
                for _ in 0..count {
                    action = self.history_move(history, -1);
                }
                action
            }
            'j' | '+' => {
                let mut action = Action::Bell;
                for _ in 0..count {
                    action = self.history_move(history, 1);
                }
                action
            }
            _ => Action::Bell,
        }
    }

    /// Where vi motion `ch` repeated `count` times takes the cursor, if `ch` is a motion, for `operator` if one
    /// waits for it.
    fn vi_motion(&self, ch: char, count: usize, operator: Option<Operator>) -> Option<usize> {
        let line = &self.line;
        let mut at = line.cursor();
        let len = line.text().len();
        match ch {
            'h' => {
                for _ in 0..count {
                    at = line.previous(at);
                }
            }
            'l' | ' ' => {
                for _ in 0..count {
                    at = line.next(at);
                }
                // Without an operator, `l` stops on the last character.
                if operator.is_none() && at >= len && len > 0 {
                    at = line.previous(len).max(line.cursor());
                }
            }
            '0' => at = 0,
            '^' => at = first_non_blank(line),
            '$' => at = len,
            // `cw` on a word changes to its end, as vi's `ce` (readline does the same).
            'w' | 'W' if operator == Some(Operator::Change) && line.char_at(at).is_some_and(|c| !c.is_whitespace()) => {
                for _ in 0..count {
                    at = line.next(vi_word_end(line, at, ch == 'W').max(at));
                }
            }
            'w' | 'W' => {
                for _ in 0..count {
                    at = vi_word_forward(line, at, ch == 'W');
                }
            }
            'b' | 'B' => {
                for _ in 0..count {
                    at = vi_word_backward(line, at, ch == 'B');
                }
            }
            'e' | 'E' => {
                for _ in 0..count {
                    at = vi_word_end(line, at, ch == 'E');
                }
            }
            _ => return None,
        }
        Some(at)
    }

    /// The bytes an operator with motion `ch` (ending at `motion`) covers: `e` and `E` include the character they
    /// end on.
    fn motion_range(&self, ch: char, motion: usize) -> (usize, usize) {
        let cursor = self.line.cursor();
        let motion = if matches!(ch, 'e' | 'E') {
            self.line.next(motion)
        } else {
            motion
        };
        (cursor.min(motion), cursor.max(motion))
    }

    /// Applies `operator` to bytes `start..end`.
    fn apply_operator(&mut self, operator: Operator, start: usize, end: usize) -> Action {
        let text = self.line.text()[start..end].to_owned();
        match operator {
            Operator::Yank => {
                if !text.is_empty() {
                    self.previous = Last::Other;
                    self.kill(text, false);
                }
                self.line.set_cursor(start);
                self.clamp_command_cursor();
                Action::Redraw
            }
            Operator::Delete | Operator::Change => {
                if start == end && operator == Operator::Delete {
                    return Action::Bell;
                }
                self.snapshot();
                self.line.remove(start, end);
                self.line.set_cursor(start);
                // vi deletes never add to an earlier kill.
                self.previous = Last::Other;
                self.kill(text, false);
                if operator == Operator::Change {
                    self.insert_mode()
                } else {
                    self.clamp_command_cursor();
                    Action::Redraw
                }
            }
        }
    }

    /// `r` and the `f F t T` searches, given their character.
    fn vi_char_command(
        &mut self,
        command: CharCommand,
        operator: Option<Operator>,
        count: usize,
        target: char,
    ) -> Action {
        let cursor = self.line.cursor();
        match command {
            CharCommand::Replace => {
                let mut end = cursor;
                for _ in 0..count {
                    end = self.line.next(end);
                }
                if end == cursor || self.line.text()[cursor..end].chars().count() < count {
                    return Action::Bell;
                }
                self.snapshot();
                self.line.remove(cursor, end);
                self.line.set_cursor(cursor);
                let replacement: String = std::iter::repeat_n(target, count).collect();
                self.line.insert(&replacement);
                let after = self.line.cursor();
                self.line.set_cursor(self.line.previous(after));
                Action::Redraw
            }
            CharCommand::Find { forward, till } => {
                let text = self.line.text();
                let mut at = cursor;
                for _ in 0..count {
                    let found = if forward {
                        let from = self.line.next(at);
                        text[from..].find(target).map(|offset| from + offset)
                    } else {
                        text[..at].rfind(target)
                    };
                    match found {
                        Some(position) => at = position,
                        None => return Action::Bell,
                    }
                }
                if till {
                    at = if forward {
                        self.line.previous(at)
                    } else {
                        self.line.next(at)
                    };
                }
                match operator {
                    Some(operator) => {
                        let (start, end) = if forward {
                            (cursor, self.line.next(at))
                        } else {
                            (at, cursor)
                        };
                        self.apply_operator(operator, start, end)
                    }
                    None => self.move_to(at),
                }
            }
        }
    }
}

/// Meta-U, Meta-L, Meta-C.
#[derive(Debug, Clone, Copy)]
enum Case {
    Upper,
    Lower,
    Capital,
}

/// vi's character classes: blank, word (letters, digits, `_`), and other.
fn vi_class(ch: char, big: bool) -> u8 {
    if ch.is_whitespace() {
        0
    } else if big || ch.is_alphanumeric() || ch == '_' {
        1
    } else {
        2
    }
}

/// The first character that is not a blank (`^`).
fn first_non_blank(line: &LineBuffer) -> usize {
    let mut at = 0;
    while at < line.text().len() && line.char_at(at).is_some_and(char::is_whitespace) {
        at = line.next(at);
    }
    at
}

/// vi `w` (`W` with `big`): the start of the next word.
fn vi_word_forward(line: &LineBuffer, mut at: usize, big: bool) -> usize {
    let len = line.text().len();
    if let Some(ch) = line.char_at(at) {
        let class = vi_class(ch, big);
        while at < len
            && line
                .char_at(at)
                .is_some_and(|ch| vi_class(ch, big) == class && class != 0)
        {
            at = line.next(at);
        }
    }
    while at < len && line.char_at(at).is_some_and(char::is_whitespace) {
        at = line.next(at);
    }
    at
}

/// vi `b` (`B` with `big`): the start of this or the previous word.
fn vi_word_backward(line: &LineBuffer, mut at: usize, big: bool) -> usize {
    while at > 0 && line.char_before(at).is_some_and(char::is_whitespace) {
        at = line.previous(at);
    }
    if let Some(ch) = line.char_before(at) {
        let class = vi_class(ch, big);
        while at > 0 && line.char_before(at).is_some_and(|ch| vi_class(ch, big) == class) {
            at = line.previous(at);
        }
    }
    at
}

/// vi `e` (`E` with `big`): the last character of this or the next word.
fn vi_word_end(line: &LineBuffer, at: usize, big: bool) -> usize {
    let len = line.text().len();
    let mut pos = line.next(at);
    while pos < len && line.char_at(pos).is_some_and(char::is_whitespace) {
        pos = line.next(pos);
    }
    let Some(ch) = line.char_at(pos) else {
        return at;
    };
    let class = vi_class(ch, big);
    loop {
        let next = line.next(pos);
        if next >= len || line.char_at(next).is_none_or(|ch| vi_class(ch, big) != class) {
            return pos;
        }
        pos = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interactive::keys::decode_all;

    /// The editor after typing `bytes` in `mode` with `history`, and the last action.
    fn typed(mode: EditMode, bytes: &[u8], history: &[&str]) -> (Editor, Action) {
        let history: Vec<String> = history.iter().map(|line| (*line).to_owned()).collect();
        let mut editor = Editor::new(mode);
        let mut action = Action::Redraw;
        for key in decode_all(bytes) {
            action = editor.key(key, &history);
        }
        (editor, action)
    }

    fn text(mode: EditMode, bytes: &[u8]) -> (String, usize) {
        let (editor, _) = typed(mode, bytes, &[]);
        (editor.view().text.to_owned(), editor.view().cursor)
    }

    // KNSH-107: emacs movement and editing keys behave as readline's.
    #[test]
    fn emacs_keys_edit_like_readline() {
        assert_eq!(text(EditMode::Emacs, b"hello\x01X"), ("Xhello".into(), 1));
        assert_eq!(text(EditMode::Emacs, b"hello\x02\x02\x7f"), ("helo".into(), 2));
        assert_eq!(text(EditMode::Emacs, b"one two\x17"), ("one ".into(), 4));
        assert_eq!(text(EditMode::Emacs, b"one two\x17\x17\x19"), ("one two".into(), 7));
        assert_eq!(text(EditMode::Emacs, b"one two\x01\x0b"), (String::new(), 0));
        assert_eq!(text(EditMode::Emacs, b"one two\x1bb\x1bb\x1bf"), ("one two".into(), 3));
        assert_eq!(text(EditMode::Emacs, b"ab\x14"), ("ba".into(), 2));
        assert_eq!(text(EditMode::Emacs, b"one two\x1bb\x1bu"), ("one TWO".into(), 7));
        assert_eq!(text(EditMode::Emacs, b"abc\x1f"), (String::new(), 0));
        assert_eq!(text(EditMode::Emacs, b"a\x16\x01"), ("a\u{1}".into(), 2));
        assert_eq!(text(EditMode::Emacs, b"x\x1b[D\x1b[3~"), (String::new(), 0));
        let (_, action) = typed(EditMode::Emacs, b"\x04", &[]);
        assert_eq!(action, Action::Eof);
        let (_, action) = typed(EditMode::Emacs, b"ls\r", &[]);
        assert_eq!(action, Action::Accept("ls".into()));
        let (_, action) = typed(EditMode::Emacs, b"ls\x03", &[]);
        assert_eq!(action, Action::Interrupt);
        let (_, action) = typed(EditMode::Emacs, b"ls\t\t", &[]);
        assert_eq!(action, Action::Complete { list: true });
    }

    #[test]
    fn kill_ring_appends_consecutive_kills_and_cycles() {
        assert_eq!(text(EditMode::Emacs, b"a b c\x17\x17\x19"), ("a b c".into(), 5));
        // Two separate kills, then yank and yank-pop.
        assert_eq!(
            text(EditMode::Emacs, b"first\x15second\x15\x19\x1by"),
            ("first".into(), 5)
        );
    }

    #[test]
    fn history_walk_and_last_argument() {
        let history = ["echo one", "ls -l /tmp"];
        let (editor, _) = typed(EditMode::Emacs, b"\x1b[A", &history);
        assert_eq!(editor.view().text, "ls -l /tmp");
        let (editor, _) = typed(EditMode::Emacs, b"new\x10\x10\x0e\x0e", &history);
        assert_eq!(editor.view().text, "new");
        let (editor, _) = typed(EditMode::Emacs, b"cat \x1b.", &history);
        assert_eq!(editor.view().text, "cat /tmp");
        let (editor, _) = typed(EditMode::Emacs, b"cat \x1b.\x1b.", &history);
        assert_eq!(editor.view().text, "cat one");
        let (_, action) = typed(EditMode::Emacs, b"\x1b[A", &[]);
        assert_eq!(action, Action::Bell);
    }

    #[test]
    fn reverse_search_finds_older_lines() {
        let history = ["make test", "ls", "make build", "pwd"];
        let (editor, _) = typed(EditMode::Emacs, b"\x12make", &history);
        assert_eq!(editor.view().text, "make build");
        assert_eq!(
            editor.view().search_prompt.as_deref(),
            Some("(reverse-i-search)`make': ")
        );
        let (editor, _) = typed(EditMode::Emacs, b"\x12make\x12", &history);
        assert_eq!(editor.view().text, "make test");
        let (_, action) = typed(EditMode::Emacs, b"\x12make\x12\r", &history);
        assert_eq!(action, Action::Accept("make test".into()));
        let (editor, _) = typed(EditMode::Emacs, b"x\x12zzz", &history);
        assert_eq!(
            editor.view().search_prompt.as_deref(),
            Some("(failed reverse-i-search)`zzz': ")
        );
        let (editor, _) = typed(EditMode::Emacs, b"x\x12make\x07", &history);
        assert_eq!((editor.view().text, editor.view().search_prompt), ("x", None));
        // Another key ends the search on the line found and acts.
        let (editor, _) = typed(EditMode::Emacs, b"\x12pw\x05!", &history);
        assert_eq!(editor.view().text, "pwd!");
    }

    // KNSH-107: vi mode basics.
    #[test]
    fn vi_mode_basics() {
        assert_eq!(text(EditMode::Vi, b"hello world\x1b0dw"), ("world".into(), 0));
        assert_eq!(text(EditMode::Vi, b"hello world\x1bbD"), ("hello ".into(), 5));
        assert_eq!(text(EditMode::Vi, b"hello world\x1b0cwbye"), ("bye world".into(), 3));
        assert_eq!(text(EditMode::Vi, b"hello\x1b0xx"), ("llo".into(), 0));
        assert_eq!(text(EditMode::Vi, b"hello\x1b02x"), ("llo".into(), 0));
        assert_eq!(text(EditMode::Vi, b"hello\x1b0rj"), ("jello".into(), 0));
        assert_eq!(text(EditMode::Vi, b"abc\x1b0~~"), ("ABc".into(), 2));
        assert_eq!(text(EditMode::Vi, b"a b c\x1b0wwiX"), ("a b Xc".into(), 5));
        assert_eq!(text(EditMode::Vi, b"a-b c\x1b0e"), ("a-b c".into(), 1));
        assert_eq!(text(EditMode::Vi, b"a b c d\x1b02dw"), ("c d".into(), 0));
        assert_eq!(text(EditMode::Vi, b"a b c d\x1b0d2w"), ("c d".into(), 0));
        assert_eq!(text(EditMode::Vi, b"a-b c\x1b0E"), ("a-b c".into(), 2));
        assert_eq!(text(EditMode::Vi, b"one two\x1bddix"), ("x".into(), 1));
        assert_eq!(text(EditMode::Vi, b"one two\x1b0dwP"), ("one two".into(), 3));
        assert_eq!(text(EditMode::Vi, b"one two\x1b0fwD"), ("one t".into(), 4));
        assert_eq!(text(EditMode::Vi, b"one two\x1b0dtw"), ("wo".into(), 0));
        assert_eq!(text(EditMode::Vi, b"one\x1bAs\x1bu"), ("one".into(), 2));
        assert_eq!(text(EditMode::Vi, b"one\x1bIx"), ("xone".into(), 1));
        let (_, action) = typed(EditMode::Vi, b"ls\x1b\r", &[]);
        assert_eq!(action, Action::Accept("ls".into()));
        let (editor, _) = typed(EditMode::Vi, b"\x1bk", &["old"]);
        assert_eq!((editor.view().text, editor.view().cursor), ("old", 0));
    }

    #[test]
    fn begin_keeps_the_kill_ring_only() {
        let (mut editor, _) = typed(EditMode::Emacs, b"gone\x15", &[]);
        editor.begin(EditMode::Emacs);
        assert_eq!(editor.view().text, "");
        editor.key(Key::Control(b'Y'), &[]);
        assert_eq!(editor.view().text, "gone");
    }
}
