//! The interactive shell's read-edit-run loop (KNSH-107): prompts, the line editor, continuation lines, history
//! expansion and the history list, completion, OSC 133 marks, and the history file at exit.
//!
//! The loop runs over a [`Terminal`]: [`DescriptorTerminal`] is the real one (the shell's terminal through
//! [`knsh_platform::Descriptors`]); tests drive a scripted one. Every command still runs through the interpreter and
//! its spawner. A human session is never decided or blocked (FR-SES-22): nothing here consults the supervisor, and an
//! error (a refused construct, a failed expansion, an unreadable history file) is reported and the loop goes on.

use std::collections::VecDeque;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use knsh_platform::{Descriptors, LocalTime, SharedFd, TerminalSettings};

use super::complete::{columns_listing, common_prefix, quote_match};
use super::editor::{Action, EditMode, Editor};
use super::expansion;
use super::keys::{ESCAPE_TIMEOUT, Key, KeyDecoder};
use super::marks;
use super::prompt::{self, PromptClock, PromptInfo};
use super::render::{IGNORE_END, IGNORE_START, Prompt, Screen};
use crate::eval::interactive::{LineStatus, continues_line, is_incomplete};
use crate::{InterpError, Interpreter, Status};

/// Bash's default `PS1` for an interactive shell.
pub const DEFAULT_PS1: &str = "\\s-\\v\\$ ";

/// Bash's default `PS2`.
pub const DEFAULT_PS2: &str = "> ";

/// Readline's `completion-query-items`: more matches than this are listed only after asking.
const COMPLETION_QUERY_ITEMS: usize = 100;

/// The width assumed when the terminal reports none.
const DEFAULT_COLUMNS: usize = 80;

/// Where the session reads keys and draws.
pub trait Terminal {
    /// Reads at most `buffer.len()` bytes, waiting at most `timeout` (`None`: until input arrives): `Ok(None)` when
    /// the time ran out, `Ok(Some(0))` at end of input.
    ///
    /// # Errors
    ///
    /// The system's error when the input cannot be read.
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<Option<usize>>;

    /// Writes `bytes` (the prompt, the line, marks, messages), ignoring failure as readline does.
    fn write(&mut self, bytes: &[u8]);

    /// The width in columns, read again each time (a resized window is followed).
    fn columns(&self) -> usize;

    /// Sets the terminal up for the line editor: `false` when the input is not a terminal, and lines are then read
    /// as they come.
    fn start_editing(&mut self) -> bool;

    /// Puts the terminal back as it was before [`Terminal::start_editing`].
    fn stop_editing(&mut self);
}

/// The shell's terminal through the platform's descriptors: input from one descriptor (the shell's standard input),
/// prompts and the line drawn on another (its standard error, as bash's readline draws).
pub struct DescriptorTerminal {
    descriptors: Arc<dyn Descriptors>,
    input: SharedFd,
    output: SharedFd,
    saved: Option<TerminalSettings>,
}

impl std::fmt::Debug for DescriptorTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DescriptorTerminal")
            .field("input", &self.input)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}

impl DescriptorTerminal {
    /// A terminal reading `input` and drawing on `output` through `descriptors`.
    #[must_use]
    pub fn new(descriptors: Arc<dyn Descriptors>, input: SharedFd, output: SharedFd) -> Self {
        Self {
            descriptors,
            input,
            output,
            saved: None,
        }
    }
}

impl Terminal for DescriptorTerminal {
    fn read(&mut self, buffer: &mut [u8], timeout: Option<Duration>) -> io::Result<Option<usize>> {
        if let Some(timeout) = timeout
            && !self
                .descriptors
                .wait_readable(&self.input, timeout)
                .map_err(|error| io::Error::other(error.to_string()))?
        {
            return Ok(None);
        }
        self.descriptors
            .read(&self.input, buffer)
            .map(Some)
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn write(&mut self, bytes: &[u8]) {
        let _ = self.descriptors.write_all(&self.output, bytes);
    }

    fn columns(&self) -> usize {
        self.descriptors
            .terminal_columns(&self.output)
            .or_else(|| self.descriptors.terminal_columns(&self.input))
            .map_or(DEFAULT_COLUMNS, usize::from)
    }

    fn start_editing(&mut self) -> bool {
        match self.descriptors.set_editor_input(&self.input) {
            Ok(Some(saved)) => {
                self.saved = Some(saved);
                true
            }
            Ok(None) | Err(_) => false,
        }
    }

    fn stop_editing(&mut self) {
        if let Some(saved) = self.saved.take() {
            let _ = self.descriptors.restore_terminal(&self.input, &saved);
        }
    }
}

/// What the prompt escapes need from the host, read once at start-up as bash reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostInfo {
    /// The host's name (`\h`, `\H`, and OSC 7).
    pub host: String,
    /// The user's login name (`\u`).
    pub user: String,
    /// The terminal's base name (`\l`).
    pub terminal: String,
    /// The shell runs as the superuser (`\$`).
    pub superuser: bool,
}

/// What the session was asked to do at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionOptions {
    /// Write OSC 133 and OSC 7 marks (the terminal is the shell's standard output, NFR-COMPAT-10).
    pub marks: bool,
    /// The file a login shell sources as it exits (`~/.bash_logout`).
    pub logout_file: Option<PathBuf>,
}

/// One line read from the terminal.
enum Read {
    /// A line (without its newline).
    Line(String),
    /// End of input on an empty line.
    Eof,
    /// Ctrl-C.
    Interrupt,
}

/// A command read, over one or more lines.
enum Command {
    /// Run this text (each line ending in a newline); `entry` is what the history keeps.
    Run { text: String, entry: String },
    /// Nothing to run (a failed history expansion, `:p`, end of input inside a command).
    Skip,
    /// End of input at the prompt.
    Eof,
    /// Ctrl-C.
    Interrupt,
}

/// The time escapes' clock: the host's `strftime` in the shell's `LC_TIME` locale.
struct ShellClock<'a> {
    time: Option<&'a dyn LocalTime>,
    locale: String,
}

impl PromptClock for ShellClock<'_> {
    fn format(&self, format: &str) -> String {
        let Some(time) = self.time else {
            return String::new();
        };
        let Ok(now) = time.now() else {
            return String::new();
        };
        time.format(format, now, &self.locale)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }
}

/// The interactive shell: an interpreter, a terminal and the editor's state between lines.
pub struct Session<T: Terminal> {
    shell: Interpreter,
    terminal: T,
    host: HostInfo,
    time: Option<Arc<dyn LocalTime>>,
    options: SessionOptions,
    editor: Editor,
    decoder: KeyDecoder,
    keys: VecDeque<Key>,
    screen: Screen,
    /// Bash's `\#`: the number of the next command.
    command_number: usize,
    /// A line ran since the last prompt (its `D` mark is due).
    ran: bool,
}

impl<T: Terminal> std::fmt::Debug for Session<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("host", &self.host)
            .field("command_number", &self.command_number)
            .finish_non_exhaustive()
    }
}

impl<T: Terminal> Session<T> {
    /// A session running `shell` (made interactive with
    /// [`Interpreter::with_job_control`](crate::Interpreter::with_job_control)) on `terminal`. As bash's
    /// interactive start-up: emacs editing, the history list and history expansion on; `PS1`, `PS2` and
    /// `HISTFILE` (`~/.bash_history`) set when unset. Start-up files are sourced by the host after this, then
    /// [`Session::load_history`].
    pub fn new(mut shell: Interpreter, terminal: T, host: HostInfo, options: SessionOptions) -> Self {
        {
            let state = shell.state_mut();
            let opts = state.options_mut();
            opts.emacs = true;
            opts.vi = false;
            opts.history = true;
            opts.histexpand = true;
            if state.variable("PS1").is_none() {
                state.set_variable("PS1", DEFAULT_PS1);
            }
            if state.variable("PS2").is_none() {
                state.set_variable("PS2", DEFAULT_PS2);
            }
            if state.variable("HISTFILE").is_none()
                && let Some(home) = state.variable("HOME").map(|home| home.to_string_lossy().into_owned())
            {
                state.set_variable("HISTFILE", format!("{}/.bash_history", home.trim_end_matches('/')));
            }
        }
        Self {
            shell,
            terminal,
            host,
            time: None,
            options,
            editor: Editor::new(EditMode::Emacs),
            decoder: KeyDecoder::new(),
            keys: VecDeque::new(),
            screen: Screen::new(),
            command_number: 1,
            ran: false,
        }
    }

    /// The same session reading the time escapes' clock from `time`.
    #[must_use]
    pub fn with_local_time(mut self, time: Arc<dyn LocalTime>) -> Self {
        self.time = Some(time);
        self
    }

    /// The interpreter, to source start-up files before the first prompt.
    pub fn shell_mut(&mut self) -> &mut Interpreter {
        &mut self.shell
    }

    /// The interpreter.
    #[must_use]
    pub fn shell(&self) -> &Interpreter {
        &self.shell
    }

    /// As bash's `load_history`, after the start-up files: `HISTSIZE` and `HISTFILESIZE` default to 500, then the
    /// lines of `HISTFILE` are read. An unreadable file is reported; the shell starts anyway.
    pub fn load_history(&mut self) {
        let state = self.shell.state_mut();
        if state.variable("HISTSIZE").is_none() {
            state.set_variable("HISTSIZE", super::history::DEFAULT_HISTORY_SIZE.to_string());
        }
        if state.variable("HISTFILESIZE").is_none() {
            let size = state
                .variable("HISTSIZE")
                .map_or_else(String::new, |size| size.to_string_lossy().into_owned());
            state.set_variable("HISTFILESIZE", size);
        }
        if let Some(path) = self.history_file()
            && let Err(reason) = self.shell.read_history_file(&path)
        {
            self.message(&format!("{}: {reason}", path.display()));
        }
    }

    /// `HISTFILE` as an absolute path, when set and not empty.
    fn history_file(&self) -> Option<PathBuf> {
        let state = self.shell.state();
        let file = state.variable("HISTFILE")?.to_string_lossy().into_owned();
        (!file.is_empty()).then(|| state.cwd().join(file))
    }

    /// Writes one of the shell's messages (`knsh: …`) on the terminal.
    fn message(&mut self, text: &str) {
        let line = format!("{}: {text}\n", self.shell.state().name());
        self.terminal.write(line.as_bytes());
    }

    /// Runs the shell until `exit` or end of input, then saves the history, sources the logout file and runs the
    /// `EXIT` trap: the shell's exit status.
    ///
    /// # Errors
    ///
    /// As [`Interpreter::finish`]. Errors of single lines are reported and the loop goes on.
    pub fn run(&mut self) -> Result<Status, InterpError> {
        while !self.shell.has_exited() {
            let _ = self.shell.notify_jobs();
            self.prompt_command();
            if self.shell.has_exited() {
                break;
            }
            match self.read_command() {
                Command::Eof => {
                    // Bash says `exit` when the input ends at the prompt.
                    self.terminal.write(b"exit\n");
                    break;
                }
                Command::Interrupt => {
                    self.shell.state_mut().set_last_status(Status::new(130));
                }
                Command::Skip => {}
                Command::Run { text, entry } => self.execute(&text, &entry),
            }
        }
        self.save_history();
        if let Some(file) = self.options.logout_file.clone()
            && let Err(error) = self.shell.source_startup_file(&file)
        {
            self.message(&error.to_string());
        }
        let status = self.shell.finish()?;
        if self.options.marks && self.ran {
            self.terminal
                .write(marks::command_end(i32::from(status.code())).as_bytes());
        }
        Ok(status)
    }

    /// Writes the history file at exit, as bash: appended to with `histappend`, replaced otherwise, then cut to
    /// `HISTFILESIZE` lines.
    fn save_history(&mut self) {
        if !self.shell.state().options().history {
            return;
        }
        let Some(path) = self.history_file() else { return };
        let append = self.shell.state().options().histappend;
        if let Err(reason) = self.shell.write_history_file(&path, append) {
            self.message(&format!("{}: {reason}", path.display()));
        }
    }

    /// Runs `PROMPT_COMMAND` (a string, or each element of an array, bash 5.1) before the prompt.
    fn prompt_command(&mut self) {
        let commands = self.shell.prompt_commands();
        for command in commands {
            if command.trim().is_empty() {
                continue;
            }
            let status = self.shell.state().last_status();
            let text = format!("{command}\n");
            if let Err(error) = self.shell.run_line(&text) {
                self.message(&error.to_string());
            }
            // Bash keeps `$?` of the last command line across `PROMPT_COMMAND`.
            self.shell.state_mut().set_last_status(status);
            if self.shell.has_exited() {
                return;
            }
        }
    }

    /// Runs `text` as the next command, after saving `entry` to the history.
    fn execute(&mut self, text: &str, entry: &str) {
        if self.shell.state().options().history {
            self.shell.add_history(entry);
        }
        self.command_number += 1;
        if self.options.marks {
            self.terminal.write(marks::OUTPUT_START.as_bytes());
        }
        match self.shell.run_line(text) {
            Ok(LineStatus::Ran(_) | LineStatus::Incomplete) => {}
            Err(error) => {
                self.message(&error.to_string());
                self.shell.state_mut().set_last_status(Status::new(2));
            }
        }
        self.ran = true;
    }

    /// What the prompt escapes show now.
    fn prompt_info(&self) -> PromptInfo {
        let state = self.shell.state();
        let text = |name: &str| state.variable(name).map(|value| value.to_string_lossy().into_owned());
        let cwd = text("PWD")
            .filter(|pwd| pwd.starts_with('/'))
            .unwrap_or_else(|| state.cwd().to_string_lossy().into_owned());
        PromptInfo {
            host: self.host.host.clone(),
            user: self.host.user.clone(),
            terminal: self.host.terminal.clone(),
            shell: state.name().to_owned(),
            cwd,
            home: text("HOME"),
            dirtrim: text("PROMPT_DIRTRIM").and_then(|value| value.trim().parse().ok()),
            jobs: self.shell.job_count(),
            history_number: state.history().next_number(),
            command_number: self.command_number,
            superuser: self.host.superuser,
        }
    }

    /// Prompt string variable `name` (`PS1`, `PS2`) decoded and expanded.
    fn prompt_text(&mut self, name: &str) -> String {
        let raw = self
            .shell
            .state()
            .variable(name)
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let info = self.prompt_info();
        let locale = ["LC_ALL", "LC_TIME", "LANG"]
            .iter()
            .find_map(|name| {
                self.shell
                    .state()
                    .variable(name)
                    .map(|value| value.to_string_lossy().into_owned())
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_default();
        let clock = ShellClock {
            time: self.time.as_deref(),
            locale,
        };
        let decoded = prompt::decode(&raw, &info, &clock, true);
        self.shell.expand_prompt(&decoded)
    }

    /// The primary prompt, after the marks that come before it.
    fn primary_prompt(&mut self) -> Prompt {
        let text = self.prompt_text("PS1");
        if self.options.marks {
            let mut before = String::new();
            if self.ran {
                before.push_str(&marks::command_end(i32::from(self.shell.state().last_status().code())));
                self.ran = false;
            }
            before.push_str(&crate::osc7(
                self.host.host.as_bytes(),
                self.shell.state().cwd().as_os_str().as_bytes(),
            ));
            before.push_str(marks::PROMPT_START);
            self.terminal.write(before.as_bytes());
        }
        self.prompt_with_mark(&text)
    }

    /// `text` as a prompt, with OSC 133 `B` at its end when marks are wanted (written once, taking no column).
    fn prompt_with_mark(&self, text: &str) -> Prompt {
        if self.options.marks {
            Prompt::new(text).with_mark(&format!("{IGNORE_START}{}{IGNORE_END}", marks::COMMAND_START))
        } else {
            Prompt::new(text)
        }
    }

    /// Reads one command: lines until it parses (continuation lines with `PS2`), each history-expanded.
    fn read_command(&mut self) -> Command {
        let mut text = String::new();
        let mut entry = String::new();
        let mut verbatim_join = false;
        let mut first = true;
        loop {
            let prompt = if first {
                self.primary_prompt()
            } else {
                let text = self.prompt_text("PS2");
                Prompt::new(&text)
            };
            let line = match self.read_line(&prompt) {
                Read::Line(line) => line,
                Read::Eof if first => return Command::Eof,
                Read::Eof => {
                    self.message("syntax error: unexpected end of file");
                    self.shell.state_mut().set_last_status(Status::new(2));
                    return Command::Skip;
                }
                Read::Interrupt => return Command::Interrupt,
            };
            let line = if self.shell.state().options().histexpand {
                let extglob = self.shell.state().options().extglob;
                match expansion::expand(&line, self.shell.state().history(), extglob) {
                    Ok(Some(expanded)) => {
                        // Bash shows the line it will run.
                        self.terminal.write(format!("{}\n", expanded.line).as_bytes());
                        if expanded.print_only {
                            if self.shell.state().options().history {
                                self.shell.add_history(&expanded.line);
                            }
                            return Command::Skip;
                        }
                        expanded.line
                    }
                    Ok(None) => line,
                    Err(error) => {
                        self.message(&error.to_string());
                        return Command::Skip;
                    }
                }
            } else {
                line
            };
            entry = if first {
                line.clone()
            } else {
                join_history(&entry, &line, verbatim_join || self.shell.state().options().lithist)
            };
            text.push_str(&line);
            text.push('\n');
            first = false;
            if continues_line(&text) {
                verbatim_join = false;
                continue;
            }
            match self.shell.parse_error(&text) {
                Some(error) if is_incomplete(&error, &text) => {
                    // Inside a quote or a here-document the newline is part of the text: kept in the history.
                    verbatim_join = matches!(
                        error,
                        knsh_bash::ParseError::Lex(knsh_bash::LexError::Unterminated { .. })
                            | knsh_bash::ParseError::MissingHereDocumentBody { .. }
                    );
                }
                _ => return Command::Run { text, entry },
            }
        }
    }

    /// The next key, reading the terminal as needed: `None` at end of input.
    fn next_key(&mut self) -> Option<Key> {
        loop {
            if let Some(key) = self.keys.pop_front() {
                return Some(key);
            }
            let timeout = self.decoder.is_pending().then_some(ESCAPE_TIMEOUT);
            let mut buffer = [0_u8; 256];
            match self.terminal.read(&mut buffer, timeout) {
                Ok(None) => self.keys.extend(self.decoder.timeout()),
                Ok(Some(0)) | Err(_) => {
                    if let Some(key) = self.decoder.timeout() {
                        return Some(key);
                    }
                    return None;
                }
                Ok(Some(count)) => {
                    for &byte in &buffer[..count] {
                        if let Some(key) = self.decoder.feed(byte) {
                            self.keys.push_back(key);
                        }
                    }
                }
            }
        }
    }

    /// Reads one line with `prompt`: with the line editor when editing is on and the input is a terminal, as typed
    /// otherwise.
    fn read_line(&mut self, prompt: &Prompt) -> Read {
        let options = self.shell.state().options();
        let mode = if options.vi {
            Some(EditMode::Vi)
        } else if options.emacs {
            Some(EditMode::Emacs)
        } else {
            None
        };
        match mode {
            Some(mode) if self.terminal.start_editing() => {
                let read = self.edit_line(prompt, mode);
                self.terminal.stop_editing();
                read
            }
            _ => self.plain_line(prompt),
        }
    }

    /// Reads a line as the terminal delivers it (no line editing).
    fn plain_line(&mut self, prompt: &Prompt) -> Read {
        self.terminal.write(prompt.full().as_bytes());
        let mut line = Vec::new();
        let mut buffer = [0_u8; 1];
        loop {
            match self.terminal.read(&mut buffer, None) {
                Ok(Some(1)) if buffer[0] == b'\n' => break,
                Ok(Some(1)) => {
                    if line.len() < super::line::MAX_LINE_LEN {
                        line.push(buffer[0]);
                    }
                }
                Ok(_) | Err(_) if line.is_empty() => return Read::Eof,
                Ok(_) | Err(_) => break,
            }
        }
        Read::Line(String::from_utf8_lossy(&line).into_owned())
    }

    /// Draws the line again (`first`: the whole prompt first).
    fn redraw(&mut self, prompt: &Prompt, first: bool) {
        let columns = self.terminal.columns();
        let view = self.editor.view();
        let search;
        let shown = match &view.search_prompt {
            Some(text) => {
                search = Prompt::new(text);
                &search
            }
            None => prompt,
        };
        let out = self.screen.draw(shown, view.text, view.cursor, columns, first);
        self.terminal.write(out.as_bytes());
    }

    /// Moves below the line, so what follows starts on a row of its own.
    fn leave_line(&mut self, prompt: &Prompt) {
        let columns = self.terminal.columns();
        let view = self.editor.view();
        let out = self.screen.finish(prompt, view.text, columns);
        self.terminal.write(out.as_bytes());
    }

    /// Reads a line with the editor in `mode`.
    fn edit_line(&mut self, prompt: &Prompt, mode: EditMode) -> Read {
        self.editor.begin(mode);
        self.screen = Screen::new();
        self.redraw(prompt, true);
        loop {
            let Some(key) = self.next_key() else {
                self.leave_line(prompt);
                return Read::Eof;
            };
            let action = self.editor.key(key, self.shell.state().history().entries());
            match action {
                Action::Redraw => self.redraw(prompt, false),
                Action::Bell => {
                    self.redraw(prompt, false);
                    self.terminal.write(b"\x07");
                }
                Action::Accept(text) => {
                    self.redraw(prompt, false);
                    self.leave_line(prompt);
                    return Read::Line(text);
                }
                Action::Eof => return Read::Eof,
                Action::Interrupt => {
                    self.terminal.write(b"^C");
                    self.leave_line(prompt);
                    return Read::Interrupt;
                }
                Action::ClearScreen => {
                    self.terminal.write(b"\x1b[H\x1b[2J");
                    self.screen = Screen::new();
                    self.redraw(prompt, true);
                }
                Action::Complete { list } => self.complete(prompt, list),
            }
        }
    }

    /// Tab: completes the word before the cursor, or lists the possibilities.
    fn complete(&mut self, prompt: &Prompt, list: bool) {
        let (text, cursor) = {
            let line = self.editor.line();
            (line.text().to_owned(), line.cursor())
        };
        let completion = self.shell.complete(&text, cursor);
        if let Some(message) = &completion.message {
            self.leave_line(prompt);
            self.message(message);
            self.screen = Screen::new();
            self.redraw(prompt, true);
            return;
        }
        let quote = |entry: &str| {
            if completion.filenames {
                quote_match(entry, completion.quote)
            } else {
                entry.to_owned()
            }
        };
        match completion.matches.as_slice() {
            [] => self.terminal.write(b"\x07"),
            [only] => {
                let mut insert = quote(only);
                let directory = completion.filenames && only.ends_with('/');
                if !directory {
                    if let Some(open) = completion.quote {
                        insert.push(open);
                    }
                    if !completion.nospace {
                        insert.push(' ');
                    }
                }
                if self.editor.replace_before_cursor(completion.start, &insert) {
                    self.redraw(prompt, false);
                } else {
                    self.terminal.write(b"\x07");
                }
            }
            matches => {
                let prefix = common_prefix(matches);
                if prefix.len() > completion.word.len() {
                    if self.editor.replace_before_cursor(completion.start, &quote(&prefix)) {
                        self.redraw(prompt, false);
                    }
                } else if list {
                    self.list_matches(prompt, matches, completion.filenames);
                } else {
                    self.terminal.write(b"\x07");
                }
            }
        }
    }

    /// Lists `matches` below the line (their last component for file names), asking first when there are many,
    /// then draws the prompt and line again.
    fn list_matches(&mut self, prompt: &Prompt, matches: &[String], filenames: bool) {
        self.leave_line(prompt);
        if matches.len() > COMPLETION_QUERY_ITEMS {
            self.terminal
                .write(format!("Display all {} possibilities? (y or n)", matches.len()).as_bytes());
            let answer = loop {
                match self.next_key() {
                    Some(Key::Char('y' | 'Y' | ' ')) => break true,
                    Some(Key::Char('n' | 'N') | Key::Control(_) | Key::Escape | Key::Backspace) | None => break false,
                    Some(_) => self.terminal.write(b"\x07"),
                }
            };
            self.terminal.write(b"\r\n");
            if !answer {
                self.screen = Screen::new();
                self.redraw(prompt, true);
                return;
            }
        }
        let shown: Vec<String> = matches
            .iter()
            .map(|entry| {
                if filenames {
                    let trimmed = entry.strip_suffix('/').unwrap_or(entry);
                    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
                    if entry.ends_with('/') {
                        format!("{last}/")
                    } else {
                        last.to_owned()
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();
        let listing = columns_listing(&shown, self.terminal.columns());
        self.terminal.write(listing.as_bytes());
        self.screen = Screen::new();
        self.redraw(prompt, true);
    }
}

/// The history entry for a command read over several lines, as bash's `cmdhist`: the lines joined with `; `, or a
/// blank after a word that a command may follow directly (`then`, `do`, `{`, `|`, …); with `verbatim` (inside a
/// quote or a here-document, or `lithist`) with the newline.
fn join_history(entry: &str, line: &str, verbatim: bool) -> String {
    if verbatim {
        return format!("{entry}\n{line}");
    }
    let trimmed = entry.trim_end();
    let last = trimmed.rsplit(char::is_whitespace).next().unwrap_or("");
    let blank_only = trimmed.is_empty()
        || trimmed.ends_with([';', '&', '|', '(', '{'])
        || matches!(
            last,
            "do" | "then" | "else" | "elif" | "in" | "if" | "while" | "until" | "!"
        );
    if blank_only {
        format!("{trimmed} {line}")
    } else {
        format!("{trimmed}; {line}")
    }
}

#[cfg(test)]
mod tests;
