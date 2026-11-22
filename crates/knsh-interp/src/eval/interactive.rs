//! The interpreter's side of the interactive shell (KNSH-107; NFR-COMPAT-02): running a line typed at the prompt
//! (or saying it needs more lines), expanding a decoded prompt string, generating completions, and the `history`,
//! `complete` and `compgen` builtins.
//!
//! The line editor, the history list's rules and the completion model are pure code in
//! [`crate::interactive`]; what needs the shell (its variables, functions, aliases, the filesystem, running a
//! completion function) is here.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use knsh_bash::{Command, ParseError, Span};

use super::{EVAL_STACK_SIZE, Interpreter, Run, Stop};
use crate::error::InterpError;
use crate::interactive::complete::{
    self, CompAction, CompSpec, SpecError, SpecRequest, parse_spec, print_spec, word_at,
};
use crate::interactive::expansion;
use crate::interactive::history::{self, HistControl, MAX_HISTORY_FILE};
use crate::quote;
use crate::status::Status;
use crate::vars::Value;

/// Entries of one directory read at most while completing a file name or a command.
const MAX_COMPLETION_ENTRIES: usize = 65_536;

/// Matches one completion keeps at most.
const MAX_MATCHES: usize = 65_536;

/// Bash 5.2's builtins, as `compgen -b` lists them.
const BASH_BUILTINS: &[&str] = &[
    ".",
    ":",
    "[",
    "alias",
    "bg",
    "bind",
    "break",
    "builtin",
    "caller",
    "cd",
    "command",
    "compgen",
    "complete",
    "compopt",
    "continue",
    "declare",
    "dirs",
    "disown",
    "echo",
    "enable",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "fc",
    "fg",
    "getopts",
    "hash",
    "help",
    "history",
    "jobs",
    "kill",
    "let",
    "local",
    "logout",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "return",
    "set",
    "shift",
    "shopt",
    "source",
    "suspend",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
];

/// Bash 5.2's usage line for `complete`.
const COMPLETE_USAGE: &str = "complete: usage: complete [-abcdefgjksuv] [-pr] [-DEI] [-o option] [-A action] [-G globpat] \
                              [-W wordlist] [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [name ...]";

/// Bash 5.2's usage line for `compgen`.
const COMPGEN_USAGE: &str = "compgen: usage: compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist] \
                             [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [word]";

/// Bash 5.2's usage line for `history`.
const HISTORY_USAGE: &str =
    "history: usage: history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]";

/// What became of a line typed at the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStatus {
    /// It ran (or was a syntax error, reported, status 2) with this status.
    Ran(Status),
    /// It is not finished (an open quote, `if` without `fi`, a trailing `|`): the shell reads another line with
    /// `PS2` and tries again with both.
    Incomplete,
}

/// The completions of the word before the cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Completion {
    /// Byte offset where the word starts (after an open quote).
    pub start: usize,
    /// The word with its quoting removed.
    pub word: String,
    /// The quote left open before the word, if any.
    pub quote: Option<char>,
    /// The matches, each replacing the whole word; a directory ends with `/` when `filenames`.
    pub matches: Vec<String>,
    /// The matches are file names: quoted when inserted, listed by their last component.
    pub filenames: bool,
    /// No space after a single match (`-o nospace`).
    pub nospace: bool,
    /// A completion function failed or a form is not supported: the message to show.
    pub message: Option<String>,
}

/// Whether `error`, found parsing `text`, means the input ended too soon: an open quote or substitution, a compound
/// command not closed, a here-document whose body has not ended, or an operator that needs a command after it at the
/// end. The interactive shell then reads more lines, as bash does.
#[must_use]
pub fn is_incomplete(error: &ParseError, text: &str) -> bool {
    match error {
        ParseError::Lex(knsh_bash::LexError::Unterminated { .. })
        | ParseError::Unclosed { .. }
        | ParseError::MissingHereDocumentBody { .. } => true,
        ParseError::MissingCommand { span } => text.get(span.end..).is_some_and(|rest| rest.trim().is_empty()),
        _ => false,
    }
}

/// Whether `text` ends with a backslash that continues the line (an odd number of backslashes before the final
/// newline, outside single quotes): bash reads another line.
#[must_use]
pub fn continues_line(text: &str) -> bool {
    let Some(body) = text.strip_suffix('\n') else {
        return false;
    };
    let backslashes = body.bytes().rev().take_while(|byte| *byte == b'\\').count();
    if backslashes % 2 == 0 {
        return false;
    }
    // Inside single quotes a backslash is literal; count quotes outside double quotes and escapes.
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for byte in body.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if !single => escaped = true,
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            _ => {}
        }
    }
    !single
}

impl Interpreter {
    /// Whether the shell ended by `exit`, `set -e`, a signal or `exec`: an interactive host stops reading lines
    /// and calls [`Interpreter::finish`] (KNSH-107).
    #[must_use]
    pub fn has_exited(&self) -> bool {
        self.exited
    }

    /// The number of jobs the shell knows (bash's `\j`).
    #[must_use]
    pub fn job_count(&self) -> usize {
        self.jobs.numbers().len()
    }

    /// Runs `text`, one or more lines typed at the prompt (each ending in a newline), as bash runs what it reads
    /// interactively: [`LineStatus::Incomplete`] when more lines are needed, otherwise the status. A syntax error is
    /// reported as an interactive bash reports it (``knsh: syntax error near unexpected token `)'``), status 2.
    ///
    /// # Errors
    ///
    /// As [`Interpreter::run`]: a construct the interpreter refuses ([`InterpError::Unsupported`]) is returned for
    /// the host to report; nothing of the line ran.
    pub fn run_line(&mut self, text: &str) -> Result<LineStatus, InterpError> {
        if continues_line(text) {
            return Ok(LineStatus::Incomplete);
        }
        match knsh_bash::parse_with(text, self.parse_options()) {
            Ok(script) => self.run(&script, text).map(LineStatus::Ran),
            Err(error) if is_incomplete(&error, text) => Ok(LineStatus::Incomplete),
            Err(error) => {
                let message = super::nested::describe(&error, text)
                    .map_or_else(|| format!("syntax error: {error}"), |syntax| syntax.message);
                let line = format!("{}: {message}\n", self.state.name());
                self.write_shell(2, line.as_bytes());
                self.state.set_last_status(Status::new(2));
                Ok(LineStatus::Ran(Status::new(2)))
            }
        }
    }

    /// The parse error of `text` as the shell reads it now (its `extglob` and other parse options), if any: the
    /// session asks whether a command needs more lines.
    pub(crate) fn parse_error(&self, text: &str) -> Option<ParseError> {
        knsh_bash::parse_with(text, self.parse_options()).err()
    }

    /// The commands `PROMPT_COMMAND` holds: its value, or each element of it as an array (bash 5.1).
    pub(crate) fn prompt_commands(&self) -> Vec<String> {
        match self.state.value("PROMPT_COMMAND") {
            Ok(Some(value)) => match &*value {
                Value::Scalar(text) => vec![text.to_string_lossy().into_owned()],
                Value::Indexed(elements) => elements.values().map(|v| v.to_string_lossy().into_owned()).collect(),
                Value::Assoc(_) => Vec::new(),
            },
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    /// Sources `path` as bash sources a start-up file (`.bashrc`, `/etc/profile`): `$?` is its status. An error is
    /// reported and the shell goes on (a human session is never blocked, FR-SES-22).
    ///
    /// # Errors
    ///
    /// As [`Interpreter::run`].
    pub fn source_startup_file(&mut self, path: &Path) -> Result<Status, InterpError> {
        let text = format!(". {}\n", quote::single(&path.to_string_lossy()));
        let script = knsh_bash::parse_with(&text, self.parse_options()).map_err(|_| InterpError::Unsupported {
            feature: crate::error::Unsupported::Unparsed,
            span: Span::new(0, text.len()),
        })?;
        self.run(&script, &text)
    }

    /// `decoded` (a prompt string after [`crate::interactive::decode_prompt`]) with parameter, command and
    /// arithmetic substitution done as in a here-document, bash's `promptvars` expansion. On an expansion error the
    /// error is reported and `decoded` is returned unexpanded, so a prompt is always shown.
    pub fn expand_prompt(&mut self, decoded: &str) -> String {
        if !decoded.contains(['$', '`', '\\']) {
            return decoded.to_owned();
        }
        let status = self.state.last_status();
        let result = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("knsh-prompt".to_owned())
                .stack_size(EVAL_STACK_SIZE)
                .spawn_scoped(scope, || self.expand_text(decoded))
                .ok()
                .and_then(|worker| worker.join().ok())
        });
        // Expanding the prompt never changes `$?` (a command substitution in it sets it only inside).
        self.state.set_last_status(status);
        match result {
            Some(Ok(text)) => text,
            Some(Err(message)) => {
                if !message.is_empty() {
                    let line = format!("{}: {message}\n", self.state.name());
                    self.write_shell(2, line.as_bytes());
                }
                decoded.to_owned()
            }
            None => decoded.to_owned(),
        }
    }

    /// `text` expanded as the body of an unquoted here-document: the message on failure (empty when it was
    /// already reported).
    fn expand_text(&mut self, text: &str) -> Result<String, String> {
        let delimiter = (0..=u32::MAX)
            .map(|n| format!("KNSH_TEXT_{n}"))
            .find(|delimiter| !text.contains(delimiter.as_str()))
            .unwrap_or_default();
        // A backslash ending the text would join the delimiter's line to it (a here-document's line continuation)
        // and leave the document open: doubled, it stays one literal backslash, as bash's prompt shows it.
        let trailing = text.bytes().rev().take_while(|byte| *byte == b'\\').count();
        let tail = if trailing % 2 == 1 { "\\" } else { "" };
        let source = format!(":<<{delimiter}\n{text}{tail}\n{delimiter}\n");
        let script = knsh_bash::parse_with(&source, self.parse_options()).map_err(|error| error.to_string())?;
        let budget = self.max_depth.saturating_sub(self.depth);
        self.check_nested(&script.items, &source, budget)
            .map_err(|error| error.to_string())?;
        let Some((redirect_span, document)) = script.commands().find_map(|command| match command {
            Command::Simple(simple) => simple.redirections.iter().find_map(|redirect| {
                redirect
                    .here_document
                    .as_ref()
                    .map(|document| (redirect.span, document))
            }),
            Command::Compound(_) | Command::FunctionDefinition(_) | Command::Unsupported(_) => None,
        }) else {
            return Err(String::new());
        };
        let body = crate::word::here_document_parts(document, &source).map_err(|error| error.to_string())?;
        let run = Run::new(&source);
        let result = self.expander(&run, &[]).here_document(&body, redirect_span);
        let expanded = self.expanded(result, redirect_span, &run).map_err(|stop| match stop {
            Stop::Error(error) => error.to_string(),
            Stop::Discard | Stop::Exit(_) | Stop::Break { .. } | Stop::Continue { .. } | Stop::Return(_) => {
                String::new()
            }
        })?;
        self.close_substituted(0);
        Ok(expanded.strip_suffix('\n').unwrap_or(&expanded).to_owned())
    }

    // ---- Completion ----

    /// The completions of the word before byte `cursor` of `line`, as bash's programmable completion finds them:
    /// a variable name after `$`; command names in command position (or the `complete -I` specification); the
    /// specification `complete` gave the command (or `complete -D`'s), with its fallbacks; file names otherwise.
    pub fn complete(&mut self, line: &str, cursor: usize) -> Completion {
        // A cursor past the end or inside a character (a caller's mistake) is moved back onto a boundary rather than
        // panicking on the slices below.
        let mut cursor = cursor.min(line.len());
        while !line.is_char_boundary(cursor) {
            cursor -= 1;
        }
        let word = word_at(line, cursor);
        let mut completion = Completion {
            start: word.start,
            word: word.text.clone(),
            quote: word.quote,
            ..Completion::default()
        };
        // The text before the word, without the quote that opens it. A quote inside a word (`a"b`) does not start
        // it, so only a quote right before the word's start is dropped.
        let opened = word.quote.is_some_and(|quote| line[..word.start].ends_with(quote));
        let before = &line[..word.start - usize::from(opened)];
        let (command_position, command, words) = command_context(before);
        let text = word.text.as_str();
        if word.quote.is_none() && text.starts_with('$') && !text.starts_with("$(") {
            let braced = text.starts_with("${");
            let prefix = text.trim_start_matches("${").trim_start_matches('$');
            let mut names: Vec<String> = self
                .state
                .variable_names()
                .into_iter()
                .filter(|name| name.starts_with(prefix))
                .map(|name| {
                    if braced {
                        format!("${{{name}}}")
                    } else {
                        format!("${name}")
                    }
                })
                .collect();
            names.sort();
            completion.matches = names;
            return completion;
        }
        let spec = if command_position {
            if line[..word.start].trim().is_empty() && text.is_empty() {
                self.state.completions().empty.clone()
            } else {
                self.state.completions().initial.clone()
            }
        } else {
            let table = self.state.completions();
            command.as_deref().and_then(|name| {
                table
                    .by_command
                    .get(name)
                    .or_else(|| table.by_command.get(name.rsplit('/').next().unwrap_or(name)))
                    .or(table.default.as_ref())
                    .cloned()
            })
        };
        if let Some(spec) = spec {
            let cword = words.len();
            match self.generate(&spec, text, Some((line, cursor, &words, cword, command.as_deref()))) {
                Ok(matches) => completion.matches = matches,
                Err(message) => completion.message = Some(message),
            }
            completion.filenames = spec.options.filenames
                || spec
                    .actions
                    .iter()
                    .any(|action| matches!(action, CompAction::File | CompAction::Directory));
            completion.nospace = spec.options.nospace;
            if spec.options.plusdirs {
                completion
                    .matches
                    .extend(self.file_matches(text, FileKind::Directories));
            }
            if completion.matches.is_empty() {
                if spec.options.dirnames {
                    completion.matches = self.file_matches(text, FileKind::Directories);
                    completion.filenames = true;
                } else if spec.options.default || spec.options.bashdefault {
                    completion.matches = self.file_matches(text, FileKind::All);
                    completion.filenames = true;
                }
            }
        } else if command_position {
            if text.contains('/') {
                completion.matches = self.file_matches(text, FileKind::Commands);
                completion.filenames = true;
            } else {
                completion.matches = self.command_names(text);
            }
        } else {
            completion.matches = self.file_matches(text, FileKind::All);
            completion.filenames = true;
        }
        if completion.filenames {
            for entry in &mut completion.matches {
                if !entry.ends_with('/') && self.is_directory_name(entry) {
                    entry.push('/');
                }
            }
        }
        completion.matches.dedup();
        completion
    }

    /// Whether `name` (as typed, `~/` allowed) names a directory.
    fn is_directory_name(&self, name: &str) -> bool {
        let path = self.completion_path(name);
        self.fs
            .status(&path, true)
            .is_ok_and(|status| status.file_type == knsh_platform::FileType::Directory)
    }

    /// The absolute path `name` (as typed) names: `~/` is `$HOME`, a relative name is under the working directory.
    fn completion_path(&self, name: &str) -> PathBuf {
        let expanded = match (name.strip_prefix('~'), self.state.variable("HOME")) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                format!("{}{rest}", home.to_string_lossy())
            }
            _ => name.to_owned(),
        };
        self.state.cwd().join(expanded)
    }

    /// File names starting with `text` (as typed: a directory part, then a prefix), of `kind`; hidden names only
    /// when the prefix starts with `.`; sorted.
    fn file_matches(&self, text: &str, kind: FileKind) -> Vec<String> {
        if text.starts_with('~') && !text.contains('/') {
            // `~user` would need the user database's names: not completed.
            return Vec::new();
        }
        let (directory, prefix) = match text.rfind('/') {
            Some(slash) => (&text[..=slash], &text[slash + 1..]),
            None => ("", text),
        };
        let listed = if directory.is_empty() {
            self.state.cwd().to_path_buf()
        } else {
            self.completion_path(directory)
        };
        let Ok(names) = self.fs.list_dir(&listed, MAX_COMPLETION_ENTRIES) else {
            return Vec::new();
        };
        let mut out: Vec<String> = names
            .into_iter()
            .filter_map(|name| name.into_string().ok())
            .filter(|name| name.starts_with(prefix) && (prefix.starts_with('.') || !name.starts_with('.')))
            .filter(|name| name != "." && name != "..")
            .filter(|name| {
                let path = listed.join(name);
                let is_dir = || {
                    self.fs
                        .status(&path, true)
                        .is_ok_and(|status| status.file_type == knsh_platform::FileType::Directory)
                };
                match kind {
                    FileKind::All => true,
                    FileKind::Directories => is_dir(),
                    FileKind::Commands => is_dir() || crate::lookup::is_executable(&*self.fs, &path),
                }
            })
            .map(|name| format!("{directory}{name}"))
            .take(MAX_MATCHES)
            .collect();
        out.sort();
        out
    }

    /// Command names starting with `prefix`: aliases, reserved words, builtins, functions and programs on `PATH`,
    /// sorted without repeats.
    fn command_names(&self, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        names.extend(self.state.aliases().keys().cloned());
        names.extend(super::builtins::KEYWORDS.iter().map(|word| (*word).to_owned()));
        names.extend(BASH_BUILTINS.iter().map(|name| (*name).to_owned()));
        names.extend(self.state.functions().keys().cloned());
        names.retain(|name| name.starts_with(prefix));
        if let Some(path) = self
            .state
            .variable("PATH")
            .map(|path| path.to_string_lossy().into_owned())
        {
            for directory in path.split(':') {
                let directory = if directory.is_empty() {
                    self.state.cwd().to_path_buf()
                } else {
                    self.state.cwd().join(directory)
                };
                let Ok(entries) = self.fs.list_dir(&directory, MAX_COMPLETION_ENTRIES) else {
                    continue;
                };
                for entry in entries {
                    let Ok(name) = entry.into_string() else { continue };
                    if name.starts_with(prefix) && crate::lookup::is_executable(&*self.fs, &directory.join(&name)) {
                        names.push(name);
                    }
                }
                if names.len() > MAX_MATCHES {
                    break;
                }
            }
        }
        names.sort();
        names.dedup();
        names.truncate(MAX_MATCHES);
        names
    }

    /// What `spec` generates for `word`, as bash's `gen_compspec_completions`: the actions, the word list, the
    /// function (only while completing a line: `context` is the line, cursor, words before the word, its index and
    /// the command), then `-X`, `-P` and `-S`. `Err` with a message for what cannot be generated here.
    #[allow(clippy::type_complexity)] // The completion context, passed through once.
    fn generate(
        &mut self,
        spec: &CompSpec,
        word: &str,
        context: Option<(&str, usize, &[String], usize, Option<&str>)>,
    ) -> Result<Vec<String>, String> {
        if spec.command.is_some() {
            return Err("complete -C: not supported (KNSH-107)".to_owned());
        }
        if spec.glob.is_some() {
            return Err("complete -G: not supported (KNSH-107)".to_owned());
        }
        let mut matches: Vec<String> = Vec::new();
        for action in &spec.actions {
            matches.extend(self.action_matches(*action, word));
        }
        if let Some(list) = &spec.wordlist {
            let expanded = self.expand_text(list).map_err(|message| {
                if message.is_empty() {
                    "complete -W: the word list could not be expanded".to_owned()
                } else {
                    message
                }
            })?;
            let ifs = self
                .state
                .variable("IFS")
                .map_or_else(|| " \t\n".to_owned(), |ifs| ifs.to_string_lossy().into_owned());
            matches.extend(
                expanded
                    .split(|ch: char| ifs.contains(ch))
                    .filter(|part| !part.is_empty() && part.starts_with(word))
                    .map(str::to_owned),
            );
        }
        if let Some(function) = &spec.function {
            let Some((line, cursor, words, cword, command)) = context else {
                return Err("compgen -F: not supported outside completion (KNSH-107)".to_owned());
            };
            matches.extend(self.call_completion_function(function, line, cursor, words, cword, command, word)?);
        }
        if let Some(filter) = &spec.filter {
            let (negated, pattern) = match filter.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, filter.as_str()),
            };
            let pattern = pattern.replace('&', word);
            let flags = crate::pattern::Flags {
                extglob: self.state.options().extglob,
                nocase: false,
            };
            let compiled = crate::pattern::Pattern::new(&pattern_chars(&pattern), flags);
            // `-X pat` removes the matches `pat` matches; `-X '!pat'` keeps only those.
            matches.retain(|entry| compiled.matches_str(entry) == negated);
        }
        if !spec.options.nosort {
            matches.sort();
        }
        matches.dedup();
        matches.truncate(MAX_MATCHES);
        let prefix = spec.prefix.as_deref().unwrap_or("");
        let suffix = spec.suffix.as_deref().unwrap_or("");
        if !prefix.is_empty() || !suffix.is_empty() {
            for entry in &mut matches {
                *entry = format!("{prefix}{entry}{suffix}");
            }
        }
        Ok(matches)
    }

    /// The names action `action` generates that start with `word`.
    fn action_matches(&self, action: CompAction, word: &str) -> Vec<String> {
        let starts = |name: &&str| name.starts_with(word);
        let owned = |names: Vec<&str>| names.into_iter().filter(starts).map(str::to_owned).collect::<Vec<_>>();
        match action {
            CompAction::Alias => owned(self.state.aliases().keys().map(String::as_str).collect()),
            CompAction::Builtin | CompAction::Enabled | CompAction::HelpTopic => owned(BASH_BUILTINS.to_vec()),
            CompAction::Disabled | CompAction::Job | CompAction::Running | CompAction::Stopped => Vec::new(),
            CompAction::Command => self.command_names(word),
            CompAction::Directory => self.file_matches(word, FileKind::Directories),
            CompAction::File => self.file_matches(word, FileKind::All),
            CompAction::Export => owned(
                self.state
                    .variable_names()
                    .into_iter()
                    .filter(|name| self.state.is_exported(name))
                    .collect(),
            ),
            CompAction::Keyword => owned(super::builtins::KEYWORDS.to_vec()),
            CompAction::Variable => owned(self.state.variable_names()),
            CompAction::ArrayVar => owned(
                self.state
                    .variable_names()
                    .into_iter()
                    .filter(|name| {
                        matches!(
                            self.state.value(name),
                            Ok(Some(value)) if matches!(*value, Value::Indexed(_) | Value::Assoc(_))
                        )
                    })
                    .collect(),
            ),
            CompAction::Function => owned(self.state.functions().keys().map(String::as_str).collect()),
            CompAction::SetOpt => owned(
                crate::options::set_o_listing(self.state.options())
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect(),
            ),
            CompAction::Shopt => owned(
                crate::options::shopt_listing(self.state.options())
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect(),
            ),
            CompAction::Signal => owned(knsh_platform::signals::NAMES.iter().map(|(_, name)| *name).collect()),
        }
    }

    /// Calls completion function `function` as bash does: `COMP_WORDS`, `COMP_CWORD`, `COMP_LINE`, `COMP_POINT`,
    /// `COMP_TYPE` and `COMP_KEY` set, arguments the command, the word and the word before it; its `COMPREPLY` are
    /// the matches. The variables are removed afterwards and `$?` is kept.
    #[allow(clippy::too_many_arguments)] // Bash's completion-function interface, one argument per variable.
    fn call_completion_function(
        &mut self,
        function: &str,
        line: &str,
        cursor: usize,
        words: &[String],
        cword: usize,
        command: Option<&str>,
        word: &str,
    ) -> Result<Vec<String>, String> {
        if self.state.function(function).is_none() {
            return Err(format!("{function}: function not found"));
        }
        let mut all: Vec<String> = words.to_vec();
        all.push(word.to_owned());
        let quoted: Vec<String> = all.iter().map(|word| quote::single(word)).collect();
        let previous = cword
            .checked_sub(1)
            .and_then(|index| all.get(index))
            .map_or("", String::as_str);
        let point = line[..cursor].chars().count();
        let text = format!(
            "COMP_WORDS=({words}); COMP_CWORD={cword}; COMP_LINE={line}; COMP_POINT={point}; COMP_TYPE=9; \
             COMP_KEY=9; COMPREPLY=(); {function} {command} {word} {previous}\n",
            // Quoted like every other piece of the text: the name is data from `complete -F`, never shell syntax.
            function = quote::single(function),
            words = quoted.join(" "),
            line = quote::single(line),
            command = quote::single(command.unwrap_or("")),
            word = quote::single(word),
            previous = quote::single(previous),
        );
        let status = self.state.last_status();
        let script = knsh_bash::parse_with(&text, self.parse_options()).map_err(|error| error.to_string())?;
        let result = self.run(&script, &text);
        let replies: Vec<String> = match self.state.value("COMPREPLY") {
            Ok(Some(value)) => match &*value {
                Value::Indexed(elements) => elements.values().map(|v| v.to_string_lossy().into_owned()).collect(),
                Value::Scalar(text) => vec![text.to_string_lossy().into_owned()],
                Value::Assoc(_) => Vec::new(),
            },
            Ok(None) | Err(_) => Vec::new(),
        };
        let cleanup = "unset COMP_WORDS COMP_CWORD COMP_LINE COMP_POINT COMP_TYPE COMP_KEY COMPREPLY\n";
        if let Ok(script) = knsh_bash::parse(cleanup) {
            let _ = self.run(&script, cleanup);
        }
        self.state.set_last_status(status);
        result.map_err(|error| error.to_string())?;
        Ok(replies)
    }

    // ---- Builtins ----

    /// `history [n]`, `history -c`, `history -d offset`, `history -anrw [file]`, `history -p arg…`,
    /// `history -s arg…` (KNSH-107).
    #[allow(clippy::too_many_lines)] // One branch per option, in bash's order (`history_builtin`).
    pub(super) fn history_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let mut flags = String::new();
        let mut rest = args;
        while let Some((arg, after)) = rest.split_first() {
            if arg == "--" {
                rest = after;
                break;
            }
            if arg.len() < 2 || !arg.starts_with('-') || arg[1..].starts_with(|ch: char| ch.is_ascii_digit()) {
                break;
            }
            for letter in arg.chars().skip(1) {
                if !"cdanrwps".contains(letter) {
                    self.report(span, run, format_args!("history: -{letter}: invalid option"));
                    self.report_plain(format_args!("{HISTORY_USAGE}"));
                    return Status::new(2);
                }
                flags.push(letter);
                if letter == 'd' {
                    break;
                }
            }
            rest = after;
            if flags.contains('d') {
                break;
            }
        }
        let has = |letter: char| flags.contains(letter);
        if has('c') {
            self.state.history_mut().clear();
            if flags == "c" {
                return Status::SUCCESS;
            }
        }
        if has('d') {
            let Some(offset) = rest.first() else {
                self.report(span, run, format_args!("history: -d: option requires an argument"));
                self.report_plain(format_args!("{HISTORY_USAGE}"));
                return Status::new(2);
            };
            let history = self.state.history();
            let number = match offset.parse::<i64>() {
                // Bash 5: a negative offset counts back from the end.
                Ok(n) if n < 0 => i64::try_from(history.next_number()).ok().map(|next| next + n),
                Ok(n) => Some(n),
                Err(_) => None,
            };
            let deleted = number
                .and_then(|n| usize::try_from(n).ok())
                .is_some_and(|n| self.state.history_mut().delete(n));
            if !deleted {
                self.report(
                    span,
                    run,
                    format_args!("history: {offset}: history position out of range"),
                );
                return Status::FAILURE;
            }
            return Status::SUCCESS;
        }
        if has('p') {
            let mut out = String::new();
            for arg in rest {
                match expansion::expand(arg, self.state.history(), self.state.options().extglob) {
                    Ok(expanded) => {
                        out.push_str(&expanded.map_or_else(|| arg.clone(), |expansion| expansion.line));
                        out.push('\n');
                    }
                    Err(error) => {
                        self.report(span, run, format_args!("history: {error}"));
                        return Status::FAILURE;
                    }
                }
            }
            return self.print("history", out.as_bytes(), span, run);
        }
        if has('s') {
            let history = self.state.history_mut();
            history.pop();
            if !rest.is_empty() {
                history.push(rest.join(" "));
            }
            return Status::SUCCESS;
        }
        if has('n') {
            self.report(span, run, format_args!("history: -n: not supported (KNSH-107)"));
            return Status::FAILURE;
        }
        if has('a') || has('r') || has('w') {
            let file = match rest.first() {
                Some(file) => Some(file.clone()),
                None => self
                    .state
                    .variable("HISTFILE")
                    .map(|file| file.to_string_lossy().into_owned())
                    .filter(|file| !file.is_empty()),
            };
            let Some(file) = file else {
                // Bash does nothing without a file.
                return Status::SUCCESS;
            };
            let path = self.state.cwd().join(&file);
            let result = if has('r') {
                self.read_history_file(&path)
            } else {
                self.write_history_file(&path, has('a'))
            };
            if let Err(reason) = result {
                self.report(span, run, format_args!("history: {file}: {reason}"));
                return Status::FAILURE;
            }
            return Status::SUCCESS;
        }
        let history = self.state.history();
        let count = match rest.first().map(|n| (n, n.parse::<usize>())) {
            None => history.entries().len(),
            Some((_, Ok(n))) => n.min(history.entries().len()),
            Some((n, Err(_))) => {
                let n = n.clone();
                self.report(span, run, format_args!("history: {n}: numeric argument required"));
                return Status::FAILURE;
            }
        };
        let entries = history.entries();
        let first = entries.len() - count;
        let mut out = String::new();
        for (offset, entry) in entries[first..].iter().enumerate() {
            let _ = writeln!(out, "{:5}  {entry}", history.base() + first + offset);
        }
        self.print("history", out.as_bytes(), span, run)
    }

    /// `history -r`: adds the lines of history file `path`.
    ///
    /// # Errors
    ///
    /// The system's reason when the file cannot be read.
    pub fn read_history_file(&mut self, path: &Path) -> Result<(), String> {
        let bytes = self.read_history_bytes(path)?;
        let limit = history::size_limit(self.variable_text("HISTSIZE").as_deref());
        self.state.history_mut().read_file(&bytes, limit);
        Ok(())
    }

    /// The bytes of history file `path` (its last [`MAX_HISTORY_FILE`] when larger).
    fn read_history_bytes(&self, path: &Path) -> Result<Vec<u8>, String> {
        match self.fs.read(path, MAX_HISTORY_FILE) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.is_not_found() => Ok(Vec::new()),
            Err(_) => {
                // Too large or unreadable: read from the end through a reader, bounded.
                let mut reader = self.fs.open_read(path).map_err(|error| error.to_string())?;
                let mut bytes = Vec::new();
                let mut chunk = vec![0_u8; 1 << 16];
                let limit = usize::try_from(MAX_HISTORY_FILE).unwrap_or(usize::MAX);
                loop {
                    let read = reader.read(&mut chunk).map_err(|error| error.to_string())?;
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.len() > limit {
                        bytes.drain(..bytes.len() - limit);
                    }
                }
                // Start at a whole line.
                if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                    bytes.drain(..=newline);
                }
                Ok(bytes)
            }
        }
    }

    /// Writes the history to file `path` (owner-only, by atomic replace): the whole list, or with `append` the
    /// file's lines followed by the entries added since it was last read or written; then cut to `HISTFILESIZE`
    /// lines (bash's `history_truncate_file`). The entries count as saved afterwards.
    ///
    /// # Errors
    ///
    /// The system's reason when the file cannot be read or written.
    pub fn write_history_file(&mut self, path: &Path, append: bool) -> Result<(), String> {
        let limit = history::size_limit(self.variable_text("HISTFILESIZE").as_deref());
        let text = if append {
            let existing = self.read_history_bytes(path)?;
            let existing = String::from_utf8_lossy(&existing).into_owned();
            let unsaved = self.state.history().unsaved();
            history::file_text(existing.lines().chain(unsaved.iter().map(String::as_str)), limit)
        } else {
            history::file_text(self.state.history().entries().iter().map(String::as_str), limit)
        };
        // A history file that is a symlink (to a dotfiles repository, say) is written where it points, as bash
        // writes through it; replacing the link itself would silently stop updating its target.
        let target = match self.fs.status(path, false) {
            Ok(status) if status.file_type == knsh_platform::FileType::Symlink => self
                .fs
                .canonicalise(path)
                .map_or_else(|_| path.to_path_buf(), |resolved| resolved.as_path().to_path_buf()),
            Ok(_) | Err(_) => path.to_path_buf(),
        };
        self.fs
            .atomic_replace(&target, &text, 0o600)
            .map_err(|error| error.to_string())?;
        self.state.history_mut().mark_saved();
        Ok(())
    }

    /// Saves `line` to the history as an interactive shell does: `HISTCONTROL`, then `HISTSIZE`. `false` when it
    /// was not saved.
    pub fn add_history(&mut self, line: &str) -> bool {
        let control = HistControl::parse(self.variable_text("HISTCONTROL").as_deref());
        let limit = history::size_limit(self.variable_text("HISTSIZE").as_deref());
        self.state.history_mut().add(line, control, limit)
    }

    /// `complete` (KNSH-107).
    pub(super) fn complete_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let request = match parse_spec(args, false) {
            Ok(request) => request,
            Err(error) => return self.spec_error("complete", COMPLETE_USAGE, &error, span, run),
        };
        let special = request.default || request.empty || request.initial;
        let only_print = request.spec == CompSpec::default() && !request.remove;
        if request.print || (only_print && request.operands.is_empty() && !special) {
            return self.print_specs(&request, span, run);
        }
        if request.remove {
            return self.remove_specs(&request, span, run);
        }
        let table = self.state.completions_mut();
        if request.default {
            table.default = Some(request.spec.clone());
        }
        if request.empty {
            table.empty = Some(request.spec.clone());
        }
        if request.initial {
            table.initial = Some(request.spec.clone());
        }
        for name in &request.operands {
            table.by_command.insert(name.clone(), request.spec.clone());
        }
        Status::SUCCESS
    }

    /// `complete -p [name …]`.
    fn print_specs(&mut self, request: &SpecRequest, span: Span, run: &Run<'_>) -> Status {
        let table = self.state.completions().clone();
        let mut out = String::new();
        let mut status = Status::SUCCESS;
        let special = [
            (request.default, &table.default, "-D"),
            (request.empty, &table.empty, "-E"),
            (request.initial, &table.initial, "-I"),
        ];
        let any_special = special.iter().any(|(asked, _, _)| *asked);
        if request.operands.is_empty() && !any_special {
            for (name, spec) in &table.by_command {
                out.push_str(&print_spec(spec, name));
                out.push('\n');
            }
            for (_, spec, flag) in special {
                if let Some(spec) = spec {
                    out.push_str(&print_spec(spec, flag));
                    out.push('\n');
                }
            }
        } else {
            for (asked, spec, flag) in special {
                if asked && let Some(spec) = spec {
                    out.push_str(&print_spec(spec, flag));
                    out.push('\n');
                }
            }
            for name in &request.operands {
                if let Some(spec) = table.by_command.get(name) {
                    out.push_str(&print_spec(spec, name));
                    out.push('\n');
                } else {
                    self.report(span, run, format_args!("complete: {name}: no completion specification"));
                    status = Status::FAILURE;
                }
            }
        }
        let printed = self.print("complete", out.as_bytes(), span, run);
        if printed.is_success() { status } else { printed }
    }

    /// `complete -r [name …]`.
    fn remove_specs(&mut self, request: &SpecRequest, span: Span, run: &Run<'_>) -> Status {
        let special = request.default || request.empty || request.initial;
        let table = self.state.completions_mut();
        if request.default {
            table.default = None;
        }
        if request.empty {
            table.empty = None;
        }
        if request.initial {
            table.initial = None;
        }
        if request.operands.is_empty() && !special {
            *table = complete::CompletionTable::default();
            return Status::SUCCESS;
        }
        let mut missing = Vec::new();
        for name in &request.operands {
            if table.by_command.remove(name).is_none() {
                missing.push(name.clone());
            }
        }
        for name in &missing {
            self.report(span, run, format_args!("complete: {name}: no completion specification"));
        }
        if missing.is_empty() {
            Status::SUCCESS
        } else {
            Status::FAILURE
        }
    }

    /// `compgen [option …] [word]` (KNSH-107).
    pub(super) fn compgen_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        let request = match parse_spec(args, true) {
            Ok(request) => request,
            Err(error) => return self.spec_error("compgen", COMPGEN_USAGE, &error, span, run),
        };
        let word = request.operands.first().cloned().unwrap_or_default();
        match self.generate(&request.spec, &word, None) {
            Ok(mut matches) => {
                let fallback = matches.is_empty()
                    && (request.spec.options.default
                        || request.spec.options.bashdefault
                        || request.spec.options.dirnames);
                if fallback {
                    let kind = if request.spec.options.dirnames {
                        FileKind::Directories
                    } else {
                        FileKind::All
                    };
                    matches = self.file_matches(&word, kind);
                }
                if request.spec.options.plusdirs {
                    matches.extend(self.file_matches(&word, FileKind::Directories));
                }
                if matches.is_empty() {
                    return Status::FAILURE;
                }
                let mut out = matches.join("\n");
                out.push('\n');
                self.print("compgen", out.as_bytes(), span, run)
            }
            Err(message) => {
                self.report(span, run, format_args!("compgen: {message}"));
                Status::new(2)
            }
        }
    }

    /// Reports a refused `complete` or `compgen` argument as bash does, with its status.
    fn spec_error(&mut self, name: &str, usage: &str, error: &SpecError, span: Span, run: &Run<'_>) -> Status {
        match error {
            SpecError::InvalidOption(letter) => {
                self.report(span, run, format_args!("{name}: -{letter}: invalid option"));
                self.report_plain(format_args!("{usage}"));
                Status::new(2)
            }
            SpecError::MissingArgument(letter) => {
                self.report(
                    span,
                    run,
                    format_args!("{name}: -{letter}: option requires an argument"),
                );
                self.report_plain(format_args!("{usage}"));
                Status::new(2)
            }
            SpecError::InvalidAction(action) => {
                self.report(span, run, format_args!("{name}: {action}: invalid action name"));
                Status::FAILURE
            }
            SpecError::InvalidOptionName(option) => {
                self.report(span, run, format_args!("{name}: {option}: invalid option name"));
                Status::FAILURE
            }
            SpecError::UnsupportedAction(action) => {
                self.report(span, run, format_args!("{name}: -A {action}: not supported (KNSH-107)"));
                Status::new(2)
            }
        }
    }
}

/// Which file names [`Interpreter::file_matches`] keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    All,
    Directories,
    /// Directories and executable files (a command typed with a `/`).
    Commands,
}

/// A pattern's characters for [`crate::pattern::Pattern::new`]: unquoted, except one after a backslash.
fn pattern_chars(text: &str) -> Vec<crate::word::WordChar> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        let (ch, quoted) = match ch {
            '\\' => match chars.next() {
                Some(next) => (next, true),
                None => ('\\', true),
            },
            _ => (ch, false),
        };
        out.push(crate::word::WordChar {
            ch,
            quoted,
            expanded: false,
        });
    }
    out
}

/// Words that put the next word in command position.
const COMMAND_STARTERS: &[&str] = &[
    ";", "&", "|", "&&", "||", "(", "|&", ";;", ";&", ";;&", "!", "{", "do", "then", "else", "elif", "if", "while",
    "until", "time",
];

/// For the text before the word being completed: whether the word is in command position, the command's name if
/// not, and the command's words before the word (from its name on).
fn command_context(before: &str) -> (bool, Option<String>, Vec<String>) {
    // Inside a word (`X=/tm`, `--file=`): not a command position.
    let inside_word = !before.is_empty() && !before.ends_with(|ch: char| ch.is_whitespace() || ";&|(".contains(ch));
    let tokens = expansion::words(before);
    let start = tokens
        .iter()
        .rposition(|token| COMMAND_STARTERS.contains(token))
        .map_or(0, |at| at + 1);
    let mut words: Vec<String> = tokens[start..].iter().map(|token| (*token).to_owned()).collect();
    // Assignments before the command are not its words.
    while words
        .first()
        .is_some_and(|word| crate::word::assignment_value_start(word).is_some())
    {
        words.remove(0);
    }
    if inside_word {
        // The text the word continues is not a word of its own.
        words.pop();
    }
    let command_position = words.is_empty() && !inside_word;
    let command = words.first().map(|word| complete::word_at(word, word.len()).text);
    (command_position, command, words)
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: the shell reads more lines while the input is unfinished, as bash does.
    #[test]
    fn unfinished_input_is_recognised() {
        for text in [
            "echo 'a\n",
            "if true; then\n",
            "echo a |\n",
            "cat <<EOF\nx\n",
            "for x in a\n",
            "echo $(\n",
        ] {
            let error = knsh_bash::parse(text).unwrap_err();
            assert!(is_incomplete(&error, text), "{text:?}: {error:?}");
        }
        let text = "echo )\n";
        let error = knsh_bash::parse(text).unwrap_err();
        assert!(!is_incomplete(&error, text));
        assert!(continues_line("echo a \\\n"));
        assert!(!continues_line("echo a \\\\\n"));
        assert!(!continues_line("echo 'a \\\n"));
    }

    #[test]
    fn command_positions() {
        assert_eq!(command_context(""), (true, None, Vec::new()));
        assert_eq!(command_context("ls | "), (true, None, Vec::new()));
        assert_eq!(command_context("FOO=1 "), (true, None, Vec::new()));
        let (position, command, words) = command_context("sudo git ");
        assert!(!position);
        assert_eq!(command.as_deref(), Some("sudo"));
        assert_eq!(words, ["sudo", "git"]);
        assert!(!command_context("X=").0);
        assert!(command_context("if ").0);
    }
}
