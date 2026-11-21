//! Redirections and the shell's descriptor table (KNSH-099, KNSH-105; NFR-COMPAT-02).
//!
//! The interpreter does not move descriptors of its own process around: it keeps the shell's table ([`FdTable`]),
//! which says what each number holds for the script (one of the spawner's standard descriptors, or a file the shell
//! opened through [`knsh_platform::Descriptors`]). A command receives exactly that table
//! ([`CommandRequest::descriptors`](knsh_platform::CommandRequest::descriptors)): every number the script holds
//! open and nothing else, so neither the interpreter's own descriptors nor bash's internal copies (saved above 9,
//! close-on-exec) ever reach a child.
//!
//! Redirections apply left to right, each seeing the ones before it, so `2>&1 >file` sends errors where output went
//! before and `>file 2>&1` sends both to the file. Each change is recorded ([`Saved`]) and undone after the command,
//! newest first, which restores every number to what it held, as bash's undo list does; `exec` with only
//! redirections keeps them. A `{name}>file` descriptor is not undone: bash lets it outlive the command and leaves
//! closing it to the script. When a redirection fails, bash's message is reported (through the descriptors as they
//! stand, so `2>/dev/null` before it silences it), those already applied are undone, and the command does not run
//! (status 1).
//!
//! A here-document (KNSH-105) is read like a here-string: its body (expanded as double-quoted text unless the
//! delimiter was quoted, tabs at line starts removed for `<<-`) becomes a descriptor reading exactly that text, on
//! standard input unless a number is given. A coprocess's ends are held close-on-exec ([`FdTable::set_private`]):
//! the shell's redirections duplicate them, commands never receive them.
//!
//! Bash's special names are the shell's own table here: `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N`
//! duplicate descriptor 0, 1, 2 or `N` (on macOS bash opens the real `/dev/fd`, which in bash's process is the same
//! table; in the interpreter's process it is not, so the real one is never opened). `/dev/tcp/…` and `/dev/udp/…`,
//! which bash turns into network connections from the shell itself, are refused: the shell makes no connection of
//! its own, and everything an agent's commands reach goes through the sandbox and the proxy (FR-NET-08, decision
//! recorded in `specs/09-reference/decisions.md`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use knsh_bash::{CommandWord, IoNumber, Redirect, RedirectionOperator};
use knsh_platform::{ChildDescriptor, MAX_PLACED_FD, OpenMode, PlatformError, StandardStream};

use super::{Flow, Interpreter, Run, unsupported};
use crate::error::Unsupported;

/// Highest descriptor number a script may use: what a command can be given ([`MAX_PLACED_FD`]), below macOS's
/// default limit of 256 open descriptors. Bash allows up to its process limit; a higher number here is bash's
/// `Bad file descriptor`.
pub(crate) const MAX_FD: u32 = 255;

const _: () = assert!(MAX_FD as i64 == MAX_PLACED_FD as i64);

/// Where `{name}>file` descriptors start, as in bash (`SHELL_FD_BASE`).
const NAMED_FD_BASE: u32 = 10;

/// Where process substitution and coprocess descriptors are placed: the highest free number below this, as bash's
/// `/dev/fd/63`, `/dev/fd/62`, … (KNSH-105).
pub(crate) const SUBSTITUTION_FD_TOP: u32 = 64;

/// The shell's descriptors: what each number holds for the script. A number not listed is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FdTable {
    slots: BTreeMap<u32, ChildDescriptor>,
    /// Numbers the shell holds close-on-exec, as bash holds a coprocess's ends (KNSH-105): usable by the shell's own
    /// redirections and builtins, never given to a command. A number loses the mark when anything else is put
    /// there.
    private: BTreeSet<u32>,
}

impl FdTable {
    /// Descriptors 0, 1 and 2 as the spawner's own standard descriptors: a shell started without redirections.
    pub(crate) fn standard() -> Self {
        let slots = [
            (0, StandardStream::Input),
            (1, StandardStream::Output),
            (2, StandardStream::Error),
        ]
        .into_iter()
        .map(|(fd, stream)| (fd, ChildDescriptor::Standard(stream)))
        .collect();
        Self {
            slots,
            private: BTreeSet::new(),
        }
    }

    /// What `fd` holds, if it is open.
    pub(crate) fn get(&self, fd: u32) -> Option<&ChildDescriptor> {
        self.slots.get(&fd)
    }

    /// Sets (or with `None` closes) `fd`: a pipeline stage's standard input and output (KNSH-100).
    pub(crate) fn set(&mut self, fd: u32, slot: Option<ChildDescriptor>) {
        self.replace(fd, slot);
    }

    /// Puts `slot` at `fd`, held by the shell alone: never given to a command (a coprocess's ends, KNSH-105).
    pub(crate) fn set_private(&mut self, fd: u32, slot: ChildDescriptor) {
        self.replace(fd, Some(slot));
        self.private.insert(fd);
    }

    /// The highest closed number below `top` and from 10 up (bash's `SHELL_FD_BASE`), for a descriptor the shell
    /// places itself (KNSH-105).
    pub(crate) fn free_below(&self, top: u32) -> Option<u32> {
        (NAMED_FD_BASE..top.min(MAX_FD + 1))
            .rev()
            .find(|fd| !self.slots.contains_key(fd))
    }

    /// Sets (or with `None` closes) `fd`, returning what it held.
    fn replace(&mut self, fd: u32, slot: Option<ChildDescriptor>) -> Option<ChildDescriptor> {
        self.private.remove(&fd);
        match slot {
            Some(slot) => self.slots.insert(fd, slot),
            None => self.slots.remove(&fd),
        }
    }

    /// The lowest closed number from `base` up to [`MAX_FD`].
    fn free_from(&self, base: u32) -> Option<u32> {
        (base..=MAX_FD).find(|fd| !self.slots.contains_key(fd))
    }

    /// The table a command receives: every open number but the shell's own, in order.
    pub(crate) fn child_table(&self) -> Vec<(i32, ChildDescriptor)> {
        self.slots
            .iter()
            .filter(|(fd, _)| !self.private.contains(fd))
            .filter_map(|(&fd, slot)| Some((i32::try_from(fd).ok()?, slot.clone())))
            .collect()
    }
}

/// What applying redirections changed: each number and what it held before, oldest first.
#[derive(Debug, Default)]
#[must_use = "redirections must be undone with `Interpreter::restore`, or dropped only when they persist (`exec`)"]
pub(crate) struct Saved {
    previous: Vec<(u32, Option<ChildDescriptor>)>,
}

impl Saved {
    /// Nothing to undo.
    pub(crate) fn none() -> Self {
        Self::default()
    }
}

/// Which descriptor a redirection changes.
enum Dest {
    /// This number.
    Number(u32),
    /// Standard output and standard error (`&>`, `>&file`).
    Both,
    /// A new number of 10 or above, stored in the variable (`{name}>file`); for a close, the number it holds.
    Variable(String),
}

/// A redirection's failure: bash's message, without the `name: line n: ` prefix.
type Refusal = String;

/// `EBADF` on macOS: writing to a closed descriptor.
const EBADF: i32 = 9;

/// `EIO`: a write that failed without an `errno`.
const fn libc_eio() -> i32 {
    5
}

/// The text bash gives for `errno` (`strerror`): the system's message without std's ` (os error n)` suffix.
pub(crate) fn strerror(errno: i32) -> String {
    let text = std::io::Error::from_raw_os_error(errno).to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// Bash's message for a file `word` that could not be opened as `mode`.
fn open_refusal(word: &str, mode: OpenMode, error: &PlatformError) -> Refusal {
    match error {
        error if mode == OpenMode::NoClobber && error.is_already_exists() => {
            format!("{word}: cannot overwrite existing file")
        }
        PlatformError::Os { errno, .. } => format!("{word}: {}", strerror(*errno)),
        other => format!("{word}: {other}"),
    }
}

/// The descriptor number `text` spells: digits only, within [`MAX_FD`]. `Err` with bash's message otherwise
/// (`None` when it is not a number at all).
fn descriptor_number(text: &str) -> Option<Result<u32, Refusal>> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(match text.parse::<u32>() {
        Ok(fd) if fd <= MAX_FD => Ok(fd),
        Ok(_) => Err(format!("{text}: Bad file descriptor")),
        Err(_) => Err("file descriptor out of range: Bad file descriptor".to_owned()),
    })
}

/// The descriptor bash's special file name `word` duplicates: `/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
/// `/dev/fd/N`.
fn special_descriptor(word: &str) -> Option<Result<u32, Refusal>> {
    match word {
        "/dev/stdin" => Some(Ok(0)),
        "/dev/stdout" => Some(Ok(1)),
        "/dev/stderr" => Some(Ok(2)),
        _ => descriptor_number(word.strip_prefix("/dev/fd/")?)
            .map(|number| number.map_err(|_| format!("{word}: Bad file descriptor"))),
    }
}

/// Whether `word` is a network redirection bash would open itself (`/dev/tcp/host/port`, `/dev/udp/host/port`).
fn is_network(word: &str) -> bool {
    word.starts_with("/dev/tcp/") || word.starts_with("/dev/udp/")
}

impl Interpreter {
    /// Applies `redirects` left to right to the shell's table and returns what to undo. A redirection that fails
    /// is reported, everything applied before it undone, and `Ok(None)` returned: the command must not run, and its
    /// status is 1. An expansion error in a target undoes the same way before it stops evaluation.
    pub(super) fn redirect(&mut self, redirects: &[Redirect], run: &Run<'_>) -> Flow<Option<Saved>> {
        let mut saved = Saved::none();
        for redirect in redirects {
            match self.apply(redirect, &mut saved, run) {
                Ok(Ok(())) => {}
                Ok(Err(refusal)) => {
                    // Reported before the undo, as bash does: `cmd 2>/dev/null <missing` says nothing.
                    self.report(redirect.span, run, format_args!("{refusal}"));
                    self.restore(saved);
                    return Ok(None);
                }
                Err(stop) => {
                    self.restore(saved);
                    return Err(stop);
                }
            }
        }
        // `|&` after the command: its standard error joins its standard output, after its own redirections
        // (KNSH-100).
        if std::mem::take(&mut self.pipe_stderr) {
            let output = self.fds.get(1).cloned();
            saved.previous.push((2, self.fds.replace(2, output)));
        }
        Ok(Some(saved))
    }

    /// Undoes `saved`, newest change first.
    pub(super) fn restore(&mut self, saved: Saved) {
        for (fd, previous) in saved.previous.into_iter().rev() {
            self.fds.replace(fd, previous);
        }
    }

    /// Writes `bytes` where the shell's descriptor `fd` points: the shell's own messages go to its descriptor 2.
    /// A failed write is ignored, as bash ignores it; a closed descriptor (or standard input) swallows the bytes.
    pub(super) fn write_shell(&mut self, fd: u32, bytes: &[u8]) {
        match self.fds.get(fd).cloned() {
            Some(ChildDescriptor::Standard(StandardStream::Error)) => super::write_shared(&self.diagnostics, bytes),
            Some(ChildDescriptor::Standard(StandardStream::Output)) => super::write_shared(&self.output, bytes),
            Some(ChildDescriptor::Open(file)) => {
                let _ = self.descriptors.write_all(&file, bytes);
            }
            Some(ChildDescriptor::Standard(StandardStream::Input)) | None => {}
        }
    }

    /// Writes `bytes` where the shell's descriptor `fd` points, as a builtin's output does (KNSH-101): `Err` with the
    /// `errno` when it fails, `EBADF` for a closed descriptor, so the builtin reports bash's `write error`.
    pub(super) fn write_out(&mut self, fd: u32, bytes: &[u8]) -> Result<(), i32> {
        let to_shared = |writer: &super::SharedWriter| {
            let mut writer = writer.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            writer
                .write_all(bytes)
                .and_then(|()| writer.flush())
                .map_err(|error| error.raw_os_error().unwrap_or(libc_eio()))
        };
        match self.fds.get(fd).cloned() {
            Some(ChildDescriptor::Standard(StandardStream::Error)) => to_shared(&self.diagnostics),
            Some(ChildDescriptor::Standard(StandardStream::Output)) => to_shared(&self.output),
            Some(ChildDescriptor::Open(file)) => self
                .descriptors
                .write_all(&file, bytes)
                .map_err(|error| error.errno().unwrap_or(libc_eio())),
            // The shell's standard input is not opened for writing.
            Some(ChildDescriptor::Standard(StandardStream::Input)) | None => Err(EBADF),
        }
    }

    /// Applies one redirection, recording what it changed in `saved`.
    fn apply(&mut self, redirect: &Redirect, saved: &mut Saved, run: &Run<'_>) -> Flow<Result<(), Refusal>> {
        use RedirectionOperator as Op;

        let explicit = match redirect.fd {
            None => None,
            Some(IoNumber { value: None, .. }) => {
                return Ok(Err("file descriptor out of range: Bad file descriptor".to_owned()));
            }
            Some(IoNumber { value: Some(fd), .. }) if fd > MAX_FD => {
                return Ok(Err(format!("{fd}: Bad file descriptor")));
            }
            Some(IoNumber { value: Some(fd), .. }) => Some(fd),
        };
        let default = match redirect.operator {
            Op::Input
            | Op::ReadWrite
            | Op::DuplicateInput
            | Op::HereString
            | Op::HereDocument
            | Op::HereDocumentStripTabs => 0,
            Op::Output | Op::Append | Op::Clobber | Op::DuplicateOutput | Op::OutputAll | Op::AppendAll => 1,
        };
        let dest = match (&redirect.variable, explicit) {
            (Some(variable), _) => Dest::Variable(variable.name.clone()),
            (None, Some(fd)) => Dest::Number(fd),
            (None, None) => Dest::Number(default),
        };
        let output = if self.state.options().noclobber {
            OpenMode::NoClobber
        } else {
            OpenMode::Truncate
        };
        match redirect.operator {
            // KNSH-105: the body, expanded unless its delimiter was quoted, read as a here-string's text is.
            Op::HereDocument | Op::HereDocumentStripTabs => {
                let Some(document) = &redirect.here_document else {
                    return Err(unsupported(Unsupported::HereDocument, redirect.span).into());
                };
                let body = crate::word::here_document_parts(document, run.source)?;
                let result = self.expander(run, &[]).here_document(&body, redirect.span);
                let text = self.expanded(result, redirect.span, run)?;
                Ok(self.here_text(dest, text.as_bytes(), saved))
            }
            Op::HereString => {
                let mut text = self.string(&redirect.target, run)?;
                text.push('\n');
                Ok(self.here_text(dest, text.as_bytes(), saved))
            }
            Op::DuplicateInput | Op::DuplicateOutput => {
                let word = match self.target_word(&redirect.target, run)? {
                    Ok(word) => word,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let to_file = redirect.operator == Op::DuplicateOutput
                    && redirect.variable.is_none()
                    && explicit.is_none_or(|fd| fd == 1);
                Ok(self.duplicate(dest, &word, to_file, &redirect.target, output, saved, run))
            }
            Op::Input | Op::Output | Op::Append | Op::Clobber | Op::ReadWrite | Op::OutputAll | Op::AppendAll => {
                let mode = match redirect.operator {
                    Op::Input => OpenMode::Read,
                    Op::Output | Op::OutputAll => output,
                    Op::Clobber => OpenMode::Truncate,
                    Op::ReadWrite => OpenMode::ReadWrite,
                    Op::Append | Op::AppendAll => OpenMode::Append,
                    // Handled by the arms above; never reached here.
                    Op::HereDocument
                    | Op::HereDocumentStripTabs
                    | Op::HereString
                    | Op::DuplicateInput
                    | Op::DuplicateOutput => {
                        return Err(unsupported(Unsupported::Redirection, redirect.span).into());
                    }
                };
                let both = matches!(redirect.operator, Op::OutputAll | Op::AppendAll);
                if both && redirect.variable.is_some() {
                    return Ok(Err(format!("{}: ambiguous redirect", written(&redirect.target, run))));
                }
                let word = match self.target_word(&redirect.target, run)? {
                    Ok(word) => word,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let slot = match self.open_file(&word, mode) {
                    Ok(slot) => slot,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                Ok(self.place(if both { Dest::Both } else { dest }, Some(slot), saved))
            }
        }
    }

    /// Puts a descriptor reading exactly `text` at `dest`: a here-string or here-document.
    fn here_text(&mut self, dest: Dest, text: &[u8], saved: &mut Saved) -> Result<(), Refusal> {
        let slot = match self.descriptors.here_string(text) {
            Ok(fd) => ChildDescriptor::Open(fd),
            Err(error) => {
                let reason = error.errno().map_or_else(|| error.to_string(), strerror);
                return Err(format!("cannot create temp file for here-document: {reason}"));
            }
        };
        self.place(dest, Some(slot), saved)
    }

    /// `n>&word` and `n<&word`: `-` closes `n`, a number `m` (or `m-`, which then closes `m`) duplicates it, and for
    /// `>&word` on standard output (`to_file`) any other word is a file for standard output and error.
    #[allow(clippy::too_many_arguments)]
    fn duplicate(
        &mut self,
        dest: Dest,
        word: &str,
        to_file: bool,
        target: &CommandWord,
        output: OpenMode,
        saved: &mut Saved,
        run: &Run<'_>,
    ) -> Result<(), Refusal> {
        if word == "-" {
            return self.place(dest, None, saved);
        }
        let (number, moves) = match word.strip_suffix('-') {
            Some(number) if !number.is_empty() => (number, true),
            Some(_) | None => (word, false),
        };
        match descriptor_number(number) {
            Some(Ok(source)) => {
                let Some(slot) = self.fds.get(source).cloned() else {
                    return Err(format!("{source}: Bad file descriptor"));
                };
                // `n>&n` and `n>&n-` leave `n` as it is: bash neither duplicates nor closes a descriptor onto itself.
                let onto_itself = matches!(dest, Dest::Number(fd) if fd == source);
                self.place(dest, Some(slot), saved)?;
                if moves && !onto_itself {
                    saved.previous.push((source, self.fds.replace(source, None)));
                }
                Ok(())
            }
            Some(Err(refusal)) => Err(refusal),
            None if to_file => {
                let slot = self.open_file(word, output)?;
                self.place(Dest::Both, Some(slot), saved)
            }
            None => Err(format!("{}: ambiguous redirect", written(target, run))),
        }
    }

    /// Puts `slot` (or closes, for `None`) at `dest`, recording the change unless the destination is a variable's.
    fn place(&mut self, dest: Dest, slot: Option<ChildDescriptor>, saved: &mut Saved) -> Result<(), Refusal> {
        match dest {
            Dest::Number(fd) => saved.previous.push((fd, self.fds.replace(fd, slot))),
            Dest::Both => {
                saved.previous.push((1, self.fds.replace(1, slot.clone())));
                saved.previous.push((2, self.fds.replace(2, slot)));
            }
            Dest::Variable(name) => match slot {
                // `{name}>&-`: the descriptor whose number the variable holds.
                None => {
                    let value = self
                        .state
                        .variable(&name)
                        .and_then(|value| value.to_str())
                        .map(str::to_owned);
                    let fd = value.as_deref().and_then(descriptor_number).and_then(Result::ok);
                    match fd {
                        Some(fd) if self.fds.get(fd).is_some() => {
                            self.fds.replace(fd, None);
                        }
                        Some(_) | None => {
                            return Err(format!("{}: Bad file descriptor", value.unwrap_or_default()));
                        }
                    }
                }
                Some(slot) => {
                    // Bash's `redir_varassign` fails on a read-only variable (KNSH-101): checked before a number is
                    // taken, so nothing stays open.
                    if self.state.is_readonly(&name) {
                        return Err(format!("{name}: cannot assign fd to variable"));
                    }
                    let Some(fd) = self.fds.free_from(NAMED_FD_BASE) else {
                        return Err(format!("{{{name}}}: Too many open files"));
                    };
                    self.fds.replace(fd, Some(slot));
                    if self.state.assign(&name, fd.to_string().into(), false).is_err() {
                        self.fds.replace(fd, None);
                        return Err(format!("{name}: cannot assign fd to variable"));
                    }
                }
            },
        }
        Ok(())
    }

    /// What a file redirection's `word` opens as `mode`: the shell's own descriptor for bash's special names, a
    /// refusal for a network name, otherwise the file (relative to the working directory).
    fn open_file(&mut self, word: &str, mode: OpenMode) -> Result<ChildDescriptor, Refusal> {
        if is_network(word) {
            return Err(format!(
                "{word}: network redirections are refused: the shell opens no connection of its own (FR-NET-08)"
            ));
        }
        if let Some(number) = special_descriptor(word) {
            let fd = number?;
            return self
                .fds
                .get(fd)
                .cloned()
                .ok_or_else(|| format!("{word}: Bad file descriptor"));
        }
        if word.is_empty() {
            return Err(": No such file or directory".to_owned());
        }
        let path = self.state.cwd().join(word);
        // KNSH-101: a file created gets the shell's umask, once the shell has one of its own.
        let opened = match self.state.umask() {
            Some(umask) => self.descriptors.open_masked(&path, mode, umask),
            None => self.descriptors.open(&path, mode),
        };
        opened
            .map(ChildDescriptor::Open)
            .map_err(|error| open_refusal(word, mode, &error))
    }

    /// The single word a redirection target expands into, as bash expands it (brace, tilde, parameter and
    /// arithmetic expansion, splitting, pathname expansion; POSIX mode neither splits nor, in a non-interactive
    /// shell, matches file names, KNSH-106): anything but one word is bash's `ambiguous redirect`.
    fn target_word(&mut self, target: &CommandWord, run: &Run<'_>) -> Flow<Result<String, Refusal>> {
        let mut words = self.redirection_arguments(target, run)?;
        Ok(match (words.pop(), words.is_empty()) {
            (Some(word), true) => Ok(word),
            (Some(_) | None, _) => Err(format!("{}: ambiguous redirect", written(target, run))),
        })
    }
}

/// The target as written, for messages.
fn written<'s>(target: &CommandWord, run: &Run<'s>) -> &'s str {
    target.span.text(run.source).unwrap_or_default()
}
