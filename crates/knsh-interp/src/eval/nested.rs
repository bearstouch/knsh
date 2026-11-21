//! `eval` and `source` (`.`): text the shell parses and runs itself, in its own state (KNSH-101; NFR-COMPAT-02).
//!
//! The text is parsed with the same parser as the script ([`knsh_bash::parse_with`]), checked as a script is
//! ([`crate::check`]), and run by the same evaluator, so every command in it is looked up, decided and started
//! exactly as one written in the script: through [`CommandSpawner`](knsh_platform::CommandSpawner), the seam
//! KNSH-108 decides at. What the check refuses stops the run there, as an expansion's refusal does.
//!
//! Messages from inside a sourced file are named after the file (bash's `BASH_SOURCE`), and lines are counted in
//! it; inside `eval` lines count on from the `eval` command's line. Bash parses such text one line at a time and
//! runs each before reading the next, so a syntax error stops only what follows it: the lines before the error are
//! run first, then the error is reported (`syntax error near unexpected token`, `syntax error: unexpected end of
//! file`) and the status is 2. A parse failure that cannot be reported exactly as bash would (an unterminated
//! quote, a construct the parser does not read) is refused instead.

use std::fmt::Write as _;
use std::path::PathBuf;

use knsh_bash::{ParseError, ParseOptions, Script, Span};
use knsh_platform::FileKind;

use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::check;
use crate::error::{InterpError, Unsupported};
use crate::status::Status;

/// Largest file `source` reads: the parser's own input limit, so a file is refused before it is read whole.
pub(crate) const MAX_SOURCE_LEN: usize = knsh_bash::MAX_INPUT_LEN;

/// Most bytes of `eval`, `source` and alias text run at once, counting every level still running: the parser's
/// input limit, so the nested texts in flight together are no longer than one script. Each level keeps its text and
/// its parsed tree until it ends, and a tree costs far more than its text (about 36 MB for 64 KiB of `:` lines, the
/// parser's token limit), so without this bound text that runs itself again (`. ./self.sh`, `x='eval "$x"'`) could
/// hold a tree for each of [`MAX_EVAL_DEPTH`] levels, tens of gigabytes. Text bytes bound tokens, and so trees:
/// real scripts nest a few small files.
///
/// [`MAX_EVAL_DEPTH`]: crate::MAX_EVAL_DEPTH
pub(crate) const MAX_NESTED_TEXT: usize = knsh_bash::MAX_INPUT_LEN;

/// Bash's `EX_BINARY_FILE`: `source` of a binary file.
const BINARY_FILE: Status = Status::new(126);

/// Where nested text comes from, for its messages.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// An `eval` string: syntax errors read `name: eval: line n: …`.
    Eval,
    /// A sourced file: messages read `file: line n: …`.
    Source,
}

/// How bash reports a syntax error in nested text.
struct SyntaxError {
    /// The message after `line n: `.
    message: String,
    /// The line it is reported on, in the text (1 for the first).
    line: usize,
    /// The line echoed after it (`` `a )' ``), for an unexpected token.
    echoed: Option<String>,
    /// Where the commands bash would have run before the error end: the start of the error's line.
    run_before: usize,
}

impl Interpreter {
    /// The parse options a line is read with, from the shell's options (as bash reads each line with the options
    /// set before it).
    pub(super) fn parse_options(&self) -> ParseOptions {
        let mut options = ParseOptions::default()
            .with_redirection_variables(true)
            .with_arrays(true)
            .with_coproc(true);
        options.extglob = self.state.options().extglob;
        options
    }

    /// Checks nested text before it runs, within the nesting the shell has left; past it, the error names the
    /// shell's whole limit.
    pub(super) fn check_nested(
        &self,
        items: &[knsh_bash::ListItem],
        source: &str,
        budget: usize,
    ) -> Result<(), InterpError> {
        check::check(items, source, budget, self.times.is_some()).map_err(|error| match error {
            InterpError::DepthExceeded { .. } => InterpError::DepthExceeded { limit: self.max_depth },
            other => other,
        })
    }

    /// `eval [arg …]`: the arguments joined with spaces, run as shell input.
    pub(super) fn eval_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (_, args) = match self.options("eval", "[arg ...]", "", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        if args.is_empty() {
            return Ok(Status::SUCCESS);
        }
        let text = args.join(" ");
        let nested = Run::nested(&text, run.origin, run.line(span).saturating_sub(1));
        self.trace_level += 1;
        let result = self.run_text(&nested, Kind::Eval, span);
        self.trace_level -= 1;
        result
    }

    /// `source file [args …]` and `. file [args …]` (`name`).
    pub(super) fn source_builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (_, args) = match self.options(name, "filename [arguments]", "", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let Some((file, parameters)) = args.split_first() else {
            self.report(span, run, format_args!("{name}: filename argument required"));
            self.report_plain(format_args!("{name}: usage: {name} filename [arguments]"));
            self.usage_error = true;
            return Ok(Status::new(2));
        };
        // The shell's own descriptors (`. /dev/stdin`) are not files the interpreter can read.
        if file.starts_with("/dev/fd/") || matches!(file.as_str(), "/dev/stdin" | "/dev/stdout" | "/dev/stderr") {
            return Err(unsupported(Unsupported::SourceDescriptor, span).into());
        }
        let Some(found) = self.find_source(file) else {
            // KNSH-106: POSIX mode does not look in the working directory; not finding the file ends a
            // non-interactive shell unless `command` runs `.`.
            self.report(span, run, format_args!("{name}: {file}: file not found"));
            return self.source_failed();
        };
        let path = self.state.cwd().join(&found);
        match self
            .fs
            .canonicalise(&path)
            .and_then(|canonical| self.fs.metadata(canonical.as_path()))
        {
            Ok(metadata) if metadata.kind == FileKind::Directory => {
                self.report(span, run, format_args!("{name}: {found}: is a directory"));
                return Ok(Status::FAILURE);
            }
            Ok(_) => {}
            Err(error) => {
                let reason = super::redirect::strerror(error.errno().unwrap_or(2));
                self.report(span, run, format_args!("{found}: {reason}"));
                return self.source_failed();
            }
        }
        let bytes = match self.fs.read(&path, MAX_SOURCE_LEN as u64) {
            Ok(bytes) => bytes,
            Err(knsh_platform::PlatformError::TooLarge { .. }) => {
                return Err(InterpError::ExpansionLimit {
                    what: "bytes of a sourced file",
                    limit: MAX_SOURCE_LEN,
                }
                .into());
            }
            Err(error) => {
                let reason = super::redirect::strerror(error.errno().unwrap_or(5));
                self.report(span, run, format_args!("{found}: {reason}"));
                return self.source_failed();
            }
        };
        if is_binary(&bytes) {
            self.report(span, run, format_args!("{name}: {found}: cannot execute binary file"));
            return Ok(BINARY_FILE);
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return Err(unsupported(Unsupported::NonUtf8Script, span).into());
        };
        // Arguments replace the positional parameters while the file runs, and are put back after, whatever it did.
        let saved = (!parameters.is_empty()).then(|| {
            let saved = self.state.positional().to_vec();
            self.state.set_positional(parameters.to_vec());
            saved
        });
        let nested = Run::nested(&text, Some(&found), 0);
        // KNSH-103: `source` is a frame of the call stack (`FUNCNAME` shows `source`, `BASH_SOURCE` the file).
        self.state.push_frame(crate::state::Frame {
            function: None,
            file: Some(found.clone()),
            line: run.line(span),
        });
        self.sourcing += 1;
        self.trace_level += 1;
        // KNSH-104: a sourced file does not inherit `DEBUG` without `set -T`; `RETURN` runs as it returns.
        let debug = (!self.state.options().functrace)
            .then(|| self.state.traps_mut().take(crate::trap::TrapId::Debug))
            .flatten();
        let result = self.run_text(&nested, Kind::Source, span);
        let result = match result {
            Ok(status) | Err(Stop::Return(status)) => self.return_trap(status, span, run).map(|()| status),
            other => other,
        };
        if let Some(debug) = debug {
            self.state
                .traps_mut()
                .restore_if_unset(crate::trap::TrapId::Debug, debug);
        }
        self.trace_level -= 1;
        self.sourcing -= 1;
        self.state.pop_frame();
        if let Some(saved) = saved {
            self.state.set_positional(saved);
        }
        match result {
            Err(Stop::Return(status)) => Ok(status),
            other => other,
        }
    }

    /// The status of `.` failing to open or read its file: 1, or in POSIX mode the end of a non-interactive shell
    /// with status 1 unless `command` runs `.` (bash's `FEVAL_LONGJMP`, KNSH-106).
    fn source_failed(&mut self) -> Flow<Status> {
        if self.posix_fatal() && self.command_depth == 0 {
            return Err(self.posix_error());
        }
        Ok(Status::FAILURE)
    }

    /// The file `source name` reads: `name` itself when it holds a `/`, otherwise the first regular file of that
    /// name in a `PATH` entry, or (outside POSIX mode, bash's `source_searches_cwd`) `name` in the working
    /// directory; `None` when POSIX mode finds none (KNSH-106).
    fn find_source(&self, name: &str) -> Option<String> {
        if name.contains('/') {
            return Some(name.to_owned());
        }
        if let Some(path) = self.state.variable("PATH") {
            for entry in path.as_encoded_bytes().split(|&byte| byte == b':') {
                let entry = String::from_utf8_lossy(entry);
                let dir = if entry.is_empty() { "." } else { entry.as_ref() };
                let candidate = PathBuf::from(dir).join(name);
                let absolute = self.state.cwd().join(&candidate);
                let regular = self
                    .fs
                    .canonicalise(&absolute)
                    .and_then(|canonical| self.fs.metadata(canonical.as_path()))
                    .is_ok_and(|metadata| metadata.kind == FileKind::File);
                if regular {
                    return Some(candidate.display().to_string());
                }
            }
        }
        (!self.state.options().source_skips_cwd).then(|| name.to_owned())
    }

    /// Parses, checks and runs the text of `nested`. Its status is its last command's, or 0 if it ran none.
    fn run_text(&mut self, nested: &Run<'_>, kind: Kind, span: Span) -> Flow<Status> {
        let result = self.holding_nested(nested.source.len(), |shell| {
            let script = match knsh_bash::parse_with(nested.source, shell.parse_options()) {
                Ok(script) => script,
                Err(error) => return shell.syntax_error(&error, nested, kind, span),
            };
            shell.run_parsed(&script, nested)
        });
        // KNSH-106: a usage error of a builtin the text ran (`eval 'pwd -Q'`) is not `eval`'s or `.`'s own: bash
        // converts it to status 2 as that builtin ends, so it must not end the shell as the special builtin's.
        self.usage_error = false;
        result
    }

    /// Runs `body` while `len` more bytes of nested text are held, within [`MAX_NESTED_TEXT`]: past it the run
    /// fails with [`InterpError::ExpansionLimit`] before the text is parsed.
    pub(super) fn holding_nested(&mut self, len: usize, body: impl FnOnce(&mut Self) -> Flow<Status>) -> Flow<Status> {
        let held = self.nested_bytes.saturating_add(len);
        if held > MAX_NESTED_TEXT {
            return Err(InterpError::ExpansionLimit {
                what: "bytes of eval, source and alias text running at once",
                limit: MAX_NESTED_TEXT,
            }
            .into());
        }
        let before = std::mem::replace(&mut self.nested_bytes, held);
        let result = body(self);
        self.nested_bytes = before;
        result
    }

    /// Checks and runs `script`, parsed from `nested`'s text.
    fn run_parsed(&mut self, script: &Script, nested: &Run<'_>) -> Flow<Status> {
        let budget = self.max_depth.saturating_sub(self.depth);
        self.check_nested(&script.items, nested.source, budget)?;
        if script.items.is_empty() {
            return Ok(Status::SUCCESS);
        }
        self.script(&script.items, nested)
    }

    /// A syntax error in nested text: what bash would have run before it is run, then the error is reported with
    /// status 2; refused when it cannot be reported as bash does.
    fn syntax_error(&mut self, error: &ParseError, nested: &Run<'_>, kind: Kind, span: Span) -> Flow<Status> {
        let refused = || -> Stop { unsupported(Unsupported::Unparsed, span).into() };
        let Some(syntax) = describe(error, nested.source) else {
            return Err(refused());
        };
        let before = nested.source.get(..syntax.run_before).unwrap_or("");
        if !before.trim().is_empty() {
            // The complete lines before the error's line, as bash would have read and run them.
            if before.ends_with("\\\n") {
                return Err(refused());
            }
            let Ok(script) = knsh_bash::parse_with(before, self.parse_options()) else {
                return Err(refused());
            };
            let prefix = Run::nested(before, nested.origin, nested.line_base);
            self.run_parsed(&script, &prefix)?;
        }
        let name = nested
            .origin
            .map_or_else(|| self.state.name().to_owned(), ToOwned::to_owned);
        let place = match kind {
            Kind::Eval => format!("{name}: eval: line {}", nested.line_base + syntax.line),
            Kind::Source => format!("{name}: line {}", nested.line_base + syntax.line),
        };
        let mut text = format!("{place}: {}\n", syntax.message);
        if let Some(echoed) = syntax.echoed {
            let _ = writeln!(text, "{place}: `{echoed}'");
        }
        self.write_shell(2, text.as_bytes());
        // KNSH-106: in POSIX mode a syntax error in `eval` or `.` text ends a non-interactive shell with status 2,
        // unless `command` runs the builtin.
        if self.posix_fatal() && self.command_depth == 0 {
            return Err(self.usage_exit());
        }
        self.state.set_last_status(Status::new(2));
        Ok(Status::new(2))
    }
}

/// Bash's report of `error` in `text`, if it can be given exactly.
fn describe(error: &ParseError, text: &str) -> Option<SyntaxError> {
    let line_of = |at: usize| text.get(..at).map_or(1, |before| before.matches('\n').count() + 1);
    let line_start = |at: usize| {
        text.get(..at)
            .and_then(|before| before.rfind('\n'))
            .map_or(0, |at| at + 1)
    };
    let line_text = |at: usize| {
        let start = line_start(at);
        let end = text[start..].find('\n').map_or(text.len(), |end| start + end);
        text[start..end].to_owned()
    };
    // Bash counts the line after a final newline when it reaches the end of the text.
    let end_line = text.matches('\n').count() + 1;
    let end_of_file = |opened: usize| SyntaxError {
        message: "syntax error: unexpected end of file".to_owned(),
        line: end_line,
        echoed: None,
        run_before: line_start(opened),
    };
    let blank_after = |at: usize| {
        text.get(at..).is_some_and(|rest| {
            rest.lines()
                .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        })
    };
    match error {
        ParseError::UnexpectedToken { span, .. } => {
            let token = span.text(text)?;
            let token = if token == "\n" { "newline" } else { token };
            Some(SyntaxError {
                message: format!("syntax error near unexpected token `{token}'"),
                line: line_of(span.start),
                echoed: Some(line_text(span.start)),
                run_before: line_start(span.start),
            })
        }
        ParseError::MissingRedirectionTarget { span } => {
            // Only a redirection at the end of its line: the token bash meets is the newline.
            let rest = text.get(span.end..)?;
            let next = rest.trim_start_matches([' ', '\t']);
            (next.is_empty() || next.starts_with('\n')).then(|| SyntaxError {
                message: "syntax error near unexpected token `newline'".to_owned(),
                line: line_of(span.start),
                echoed: Some(line_text(span.start)),
                run_before: line_start(span.start),
            })
        }
        ParseError::MissingCommand { span } if blank_after(span.end) => Some(end_of_file(span.start)),
        ParseError::Unclosed { span } => Some(end_of_file(span.start)),
        ParseError::MissingCommand { .. }
        | ParseError::Lex(_)
        | ParseError::MissingHereDocumentBody { .. }
        | ParseError::Unsupported { .. }
        | ParseError::NestingTooDeep { .. } => None,
    }
}

/// Bash's `check_binary_file` on the first 80 bytes: an ELF header, or a NUL before the first newline (anywhere in
/// the sample after a `#!` line).
fn is_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(80)];
    if sample.starts_with(b"\x7fELF") {
        return true;
    }
    let interpreter_line = sample.starts_with(b"#!");
    for &byte in sample {
        if byte == b'\n' && !interpreter_line {
            return false;
        }
        if byte == 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_files_are_found_as_bash_finds_them() {
        assert!(is_binary(b"\x7fELF\x02"));
        assert!(is_binary(b"ab\0cd"));
        assert!(!is_binary(b"echo hi\n\0"));
        assert!(is_binary(b"#!/bin/sh\necho\0"));
        assert!(!is_binary(b"echo hi"));
    }

    #[test]
    fn syntax_errors_are_described_as_bash_reports_them() {
        let text = "echo a\n)\necho b\n";
        let error = knsh_bash::parse(text).unwrap_err();
        let described = describe(&error, text).unwrap();
        assert_eq!(described.message, "syntax error near unexpected token `)'");
        assert_eq!(described.line, 2);
        assert_eq!(described.echoed.as_deref(), Some(")"));
        assert_eq!(described.run_before, 7);
        let text = "echo one\nif true\n";
        let error = knsh_bash::parse(text).unwrap_err();
        let described = describe(&error, text).unwrap();
        assert_eq!(described.message, "syntax error: unexpected end of file");
        assert_eq!(described.line, 3);
        assert_eq!(described.run_before, 9);
        // An unterminated quote is refused rather than reported differently from bash.
        let error = knsh_bash::parse("echo 'a").unwrap_err();
        assert!(describe(&error, "echo 'a").is_none());
    }
}
