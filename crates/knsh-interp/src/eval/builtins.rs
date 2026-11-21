//! Running a command name: a builtin the interpreter runs itself, or a program found on `PATH` (KNSH-101;
//! NFR-COMPAT-02, NFR-COMPAT-09), and the builtins that find or describe commands: `command`, `builtin`, `type`,
//! `hash` and `exec`.
//!
//! - Assignments before a builtin (`HOME=/x cd`) are made in the shell for the builtin's run only and exported to
//!   what it starts, then undone, as bash's temporary environment; `export` and `readonly` keep the ones they name.
//! - A program found by searching `PATH` is remembered in the hash table (bash's `phash_insert`) and run from it
//!   afterwards; a command's own `PATH=…` and `command -p` search without the table, as bash does.
//! - Every program, whatever started it (a command, `command`, `exec`, `eval`, `source`), starts through
//!   [`CommandSpawner`](knsh_platform::CommandSpawner), the seam KNSH-108 decides at.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use knsh_bash::Span;
use knsh_platform::{CommandRequest, Started};

use super::{Flow, Interpreter, Run, Sink, Stop, is_bash_builtin, is_native_builtin, is_refused_builtin, unsupported};
use crate::error::Unsupported;
use crate::lookup::{self, Missing, Refusal, Resolved};
use crate::quote;
use crate::status::Status;

/// The search path `command -p` uses: macOS's `confstr(_CS_PATH)`, bash's `conf_standard_path` there.
pub(super) const STANDARD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Bash's reserved words, which `type` and `command -v` report as keywords.
const KEYWORDS: &[&str] = &[
    "!", "[[", "]]", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "in",
    "select", "then", "time", "until", "while", "{", "}",
];

/// How a program is searched for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Search {
    /// `PATH` (the command's own `PATH=…` if it has one) and the hash table.
    Normal,
    /// `command -p`: the standard path, without the hash table.
    Standard,
}

/// What `type` and `command -v`/`-V` print for each name (bash's `CDESC_*` flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Describe {
    /// `type`, `command -V`: `ls is /bin/ls`.
    Sentence,
    /// `type -t`: `file`.
    Kind,
    /// `type -p`, `type -P`: the path of a file only.
    PathOnly,
    /// `command -v`: what would run, reusable as input (`alias ll='ls -l'`, `cd`, `/bin/ls`).
    Reusable,
}

/// Whether declaration builtin `name` run with `args` keeps the temporary assignments it names (bash's
/// `att_propagate`): `export` (not `export -n`, which only removes the attribute), `readonly`, and `declare` or
/// `typeset` turning on `-x` or `-r` (`x=1 declare -r x` leaves `x` read-only, as `x=1 readonly x` does).
fn propagates(name: &str, args: &[String]) -> bool {
    let options = || {
        args.iter()
            .take_while(|arg| arg.len() > 1 && (arg.starts_with('-') || arg.starts_with('+')) && *arg != "--")
            .filter(|arg| arg.starts_with('-'))
            .flat_map(|arg| arg.chars().skip(1))
    };
    match name {
        "export" => !options().any(|letter| letter == 'n'),
        "readonly" => true,
        "declare" | "typeset" => options().any(|letter| matches!(letter, 'x' | 'r')),
        _ => false,
    }
}

impl Interpreter {
    /// Runs command `name` with `args`: a builtin, or the program `name` names, with `assignments` before it.
    pub(super) fn invoke(
        &mut self,
        name: &str,
        args: &[String],
        assignments: &[(String, OsString)],
        search: Search,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        if is_native_builtin(name) {
            // `a=1 let …` gives `let` a scope bash's arithmetic reads and assigns in: not emulated.
            if name == "let" && !assignments.is_empty() {
                return Err(unsupported(Unsupported::Builtin, span).into());
            }
            return self.with_temporary(name, args, assignments, |shell| shell.builtin(name, args, span, run));
        }
        if is_refused_builtin(name) {
            return Err(unsupported(Unsupported::Builtin, span).into());
        }
        self.external(name, args, assignments, search, span, run)
    }

    /// Runs `body` with `assignments` made in the shell and exported, then puts back what they replaced: bash's
    /// temporary environment for a builtin. `export`, `readonly`, and `declare`/`typeset` with `-x` or `-r`, keep
    /// those they name without a value, as bash moves such a variable out of the temporary environment
    /// (`att_propagate`).
    fn with_temporary(
        &mut self,
        name: &str,
        args: &[String],
        assignments: &[(String, OsString)],
        body: impl FnOnce(&mut Self) -> Flow<Status>,
    ) -> Flow<Status> {
        if assignments.is_empty() {
            return body(self);
        }
        let saved: Vec<_> = assignments
            .iter()
            .map(|(variable, value)| {
                let previous = self.state.save_variable(variable);
                self.state.set_temporary(variable, value.clone());
                (variable.clone(), previous)
            })
            .collect();
        let result = body(self);
        let kept: Vec<&str> = if propagates(name, args) {
            args.iter()
                .map(String::as_str)
                .filter(|arg| !arg.contains('='))
                .collect()
        } else {
            Vec::new()
        };
        for (variable, previous) in saved.into_iter().rev() {
            if !kept.contains(&variable.as_str()) {
                self.state.restore_variable(&variable, previous);
            }
        }
        result
    }

    /// The builtin `name` (one of [`NATIVE_BUILTINS`](super::NATIVE_BUILTINS)) with `args`.
    pub(super) fn builtin(&mut self, name: &str, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        match name {
            ":" | "true" => Ok(Status::SUCCESS),
            "false" => Ok(Status::FAILURE),
            "let" => self.let_builtin(args, span, run),
            "echo" => Ok(self.echo_builtin(args, span, run)),
            "umask" => self.umask_builtin(args, span, run),
            "cd" => Ok(self.cd_builtin(args, span, run)),
            "pwd" => Ok(self.pwd_builtin(args, span, run)),
            "export" | "readonly" | "declare" | "typeset" | "local" => self.declare_builtin(name, args, span, run),
            "unset" => self.unset_builtin(args, span, run),
            "mapfile" | "readarray" => self.mapfile_builtin(name, args, span, run),
            "shift" => self.shift_builtin(args, span, run),
            "set" => self.set_builtin(args, span),
            "exit" => self.exit_builtin(args, span, run),
            "return" => self.return_builtin(args, span, run),
            "break" | "continue" => self.loop_builtin(name, args, span, run),
            "eval" => self.eval_builtin(args, span, run),
            "source" | "." => self.source_builtin(name, args, span, run),
            "alias" => Ok(self.alias_builtin(args, span, run)),
            "unalias" => Ok(self.unalias_builtin(args, span, run)),
            "builtin" => self.builtin_builtin(args, span, run),
            "command" => self.command_builtin(args, span, run),
            "type" => self.type_builtin(args, span, run),
            "hash" => Ok(self.hash_builtin(args, span, run)),
            "exec" => self.exec_builtin(args, &[], span, run),
            "test" | "[" => self.test_builtin(name, args, span, run),
            "printf" => self.printf_builtin(args, span, run),
            "read" => self.read_builtin(args, span, run),
            _ => match self.job_builtin(name, args, span, run) {
                Some(result) => result,
                None => Err(unsupported(Unsupported::Builtin, span).into()),
            },
        }
    }

    /// Writes a builtin's output to the shell's standard output: 0, or bash's `name: write error: …` and 1.
    pub(super) fn print(&mut self, name: &str, text: &[u8], span: Span, run: &Run<'_>) -> Status {
        if text.is_empty() {
            return Status::SUCCESS;
        }
        match self.write_out(1, text) {
            Ok(()) => Status::SUCCESS,
            Err(errno) => {
                let reason = super::redirect::strerror(errno);
                self.report(span, run, format_args!("{name}: write error: {reason}"));
                Status::FAILURE
            }
        }
    }

    /// Finds program `name` as bash's `search_for_command` does: the hash table first, then `PATH` (or the
    /// standard path, or the command's own `PATH=…`), remembering what `PATH` found.
    fn resolve(&mut self, name: &str, assignments: &[(String, OsString)], search: Search) -> Resolved {
        let own_path = assignments
            .iter()
            .rev()
            .find(|(assigned, _)| assigned == "PATH")
            .map(|(_, value)| value.clone());
        let path: Option<OsString> = match search {
            Search::Standard => Some(STANDARD_PATH.into()),
            Search::Normal => own_path
                .clone()
                .or_else(|| self.state.variable("PATH").map(ToOwned::to_owned)),
        };
        // Bash hashes only what a search of the shell's own `PATH` found.
        let hashable = search == Search::Normal && own_path.is_none() && path.is_some() && !name.contains('/');
        if hashable && let Some(program) = self.state.hash_use(name) {
            // `hash -p` may have stored a relative path; it names a file from the working directory.
            return Resolved::Program(self.state.cwd().join(program));
        }
        let resolved = lookup::find(&*self.fs, name, path.as_deref(), self.state.cwd());
        if hashable && let Resolved::Program(program) = &resolved {
            self.state.hash_insert(name, program.clone(), 1);
        }
        resolved
    }

    /// Runs the program `name` names with `args` and `assignments` in its environment.
    fn external(
        &mut self,
        name: &str,
        args: &[String],
        assignments: &[(String, OsString)],
        search: Search,
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        match self.resolve(name, assignments, search) {
            Resolved::Program(program) => {
                let request = self.request(program, name.into(), args, self.state.environment(assignments));
                self.run_program(&request, name, span, run)
            }
            Resolved::NotFound(missing) => {
                let reason = match missing {
                    Missing::NotOnPath => "command not found",
                    Missing::NoSuchFile => "No such file or directory",
                };
                self.report(span, run, format_args!("{name}: {reason}"));
                Ok(Status::NOT_FOUND)
            }
            Resolved::NotExecutable(refusal) => {
                let reason = match refusal {
                    Refusal::Directory => "Is a directory",
                    Refusal::PermissionDenied => "Permission denied",
                };
                self.report(span, run, format_args!("{name}: {reason}"));
                Ok(Status::NOT_EXECUTABLE)
            }
        }
    }

    /// The request that runs `program` as `argv0` with `args` and `env`, in the shell's directory, descriptors and
    /// umask.
    fn request(
        &self,
        program: PathBuf,
        argv0: OsString,
        args: &[String],
        env: Vec<(OsString, OsString)>,
    ) -> CommandRequest {
        CommandRequest {
            program,
            argv0,
            args: args.iter().map(OsString::from).collect(),
            env,
            cwd: self.state.cwd().to_path_buf(),
            descriptors: self.fds.child_table(),
            umask: self.state.umask(),
        }
    }

    /// Starts `request` and waits for it, unless it is a pipeline stage's program, which the pipeline waits for.
    fn run_program(&mut self, request: &CommandRequest, name: &str, span: Span, run: &Run<'_>) -> Flow<Status> {
        let outcome = match self.start_command(request)? {
            Started::Refused(outcome) => outcome,
            Started::Running(child) if self.sink == Sink::Open => {
                self.sink = Sink::Started(child);
                return Ok(Status::SUCCESS);
            }
            Started::Running(child) => self.wait_alone(child)?,
        };
        Ok(self.outcome_status(outcome, name, span, run))
    }

    /// `exec [-cl] [-a name] [command [args …]]` with `assignments` before it: without a command, only its
    /// redirections, which then last (KNSH-099); with one, the program runs and the shell ends with its status, as
    /// if replaced by it. A program that cannot run ends a non-interactive shell too (127 or 126).
    pub(super) fn exec_builtin(
        &mut self,
        args: &[String],
        assignments: &[(String, OsString)],
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        let mut clean = false;
        let mut login = false;
        let mut argv0: Option<String> = None;
        let mut rest = args;
        while let Some(first) = rest.first() {
            if first == "--" {
                rest = &rest[1..];
                break;
            }
            let Some(letters) = first.strip_prefix('-').filter(|letters| !letters.is_empty()) else {
                break;
            };
            rest = &rest[1..];
            for (at, letter) in letters.char_indices() {
                match letter {
                    'c' => clean = true,
                    'l' => login = true,
                    'a' => {
                        // The name is the rest of the word, or the next word.
                        let attached = &letters[at + 1..];
                        if attached.is_empty() {
                            let Some((next, after)) = rest.split_first() else {
                                self.report(span, run, format_args!("exec: -a: option requires an argument"));
                                self.report_plain(format_args!(
                                    "exec: usage: exec [-cl] [-a name] [command [argument ...]] [redirection ...]"
                                ));
                                return self.exec_failed(Status::new(2));
                            };
                            argv0 = Some(next.clone());
                            rest = after;
                        } else {
                            argv0 = Some(attached.to_owned());
                        }
                        break;
                    }
                    bad => {
                        self.report(span, run, format_args!("exec: -{bad}: invalid option"));
                        self.report_plain(format_args!(
                            "exec: usage: exec [-cl] [-a name] [command [argument ...]] [redirection ...]"
                        ));
                        return self.exec_failed(Status::new(2));
                    }
                }
            }
        }
        let Some((name, command_args)) = rest.split_first() else {
            return Ok(Status::SUCCESS);
        };
        let resolved = if name.contains('/') {
            lookup::find(&*self.fs, name, None, self.state.cwd())
        } else {
            self.resolve(name, assignments, Search::Normal)
        };
        let program = match resolved {
            Resolved::Program(program) => program,
            Resolved::NotFound(_) => {
                self.report(span, run, format_args!("exec: {name}: not found"));
                return self.exec_failed(Status::NOT_FOUND);
            }
            Resolved::NotExecutable(refusal) => {
                let reason = match refusal {
                    Refusal::Directory => "Is a directory",
                    Refusal::PermissionDenied => "Permission denied",
                };
                self.report(span, run, format_args!("exec: {name}: cannot execute: {reason}"));
                return self.exec_failed(Status::NOT_EXECUTABLE);
            }
        };
        let shown = argv0.unwrap_or_else(|| name.clone());
        let shown = if login { format!("-{shown}") } else { shown };
        let env = if clean {
            Vec::new()
        } else {
            let mut env = self.state.environment(assignments);
            // Bash lowers `SHLVL` for the program that replaces it, so a shell started there has the same level.
            if !self.is_subshell
                && let Some((_, level)) = env.iter_mut().find(|(key, _)| key == "SHLVL")
                && let Some(number) = level.to_str().and_then(|text| text.trim().parse::<i64>().ok())
            {
                *level = number.saturating_sub(1).to_string().into();
            }
            env
        };
        let request = self.request(program, shown.into(), command_args, env);
        // A pipeline stage: the pipeline waits for the program. A subshell's stage ends with it anyway; the shell's
        // own foreground job ends the shell once waited for.
        if self.sink == Sink::Open {
            let started = self.run_program(&request, name, span, run)?;
            if self.sink == Sink::Open {
                // The program could not start: its status is known now, and it ends the shell as a program `exec`
                // could not find does (a non-interactive shell or a subshell only).
                return self.exec_failed(started);
            }
            if !self.is_subshell {
                self.exit_after_job = true;
            }
            return Ok(started);
        }
        let status = self.run_program(&request, name, span, run)?;
        Err(Stop::Exit(status))
    }

    /// The end of an `exec` that could not run its program: a non-interactive shell (or a subshell) exits with
    /// `status`, an interactive one goes on.
    fn exec_failed(&self, status: Status) -> Flow<Status> {
        if self.is_subshell || !self.state.is_interactive() {
            Err(Stop::Exit(status))
        } else {
            Ok(status)
        }
    }

    /// `builtin [name [args …]]`: runs the builtin `name`, never a program.
    fn builtin_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let args = match args.first() {
            Some(first) if first == "--" => &args[1..],
            _ => args,
        };
        let Some((name, rest)) = args.split_first() else {
            return Ok(Status::SUCCESS);
        };
        if is_native_builtin(name) {
            return self.builtin(name, rest, span, run);
        }
        if is_bash_builtin(name) {
            return Err(unsupported(Unsupported::Builtin, span).into());
        }
        self.report(span, run, format_args!("builtin: {name}: not a shell builtin"));
        Ok(Status::FAILURE)
    }

    /// `command [-pVv] name [args …]`: runs `name` as a builtin or program (never a function), or describes it (a
    /// function too).
    fn command_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, rest) = match self.options("command", "[-pVv] command [arg ...]", "pVv", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let standard = options.contains('p');
        // The last of `-v` and `-V` wins, as bash's option loop sets one variable.
        let describe = options.chars().rev().find_map(|letter| match letter {
            'v' => Some(Describe::Reusable),
            'V' => Some(Describe::Sentence),
            _ => None,
        });
        if let Some(describe) = describe {
            if describe == Describe::Sentence && self.describes_a_function(rest, false) {
                return Err(unsupported(Unsupported::FunctionPrint, span).into());
            }
            let mut any = false;
            for name in rest {
                let found = self.describe(name, describe, false, standard, span, run);
                if !found && describe == Describe::Sentence {
                    self.report(span, run, format_args!("command: {name}: not found"));
                }
                any |= found;
            }
            return Ok(if any { Status::SUCCESS } else { Status::FAILURE });
        }
        let Some((name, rest)) = rest.split_first() else {
            return Ok(Status::SUCCESS);
        };
        let search = if standard { Search::Standard } else { Search::Normal };
        self.invoke(name, rest, &[], search, span, run)
    }

    /// `type [-afptP] name …`.
    fn type_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, names) = match self.options("type", "[-afptP] name [name ...]", "afptP", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        let all = options.contains('a');
        let mut describe = Describe::Sentence;
        let mut force_path = false;
        for letter in options.chars() {
            match letter {
                'p' => describe = Describe::PathOnly,
                't' => describe = Describe::Kind,
                'P' => {
                    describe = Describe::PathOnly;
                    force_path = true;
                }
                _ => {}
            }
        }
        if describe == Describe::Sentence && !force_path && self.describes_a_function(names, all) {
            return Err(unsupported(Unsupported::FunctionPrint, span).into());
        }
        let mut failed = false;
        for name in names {
            let found = if force_path {
                self.describe_file(name, describe, all, false, span, run)
            } else {
                self.describe(name, describe, all, false, span, run)
            };
            if !found && describe == Describe::Sentence {
                self.report(span, run, format_args!("type: {name}: not found"));
            }
            failed |= !found;
        }
        Ok(if failed { Status::FAILURE } else { Status::SUCCESS })
    }

    /// Prints what `name` is as `describe` says (bash's `describe_command`), all of its meanings with `all`;
    /// whether it is anything. With `standard`, files are searched on the standard path.
    fn describe(
        &mut self,
        name: &str,
        describe: Describe,
        all: bool,
        standard: bool,
        span: Span,
        run: &Run<'_>,
    ) -> bool {
        let mut found = false;
        // Bash reports an alias only while aliases are expanded.
        if self.state.options().expand_aliases
            && let Some(value) = self.state.alias(name).map(ToOwned::to_owned)
        {
            let line = match describe {
                Describe::Kind => Some("alias".to_owned()),
                Describe::Sentence => Some(format!("{name} is aliased to `{value}'")),
                Describe::Reusable => Some(format!("alias {name}={}", quote::single(&value))),
                Describe::PathOnly => None,
            };
            self.describe_line(line, span, run);
            found = true;
            if !all {
                return true;
            }
        }
        if KEYWORDS.contains(&name) {
            let line = match describe {
                Describe::Kind => Some("keyword".to_owned()),
                Describe::Sentence => Some(format!("{name} is a shell keyword")),
                Describe::Reusable => Some(name.to_owned()),
                Describe::PathOnly => None,
            };
            self.describe_line(line, span, run);
            found = true;
            if !all {
                return true;
            }
        }
        if self.state.function(name).is_some() {
            // A sentence is followed by the definition, which callers refuse before describing (bash's
            // pretty-printer is not reproduced); `type -p` prints nothing for a function and stops there.
            let line = match describe {
                Describe::Kind => Some("function".to_owned()),
                Describe::Reusable => Some(name.to_owned()),
                Describe::Sentence | Describe::PathOnly => None,
            };
            self.describe_line(line, span, run);
            found = true;
            if !all {
                return true;
            }
        }
        if is_bash_builtin(name) {
            let line = match describe {
                Describe::Kind => Some("builtin".to_owned()),
                Describe::Sentence => Some(format!("{name} is a shell builtin")),
                Describe::Reusable => Some(name.to_owned()),
                Describe::PathOnly => None,
            };
            self.describe_line(line, span, run);
            found = true;
            if !all {
                return true;
            }
        }
        self.describe_file(name, describe, all, standard, span, run) || found
    }

    /// The file part of [`Interpreter::describe`]: a name with a `/`, the hash table (unless `all`), then the
    /// search path.
    fn describe_file(
        &mut self,
        name: &str,
        describe: Describe,
        all: bool,
        standard: bool,
        span: Span,
        run: &Run<'_>,
    ) -> bool {
        let file_line = |path: &str| match describe {
            Describe::Kind => "file".to_owned(),
            Describe::Sentence => format!("{name} is {path}"),
            Describe::Reusable | Describe::PathOnly => path.to_owned(),
        };
        if name.contains('/') {
            let path = self.state.cwd().join(name);
            if lookup::is_executable(&*self.fs, &path) {
                self.describe_line(Some(file_line(name)), span, run);
                return true;
            }
        }
        if !all
            && !standard
            && let Some(path) = self.state.hash_use(name)
        {
            let path = path.display().to_string();
            let line = match describe {
                Describe::Sentence => format!("{name} is hashed ({path})"),
                Describe::Kind | Describe::Reusable | Describe::PathOnly => file_line(&path),
            };
            self.describe_line(Some(line), span, run);
            return true;
        }
        let path: Option<OsString> = if standard {
            Some(STANDARD_PATH.into())
        } else {
            self.state.variable("PATH").map(ToOwned::to_owned)
        };
        let found: Vec<PathBuf> = if all {
            lookup::all_on_path(&*self.fs, name, path.as_deref(), self.state.cwd())
        } else if name.contains('/') {
            Vec::new()
        } else {
            match lookup::find(&*self.fs, name, path.as_deref(), self.state.cwd()) {
                Resolved::Program(program) => vec![program],
                Resolved::NotFound(_) | Resolved::NotExecutable(_) => Vec::new(),
            }
        };
        for program in &found {
            let line = file_line(&program.display().to_string());
            self.describe_line(Some(line), span, run);
        }
        !found.is_empty()
    }

    /// Whether describing `names` as a sentence (`type`, `command -V`) would print a function's definition, which
    /// bash re-formats with its pretty-printer (refused, KNSH-103): a function that no alias shown first hides.
    fn describes_a_function(&self, names: &[String], all: bool) -> bool {
        names.iter().any(|name| {
            let aliased = self.state.options().expand_aliases && self.state.alias(name).is_some();
            self.state.function(name).is_some() && (all || !aliased)
        })
    }

    /// Prints one line of `type` or `command -v` output, if any.
    fn describe_line(&mut self, line: Option<String>, span: Span, run: &Run<'_>) {
        if let Some(mut line) = line {
            line.push('\n');
            let _ = self.print("type", line.as_bytes(), span, run);
        }
    }

    /// `hash [-lr] [-p path] [-dt] [name …]`.
    fn hash_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Status {
        const USAGE: &str = "[-lr] [-p pathname] [-dt] [name ...]";
        let mut letters = String::new();
        let mut pathname: Option<String> = None;
        let mut rest = args;
        while let Some(first) = rest.first() {
            if first == "--" {
                rest = &rest[1..];
                break;
            }
            let Some(options) = first.strip_prefix('-').filter(|options| !options.is_empty()) else {
                break;
            };
            rest = &rest[1..];
            for (at, letter) in options.char_indices() {
                match letter {
                    'd' | 'l' | 'r' | 't' => letters.push(letter),
                    'p' => {
                        let attached = &options[at + 1..];
                        if attached.is_empty() {
                            let Some((next, after)) = rest.split_first() else {
                                self.report(span, run, format_args!("hash: -p: option requires an argument"));
                                self.report_plain(format_args!("hash: usage: hash {USAGE}"));
                                return Status::new(2);
                            };
                            pathname = Some(next.clone());
                            rest = after;
                        } else {
                            pathname = Some(attached.to_owned());
                        }
                        break;
                    }
                    bad => {
                        self.report(span, run, format_args!("hash: -{bad}: invalid option"));
                        self.report_plain(format_args!("hash: usage: hash {USAGE}"));
                        return Status::new(2);
                    }
                }
            }
        }
        let portable = letters.contains('l');
        let delete = letters.contains('d');
        let targets = letters.contains('t');
        if rest.is_empty() && (delete || targets) {
            let option = if delete { "-d" } else { "-t" };
            self.report(span, run, format_args!("hash: {option}: option requires an argument"));
            return Status::FAILURE;
        }
        let flush = letters.contains('r');
        if rest.is_empty() && !flush {
            return self.print_hash_table(portable, span, run);
        }
        if flush {
            self.state.hash_clear();
        }
        if targets {
            return self.hash_targets(rest, portable, span, run);
        }
        let mut status = Status::SUCCESS;
        for name in rest {
            if name.contains('/') {
                continue;
            }
            if let Some(path) = &pathname {
                let full = self.state.cwd().join(path);
                if super::cd::is_directory(&*self.fs, &full) {
                    self.report(span, run, format_args!("hash: {path}: Is a directory"));
                    status = Status::FAILURE;
                } else {
                    self.state.hash_insert(name, PathBuf::from(path), 0);
                }
            } else if delete {
                if !self.state.hash_remove(name) {
                    self.report(span, run, format_args!("hash: {name}: not found"));
                    status = Status::FAILURE;
                }
            } else if !is_bash_builtin(name) {
                self.state.hash_remove(name);
                let path = self.state.variable("PATH").map(ToOwned::to_owned);
                match lookup::find(&*self.fs, name, path.as_deref(), self.state.cwd()) {
                    Resolved::Program(program) => self.state.hash_insert(name, program, 0),
                    Resolved::NotFound(_) | Resolved::NotExecutable(_) => {
                        self.report(span, run, format_args!("hash: {name}: not found"));
                        status = Status::FAILURE;
                    }
                }
            }
        }
        status
    }

    /// `hash` or `hash -l` without names: the table, or bash's `hash table empty`.
    fn print_hash_table(&mut self, portable: bool, span: Span, run: &Run<'_>) -> Status {
        let entries: Vec<(String, String, u32)> = self
            .state
            .hash_entries()
            .into_iter()
            .map(|(name, entry)| (name.to_owned(), entry.path.display().to_string(), entry.hits))
            .collect();
        if entries.is_empty() {
            return self.print("hash", b"hash: hash table empty\n", span, run);
        }
        let mut text = String::new();
        if !portable {
            text.push_str("hits\tcommand\n");
        }
        for (name, path, hits) in entries {
            if portable {
                let _ = writeln!(
                    text,
                    "builtin hash -p {} {}",
                    quote::reusable(&path),
                    quote::reusable(&name)
                );
            } else {
                let _ = writeln!(text, "{hits:4}\t{path}");
            }
        }
        self.print("hash", text.as_bytes(), span, run)
    }

    /// `hash -t name …`: each name's path, by name when there are several.
    fn hash_targets(&mut self, names: &[String], portable: bool, span: Span, run: &Run<'_>) -> Status {
        let mut status = Status::SUCCESS;
        let several = names.len() > 1;
        for name in names {
            let Some(path) = self.state.hash_use(name) else {
                self.report(span, run, format_args!("hash: {name}: not found"));
                status = Status::FAILURE;
                continue;
            };
            let path = path.display().to_string();
            let line = if portable {
                format!("builtin hash -p {path} {name}\n")
            } else if several {
                format!("{name}\t{path}\n")
            } else {
                format!("{path}\n")
            };
            if self.print("hash", line.as_bytes(), span, run) != Status::SUCCESS {
                status = Status::FAILURE;
            }
        }
        status
    }
}
