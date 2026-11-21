//! The `trap` builtin and when traps run (KNSH-104; NFR-COMPAT-02), as bash 5.2's `trap.def`, `trap.c` and
//! `execute_cmd.c` do.
//!
//! - `trap cmd sig…` sets, `trap '' sig…` ignores, `trap - sig…` (or a lone signal, or a number first) resets; the
//!   command text is parsed and checked when it is set, so a trap the interpreter cannot run is refused at the
//!   `trap` command rather than when it fires. `trap`, `trap -p` and `trap -l` list.
//! - A trap runs as `eval` text would, in the shell itself; `$?` and `PIPESTATUS` are put back after it, unless it
//!   exits. `DEBUG` never runs inside a trap, and no trap runs inside itself.
//! - `EXIT` runs once, when the shell or a subshell exits (normally, through `exit` or `set -e`, or by a signal bash
//!   runs it for); the exit status stays the one it exits with unless the trap runs `exit`.
//! - `ERR` runs after a pipeline fails where `set -e` would exit (the same exemptions), then `set -e` exits.
//! - Functions do not inherit `DEBUG` and `RETURN` unless `set -T` (or `declare -ft`), nor `ERR` unless `set -E`:
//!   those are taken away for the call and put back after unless the function set its own (bash 5.2's
//!   `trap_if_untrapped`). `RETURN` runs as a function or sourced file returns; `source` does not inherit `DEBUG`.
//! - The host hands over the signals sent to the shell ([`ShellSignals`](crate::ShellSignals)); after each pipeline
//!   the shell runs their traps or takes their default action.

use std::fmt::Write as _;
use std::sync::Arc;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, Stop, unsupported};
use crate::error::{InterpError, Unsupported};
use crate::quote;
use crate::status::Status;
use crate::trap::{self, Action, Default, TrapId};

/// Bash 5.2's `trap` usage line.
const TRAP_USAGE: &str = "trap: usage: trap [-lp] [[arg] signal_spec ...]";

/// What a `trap` command changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation<'a> {
    /// Runs this command text.
    Set(&'a str),
    /// `''`: ignores.
    Ignore,
    /// `-`, or a signal alone: back to the default.
    Revert,
}

/// How bash's `trap_builtin` reads its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form<'a> {
    /// `-l`: the signal names.
    Signals,
    /// `trap` alone or `-p`: the traps on these signals (all of them when empty).
    Print(&'a [String]),
    /// Changes the traps on these signals.
    Change(Operation<'a>, &'a [String]),
    /// An action without signals: the usage line, status 2.
    Usage,
    /// An option `trap` does not take.
    InvalidOption(char),
}

/// Reads `trap`'s arguments as bash 5.2 does: options `-l` and `-p` (and `--`); then a first argument that is a
/// signal number, or a signal alone, resets; otherwise the first argument is the action (`''` ignores, `-` resets).
pub(crate) fn form(args: &[String]) -> Form<'_> {
    let mut list = false;
    let mut print = false;
    let mut rest = args;
    while let Some((arg, after)) = rest.split_first() {
        if arg == "--" {
            rest = after;
            break;
        }
        if arg.len() < 2 || !arg.starts_with('-') {
            break;
        }
        for letter in arg.chars().skip(1) {
            match letter {
                'l' => list = true,
                'p' => print = true,
                other => return Form::InvalidOption(other),
            }
        }
        rest = after;
    }
    if list {
        return Form::Signals;
    }
    let Some((first, after)) = rest.split_first() else {
        return Form::Print(rest);
    };
    if print {
        return Form::Print(rest);
    }
    let all_digits = first.bytes().all(|byte| byte.is_ascii_digit());
    if all_digits && trap::decode(first).is_some() {
        return Form::Change(Operation::Revert, rest);
    }
    if first != "-" && after.is_empty() && trap::decode(first).is_some() {
        return Form::Change(Operation::Revert, rest);
    }
    if after.is_empty() {
        return Form::Usage;
    }
    let operation = match first.as_str() {
        "" => Operation::Ignore,
        "-" => Operation::Revert,
        text => Operation::Set(text),
    };
    Form::Change(operation, after)
}

/// Whether `spec` names `SIGCHLD`, whose trap bash runs as each child ends: not reproduced with a command.
pub(crate) fn is_child_signal(spec: &str) -> bool {
    matches!(trap::decode(spec), Some(TrapId::Signal(number)) if trap::signal_name(number) == Some("SIGCHLD"))
}

/// `error`, with a refusal placed at `span` (the `trap` command) instead of inside the trap's own text.
pub(crate) fn at_command(error: InterpError, span: Span) -> InterpError {
    match error {
        InterpError::Unsupported { feature, .. } => InterpError::Unsupported { feature, span },
        other => other,
    }
}

impl Interpreter {
    /// `trap [-lp] [[action] signal …]`.
    pub(super) fn trap_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        match form(args) {
            Form::InvalidOption(letter) => {
                self.report(span, run, format_args!("trap: -{letter}: invalid option"));
                self.report_plain(format_args!("{TRAP_USAGE}"));
                Ok(Status::new(2))
            }
            Form::Usage => {
                self.report_plain(format_args!("{TRAP_USAGE}"));
                Ok(Status::new(2))
            }
            Form::Signals => {
                let text = signal_list();
                Ok(self.print("trap", text.as_bytes(), span, run))
            }
            Form::Print(specs) => self.print_traps(specs, span, run),
            Form::Change(operation, specs) => self.change_traps(operation, specs, span, run),
        }
    }

    /// `trap -p [signal …]`: `trap -- 'command' NAME` for each trap set, in bash's order.
    fn print_traps(&mut self, specs: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let mut status = Status::SUCCESS;
        let mut wanted = Vec::with_capacity(specs.len());
        for spec in specs {
            if let Some(id) = trap::decode(spec) {
                wanted.push(id);
            } else {
                self.report(span, run, format_args!("trap: {spec}: invalid signal specification"));
                status = Status::FAILURE;
            }
        }
        let filter = (!specs.is_empty()).then_some(wanted.as_slice());
        if self.state.traps().listing_refused(filter) {
            return Err(unsupported(Unsupported::Trap, span).into());
        }
        let mut text = String::new();
        let mut line = |id: TrapId, action: &Action| {
            let command = match action {
                Action::Command(command) => quote::single(command),
                Action::Ignore => "''".to_owned(),
            };
            let _ = writeln!(text, "trap -- {command} {}", id.name());
        };
        match filter {
            None => {
                for (id, action) in self.state.traps().listed() {
                    line(id, action);
                }
            }
            Some(ids) => {
                for id in ids {
                    if let Some(action) = self.state.traps().get(*id) {
                        line(*id, action);
                    }
                }
            }
        }
        let printed = self.print("trap", text.as_bytes(), span, run);
        Ok(if printed.is_success() { status } else { printed })
    }

    /// Sets, ignores or resets the traps on `specs`; an invalid one is reported and the others still change.
    fn change_traps(&mut self, operation: Operation<'_>, specs: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let action = match operation {
            Operation::Set(text) => {
                self.check_trap_text(text, span)?;
                if specs.iter().any(|spec| is_child_signal(spec)) {
                    return Err(unsupported(Unsupported::Trap, span).into());
                }
                Some(Action::Command(Arc::from(text)))
            }
            Operation::Ignore => Some(Action::Ignore),
            Operation::Revert => None,
        };
        let interactive = self.state.is_interactive();
        let mut status = Status::SUCCESS;
        for spec in specs {
            if let Some(id) = trap::decode(spec) {
                self.state.traps_mut().set(id, action.clone(), interactive);
            } else {
                self.report(span, run, format_args!("trap: {spec}: invalid signal specification"));
                status = Status::FAILURE;
            }
        }
        Ok(status)
    }

    /// Parses and checks a trap's command text now, so a trap the interpreter cannot run is refused here rather
    /// than when it fires.
    fn check_trap_text(&self, text: &str, span: Span) -> Flow<()> {
        let script = knsh_bash::parse_with(text, self.parse_options())
            .map_err(|_| Stop::Error(unsupported(Unsupported::Unparsed, span)))?;
        let budget = self.max_depth.saturating_sub(self.depth);
        self.check_nested(&script.items, text, budget)
            .map_err(|error| Stop::Error(at_command(error, span)))
    }

    /// Runs `text` as trap `id`, fired at the command at `span`: as `eval` text, then `$?` and `PIPESTATUS` put back
    /// unless it exits (or returns, breaks or continues, which go on outwards).
    pub(super) fn run_trap(&mut self, id: TrapId, text: &str, span: Span, run: &Run<'_>) -> Flow<()> {
        let status = self.state.last_status();
        let pipestatus = self.state.pipestatus().to_vec();
        // A trap's commands are parsed afresh, so they are subject to `set -e` and `ERR` even when the trap fires
        // inside a condition or an `&&` operand, as bash's trap text never carries the `CMD_IGNORE_RETURN` mark.
        let errexit_ignored = std::mem::take(&mut self.errexit_ignored);
        self.traps_running.push(id);
        let nested = Run::nested(text, run.origin, run.line(span).saturating_sub(1));
        let result = self.holding_nested(text.len(), |shell| {
            let script = knsh_bash::parse_with(nested.source, shell.parse_options())
                .map_err(|_| Stop::Error(unsupported(Unsupported::Unparsed, span)))?;
            let budget = shell.max_depth.saturating_sub(shell.depth);
            shell
                .check_nested(&script.items, nested.source, budget)
                .map_err(|error| Stop::Error(at_command(error, span)))?;
            shell.script(&script.items, &nested)
        });
        self.traps_running.pop();
        self.errexit_ignored = errexit_ignored;
        match result {
            Ok(_) | Err(Stop::Discard) => {
                self.state.set_pipestatus(pipestatus);
                self.state.set_last_status(status);
                Ok(())
            }
            Err(stop) => Err(stop),
        }
    }

    /// The shell (or subshell) exits with `status`: its `EXIT` trap runs, once, with `$?` at `status`. The status it
    /// exits with is `status`, unless the trap runs `exit`.
    ///
    /// After a signal ended the shell, `$?` in the trap stays the last command's, as bash's `termsig_handler` leaves
    /// it.
    pub(super) fn run_exit_trap(&mut self, status: Status, span: Span, run: &Run<'_>) -> Result<Status, InterpError> {
        let Some(Action::Command(text)) = self.state.traps_mut().take(TrapId::Exit) else {
            return Ok(status);
        };
        if self.terminating.is_none() {
            self.state.set_last_status(status);
        }
        match self.run_trap(TrapId::Exit, &text, span, run) {
            Ok(()) | Err(Stop::Discard | Stop::Return(_) | Stop::Break { .. } | Stop::Continue { .. }) => Ok(status),
            Err(Stop::Exit(code)) => {
                // The trap chose how the shell ends.
                self.terminating = None;
                Ok(code)
            }
            Err(Stop::Error(error)) => Err(error),
        }
    }

    /// The `DEBUG` trap, before a command (never inside a trap).
    pub(super) fn debug_trap(&mut self, span: Span, run: &Run<'_>) -> Flow<()> {
        if !self.traps_running.is_empty() {
            return Ok(());
        }
        match self.state.traps().command(TrapId::Debug) {
            Some(text) => self.run_trap(TrapId::Debug, &text, span, run),
            None => Ok(()),
        }
    }

    /// A pipeline ended with `status`: if it failed outside the contexts bash exempts, the `ERR` trap runs, then
    /// `set -e` ends the shell with that status.
    pub(super) fn command_failed(&mut self, status: Status, span: Span, run: &Run<'_>) -> Flow<()> {
        if status.is_success() || self.errexit_ignored > 0 {
            return Ok(());
        }
        if !self.traps_running.contains(&TrapId::Err)
            && let Some(text) = self.state.traps().command(TrapId::Err)
        {
            self.state.set_last_status(status);
            self.run_trap(TrapId::Err, &text, span, run)?;
        }
        if self.state.options().errexit {
            return Err(Stop::Exit(status));
        }
        Ok(())
    }

    /// Acts on the signals the host handed over since the last time: a trap runs, an ignored signal is dropped, and
    /// a signal at its default action that ends a process ends the shell with 128 plus its number (after the `EXIT`
    /// trap, for the signals bash runs it for). An interactive shell ignores `SIGINT`, `SIGTERM` and `SIGQUIT` at
    /// their default, as bash does.
    pub(super) fn act_on_signals(&mut self, span: Span, run: &Run<'_>) -> Flow<()> {
        let Some(handle) = self.signals.clone() else {
            return Ok(());
        };
        let pending = handle.take();
        for (index, &number) in pending.iter().enumerate() {
            let id = TrapId::Signal(number);
            if self.traps_running.contains(&id) {
                // Bash keeps a signal arriving during its own trap pending until the trap ends.
                handle.put_back(&[number]);
                continue;
            }
            let interactive = self.state.is_interactive();
            match self.state.traps().get(id).cloned() {
                Some(Action::Command(text)) => {
                    if let Err(stop) = self.run_trap(id, &text, span, run) {
                        handle.put_back(&pending[index + 1..]);
                        return Err(stop);
                    }
                }
                Some(Action::Ignore) => {}
                None if self.state.traps().is_hard_ignored(number) && !interactive => {}
                None if interactive && matches!(trap::signal_name(number), Some("SIGINT" | "SIGTERM" | "SIGQUIT")) => {}
                None => match trap::default_action(number) {
                    Default::Nothing => {}
                    action @ (Default::TerminateWithTrap | Default::Terminate) => {
                        self.terminating = Some(number);
                        self.skip_exit_trap = action == Default::Terminate;
                        return Err(Stop::Exit(Status::from_signal(number)));
                    }
                },
            }
        }
        Ok(())
    }

    /// Takes away the traps a function called now does not inherit (`traced`: it has `declare -ft`), to give back
    /// with [`Interpreter::leave_function_traps`].
    pub(super) fn enter_function_traps(&mut self, traced: bool) -> Vec<(TrapId, Action)> {
        let functrace = self.state.options().functrace || traced;
        let errtrace = self.state.options().errtrace;
        let in_debug = self.traps_running.contains(&TrapId::Debug);
        let mut taken = Vec::new();
        let mut take = |shell: &mut Self, id: TrapId| {
            if let Some(action) = shell.state.traps_mut().take(id) {
                taken.push((id, action));
            }
        };
        if !functrace {
            take(self, TrapId::Debug);
        }
        if !errtrace {
            take(self, TrapId::Err);
        }
        if in_debug || !functrace {
            take(self, TrapId::Return);
        }
        taken
    }

    /// Gives back the traps [`Interpreter::enter_function_traps`] took, except where the function set its own.
    pub(super) fn leave_function_traps(&mut self, taken: Vec<(TrapId, Action)>) {
        for (id, action) in taken {
            self.state.traps_mut().restore_if_unset(id, action);
        }
    }

    /// The `RETURN` trap, as a function or sourced file returns with `status` (`$?` in the trap).
    pub(super) fn return_trap(&mut self, status: Status, span: Span, run: &Run<'_>) -> Flow<()> {
        if self.traps_running.contains(&TrapId::Return) {
            return Ok(());
        }
        match self.state.traps().command(TrapId::Return) {
            Some(text) => {
                self.state.set_last_status(status);
                self.run_trap(TrapId::Return, &text, span, run)
            }
            None => Ok(()),
        }
    }
}

/// `trap -l`: every signal as ` n) SIGNAME`, five to a line separated by tabs, as bash 5.2's `display_signal_list`.
fn signal_list() -> String {
    let mut text = String::new();
    let mut column = 0;
    for (number, name) in knsh_platform::signals::NAMES {
        let _ = write!(text, "{number:2}) {name}");
        column += 1;
        if column < 5 {
            text.push('\t');
        } else {
            text.push('\n');
            column = 0;
        }
    }
    if column != 0 {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    // KNSH-104: arguments are read as bash 5.2's `trap_builtin` reads them.
    #[test]
    fn forms_follow_bash() {
        let args = strings(&["echo hi", "EXIT", "INT"]);
        assert_eq!(form(&args), Form::Change(Operation::Set("echo hi"), &args[1..]));
        let args = strings(&["2"]);
        assert_eq!(form(&args), Form::Change(Operation::Revert, &args[..]));
        let args = strings(&["2", "TERM"]);
        assert_eq!(form(&args), Form::Change(Operation::Revert, &args[..]));
        let args = strings(&["INT"]);
        assert_eq!(form(&args), Form::Change(Operation::Revert, &args[..]));
        let args = strings(&["", "INT"]);
        assert_eq!(form(&args), Form::Change(Operation::Ignore, &args[1..]));
        let args = strings(&["-", "INT"]);
        assert_eq!(form(&args), Form::Change(Operation::Revert, &args[1..]));
        assert_eq!(form(&strings(&["--", "-"])), Form::Usage);
        assert_eq!(form(&strings(&["echo"])), Form::Usage);
        assert_eq!(form(&[]), Form::Print(&[]));
        assert_eq!(form(&strings(&["-l", "INT"])), Form::Signals);
        assert_eq!(form(&strings(&["-x"])), Form::InvalidOption('x'));
        let args = strings(&["-p", "INT"]);
        assert_eq!(form(&args), Form::Print(&args[1..]));
    }

    // KNSH-104: `trap -l` lays the names out five to a line, as bash 5.2 does.
    #[test]
    fn signal_list_has_five_columns() {
        let text = signal_list();
        let first = text.lines().next().unwrap();
        assert_eq!(first, " 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP");
        assert!(text.ends_with('\n'));
    }
}
