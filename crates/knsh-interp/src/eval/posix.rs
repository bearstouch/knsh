//! Bash's POSIX mode in the evaluator (KNSH-106; NFR-COMPAT-02): not a dialect of its own, but the flag
//! [`ShellOptions::posix`](crate::ShellOptions::posix) read where bash 5.2 reads `posixly_correct`.
//!
//! What this module holds is what POSIX mode changes about running a simple command, after bash 5.2's
//! `execute_simple_command` and `execute_builtin`:
//!
//! - The special builtins are found before functions, and `command` takes their special properties away.
//! - Assignments before a special builtin stay after it, exported, as bash's `merge_temporary_env` leaves them.
//! - A special builtin failing with bash's `EX_USAGE` (an invalid option, a missing operand, `return` outside a
//!   function) ends a non-interactive shell with status 2, unless its status is being tested (an `if` condition, an
//!   `&&` or `||` operand but the last, `!`), as bash's `special_builtin_failed` check does. `export` or
//!   `readonly` failing to make an assignment (bash's `EX_BADASSIGN`) ends it with status 1, tested or not.
//!
//! The other changes sit where bash makes them: function names (`function`), `.` and `eval` (`nested`), the
//! expansion errors that end the shell (`expand`), tilde expansion of words like assignments (`expand`),
//! redirection words (`redirect`), `echo`, `trap`, `alias`, `export -p`, `shift`, `break` and `type`.

use std::ffi::OsString;

use knsh_bash::Span;

use super::{Flow, Interpreter, Run, Stop, builtins::Search};
use crate::status::Status;

/// The POSIX special builtins, as bash 5.2's `mkbuiltins.c` marks them (`source` among them).
const SPECIAL_BUILTINS: &[&str] = &[
    ":", ".", "source", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set", "shift",
    "times", "trap", "unset",
];

/// Whether `name` is a POSIX special builtin (bash's `find_special_builtin`).
pub(crate) fn is_special_builtin(name: &str) -> bool {
    SPECIAL_BUILTINS.contains(&name)
}

/// Bash's status for a special builtin's usage error once it ends the shell (`builtin_status (EX_USAGE)`).
const USAGE_STATUS: Status = Status::new(2);

impl Interpreter {
    /// Whether the errors POSIX mode makes fatal end this shell: POSIX mode is on and the shell is not interactive
    /// (bash's `posixly_correct && interactive_shell == 0`).
    pub(super) fn posix_fatal(&self) -> bool {
        self.state.options().posix() && !self.state.is_interactive()
    }

    /// Whether, in POSIX mode, `name` runs as a special builtin: found before any function of that name.
    pub(super) fn runs_as_special(&self, name: &str) -> bool {
        self.state.options().posix() && is_special_builtin(name)
    }

    /// Runs special builtin `name` with `args` in POSIX mode, `assignments` before it made in the shell for good
    /// and exported (bash's `push_posix_temp_var`: each is set where the variable is visible, a local one in a
    /// function). A usage error ends a non-interactive shell with status 2 unless the status is being tested.
    pub(super) fn special_builtin(
        &mut self,
        name: &str,
        args: &[String],
        assignments: &[(String, OsString)],
        span: Span,
        run: &Run<'_>,
    ) -> Flow<Status> {
        for (variable, value) in assignments {
            self.state.set_special_temporary(variable, value.clone());
        }
        self.usage_error = false;
        self.bad_assignment = false;
        let result = if name == "exec" {
            self.exec_builtin(args, &[], span, run)
        } else {
            self.invoke(name, args, &[], Search::Normal, span, run)
        };
        let usage = std::mem::take(&mut self.usage_error);
        let bad_assignment = std::mem::take(&mut self.bad_assignment);
        match result {
            // Bash's `EX_BADASSIGN` ends the shell before the tested-status check (`execute_builtin_or_function`).
            Ok(_) if bad_assignment && self.posix_fatal() => Err(self.posix_error()),
            Ok(_) if usage && self.posix_fatal() && self.errexit_ignored == 0 => Err(self.usage_exit()),
            other => other,
        }
    }

    /// Ends the shell with bash's `EX_BADUSAGE` (status 2) after a POSIX-mode error that bash ends it so for
    /// (`last_command_exit_value = EX_BADUSAGE; jump_to_top_level (ERREXIT)`).
    pub(super) fn usage_exit(&mut self) -> Stop {
        self.state.set_last_status(USAGE_STATUS);
        Stop::Exit(USAGE_STATUS)
    }

    /// A POSIX-mode error that ends a non-interactive shell with status 1 (bash's `jump_to_top_level` with
    /// `ERREXIT`, `FORCE_EOF` or `EXITPROG` and `last_command_exit_value` 1); in an interactive shell the rest of
    /// the line is abandoned with status 1.
    pub(super) fn posix_error(&mut self) -> Stop {
        self.state.set_last_status(Status::FAILURE);
        if self.state.is_interactive() {
            Stop::Discard
        } else {
            Stop::Exit(Status::FAILURE)
        }
    }
}
