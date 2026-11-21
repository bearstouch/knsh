//! The shell's traps and the signals it is sent (KNSH-104; NFR-COMPAT-02).
//!
//! [`Traps`] is the table `trap` changes: a command or "ignore" for `EXIT`, each signal, `DEBUG`, `ERR` and `RETURN`,
//! and the signals the shell was started ignoring, which a non-interactive shell can neither trap nor reset (bash's
//! "hard-ignored" signals). It is part of the shell state, so a subshell starts with a copy, which it resets as bash's
//! forked subshell does ([`Traps::reset_for_subshell`]).
//!
//! The interpreter never installs a signal handler: it runs in a multithreaded process it does not own. The host
//! catches the signals meant for the shell and hands them over through a [`ShellSignals`] handle; the shell acts on
//! them between commands, as bash runs its pending traps after each command.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use knsh_platform::{SignalSet, signals};

/// What a trap does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Runs this command text (parsed and checked when the trap was set).
    Command(Arc<str>),
    /// `trap '' sig`: the signal is ignored (for `DEBUG`, `ERR` and `RETURN`: nothing runs).
    Ignore,
}

/// What a trap is set on: bash's signal numbers with its special traps after them, in the order `trap` lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TrapId {
    /// `EXIT` (signal 0): when the shell exits.
    Exit,
    /// A signal, by number.
    Signal(i32),
    /// `DEBUG`: before each simple command and some compound commands.
    Debug,
    /// `ERR`: after a command fails where `set -e` would exit.
    Err,
    /// `RETURN`: when a function or a sourced file returns.
    Return,
}

impl TrapId {
    /// The name `trap -p` prints: `EXIT`, `SIGINT`, `DEBUG`, …
    pub(crate) fn name(self) -> String {
        match self {
            Self::Exit => "EXIT".to_owned(),
            Self::Signal(number) => signal_name(number).map_or_else(|| number.to_string(), str::to_owned),
            Self::Debug => "DEBUG".to_owned(),
            Self::Err => "ERR".to_owned(),
            Self::Return => "RETURN".to_owned(),
        }
    }
}

/// The name bash gives signal `number` (`SIGINT`), if this platform has it.
pub(crate) fn signal_name(number: i32) -> Option<&'static str> {
    signals::NAMES
        .iter()
        .find(|(signal, _)| *signal == number)
        .map(|(_, name)| *name)
}

/// The highest signal number plus one (bash's `NSIG`).
fn signal_count() -> i32 {
    signals::NAMES.iter().map(|(signal, _)| *signal).max().unwrap_or(0) + 1
}

/// Bash's `decode_signal` as `trap` calls it (`DSIG_NOCASE | DSIG_SIGPREFIX`): a number from 0 (`EXIT`) to the
/// highest signal, or a name in any case with or without `SIG` (`int`, `SIGINT`, `SigInt`), or `EXIT`, `DEBUG`,
/// `ERR` or `RETURN` (in any case, never with `SIG`). `None` for anything else.
pub(crate) fn decode(spec: &str) -> Option<TrapId> {
    if !spec.is_empty() && spec.bytes().all(|byte| byte.is_ascii_digit()) {
        let number: i32 = spec.parse().ok()?;
        return match number {
            0 => Some(TrapId::Exit),
            number if number < signal_count() && signal_name(number).is_some() => Some(TrapId::Signal(number)),
            _ => None,
        };
    }
    for (name, id) in [
        ("EXIT", TrapId::Exit),
        ("DEBUG", TrapId::Debug),
        ("ERR", TrapId::Err),
        ("RETURN", TrapId::Return),
    ] {
        if spec.eq_ignore_ascii_case(name) {
            return Some(id);
        }
    }
    signals::NAMES.iter().find_map(|(number, name)| {
        let short = name.strip_prefix("SIG").unwrap_or(name);
        (spec.eq_ignore_ascii_case(short) || spec.eq_ignore_ascii_case(name)).then_some(TrapId::Signal(*number))
    })
}

/// What a signal does to a shell that neither traps nor ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Default {
    /// Ends the shell, and runs its `EXIT` trap first: bash's `terminating_signals`, whose handler runs the trap
    /// (`termsig_handler`) once an `EXIT` trap is set.
    TerminateWithTrap,
    /// Ends the shell without running the `EXIT` trap (`SIGQUIT`, `SIGPROF`, `SIGKILL`).
    Terminate,
    /// Nothing the shell acts on: ignored by default (`SIGCHLD`, `SIGWINCH`), or a stop or continue the host handles.
    Nothing,
}

/// The default action of signal `number`, as bash's shell sees it.
pub(crate) fn default_action(number: i32) -> Default {
    match signal_name(number) {
        Some(
            "SIGHUP" | "SIGINT" | "SIGILL" | "SIGTRAP" | "SIGABRT" | "SIGEMT" | "SIGFPE" | "SIGBUS" | "SIGSEGV"
            | "SIGSYS" | "SIGPIPE" | "SIGALRM" | "SIGTERM" | "SIGXCPU" | "SIGXFSZ" | "SIGVTALRM" | "SIGUSR1"
            | "SIGUSR2",
        ) => Default::TerminateWithTrap,
        Some("SIGQUIT" | "SIGPROF" | "SIGKILL" | "SIGSTKFLT" | "SIGPWR") => Default::Terminate,
        Some(_) | None => Default::Nothing,
    }
}

/// The shell's trap table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Traps {
    /// The traps set, by what they are set on.
    table: BTreeMap<TrapId, Action>,
    /// The signals the shell was started ignoring: in a non-interactive shell `trap` leaves them ignored, silently.
    hard_ignored: SignalSet,
    /// This is a subshell whose parent had command traps, which it reset: bash 5.2 still lists the parent's with
    /// `trap` until the subshell changes one (its `SUBSHELL_RESETTRAP`), which is not reproduced, so listing is
    /// refused meanwhile.
    reset_parent_commands: bool,
}

impl Traps {
    /// The table of a shell started ignoring `ignored`.
    pub(crate) fn with_hard_ignored(ignored: SignalSet) -> Self {
        Self {
            hard_ignored: ignored,
            ..Self::default()
        }
    }

    /// The trap on `id`, if one is set.
    pub(crate) fn get(&self, id: TrapId) -> Option<&Action> {
        self.table.get(&id)
    }

    /// The command of the trap on `id`, if it runs one.
    pub(crate) fn command(&self, id: TrapId) -> Option<Arc<str>> {
        match self.table.get(&id) {
            Some(Action::Command(text)) => Some(Arc::clone(text)),
            Some(Action::Ignore) | None => None,
        }
    }

    /// Whether signal `number` was ignored when the shell started.
    pub(crate) fn is_hard_ignored(&self, number: i32) -> bool {
        self.hard_ignored.contains(number)
    }

    /// Sets the trap on `id` to `action` (`None`: reset to the default). In a non-interactive shell a signal ignored
    /// at entry is left as it is, as bash does without a message.
    pub(crate) fn set(&mut self, id: TrapId, action: Option<Action>, interactive: bool) {
        self.reset_parent_commands = false;
        if let TrapId::Signal(number) = id
            && self.hard_ignored.contains(number)
            && !interactive
        {
            return;
        }
        match action {
            Some(action) => {
                self.table.insert(id, action);
            }
            None => {
                self.table.remove(&id);
            }
        }
    }

    /// Takes the trap on `id` away (for a function's body, which does not inherit it), returning it.
    pub(crate) fn take(&mut self, id: TrapId) -> Option<Action> {
        self.table.remove(&id)
    }

    /// Puts `action` back on `id` unless a trap was set there meanwhile (bash 5.2's `trap_if_untrapped`, after a
    /// function that did not inherit the trap returns).
    pub(crate) fn restore_if_unset(&mut self, id: TrapId, action: Action) {
        self.table.entry(id).or_insert(action);
    }

    /// The traps set, in `trap -p` order: `EXIT`, the signals by number, `DEBUG`, `ERR`, `RETURN`. Signals ignored at
    /// entry are listed separately ([`Traps::listed_hard_ignored`]).
    pub(crate) fn listed(&self) -> impl Iterator<Item = (TrapId, &Action)> {
        self.table.iter().map(|(id, action)| (*id, action))
    }

    /// Whether listing the traps must be refused: in a subshell that reset its parent's command traps (bash 5.2 lists
    /// those), or with a signal ignored at entry to list, which bash 3.2 leaves out and later versions print as
    /// `trap -- '' SIG…`.
    pub(crate) fn listing_refused(&self, ids: Option<&[TrapId]>) -> bool {
        if self.reset_parent_commands {
            return true;
        }
        match ids {
            None => !self.hard_ignored.is_empty(),
            Some(ids) => ids
                .iter()
                .any(|id| matches!(id, TrapId::Signal(number) if self.hard_ignored.contains(*number))),
        }
    }

    /// The signals a command the shell starts must start ignoring: those trapped with `''` and those ignored at entry
    /// (KNSH-104: bash's children inherit both ignored).
    pub(crate) fn ignored_signals(&self) -> SignalSet {
        let mut set = self.hard_ignored;
        for (id, action) in &self.table {
            if let (TrapId::Signal(number), Action::Ignore) = (id, action) {
                set.insert(*number);
            }
        }
        set
    }

    /// Resets the table as bash's forked subshell does (`reset_signal_handlers`): the `EXIT` trap and every signal
    /// trap with a command are dropped, ignored signals stay ignored; `DEBUG` and `RETURN` are dropped unless
    /// `functrace` is on, `ERR` unless `errtrace` is on.
    pub(crate) fn reset_for_subshell(&mut self, functrace: bool, errtrace: bool) {
        let had_commands = self
            .table
            .iter()
            .any(|(id, action)| matches!((id, action), (TrapId::Exit | TrapId::Signal(_), Action::Command(_))));
        self.table.retain(|id, action| match id {
            TrapId::Exit => false,
            TrapId::Signal(_) => *action == Action::Ignore,
            TrapId::Debug | TrapId::Return => functrace,
            TrapId::Err => errtrace,
        });
        self.reset_parent_commands = had_commands;
    }
}

/// A handle through which the host hands the shell the signals sent to it (KNSH-104): `Send`, `Sync` and cheap to
/// clone, so a signal-handling thread can hold one. The shell acts on each signal after the command running when it
/// arrived ends: it runs the signal's trap, ignores it, or (at the default action of a signal that ends a process)
/// runs its `EXIT` trap and ends with status 128 plus the signal's number, leaving
/// [`Interpreter::terminating_signal`](crate::Interpreter::terminating_signal) set so the host can end itself by the
/// same signal, as bash does.
#[derive(Debug, Clone, Default)]
pub struct ShellSignals {
    pending: Arc<AtomicU64>,
}

impl ShellSignals {
    /// Hands the shell signal `number` (1 to 63; anything else is ignored). A signal handed again before the shell
    /// acted on it counts once, as a pending signal does.
    pub fn raise(&self, number: i32) {
        let mut set = SignalSet::new();
        set.insert(number);
        if let Some(bit) = set.iter().next().and_then(|number| u32::try_from(number).ok()) {
            self.pending.fetch_or(1 << bit, Ordering::SeqCst);
        }
    }

    /// Takes the signals handed over and not yet acted on, in increasing order.
    pub(crate) fn take(&self) -> Vec<i32> {
        let bits = self.pending.swap(0, Ordering::SeqCst);
        (1..64).filter(|number| bits & (1 << number) != 0).collect()
    }

    /// Puts `numbers` back, to act on later.
    pub(crate) fn put_back(&self, numbers: &[i32]) {
        for &number in numbers {
            self.raise(number);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-104: signal specifications are read as bash's `trap` reads them.
    #[test]
    fn decodes_specs_as_bash_trap_does() {
        let int = TrapId::Signal(signals::SIGINT);
        assert_eq!(decode("INT"), Some(int));
        assert_eq!(decode("sigint"), Some(int));
        assert_eq!(decode("SigInt"), Some(int));
        assert_eq!(decode("2"), Some(int));
        assert_eq!(decode("0"), Some(TrapId::Exit));
        assert_eq!(decode("exit"), Some(TrapId::Exit));
        assert_eq!(decode("SIGEXIT"), None);
        assert_eq!(decode("err"), Some(TrapId::Err));
        assert_eq!(decode("99"), None);
        assert_eq!(decode("bogus"), None);
        assert_eq!(decode(""), None);
        assert_eq!(decode("-1"), None);
    }

    // KNSH-104: a subshell keeps ignored signals and drops the rest, as bash's forked subshell does.
    #[test]
    fn subshells_reset_traps_like_bash() {
        let mut traps = Traps::default();
        let command = || Some(Action::Command(Arc::from("echo")));
        traps.set(TrapId::Exit, command(), false);
        traps.set(TrapId::Signal(signals::SIGINT), command(), false);
        traps.set(TrapId::Signal(signals::SIGTERM), Some(Action::Ignore), false);
        traps.set(TrapId::Err, command(), false);
        traps.set(TrapId::Debug, command(), false);
        let mut copy = traps.clone();
        copy.reset_for_subshell(false, true);
        let left: Vec<TrapId> = copy.listed().map(|(id, _)| id).collect();
        assert_eq!(left, [TrapId::Signal(signals::SIGTERM), TrapId::Err]);
        assert!(copy.listing_refused(None));
        copy.set(TrapId::Err, None, false);
        assert!(!copy.listing_refused(None));
        assert!(copy.ignored_signals().contains(signals::SIGTERM));
    }

    // KNSH-104: a non-interactive shell cannot trap or reset a signal ignored at entry.
    #[test]
    fn hard_ignored_signals_cannot_be_trapped() {
        let mut traps = Traps::with_hard_ignored([signals::SIGINT].into_iter().collect());
        traps.set(
            TrapId::Signal(signals::SIGINT),
            Some(Action::Command(Arc::from("x"))),
            false,
        );
        assert_eq!(traps.get(TrapId::Signal(signals::SIGINT)), None);
        assert!(traps.ignored_signals().contains(signals::SIGINT));
        traps.set(TrapId::Signal(signals::SIGINT), Some(Action::Ignore), true);
        assert_eq!(traps.get(TrapId::Signal(signals::SIGINT)), Some(&Action::Ignore));
    }

    // KNSH-104: signals handed over are taken once each, in order.
    #[test]
    fn pending_signals_are_taken_once() {
        let handle = ShellSignals::default();
        handle.raise(signals::SIGTERM);
        handle.raise(signals::SIGINT);
        handle.raise(signals::SIGINT);
        handle.raise(0);
        handle.raise(99);
        assert_eq!(handle.take(), [signals::SIGINT, signals::SIGTERM]);
        assert_eq!(handle.take(), Vec::<i32>::new());
        handle.put_back(&[signals::SIGHUP]);
        assert_eq!(handle.take(), [signals::SIGHUP]);
    }

    // KNSH-104: the signals whose default ends the shell after its `EXIT` trap are bash's terminating signals.
    #[test]
    fn default_actions_follow_bash() {
        assert_eq!(default_action(signals::SIGTERM), Default::TerminateWithTrap);
        assert_eq!(default_action(signals::SIGHUP), Default::TerminateWithTrap);
        assert_eq!(default_action(signals::SIGQUIT), Default::Terminate);
        assert_eq!(default_action(signals::SIGTSTP), Default::Nothing);
    }
}
