//! External commands whose outcome is scripted per program (KNSH-096).

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use super::lock;
use crate::command::{CommandOutcome, CommandRequest, CommandSpawner};
use crate::error::PlatformError;

#[derive(Debug, Default)]
struct State {
    /// Outcomes still to give, per program. The last one is repeated forever, so a loop can run a program any number
    /// of times.
    outcomes: BTreeMap<PathBuf, VecDeque<CommandOutcome>>,
    /// Every request run, in order.
    runs: Vec<CommandRequest>,
}

/// A [`CommandSpawner`] that runs nothing: each program answers with the outcomes the test scripted for it, in
/// order, the last one repeated. A program with no script fails with [`PlatformError::NotScripted`], so a test
/// cannot pass by running something it did not expect.
#[derive(Debug, Default)]
pub struct ScriptedCommands {
    state: Mutex<State>,
}

impl ScriptedCommands {
    /// No programs scripted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues `outcome` for `program`: the next run of `program` gives the first outcome queued and not yet given;
    /// once only one is left, every later run gives it.
    pub fn on(&self, program: impl Into<PathBuf>, outcome: CommandOutcome) {
        lock(&self.state)
            .outcomes
            .entry(program.into())
            .or_default()
            .push_back(outcome);
    }

    /// Every request run, scripted or not, in order.
    #[must_use]
    pub fn runs(&self) -> Vec<CommandRequest> {
        lock(&self.state).runs.clone()
    }

    /// The `argv[0]` of every request run, in order, as text: a compact trace for assertions.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        lock(&self.state)
            .runs
            .iter()
            .map(|run| run.argv0.to_string_lossy().into_owned())
            .collect()
    }
}

impl CommandSpawner for ScriptedCommands {
    fn run(&self, request: &CommandRequest) -> Result<CommandOutcome, PlatformError> {
        let mut state = lock(&self.state);
        state.runs.push(request.clone());
        let queue = state
            .outcomes
            .get_mut(&request.program)
            .ok_or(PlatformError::NotScripted)?;
        let outcome = if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().copied()
        };
        outcome.ok_or(PlatformError::NotScripted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ExitStatus;

    fn request(program: &str) -> CommandRequest {
        CommandRequest {
            program: program.into(),
            argv0: "x".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: "/".into(),
        }
    }

    #[test]
    fn gives_outcomes_in_order_and_repeats_the_last() {
        let commands = ScriptedCommands::new();
        commands.on("/bin/x", CommandOutcome::Finished(ExitStatus::Exited(0)));
        commands.on("/bin/x", CommandOutcome::Finished(ExitStatus::Exited(1)));
        let outcomes: Vec<_> = (0..3).map(|_| commands.run(&request("/bin/x")).unwrap()).collect();
        assert_eq!(
            outcomes,
            [
                CommandOutcome::Finished(ExitStatus::Exited(0)),
                CommandOutcome::Finished(ExitStatus::Exited(1)),
                CommandOutcome::Finished(ExitStatus::Exited(1)),
            ]
        );
        assert_eq!(commands.runs().len(), 3);
    }

    #[test]
    fn refuses_an_unscripted_program_but_records_it() {
        let commands = ScriptedCommands::new();
        assert_eq!(commands.run(&request("/bin/y")), Err(PlatformError::NotScripted));
        assert_eq!(commands.names(), ["x"]);
    }
}
