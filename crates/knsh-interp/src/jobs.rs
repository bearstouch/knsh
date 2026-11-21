//! The shell's jobs: what runs, what it is waiting for, and how bash reports it (KNSH-100; NFR-COMPAT-02,
//! FR-SES-10).
//!
//! Every pipeline the shell runs is a job while it runs: a foreground pipeline until it ends (or, under job
//! control, stops), a background one (`&`) until a `wait`, `jobs` or notification reports its end. A job's members are
//! its commands in order. An external command is a child process known by its [`ChildHandle`], never by a bare
//! process id: a thread per child blocks in [`CommandSpawner::wait`] and sends what happened (a stop, a continue, the
//! exit) to the shell over one channel, so the shell waits for any of its jobs at once (`wait -n`) and no process is
//! signalled after it may have been reaped. A command the shell runs itself (a compound command in a pipeline, a
//! background list) runs on a thread with a copy of the shell, a subshell, and sends its status the same way.
//!
//! Under job control (`set -m`) a job's commands share one process group, led by its first process; the group is
//! signalled only through the spawner, which refuses once no member is held unreaped. [`JobSignals`] stops and
//! continues every job's group at once, for the supervisor's pause (FR-SES-10); without job control every command
//! is in the shell's own group, which the supervisor signals itself.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};

use knsh_platform::{
    ChildEvent, ChildHandle, CommandSpawner, ExitStatus, PlatformError, ProcessGroupId, Signal, signals,
};

use crate::error::InterpError;
use crate::status::Status;

/// Finished background jobs the shell remembers for a later `wait` (bash's `CHILD_MAX` default, 1,024): past it the
/// oldest finished job is forgotten when a new one starts. Running and stopped jobs are never forgotten.
pub const MAX_REMEMBERED_JOBS: usize = 1024;

/// Stack of a thread waiting for one child: it only blocks in a system call and sends a message.
const WAITER_STACK_SIZE: usize = 64 * 1024;

/// A job's identity for the events about it, never reused within one shell.
pub(crate) type Key = u64;

/// What one member of a job reported.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Note {
    /// A child process stopped, continued or ended, or waiting for it failed.
    Child(Result<ChildEvent, PlatformError>),
    /// A command the shell ran itself on a thread ended with this status, or with an error that stops the script.
    Inside(Result<Status, InterpError>),
    /// A command the shell runs itself on a thread under job control (a subshell): every program of the job it is
    /// waiting for stopped, by this signal, or (`None`) they run again. Its own programs are members of its own jobs,
    /// not of this one, so without this the shell would never see the job stop (Ctrl-Z on `( sleep 30 )`).
    InsideStop(Option<i32>),
}

/// One message to the shell about a member of a job.
#[derive(Debug)]
pub(crate) struct Event {
    key: Key,
    member: usize,
    note: Note,
    /// The supervisor's pause was in force when a stop was seen: the stop is not job control's.
    paused: bool,
}

/// Where a member of a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberState {
    /// Running (or not yet reported otherwise).
    Running,
    /// Stopped by this signal.
    Stopped(i32),
    /// Ended with this status.
    Done(Status),
}

/// One command of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    /// The child's process id, or `None` for a command the shell runs itself.
    pub(crate) pid: Option<i32>,
    /// Where it is.
    pub(crate) state: MemberState,
}

impl Member {
    /// A command that already ended inside the shell (an assignment, `:`) or was never started (not found).
    pub(crate) const fn done(status: Status) -> Self {
        Self {
            pid: None,
            state: MemberState::Done(status),
        }
    }

    /// A command the shell runs on a thread of its own.
    pub(crate) const fn inside() -> Self {
        Self {
            pid: None,
            state: MemberState::Running,
        }
    }

    /// A child process.
    pub(crate) const fn child(handle: ChildHandle) -> Self {
        Self {
            pid: Some(handle.pid()),
            state: MemberState::Running,
        }
    }
}

/// Where a subshell running on a thread of its own (a member of a job of its parent shell) reports that what it
/// waits for stopped or runs again (KNSH-100).
#[derive(Debug, Clone)]
pub(crate) struct Parent {
    /// The parent shell's channel.
    sender: Sender<Event>,
    /// The parent's job.
    key: Key,
    /// The subshell's index among that job's members.
    member: usize,
}

impl Parent {
    /// Tells the parent the subshell's foreground job stopped by `signal`, or (`None`) runs again. The parent may be
    /// gone (an error stopped it): nobody to tell.
    pub(crate) fn tell(&self, signal: Option<i32>) {
        let _ = self.sender.send(Event {
            key: self.key,
            member: self.member,
            note: Note::InsideStop(signal),
            paused: false,
        });
    }
}

/// The process group shared by the commands of one job under job control, set by its first process.
pub(crate) type GroupCell = Arc<Mutex<Option<ProcessGroupId>>>;

/// One job.
#[derive(Debug)]
// Four independent facts about one job (its `!`, `pipefail`, whether it was reported, whether it owns its group):
// no state machine among them.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Job {
    /// Its identity for events.
    pub(crate) key: Key,
    /// Its job number once it is in the jobs table (background or stopped), as `%n` names it.
    pub(crate) number: Option<usize>,
    /// The command text `jobs` shows.
    pub(crate) text: String,
    /// Its commands, in pipeline order.
    pub(crate) members: Vec<Member>,
    /// Its process group under job control.
    pub(crate) group: GroupCell,
    /// The pipeline's `!`.
    pub(crate) negated: bool,
    /// `pipefail` when it started.
    pub(crate) pipefail: bool,
    /// Its end or stop was reported (`jobs`, a notification), so it is not reported again.
    pub(crate) notified: bool,
    /// The job created its group (rather than sharing the group of the job it runs inside): only then does
    /// forgetting it take the group out of the registry.
    owns_group: bool,
}

impl Job {
    /// Whether every member ended.
    pub(crate) fn is_done(&self) -> bool {
        self.members
            .iter()
            .all(|member| matches!(member.state, MemberState::Done(_)))
    }

    /// Whether the job is stopped: a member is stopped and no child process of it still runs. A command the shell
    /// runs itself is stopped only as its subshell reports ([`Note::InsideStop`]): it waits for its own stopped
    /// children meanwhile.
    pub(crate) fn is_stopped(&self) -> bool {
        let stopped = self
            .members
            .iter()
            .any(|member| matches!(member.state, MemberState::Stopped(_)));
        let running = self
            .members
            .iter()
            .any(|member| member.pid.is_some() && member.state == MemberState::Running);
        stopped && !running
    }

    /// The signal that stopped it.
    pub(crate) fn stop_signal(&self) -> Option<i32> {
        self.members.iter().find_map(|member| match member.state {
            MemberState::Stopped(signal) => Some(signal),
            MemberState::Running | MemberState::Done(_) => None,
        })
    }

    /// Each member's status, as `PIPESTATUS` holds them: a stopped one is `128 + signal`, one still running 0.
    pub(crate) fn statuses(&self) -> Vec<Status> {
        self.members
            .iter()
            .map(|member| match member.state {
                MemberState::Done(status) => status,
                MemberState::Stopped(signal) => Status::from_signal(signal),
                MemberState::Running => Status::SUCCESS,
            })
            .collect()
    }

    /// The job's status: the last command's, or under `pipefail` the last failing command's (0 when none failed),
    /// then inverted by `!`.
    pub(crate) fn status(&self) -> Status {
        let statuses = self.statuses();
        let status = if self.pipefail {
            statuses
                .iter()
                .rev()
                .find(|status| !status.is_success())
                .copied()
                .unwrap_or(Status::SUCCESS)
        } else {
            statuses.last().copied().unwrap_or(Status::SUCCESS)
        };
        if self.negated { status.negated() } else { status }
    }

    /// The group, if the job has one yet.
    pub(crate) fn group(&self) -> Option<ProcessGroupId> {
        *self.group.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The process id `jobs -p` and `[n] pid` show: the group leader's under job control, else the last child's.
    pub(crate) fn shown_pid(&self) -> Option<i32> {
        self.group()
            .map(ProcessGroupId::as_raw)
            .or_else(|| self.members.iter().rev().find_map(|member| member.pid))
    }

    /// The state column of `jobs` and notifications, as bash prints it.
    pub(crate) fn state_text(&self) -> String {
        if self.is_done() {
            let status = self.status();
            let last = self.members.last().map(|member| member.state);
            return match last {
                // A job whose last command was killed is reported by that signal, as bash does.
                Some(MemberState::Done(last)) if last.code() > 128 && !self.pipefail && !self.negated => {
                    signal_description(i32::from(last.code() - 128))
                }
                _ if status.is_success() => "Done".to_owned(),
                _ => format!("Exit {}", status.code()),
            };
        }
        match self.stop_signal() {
            Some(signal) if self.is_stopped() => match signal {
                signals::SIGTSTP => "Stopped".to_owned(),
                other => format!("Stopped({})", signal_name(other)),
            },
            Some(_) | None => "Running".to_owned(),
        }
    }

    /// The job's line in `jobs` and notifications: `[n]+  State                   text`, with `&` after a running
    /// job's text, as bash prints it.
    pub(crate) fn line(&self, mark: char, with_pid: bool) -> String {
        let number = self.number.unwrap_or(0);
        let state = self.state_text();
        let running = state == "Running";
        let suffix = if running { " &" } else { "" };
        if with_pid {
            let pid = self.shown_pid().map_or_else(String::new, |pid| pid.to_string());
            format!("[{number}]{mark} {pid} {state:<24}{}{suffix}", self.text)
        } else {
            format!("[{number}]{mark}  {state:<24}{}{suffix}", self.text)
        }
    }
}

/// The name bash's `Stopped(…)` uses for `signal`.
fn signal_name(signal: i32) -> String {
    match signal {
        signals::SIGSTOP => "SIGSTOP".to_owned(),
        signals::SIGTTIN => "SIGTTIN".to_owned(),
        signals::SIGTTOU => "SIGTTOU".to_owned(),
        signals::SIGTSTP => "SIGTSTP".to_owned(),
        other => format!("signal {other}"),
    }
}

/// The text macOS's `strsignal` gives for `signal`, which bash prints for a job a signal ended.
pub(crate) fn signal_description(signal: i32) -> String {
    let text = match signal {
        signals::SIGHUP => "Hangup",
        signals::SIGINT => "Interrupt",
        signals::SIGQUIT => "Quit",
        signals::SIGABRT => "Abort trap",
        signals::SIGKILL => "Killed",
        signals::SIGSEGV => "Segmentation fault",
        signals::SIGPIPE => "Broken pipe",
        signals::SIGALRM => "Alarm clock",
        signals::SIGTERM => "Terminated",
        _ => return format!("Unknown signal: {signal}"),
    };
    format!("{text}: {signal}")
}

/// Process groups of the shell's jobs, and the supervisor's pause, shared with [`JobSignals`].
#[derive(Debug, Default)]
pub(crate) struct Registry {
    /// Groups of running jobs under job control.
    groups: Mutex<BTreeSet<ProcessGroupId>>,
    /// The supervisor paused the jobs: stops now are not job control's.
    paused: AtomicBool,
}

impl Registry {
    /// Records a job's group.
    pub(crate) fn add(&self, group: ProcessGroupId) {
        self.groups.lock().unwrap_or_else(PoisonError::into_inner).insert(group);
    }

    /// Forgets a job's group.
    pub(crate) fn remove(&self, group: ProcessGroupId) {
        self.groups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&group);
    }

    fn groups(&self) -> Vec<ProcessGroupId> {
        self.groups
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }
}

/// Stops and continues every job of one shell at once: the supervisor's pause and resume (FR-SES-10). Cheap to
/// clone, and usable from any thread while the shell runs.
///
/// Under job control each job has its own process group, which the supervisor's signal to the shell's group does
/// not reach, so the supervisor pauses them through this. Without job control (every script, every agent line) the
/// jobs are in the shell's own group and the supervisor's signal to it reaches them; this then has nothing to
/// signal. A group is signalled only through the spawner, which refuses once none of its members is held, so a
/// reused id is never signalled.
#[derive(Clone)]
pub struct JobSignals {
    registry: Arc<Registry>,
    spawner: Arc<dyn CommandSpawner>,
}

impl std::fmt::Debug for JobSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobSignals")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl JobSignals {
    pub(crate) fn new(registry: Arc<Registry>, spawner: Arc<dyn CommandSpawner>) -> Self {
        Self { registry, spawner }
    }

    /// The process groups of the shell's running jobs under job control.
    #[must_use]
    pub fn groups(&self) -> Vec<ProcessGroupId> {
        self.registry.groups()
    }

    /// Sends `SIGSTOP` to every job's group. Stops this causes are not reported as job control's (the shell does
    /// not take a paused foreground job for one the user stopped).
    ///
    /// # Errors
    ///
    /// The first refusal other than a group whose members have all ended meanwhile; every group is still tried.
    pub fn pause(&self) -> Result<(), InterpError> {
        self.registry.paused.store(true, Ordering::SeqCst);
        self.signal_all(Signal::Stop)
    }

    /// Sends `SIGCONT` to every job's group and ends the pause.
    ///
    /// # Errors
    ///
    /// As [`JobSignals::pause`].
    pub fn resume(&self) -> Result<(), InterpError> {
        let result = self.signal_all(Signal::Continue);
        self.registry.paused.store(false, Ordering::SeqCst);
        result
    }

    fn signal_all(&self, signal: Signal) -> Result<(), InterpError> {
        let mut first = Ok(());
        for group in self.registry.groups() {
            match self.spawner.signal_job(group, signal) {
                Ok(()) | Err(PlatformError::UnknownProcessGroup) => {}
                Err(error) => {
                    if first.is_ok() {
                        first = Err(InterpError::Platform(error));
                    }
                }
            }
        }
        first
    }
}

/// The jobs of one shell.
#[derive(Debug)]
pub(crate) struct Jobs {
    /// Every job not yet forgotten, by key: foreground ones while they run, background and stopped ones until
    /// reported.
    live: BTreeMap<Key, Job>,
    /// Job numbers in use, to their keys.
    numbers: BTreeMap<usize, Key>,
    /// Job numbers, least recently started, stopped or resumed first: what `%+` and `%-` follow.
    recency: Vec<usize>,
    /// The next key.
    next_key: Key,
    /// Where members report.
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    /// Groups and the pause, shared with [`JobSignals`] and the shell's subshells.
    pub(crate) registry: Arc<Registry>,
}

/// What `jobs` and the job builtins resolve a job specification to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// This job number.
    Found(usize),
    /// No job matches (bash: `no such job`).
    NoSuchJob,
    /// More than one job matches a `%name` (bash: `ambiguous job spec`).
    Ambiguous,
}

impl Jobs {
    /// No jobs, sharing `registry`.
    pub(crate) fn new(registry: Arc<Registry>) -> Self {
        let (sender, receiver) = channel();
        Self {
            live: BTreeMap::new(),
            numbers: BTreeMap::new(),
            recency: Vec::new(),
            next_key: 0,
            sender,
            receiver,
            registry,
        }
    }

    /// A new job with no members yet, live from now on; `owns_group` when `group` is its own rather than the group
    /// of the job it runs inside.
    pub(crate) fn create(
        &mut self,
        text: String,
        group: GroupCell,
        owns_group: bool,
        negated: bool,
        pipefail: bool,
    ) -> Key {
        let key = self.next_key;
        self.next_key += 1;
        self.live.insert(
            key,
            Job {
                key,
                number: None,
                text,
                members: Vec::new(),
                group,
                negated,
                pipefail,
                notified: false,
                owns_group,
            },
        );
        key
    }

    /// The live job `key`.
    pub(crate) fn get(&self, key: Key) -> Option<&Job> {
        self.live.get(&key)
    }

    /// The live job `key`, to change.
    pub(crate) fn get_mut(&mut self, key: Key) -> Option<&mut Job> {
        self.live.get_mut(&key)
    }

    /// The job numbered `number`.
    pub(crate) fn numbered(&self, number: usize) -> Option<&Job> {
        self.numbers.get(&number).and_then(|key| self.live.get(key))
    }

    /// Job numbers in use, in order.
    pub(crate) fn numbers(&self) -> Vec<usize> {
        self.numbers.keys().copied().collect()
    }

    /// Adds a member to job `key` and returns its index.
    pub(crate) fn push(&mut self, key: Key, member: Member) -> usize {
        match self.live.get_mut(&key) {
            Some(job) => {
                job.members.push(member);
                job.members.len() - 1
            }
            None => 0,
        }
    }

    /// A sender for the members of job `key` that run inside the shell.
    pub(crate) fn sender(&self) -> Sender<Event> {
        self.sender.clone()
    }

    /// Where member `member` of job `key`, a subshell on a thread of its own, reports its stops.
    pub(crate) fn parent(&self, key: Key, member: usize) -> Parent {
        Parent {
            sender: self.sender.clone(),
            key,
            member,
        }
    }

    /// An event saying member `member` of `key` ended inside the shell.
    pub(crate) fn inside_event(key: Key, member: usize, result: Result<Status, InterpError>) -> Event {
        Event {
            key,
            member,
            note: Note::Inside(result),
            paused: false,
        }
    }

    /// Starts a thread reporting what happens to `child`, member `member` of job `key`, until it ends.
    ///
    /// # Errors
    ///
    /// [`InterpError::EvaluationThread`] if the thread could not start.
    pub(crate) fn watch(
        &self,
        spawner: &Arc<dyn CommandSpawner>,
        key: Key,
        member: usize,
        child: ChildHandle,
    ) -> Result<(), InterpError> {
        let sender = self.sender.clone();
        let spawner = Arc::clone(spawner);
        let registry = Arc::clone(&self.registry);
        std::thread::Builder::new()
            .name("knsh-wait".to_owned())
            .stack_size(WAITER_STACK_SIZE)
            .spawn(move || {
                loop {
                    let result = spawner.wait(child);
                    let last = !matches!(result, Ok(ChildEvent::Stopped(_) | ChildEvent::Continued));
                    let paused = registry.paused.load(Ordering::SeqCst);
                    // The shell may be gone (an error stopped the script): nobody to tell.
                    let _ = sender.send(Event {
                        key,
                        member,
                        note: Note::Child(result),
                        paused,
                    });
                    if last {
                        break;
                    }
                }
            })
            .map(drop)
            .map_err(|_| InterpError::EvaluationThread)
    }

    /// Waits for the next event and applies it. Returns the key of the job it was about.
    ///
    /// # Errors
    ///
    /// A failure waiting for a child, or the error of a command run inside the shell, which stops the script.
    pub(crate) fn next(&mut self, job_control: bool) -> Result<Key, InterpError> {
        let event = self.receiver.recv().map_err(|_| InterpError::EvaluationThread)?;
        self.apply(&event, job_control)
    }

    /// Applies every event already sent, without blocking.
    ///
    /// # Errors
    ///
    /// As [`Jobs::next`].
    pub(crate) fn poll(&mut self, job_control: bool) -> Result<(), InterpError> {
        while let Ok(event) = self.receiver.try_recv() {
            self.apply(&event, job_control)?;
        }
        Ok(())
    }

    /// Applies `event`: unless `job_control` (the shell does job control, or is a subshell inside a job that is
    /// under it) stops and continues are not the shell's concern (bash does not even ask for them), so only ends
    /// change a member.
    fn apply(&mut self, event: &Event, job_control: bool) -> Result<Key, InterpError> {
        let key = event.key;
        let Some(member) = self
            .live
            .get_mut(&key)
            .and_then(|job| job.members.get_mut(event.member))
        else {
            // A job disowned or forgotten meanwhile: nothing it reports concerns the shell any more.
            return Ok(key);
        };
        match event.note {
            Note::Child(Ok(ChildEvent::Exited(status))) => {
                member.state = MemberState::Done(match status {
                    ExitStatus::Exited(code) => Status::from_exit_code(code),
                    ExitStatus::Signalled(signal) => Status::from_signal(signal),
                });
            }
            Note::Child(Ok(ChildEvent::Stopped(signal))) => {
                if job_control && !event.paused {
                    member.state = MemberState::Stopped(signal);
                }
            }
            Note::Child(Ok(ChildEvent::Continued)) | Note::InsideStop(None) => {
                if matches!(member.state, MemberState::Stopped(_)) {
                    member.state = MemberState::Running;
                }
            }
            Note::Inside(Ok(status)) => member.state = MemberState::Done(status),
            Note::InsideStop(Some(signal)) => {
                if job_control && member.state == MemberState::Running {
                    member.state = MemberState::Stopped(signal);
                }
            }
            Note::Child(Err(error)) => return Err(InterpError::Platform(error)),
            Note::Inside(Err(error)) => return Err(error),
        }
        Ok(key)
    }

    /// Gives job `key` a number (if it has none): one more than the highest in use, as bash numbers jobs. Forgets
    /// the oldest finished jobs past [`MAX_REMEMBERED_JOBS`].
    pub(crate) fn number(&mut self, key: Key) -> usize {
        if let Some(number) = self.live.get(&key).and_then(|job| job.number) {
            self.touch(number);
            return number;
        }
        let number = self.numbers.keys().next_back().map_or(1, |highest| highest + 1);
        if let Some(job) = self.live.get_mut(&key) {
            job.number = Some(number);
        }
        self.numbers.insert(number, key);
        self.touch(number);
        self.prune();
        number
    }

    /// Marks job `number` the most recent.
    pub(crate) fn touch(&mut self, number: usize) {
        self.recency.retain(|&seen| seen != number);
        self.recency.push(number);
    }

    /// Forgets the oldest finished numbered jobs past [`MAX_REMEMBERED_JOBS`].
    fn prune(&mut self) {
        while self.numbers.len() > MAX_REMEMBERED_JOBS {
            let oldest_done = self
                .numbers
                .iter()
                .find(|(_, key)| self.live.get(key).is_some_and(Job::is_done))
                .map(|(&number, _)| number);
            match oldest_done {
                Some(number) => {
                    self.forget_number(number);
                }
                None => break,
            }
        }
    }

    /// Forgets job `key` entirely (it ended and was reported, or was disowned). Its group leaves the registry.
    pub(crate) fn forget(&mut self, key: Key) -> Option<Job> {
        let job = self.live.remove(&key)?;
        if let Some(number) = job.number {
            self.numbers.remove(&number);
            self.recency.retain(|&seen| seen != number);
        }
        if job.owns_group
            && let Some(group) = job.group()
        {
            self.registry.remove(group);
        }
        Some(job)
    }

    /// Forgets the job numbered `number`.
    pub(crate) fn forget_number(&mut self, number: usize) -> Option<Job> {
        let key = *self.numbers.get(&number)?;
        self.forget(key)
    }

    /// `%+`: the most recent stopped job, else the most recent job.
    pub(crate) fn current(&self) -> Option<usize> {
        self.ranked().first().copied()
    }

    /// `%-`: the job after the current one in the same order.
    pub(crate) fn previous(&self) -> Option<usize> {
        self.ranked().get(1).copied()
    }

    /// Job numbers in the order `%+` and `%-` take them: stopped jobs first, most recent first.
    fn ranked(&self) -> Vec<usize> {
        let stopped = |number: &usize| self.numbered(*number).is_some_and(Job::is_stopped);
        let recent: Vec<usize> = self
            .recency
            .iter()
            .rev()
            .copied()
            .filter(|number| self.numbers.contains_key(number))
            .collect();
        recent
            .iter()
            .copied()
            .filter(stopped)
            .chain(recent.iter().copied().filter(|number| !stopped(number)))
            .collect()
    }

    /// The mark `jobs` shows for `number`: `+` current, `-` previous, else a space.
    pub(crate) fn mark(&self, number: usize) -> char {
        if self.current() == Some(number) {
            '+'
        } else if self.previous() == Some(number) {
            '-'
        } else {
            ' '
        }
    }

    /// The job `spec` names: `%%`, `%+`, `%`, `%-`, `%n`, `%name` (a job whose text starts with it), `%?text` (one
    /// whose text contains it), or `n` (a job number, for `fg`, `bg` and `disown`).
    pub(crate) fn find(&self, spec: &str) -> Lookup {
        let found = |number: Option<usize>| number.map_or(Lookup::NoSuchJob, Lookup::Found);
        let body = spec.strip_prefix('%').unwrap_or(spec);
        match body {
            "" | "%" | "+" => return found(self.current()),
            "-" => return found(self.previous()),
            _ => {}
        }
        if !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()) {
            return match body.parse::<usize>() {
                Ok(number) if self.numbers.contains_key(&number) => Lookup::Found(number),
                Ok(_) | Err(_) => Lookup::NoSuchJob,
            };
        }
        if !spec.starts_with('%') {
            return Lookup::NoSuchJob;
        }
        let matches: Vec<usize> = self
            .numbers
            .iter()
            .filter(|(_, key)| {
                self.live.get(key).is_some_and(|job| match body.strip_prefix('?') {
                    Some(text) => job.text.contains(text),
                    None => job.text.starts_with(body),
                })
            })
            .map(|(&number, _)| number)
            .collect();
        match matches.as_slice() {
            [] => Lookup::NoSuchJob,
            [only] => Lookup::Found(*only),
            [_, ..] => Lookup::Ambiguous,
        }
    }

    /// The job holding a child with process id `pid`, and the member index.
    pub(crate) fn by_pid(&self, pid: i32) -> Option<(Key, usize)> {
        self.numbers.values().find_map(|key| {
            let job = self.live.get(key)?;
            let member = job.members.iter().position(|member| member.pid == Some(pid))?;
            Some((*key, member))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(statuses: &[u8], pipefail: bool, negated: bool) -> Job {
        Job {
            key: 0,
            number: Some(1),
            text: "a | b".to_owned(),
            members: statuses.iter().map(|&code| Member::done(Status::new(code))).collect(),
            group: GroupCell::default(),
            negated,
            pipefail,
            notified: false,
            owns_group: true,
        }
    }

    // NFR-COMPAT-02: the last command's status, or under pipefail the rightmost failure, then `!`.
    #[test]
    fn job_status_follows_pipefail_and_negation() {
        assert_eq!(job(&[1, 0], false, false).status(), Status::SUCCESS);
        assert_eq!(job(&[1, 0], true, false).status(), Status::new(1));
        assert_eq!(job(&[2, 3, 0], true, false).status(), Status::new(3));
        assert_eq!(job(&[0, 0], true, false).status(), Status::SUCCESS);
        assert_eq!(job(&[1, 1], false, true).status(), Status::SUCCESS);
    }

    // The lines bash prints for jobs, column for column.
    #[test]
    fn job_lines_match_bash() {
        let mut running = job(&[], false, false);
        running.text = "sleep 30".to_owned();
        running.members = vec![Member {
            pid: Some(42),
            state: MemberState::Running,
        }];
        assert_eq!(running.line('+', false), "[1]+  Running                 sleep 30 &");
        running.members[0].state = MemberState::Stopped(signals::SIGTSTP);
        assert_eq!(running.line('+', false), "[1]+  Stopped                 sleep 30");
        running.members[0].state = MemberState::Stopped(signals::SIGTTIN);
        assert_eq!(running.line('-', false), "[1]-  Stopped(SIGTTIN)        sleep 30");
        running.members[0].state = MemberState::Done(Status::SUCCESS);
        assert_eq!(running.line(' ', false), "[1]   Done                    sleep 30");
        running.members[0].state = MemberState::Done(Status::new(3));
        assert_eq!(running.line('+', false), "[1]+  Exit 3                  sleep 30");
        running.members[0].state = MemberState::Done(Status::from_signal(signals::SIGTERM));
        assert_eq!(running.line('+', false), "[1]+  Terminated: 15          sleep 30");
    }
}
