//! The job builtins: `wait`, `jobs`, `fg`, `bg` and `disown` (KNSH-100; NFR-COMPAT-02).
//!
//! Messages and statuses follow bash: an unknown process id is `pid N is not a child of this shell` (127), an unknown
//! job `%N: no such job` (127 for `wait`, 1 otherwise), `fg` and `bg` without job control `no job control` (1). A job
//! whose end `wait` or `jobs` reports is forgotten, as bash forgets it.

use std::fmt::Write as _;

use knsh_bash::Span;
use knsh_platform::signals;

use super::{Flow, Interpreter, Run};
use crate::jobs::{Key, Lookup, MemberState};
use crate::status::Status;

/// What a `wait` operand names.
#[derive(Debug, Clone, Copy)]
enum Target {
    /// A member of a job: the process with that id.
    Member(Key, usize),
    /// A whole job.
    Job(Key),
}

impl Interpreter {
    /// The job builtin `name` with `args`, if `name` is one.
    pub(super) fn job_builtin(
        &mut self,
        name: &str,
        args: &[String],
        span: Span,
        run: &Run<'_>,
    ) -> Option<Flow<Status>> {
        Some(match name {
            "wait" => self.wait_builtin(args, span, run),
            "jobs" => self.jobs_builtin(args, span, run),
            "fg" => self.fg_builtin(args, span, run),
            "bg" => self.bg_builtin(args, span, run),
            "disown" => self.disown_builtin(args, span, run),
            _ => return None,
        })
    }

    /// Splits `args` into the leading options (single letters among `allowed`) and the operands. `Err` with the
    /// status after reporting an unknown option as bash does.
    pub(super) fn options<'a>(
        &mut self,
        name: &str,
        usage: &str,
        allowed: &str,
        args: &'a [String],
        span: Span,
        run: &Run<'_>,
    ) -> Result<(String, &'a [String]), Status> {
        let mut letters = String::new();
        let mut rest = args;
        while let Some(first) = rest.first() {
            if first == "--" {
                rest = &rest[1..];
                break;
            }
            let Some(options) = first.strip_prefix('-').filter(|options| !options.is_empty()) else {
                break;
            };
            if let Some(bad) = options.chars().find(|ch| !allowed.contains(*ch)) {
                self.report(span, run, format_args!("{name}: -{bad}: invalid option"));
                // Bash's `builtin_usage`: the usage line has no name or line number before it.
                self.report_plain(format_args!("{name}: usage: {name} {usage}"));
                // Bash's `EX_USAGE` (KNSH-106: a special builtin's ends the shell in POSIX mode).
                self.usage_error = true;
                return Err(Status::new(2));
            }
            letters.push_str(options);
            rest = &rest[1..];
        }
        Ok((letters, rest))
    }

    /// The job `spec` names for `name`, reporting bash's error (`current` for the default job) when none or more
    /// than one does.
    fn job_spec(&mut self, name: &str, spec: Option<&str>, span: Span, run: &Run<'_>) -> Option<usize> {
        let found = self.jobs.find(spec.unwrap_or("%+"));
        let label = spec.unwrap_or("current");
        match found {
            Lookup::Found(number) => Some(number),
            Lookup::NoSuchJob => {
                self.report(span, run, format_args!("{name}: {label}: no such job"));
                None
            }
            Lookup::Ambiguous => {
                self.report(span, run, format_args!("{name}: {label}: ambiguous job spec"));
                None
            }
        }
    }

    /// The key of job number `number`.
    fn key_of(&self, number: usize) -> Option<Key> {
        self.jobs.numbered(number).map(|job| job.key)
    }

    /// `wait [-n] [id …]`.
    fn wait_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, ids) = match self.options("wait", "[-n] [id ...]", "n", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        self.jobs.poll(self.tracks_stops())?;
        let mut targets = Vec::with_capacity(ids.len());
        let mut status = Status::SUCCESS;
        for id in ids {
            match self.wait_target(id) {
                Ok(target) => targets.push(target),
                Err(failure) => {
                    let message = match failure {
                        WaitFailure::NotChild => format!("wait: pid {id} is not a child of this shell"),
                        WaitFailure::NoSuchJob => format!("wait: {id}: no such job"),
                        WaitFailure::Invalid => format!("wait: `{id}': not a pid or valid job spec"),
                    };
                    self.report(span, run, format_args!("{message}"));
                    status = match failure {
                        WaitFailure::NotChild | WaitFailure::NoSuchJob => Status::NOT_FOUND,
                        WaitFailure::Invalid => Status::FAILURE,
                    };
                }
            }
        }
        if options.contains('n') {
            let keys: Option<Vec<Key>> = (!ids.is_empty()).then(|| {
                targets
                    .iter()
                    .map(|target| match target {
                        Target::Member(key, _) | Target::Job(key) => *key,
                    })
                    .collect()
            });
            return self.wait_any(keys.as_deref());
        }
        if ids.is_empty() {
            return self.wait_all();
        }
        for target in targets {
            status = self.wait_for(target)?;
        }
        Ok(status)
    }

    /// The target `id` names: a process id of one of the shell's jobs, or a job specification.
    fn wait_target(&self, id: &str) -> Result<Target, WaitFailure> {
        if id.starts_with('%') {
            return match self.jobs.find(id) {
                Lookup::Found(number) => self.key_of(number).map(Target::Job).ok_or(WaitFailure::NoSuchJob),
                Lookup::NoSuchJob | Lookup::Ambiguous => Err(WaitFailure::NoSuchJob),
            };
        }
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WaitFailure::Invalid);
        }
        let pid = id.parse::<i32>().map_err(|_| WaitFailure::NotChild)?;
        self.jobs
            .by_pid(pid)
            .map(|(key, member)| Target::Member(key, member))
            .ok_or(WaitFailure::NotChild)
    }

    /// Waits for `target`: a process's status, or a whole job's. Under job control a job that stops ends the wait
    /// with `128 + signal`. A job that ended is forgotten.
    fn wait_for(&mut self, target: Target) -> Flow<Status> {
        let job_control = self.job_control();
        let key = match target {
            Target::Member(key, _) | Target::Job(key) => key,
        };
        loop {
            let Some(job) = self.jobs.get(key) else {
                return Ok(Status::NOT_FOUND);
            };
            let status = match target {
                Target::Member(_, member) => match job.members.get(member).map(|member| member.state) {
                    Some(MemberState::Done(status)) => Some(status),
                    Some(MemberState::Running | MemberState::Stopped(_)) | None => None,
                },
                Target::Job(_) => job.is_done().then(|| job.status()),
            };
            if let Some(status) = status {
                if job.is_done() {
                    self.jobs.forget(key);
                }
                return Ok(status);
            }
            if job_control && job.is_stopped() {
                return Ok(Status::from_signal(job.stop_signal().unwrap_or(signals::SIGTSTP)));
            }
            self.jobs.next(self.tracks_stops())?;
        }
    }

    /// `wait` without operands: every running background job, then 0. Stopped jobs are not waited for.
    fn wait_all(&mut self) -> Flow<Status> {
        let job_control = self.job_control();
        loop {
            let pending = self.jobs.numbers().into_iter().any(|number| {
                self.jobs
                    .numbered(number)
                    .is_some_and(|job| !(job.is_done() || (job_control && job.is_stopped())))
            });
            if !pending {
                break;
            }
            self.jobs.next(self.tracks_stops())?;
        }
        for number in self.jobs.numbers() {
            if self.jobs.numbered(number).is_some_and(crate::jobs::Job::is_done) {
                self.jobs.forget_number(number);
            }
        }
        Ok(Status::SUCCESS)
    }

    /// `wait -n`: the status of the first job among `keys` (every job when `None`) to end, taking first a job that
    /// already ended and was not reported (lowest number first), as bash does; 127 when none is left to wait for.
    fn wait_any(&mut self, keys: Option<&[Key]>) -> Flow<Status> {
        let job_control = self.job_control();
        loop {
            let candidates: Vec<Key> = self
                .jobs
                .numbers()
                .into_iter()
                .filter_map(|number| self.key_of(number))
                .filter(|key| keys.is_none_or(|keys| keys.contains(key)))
                .collect();
            if let Some(&done) = candidates
                .iter()
                .find(|key| self.jobs.get(**key).is_some_and(crate::jobs::Job::is_done))
            {
                let status = self.jobs.get(done).map_or(Status::NOT_FOUND, crate::jobs::Job::status);
                self.jobs.forget(done);
                return Ok(status);
            }
            let running = candidates.iter().any(|key| {
                self.jobs
                    .get(*key)
                    .is_some_and(|job| !(job_control && job.is_stopped()))
            });
            if !running {
                return Ok(Status::NOT_FOUND);
            }
            self.jobs.next(self.tracks_stops())?;
        }
    }

    /// `jobs [-lprs] [spec …]`: each job's line on standard output; a job reported as ended is forgotten.
    fn jobs_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, specs) = match self.options("jobs", "[-lnprs] [jobspec ...]", "lprs", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        self.jobs.poll(self.tracks_stops())?;
        let mut status = Status::SUCCESS;
        let numbers = if specs.is_empty() {
            self.jobs.numbers()
        } else {
            let mut numbers = Vec::new();
            for spec in specs {
                match self.job_spec("jobs", Some(spec), span, run) {
                    Some(number) => numbers.push(number),
                    None => status = Status::FAILURE,
                }
            }
            numbers
        };
        let mut text = String::new();
        let mut reported = Vec::new();
        for number in numbers {
            let mark = self.jobs.mark(number);
            let Some(job) = self.jobs.numbered(number) else {
                continue;
            };
            let running = !job.is_done() && !job.is_stopped();
            if (options.contains('r') && !running) || (options.contains('s') && !job.is_stopped()) {
                continue;
            }
            if options.contains('p') {
                if let Some(pid) = job.shown_pid() {
                    let _ = writeln!(text, "{pid}");
                }
            } else {
                text.push_str(&job.line(mark, options.contains('l'), self.state.options().posix()));
                text.push('\n');
            }
            if job.is_done() {
                reported.push(number);
            }
        }
        self.write_shell(1, text.as_bytes());
        for number in reported {
            self.jobs.forget_number(number);
        }
        Ok(status)
    }

    /// `fg [spec]`: the job in the foreground, continued if stopped, and waited for.
    fn fg_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if !self.job_control() {
            self.report(span, run, format_args!("fg: no job control"));
            return Ok(Status::FAILURE);
        }
        self.jobs.poll(true)?;
        let Some(number) = self.job_spec("fg", args.first().map(String::as_str), span, run) else {
            return Ok(Status::FAILURE);
        };
        let Some(key) = self.key_of(number) else {
            return Ok(Status::FAILURE);
        };
        // A job that ended is not continued, and its group, whose id may be free again, is never given the
        // terminal (`JobTerminal::set_foreground`): bash's `job has terminated`.
        if self.jobs.get(key).is_some_and(crate::jobs::Job::is_done) {
            self.report(span, run, format_args!("fg: job has terminated"));
            return Ok(Status::FAILURE);
        }
        self.jobs.touch(number);
        let (text, group) = match self.jobs.get(key) {
            Some(job) => (job.text.clone(), job.group()),
            None => return Ok(Status::FAILURE),
        };
        self.write_shell(1, format!("{text}\n").as_bytes());
        if let (Some(terminal), Some(group)) = (&self.terminal, group) {
            // A failure is ignored, as bash ignores it: the job still runs, without the terminal.
            let _ = terminal.set_foreground(Some(group));
        }
        self.continue_job(key)?;
        self.wait_foreground(key, run)
    }

    /// `bg [spec …]`: each stopped job continued in the background.
    fn bg_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        if !self.job_control() {
            self.report(span, run, format_args!("bg: no job control"));
            return Ok(Status::FAILURE);
        }
        self.jobs.poll(true)?;
        let specs: Vec<Option<&str>> = if args.is_empty() {
            vec![None]
        } else {
            args.iter().map(|arg| Some(arg.as_str())).collect()
        };
        let mut status = Status::SUCCESS;
        for spec in specs {
            let Some(number) = self.job_spec("bg", spec, span, run) else {
                status = Status::FAILURE;
                continue;
            };
            let Some(key) = self.key_of(number) else {
                continue;
            };
            if self.jobs.get(key).is_some_and(crate::jobs::Job::is_done) {
                self.report(span, run, format_args!("bg: job has terminated"));
                status = Status::FAILURE;
                continue;
            }
            if !self.jobs.get(key).is_some_and(crate::jobs::Job::is_stopped) {
                self.report(span, run, format_args!("bg: job {number} already in background"));
                continue;
            }
            self.jobs.touch(number);
            let mark = self.jobs.mark(number);
            let text = self.jobs.get(key).map(|job| job.text.clone()).unwrap_or_default();
            self.write_shell(1, format!("[{number}]{mark} {text} &\n").as_bytes());
            self.continue_job(key)?;
        }
        Ok(status)
    }

    /// `disown [-ahr] [spec …]`: the jobs leave the table (`-h` keeps them: the shell never sends `SIGHUP` to its
    /// jobs, so there is nothing to mark).
    fn disown_builtin(&mut self, args: &[String], span: Span, run: &Run<'_>) -> Flow<Status> {
        let (options, specs) = match self.options("disown", "[-h] [-ar] [jobspec ...]", "ahr", args, span, run) {
            Ok(parsed) => parsed,
            Err(status) => return Ok(status),
        };
        self.jobs.poll(self.tracks_stops())?;
        let mut numbers = Vec::new();
        let mut status = Status::SUCCESS;
        if options.contains('a') || options.contains('r') {
            numbers = self.jobs.numbers();
            if options.contains('r') {
                numbers.retain(|number| {
                    self.jobs
                        .numbered(*number)
                        .is_some_and(|job| !job.is_done() && !job.is_stopped())
                });
            }
        } else if specs.is_empty() {
            match self.job_spec("disown", None, span, run) {
                Some(number) => numbers.push(number),
                None => status = Status::FAILURE,
            }
        } else {
            for spec in specs {
                match self.job_spec("disown", Some(spec), span, run) {
                    Some(number) => numbers.push(number),
                    None => status = Status::FAILURE,
                }
            }
        }
        if !options.contains('h') {
            for number in numbers {
                self.jobs.forget_number(number);
            }
        }
        Ok(status)
    }

    /// Reports the background jobs that ended or stopped since the last report, as an interactive bash does before
    /// its prompt: each ended job's line on the shell's descriptor 2, then it is forgotten.
    pub(super) fn notify(&mut self) -> Result<(), crate::error::InterpError> {
        self.jobs.poll(self.tracks_stops())?;
        let mut text = String::new();
        let mut ended = Vec::new();
        for number in self.jobs.numbers() {
            let mark = self.jobs.mark(number);
            let Some(key) = self.key_of(number) else {
                continue;
            };
            let Some(job) = self.jobs.get_mut(key) else {
                continue;
            };
            if job.is_done() {
                text.push_str(&job.line(mark, false, self.state.options().posix()));
                text.push('\n');
                ended.push(number);
            } else if job.is_stopped() && !job.notified {
                job.notified = true;
                text.push_str(&job.line(mark, false, self.state.options().posix()));
                text.push('\n');
            }
        }
        self.write_shell(2, text.as_bytes());
        for number in ended {
            self.jobs.forget_number(number);
        }
        Ok(())
    }
}

/// Why a `wait` operand names nothing to wait for.
#[derive(Debug, Clone, Copy)]
enum WaitFailure {
    /// A process id that is not one of the shell's jobs'.
    NotChild,
    /// A job specification naming no job.
    NoSuchJob,
    /// Neither a number nor a job specification.
    Invalid,
}
