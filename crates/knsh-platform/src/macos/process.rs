//! Process groups on the real system.
//!
//! # Why reuse-safe
//!
//! A group id equals its leader's pid. The kernel cannot hand that pid to a new process while the leader exists,
//! including as an unreaped zombie. So this module keeps every leader unreaped until it removes the group from its
//! table, and both `killpg` and the reaping happen under the same lock: a signal either finds the group in the table
//! (leader not yet reaped, id still ours) or is refused.
//!
//! Waiting must not hold that lock while it blocks, or nobody could signal a running group. [`SystemProcesses::wait`]
//! therefore blocks in `waitid(…, WNOWAIT)`, which reports the exit without reaping, and only then takes the lock,
//! removes the entry and reaps.
//!
//! A shell's children ([`Processes::spawn_child`], KNSH-100) are kept the same way in a second map of the same
//! table, with the group each joined. A job's group is signalled only while one of its members is in that map: a
//! process group id is not reused while the group has a member, and a member this instance has not reaped is still
//! a member (exited or not). Joining a group is checked and done under the lock, so the group cannot lose its last
//! held member in between.

use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::error::{Operation, PlatformError};
use crate::process::{
    ChildEvent, ChildHandle, ChildOptions, ChildSignals, ExitStatus, GroupMembership, MAX_PLACED_FD, PlacementSource,
    ProcessGroupId, Processes, SharedFd, Signal, SpawnRequest, Stdio,
};

/// Starts processes in new process groups and signals only the groups it holds.
///
/// Dropping it neither kills nor reaps the remaining children: they keep running and are reaped when the engine
/// exits. The supervisor waits for every group it starts.
#[derive(Debug, Default)]
pub struct SystemProcesses {
    /// Groups spawned and not yet reaped, by group id. Lock order: this is the only lock in the type.
    groups: Mutex<Table>,
}

/// The groups held, each tagged with a spawn generation.
#[derive(Debug, Default)]
struct Table {
    /// Incremented on every spawn.
    next_generation: u64,
    /// Unreaped leaders by group id, with the generation they were spawned in.
    entries: HashMap<i32, (u64, Child)>,
    /// Unreaped children of [`Processes::spawn_child`] by process id (KNSH-100).
    children: HashMap<i32, HeldChild>,
}

/// A child of [`Processes::spawn_child`], unreaped.
#[derive(Debug)]
struct HeldChild {
    /// The generation it was spawned in.
    generation: u64,
    /// The process.
    child: Child,
    /// The group it was placed in, `None` for the caller's.
    group: Option<i32>,
}

impl Table {
    /// Whether `group` is a group this instance may signal: a leader of [`Processes::spawn`] or a member of
    /// [`Processes::spawn_child`] in it is unreaped.
    fn holds_group(&self, group: i32) -> bool {
        self.entries.contains_key(&group) || self.children.values().any(|held| held.group == Some(group))
    }

    /// The next generation.
    fn generation(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation
    }
}

impl SystemProcesses {
    /// An instance holding no groups.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the table. A poisoned lock is still usable: the table holds no invariant that a panic can break
    /// halfway (each update is one insert or remove).
    fn table(&self) -> MutexGuard<'_, Table> {
        self.groups.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The child's stdin, stdout and stderr for `wanted`. Passed descriptors are copied: the copies move into the command
/// and are closed in this process once it has spawned, and the child gets them as 0, 1 and 2 without `FD_CLOEXEC`.
fn standard_descriptors(wanted: &Stdio) -> Result<[std::process::Stdio; 3], PlatformError> {
    match wanted {
        Stdio::Null => Ok(std::array::from_fn(|_| std::process::Stdio::null())),
        Stdio::Inherit => Ok(std::array::from_fn(|_| std::process::Stdio::inherit())),
        Stdio::Passed(fds) => {
            let copy = |fd: &SharedFd| {
                fd.try_clone_owned()
                    .map(std::process::Stdio::from)
                    .map_err(|error| PlatformError::from_io(Operation::Spawn, &error))
            };
            let [stdin, stdout, stderr] = &**fds;
            Ok([copy(stdin)?, copy(stdout)?, copy(stderr)?])
        }
    }
}

/// Sets up the child's descriptors, after the fork and in the child only.
///
/// 1. Places `request.placements` (KNSH-099): each source is first copied to a number that is not a target, then
///    each target receives its copy (or is closed), then the copies are closed. Reading every source before writing any
///    target is what makes `1>&2 2>&1` a swap, and a source whose number is also a target is never overwritten
///    before it is read.
/// 2. Closes every descriptor that is open without `FD_CLOEXEC` and not listed in `request.inherit` or placed. macOS
///    has no `pipe2` or `accept4`, so std creates pipes and sockets first and sets `FD_CLOEXEC` in a second call. A
///    fork by another thread between the two calls would hand that descriptor to this child for its whole life: a
///    hook would hold a stranger's stdout pipe open (its reader never sees end of file) and an agent command would
///    receive a descriptor from another session. A descriptor that already has `FD_CLOEXEC` (including std's own
///    pipe that reports a failed `exec`) is left alone; `exec` closes it.
/// 3. Keeps `request.inherit` open under their own numbers by clearing their `FD_CLOEXEC`, so no other child spawned
///    concurrently by this multithreaded process can inherit them.
/// 4. With a placement above stdio, executes the program itself ([`ExecImage`]): such a target may be the number of
///    std's pipe that reports a failed `exec`, which the placement replaced, so std's own report would land in the
///    placed file. A failed `exec` then ends the child with bash's status (127 for `ENOENT`, 126 otherwise) instead.
fn child_descriptors(command: &mut Command, request: &SpawnRequest) -> Result<(), PlatformError> {
    let fds: Vec<i32> = request.inherit.iter().map(AsRawFd::as_raw_fd).collect();
    let bad = |errno| PlatformError::Os {
        operation: Operation::Spawn,
        errno,
    };
    // Stdio is set up by the command itself; a number below 3 here would be silently replaced.
    if fds.iter().any(|&fd| fd < 3) {
        return Err(bad(libc::EBADF));
    }
    let placements = placements(request).ok_or_else(|| bad(libc::EINVAL))?;
    let targets: Vec<i32> = placements.iter().map(|&(target, _)| target).collect();
    let keep: Vec<i32> = fds
        .iter()
        .copied()
        .chain(
            placements
                .iter()
                .filter(|(_, source)| source.is_some())
                .map(|&(target, _)| target),
        )
        .collect();
    let mut copies = vec![-1; placements.len()];
    let image = if targets.iter().any(|&target| target > 2) {
        Some(ExecImage::new(request).ok_or_else(|| bad(libc::EINVAL))?)
    } else {
        None
    };
    // Read before the fork: no descriptor number in the child can reach the table size.
    // SAFETY: `getdtablesize` has no preconditions and touches no memory.
    let table_size = unsafe { libc::getdtablesize() };
    // The child lists the descriptors really open (`PROC_PIDLISTFDS`) rather than probing every number below the
    // table size, which costs about 10 ms per spawn when the soft limit is high (a terminal or cargo raises it to
    // `kern.maxfilesperproc`). The buffer is allocated here, before the fork, with room to spare; a list that fills
    // it may be cut short, and the child then falls back to probing every number.
    let mut listed = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        open_descriptor_capacity()
    ];
    let listed_bytes = libc::c_int::try_from(listed.len() * size_of::<libc::proc_fdinfo>()).unwrap_or(libc::c_int::MAX);
    // SAFETY: the closure runs in the forked child before `exec`. It only calls `getpid`, `proc_pidinfo` (a thin
    // wrapper of the `proc_info` system call: no lock, no allocation), `fcntl`, `dup2`, `close`, `execve` and
    // `_exit`, and reads or writes only memory allocated before the fork (`fds`, `keep`, `targets`, `placements`, `copies`,
    // `listed`, whose length in bytes `listed_bytes` never exceeds, and `image`). The listed and placed source
    // descriptors are open: `request` (and so every `SharedFd`) outlives the spawn, and the child inherited them at
    // the fork.
    unsafe {
        command.pre_exec(move || {
            // Each copy takes the lowest free number from 3 that is not a target, so writing a target never
            // overwrites a copy. A copy that lands on a target number is left open there (the target is written or
            // closed below, which replaces it) and the source copied again; at most one extra copy per target. Not
            // above every target: with a target at `MAX_PLACED_FD` that would need a number past the default limit
            // of 256 open descriptors.
            for (copy, (_, source)) in copies.iter_mut().zip(&placements) {
                if let Some(source) = source {
                    loop {
                        *copy = libc::fcntl(*source, libc::F_DUPFD, 3);
                        if *copy == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if !targets.contains(copy) {
                            break;
                        }
                    }
                }
            }
            // From the first target written on, std's pipe that reports a failed `exec` may already be one of the
            // targets (only with `image`, which is there whenever a target is above 2): reporting a failure through
            // it would write std's error bytes into the placed file. The child then ends with 126 instead.
            let failed = |image: &Option<ExecImage>| -> std::io::Error {
                if image.is_some() {
                    libc::_exit(126);
                }
                std::io::Error::last_os_error()
            };
            for (&copy, &(target, _)) in copies.iter().zip(&placements) {
                if copy == -1 {
                    libc::close(target);
                } else if libc::dup2(copy, target) == -1 {
                    return Err(failed(&image));
                }
            }
            for &copy in copies.iter().filter(|&&copy| copy != -1) {
                libc::close(copy);
            }
            let got = libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                listed.as_mut_ptr().cast(),
                listed_bytes,
            );
            match usize::try_from(got) {
                Ok(bytes) if got > 0 && got < listed_bytes => {
                    let count = bytes / size_of::<libc::proc_fdinfo>();
                    for entry in listed.iter().take(count) {
                        close_if_leaked(entry.proc_fd, &keep);
                    }
                }
                Ok(_) | Err(_) => {
                    for fd in 3..table_size {
                        close_if_leaked(fd, &keep);
                    }
                }
            }
            for &fd in &fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(failed(&image));
                }
            }
            if let Some(image) = &image {
                image.exec();
            }
            Ok(())
        });
    }
    Ok(())
}

/// `request.placements` as (target, source number) pairs, the source read in the child: a shared descriptor's own
/// number or a standard one. `None` if a target is out of range or repeated, collides with an inherited number, or a
/// standard source is not 0 to 2.
fn placements(request: &SpawnRequest) -> Option<Vec<(i32, Option<i32>)>> {
    let mut out: Vec<(i32, Option<i32>)> = Vec::with_capacity(request.placements.len());
    for placement in &request.placements {
        let target = placement.target;
        let repeated = out.iter().any(|&(seen, _)| seen == target);
        let inherited = request.inherit.iter().any(|fd| fd.as_raw_fd() == target);
        if !(0..=MAX_PLACED_FD).contains(&target) || repeated || inherited {
            return None;
        }
        let source = match &placement.source {
            None => None,
            Some(PlacementSource::Shared(fd)) => Some(fd.as_raw_fd()),
            Some(PlacementSource::Stdio(fd @ 0..=2)) => Some(*fd),
            Some(PlacementSource::Stdio(_)) => return None,
        };
        out.push((target, source));
    }
    Some(out)
}

/// What `execve` needs, built before the fork so the child allocates nothing: the program, `argv` and the
/// environment as C strings, with null-terminated pointer arrays into them.
struct ExecImage {
    /// The program's path.
    program: CString,
    /// `argv[0]` and the arguments; owns what `argv` points to.
    _args: Vec<CString>,
    /// `NAME=value` for each variable; owns what `envp` points to.
    _env: Vec<CString>,
    /// Pointers into `_args`, then a null pointer.
    argv: Vec<*const libc::c_char>,
    /// Pointers into `_env`, then a null pointer.
    envp: Vec<*const libc::c_char>,
}

// SAFETY: the pointers point into heap buffers the same value owns (`CString` contents never move when the struct
// does), are only read, and only by `execve` in the child; nothing is shared mutably across threads.
unsafe impl Send for ExecImage {}
// SAFETY: as for `Send`: the value is never mutated after it is built.
unsafe impl Sync for ExecImage {}

impl ExecImage {
    /// The image of `request`, or `None` if a string holds a NUL byte (std refuses such a command too).
    fn new(request: &SpawnRequest) -> Option<Self> {
        let c_string = |bytes: &[u8]| CString::new(bytes).ok();
        let program = c_string(request.program.as_os_str().as_bytes())?;
        let argv0 = request.argv0.as_deref().unwrap_or(request.program.as_os_str());
        let args = std::iter::once(argv0)
            .chain(request.args.iter().map(OsString::as_os_str))
            .map(|arg| c_string(arg.as_bytes()))
            .collect::<Option<Vec<CString>>>()?;
        let env = request
            .env
            .iter()
            .map(|(name, value)| {
                let mut entry = name.as_bytes().to_vec();
                if entry.contains(&b'=') {
                    return None;
                }
                entry.push(b'=');
                entry.extend_from_slice(value.as_bytes());
                c_string(&entry)
            })
            .collect::<Option<Vec<CString>>>()?;
        let pointers = |strings: &[CString]| {
            strings
                .iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        };
        Some(Self {
            argv: pointers(&args),
            envp: pointers(&env),
            program,
            _args: args,
            _env: env,
        })
    }

    /// Executes the image; returns only by ending the process. In the forked child only: async-signal-safe
    /// (`execve` and `_exit`, reading memory allocated before the fork).
    fn exec(&self) -> ! {
        // SAFETY: every pointer is valid and null-terminated (built in `new` and owned by `self`, which lives until
        // the process image is replaced or ends). `_exit` takes a plain integer.
        unsafe {
            libc::execve(self.program.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr());
            let failed_as = if *libc::__error() == libc::ENOENT { 127 } else { 126 };
            libc::_exit(failed_as)
        }
    }
}

/// Entries for the child's list of open descriptors: the parent's count now, plus room for those other threads open
/// before the fork. At least 1,024.
fn open_descriptor_capacity() -> usize {
    // SAFETY: with a null buffer, `proc_pidinfo` writes nothing and returns the bytes a list would need now.
    let needed = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    usize::try_from(needed).unwrap_or(0) / size_of::<libc::proc_fdinfo>() + 1024
}

/// In the forked child: closes `fd` if it is above stdio, open without `FD_CLOEXEC` and not one of `keep`.
/// Async-signal-safe: `fcntl` and `close` only, and `keep` was allocated before the fork.
fn close_if_leaked(fd: i32, keep: &[i32]) {
    if fd < 3 || keep.contains(&fd) {
        return;
    }
    // SAFETY: `fcntl` and `close` take plain integers and touch no memory; a number that is not open makes `fcntl`
    // return -1, and nothing is closed.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags != -1 && flags & libc::FD_CLOEXEC == 0 {
            libc::close(fd);
        }
    }
}

/// Converts the standard status of a reaped child.
fn convert(status: std::process::ExitStatus) -> ExitStatus {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitStatus::Exited(code),
        (None, Some(signal)) => ExitStatus::Signalled(signal),
        // Neither code nor signal only happens for a stopped or continued child, which `wait` never reports.
        (None, None) => ExitStatus::Signalled(0),
    }
}

/// Blocks until `pid` has exited, without reaping it (`WNOWAIT`), so its id stays reserved.
fn wait_exit_without_reaping(pid: i32) -> Result<(), PlatformError> {
    let id = libc::id_t::try_from(pid).map_err(|_| PlatformError::UnknownProcessGroup)?;
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value (it is a plain C struct of integers and pointers).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable `siginfo_t` for the duration of the call. `waitid` touches no other
        // memory, and with `WNOWAIT` it does not change the child's state.
        let rc = unsafe { libc::waitid(libc::P_PID, id, &raw mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(PlatformError::from_io(Operation::Wait, &error));
        }
    }
}

/// The command for `request`, with its descriptors set up and `membership` placing it in a group. Job setup
/// (`job`) runs in the child before the descriptor setup, which may execute the program itself.
fn build_command(
    request: &SpawnRequest,
    membership: GroupMembership,
    job: Option<&ChildOptions>,
) -> Result<Command, PlatformError> {
    if !request.program.is_absolute() {
        return Err(PlatformError::InvalidPath);
    }
    let mut command = Command::new(&request.program);
    command
        .args(&request.args)
        .env_clear()
        .envs(request.env.iter().map(|(k, v)| (k, v)));
    match membership {
        // `setpgid(0, group)` in the child before exec (and before the closures below).
        GroupMembership::Lead => {
            command.process_group(0);
        }
        GroupMembership::Join(group) => {
            command.process_group(group.as_raw());
        }
        GroupMembership::Inherit => {}
    }
    if let Some(argv0) = &request.argv0 {
        command.arg0(argv0);
    }
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    let [stdin, stdout, stderr] = standard_descriptors(&request.stdio)?;
    command.stdin(stdin).stdout(stdout).stderr(stderr);
    if let Some(options) = job {
        child_job_setup(&mut command, options);
    }
    child_descriptors(&mut command, request)?;
    Ok(command)
}

/// Signals whose disposition [`ChildSignals::Default`] resets: what an interactive shell ignores for itself.
const JOB_SIGNALS: [i32; 5] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

/// In the child, after std placed it in its group and before exec: hands it the terminal (a foreground job's leader)
/// and sets its signals as `options` says (KNSH-100).
fn child_job_setup(command: &mut Command, options: &ChildOptions) {
    let terminal = match options.group {
        GroupMembership::Lead => options.terminal.as_ref().map(AsRawFd::as_raw_fd),
        GroupMembership::Inherit | GroupMembership::Join(_) => None,
    };
    let signals = options.signals;
    // SAFETY: the closure runs in the forked child before `exec`. It only calls `sigemptyset`, `sigaddset`,
    // `pthread_sigmask`, `tcsetpgrp`, `getpgrp` and `sigaction`, all async-signal-safe, on stack values and on the
    // terminal descriptor, which the child inherited at the fork (the `SharedFd` in `options` outlives the spawn).
    unsafe {
        command.pre_exec(move || {
            if let Some(fd) = terminal {
                // With `SIGTTOU` blocked a process outside the foreground group may still set it, so a shell that
                // does not ignore `SIGTTOU` itself does not stop its child here. A failure is ignored, as bash's
                // `give_terminal_to` ignores it.
                let mut set: libc::sigset_t = std::mem::zeroed();
                let mut old: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, libc::SIGTTOU);
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut old);
                libc::tcsetpgrp(fd, libc::getpgrp());
                libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut());
            }
            let (wanted, chosen): (&[i32], libc::sighandler_t) = match signals {
                ChildSignals::Inherit => (&[], libc::SIG_DFL),
                ChildSignals::Default => (&JOB_SIGNALS, libc::SIG_DFL),
                ChildSignals::IgnoreInterrupt => (&[libc::SIGINT, libc::SIGQUIT], libc::SIG_IGN),
            };
            for &signal in wanted {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = chosen;
                if libc::sigaction(signal, &raw const action, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// The process id of a spawned `child`.
fn child_pid(child: &Child) -> Result<i32, PlatformError> {
    i32::try_from(child.id()).map_err(|_| PlatformError::Os {
        operation: Operation::Spawn,
        errno: libc::ERANGE,
    })
}

/// What `waitid` reported for a child: the `si_code` and `si_status` of the report.
fn wait_report(pid: i32, flags: libc::c_int) -> Result<Option<(libc::c_int, libc::c_int)>, PlatformError> {
    let id = libc::id_t::try_from(pid).map_err(|_| PlatformError::UnknownProcessGroup)?;
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value (it is a plain C struct of integers and pointers).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable `siginfo_t` for the duration of the call; `waitid` touches no other
        // memory.
        let rc = unsafe { libc::waitid(libc::P_PID, id, &raw mut info, flags) };
        if rc == 0 {
            // With `WNOHANG` and nothing to report, `si_pid` stays zero.
            return Ok((info.si_pid != 0).then_some((info.si_code, info.si_status)));
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::ECHILD) => return Err(PlatformError::UnknownProcessGroup),
            _ => return Err(PlatformError::from_io(Operation::Wait, &error)),
        }
    }
}

impl Processes for SystemProcesses {
    fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError> {
        // A new group led by the child itself (`setpgid(0, 0)` in the child before exec).
        let mut command = build_command(request, GroupMembership::Lead, None)?;
        let child = command
            .spawn()
            .map_err(|error| PlatformError::from_io(Operation::Spawn, &error))?;
        let pid = child_pid(&child)?;
        let mut table = self.table();
        let generation = table.generation();
        table.entries.insert(pid, (generation, child));
        Ok(ProcessGroupId::from_raw(pid))
    }

    fn spawn_child(&self, request: &SpawnRequest, options: &ChildOptions) -> Result<ChildHandle, PlatformError> {
        let mut command = build_command(request, options.group, Some(options))?;
        let spawn = |command: &mut Command| {
            let child = command
                .spawn()
                .map_err(|error| PlatformError::from_io(Operation::Spawn, &error))?;
            let pid = child_pid(&child)?;
            Ok::<_, PlatformError>((child, pid))
        };
        let (mut table, child, pid, group) = match options.group {
            // Checked and spawned under the lock: the group keeps a held member until the new one is in it.
            GroupMembership::Join(group) => {
                let table = self.table();
                if !table.holds_group(group.as_raw()) {
                    return Err(PlatformError::UnknownProcessGroup);
                }
                let (child, pid) = spawn(&mut command)?;
                (table, child, pid, Some(group.as_raw()))
            }
            GroupMembership::Lead => {
                let (child, pid) = spawn(&mut command)?;
                (self.table(), child, pid, Some(pid))
            }
            GroupMembership::Inherit => {
                let (child, pid) = spawn(&mut command)?;
                (self.table(), child, pid, None)
            }
        };
        let generation = table.generation();
        table.children.insert(
            pid,
            HeldChild {
                generation,
                child,
                group,
            },
        );
        Ok(ChildHandle::new(pid, generation, group.map(ProcessGroupId::from_raw)))
    }

    fn wait_child(&self, handle: ChildHandle) -> Result<ChildEvent, PlatformError> {
        let pid = handle.pid();
        let held = |table: &Table| {
            table
                .children
                .get(&pid)
                .is_some_and(|held| held.generation == handle.generation())
        };
        if !held(&self.table()) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        loop {
            // Blocks without the lock and without consuming anything: the child stays unreaped, so its id and its
            // group's id stay reserved while other threads signal the job.
            let report = wait_report(pid, libc::WEXITED | libc::WSTOPPED | libc::WCONTINUED | libc::WNOWAIT)?;
            match report {
                Some((libc::CLD_STOPPED, _)) => {
                    // Consume the stop (and only a stop: without `WEXITED` this never reaps).
                    if let Some((_, signal)) = wait_report(pid, libc::WSTOPPED | libc::WNOHANG)? {
                        return Ok(ChildEvent::Stopped(signal));
                    }
                }
                Some((libc::CLD_CONTINUED, _)) => {
                    if wait_report(pid, libc::WCONTINUED | libc::WNOHANG)?.is_some() {
                        return Ok(ChildEvent::Continued);
                    }
                }
                Some(_) => {
                    let mut table = self.table();
                    if !held(&table) {
                        return Err(PlatformError::UnknownProcessGroup);
                    }
                    let Some(mut entry) = table.children.remove(&pid) else {
                        return Err(PlatformError::UnknownProcessGroup);
                    };
                    drop(table);
                    // The child has exited (reported above), so this returns at once.
                    let status = entry
                        .child
                        .wait()
                        .map_err(|error| PlatformError::from_io(Operation::Wait, &error))?;
                    return Ok(ChildEvent::Exited(convert(status)));
                }
                // Not possible without `WNOHANG`; ask again.
                None => {}
            }
        }
    }

    fn signal_job(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        // Under the lock, so the last held member cannot be reaped (and the group id freed) before `killpg`.
        let table = self.table();
        if !table.holds_group(group.as_raw()) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        // SAFETY: `killpg` takes plain integers and touches no memory. A member of the group is unreaped, so the id
        // still names the group this instance's children are in.
        let rc = unsafe { libc::killpg(group.as_raw(), signal.number()) };
        drop(table);
        if rc == 0 {
            Ok(())
        } else {
            Err(PlatformError::from_io(
                Operation::Signal,
                &std::io::Error::last_os_error(),
            ))
        }
    }

    fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        // Holding the lock across `killpg` is what makes this safe: the leader cannot be reaped (and its id freed)
        // until the lock is released.
        let table = self.table();
        if !table.entries.contains_key(&group.as_raw()) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        // SAFETY: `killpg` takes plain integers and touches no memory. The group is in the table, so its leader is
        // unreaped and the id still names the group this instance created.
        let rc = unsafe { libc::killpg(group.as_raw(), signal.number()) };
        drop(table);
        if rc == 0 {
            Ok(())
        } else {
            Err(PlatformError::from_io(
                Operation::Signal,
                &std::io::Error::last_os_error(),
            ))
        }
    }

    fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError> {
        let generation = match self.table().entries.get(&group.as_raw()) {
            Some((generation, _)) => *generation,
            None => return Err(PlatformError::UnknownProcessGroup),
        };
        match wait_exit_without_reaping(group.as_raw()) {
            Ok(()) => {}
            // Another thread reaped it while this one was blocked: same outcome as calling after the reap.
            Err(PlatformError::Os {
                errno: libc::ECHILD, ..
            }) => return Err(PlatformError::UnknownProcessGroup),
            Err(error) => return Err(error),
        }
        // Only the thread that removes the entry reaps it; a second concurrent waiter finds it gone. The generation
        // check covers the case where another thread reaped the original leader and this instance then spawned a
        // new child that the kernel gave the same id: that newer entry is not ours to reap.
        let mut table = self.table();
        if table.entries.get(&group.as_raw()).map(|(g, _)| *g) != Some(generation) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        let Some((_, mut child)) = table.entries.remove(&group.as_raw()) else {
            return Err(PlatformError::UnknownProcessGroup);
        };
        drop(table);
        // The child has exited (reported above), so this returns at once.
        let status = child
            .wait()
            .map_err(|error| PlatformError::from_io(Operation::Wait, &error))?;
        Ok(convert(status))
    }

    fn exited(&self, group: ProcessGroupId) -> Result<bool, PlatformError> {
        // Under the lock, so the entry cannot be reaped (and its id reused) between the check and the call.
        let table = self.table();
        if !table.entries.contains_key(&group.as_raw()) {
            return Err(PlatformError::UnknownProcessGroup);
        }
        let id = libc::id_t::try_from(group.as_raw()).map_err(|_| PlatformError::UnknownProcessGroup)?;
        loop {
            // SAFETY: an all-zero `siginfo_t` is a valid value (a plain C struct of integers and pointers).
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a valid, writable `siginfo_t` for the duration of the call. With `WNOHANG` it does
            // not block, and with `WNOWAIT` it leaves the child unreaped.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    id,
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc == 0 {
                // `WNOHANG` with nothing to report leaves `si_pid` zero.
                return Ok(info.si_pid != 0);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(PlatformError::from_io(Operation::Wait, &error));
            }
        }
    }

    fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError> {
        let mut table = self.table();
        let (_, child) = table
            .entries
            .get_mut(&group.as_raw())
            .ok_or(PlatformError::UnknownProcessGroup)?;
        // Non-blocking, so reaping under the lock is fine.
        let status = child
            .try_wait()
            .map_err(|error| PlatformError::from_io(Operation::Wait, &error))?;
        if status.is_some() {
            table.entries.remove(&group.as_raw());
        }
        Ok(status.map(convert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Placement;

    // CLAUDE.md "Concurrency": never signal a pid that may have been reused.
    #[test]
    fn signal_refuses_unknown_process_group() {
        let processes = SystemProcesses::new();
        // Our own process group: real, alive, and not created by this instance.
        // SAFETY: `getpgrp` has no preconditions and touches no memory.
        let own = ProcessGroupId::from_raw(unsafe { libc::getpgrp() });
        assert_eq!(
            processes.signal(own, Signal::Terminate),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.wait(own), Err(PlatformError::UnknownProcessGroup));
        assert_eq!(processes.try_wait(own), Err(PlatformError::UnknownProcessGroup));
    }

    #[test]
    fn reaped_group_is_forgotten() {
        let processes = SystemProcesses::new();
        let group = processes.spawn(&SpawnRequest::new("/usr/bin/true")).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        assert_eq!(
            processes.signal(group, Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.wait(group), Err(PlatformError::UnknownProcessGroup));
    }

    #[test]
    fn spawn_passes_arguments_and_explicit_environment() {
        let processes = SystemProcesses::new();
        let request = SpawnRequest::new("/bin/sh")
            .arg("-c")
            .arg(r#"test -z "$HOME" && test "$K" = v && exit 3"#)
            .env("K", "v");
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(3)));
    }

    // KNSH-051: `exited` reports the leader's exit without reaping it, so the group can still be signalled: a member
    // that outlived the leader is stopped before the id is given up.
    #[test]
    fn exited_does_not_reap() {
        use std::io::Read;

        let (mut read, write) = std::io::pipe().unwrap();
        let out = SharedFd::new(write.into());
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        // The leader starts a member of its group, prints the member's pid and exits at once.
        let mut request = SpawnRequest::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 >/dev/null & echo $!");
        request.stdio = Stdio::Passed(Box::new([null.clone(), out, null]));
        let processes = SystemProcesses::new();
        let group = processes.spawn(&request).unwrap();
        drop(request);
        let mut pid = String::new();
        read.read_to_string(&mut pid).unwrap_or_default();
        let member: i32 = pid.trim().parse().unwrap();
        while !processes.exited(group).unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Still held after the exit: the surviving member is reached through the group.
        assert_eq!(processes.signal(group, Signal::Kill), Ok(()));
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        assert_eq!(processes.exited(group), Err(PlatformError::UnknownProcessGroup));
        // SAFETY: `kill` with signal 0 only checks that the process exists; it takes plain integers.
        let alive = || unsafe { libc::kill(member, 0) } == 0;
        for _ in 0..1000 {
            if !alive() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("the member of the group survived");
    }

    // KNSH-051: passed stdio becomes the child's 0, 1 and 2; an inherited descriptor keeps its number, and nothing
    // else leaks.
    #[test]
    fn passes_stdio_and_inherits_listed_descriptors() {
        use std::io::Read;

        let (mut out_read, out_write) = std::io::pipe().unwrap();
        let out = SharedFd::new(out_write.into());
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let (mut extra_read, extra_write) = std::io::pipe().unwrap();
        let extra = SharedFd::new(extra_write.into());
        let (_leak_read, leak_write) = std::io::pipe().unwrap();
        let (extra_fd, leak_fd) = (extra.as_raw_fd(), leak_write.as_raw_fd());
        let mut request = SpawnRequest::new("/bin/sh").arg("-c").arg(format!(
            "echo out; echo extra >&{extra_fd}; if [ -e /dev/fd/{leak_fd} ]; then echo leaked; fi"
        ));
        request.stdio = Stdio::Passed(Box::new([null.clone(), out, null]));
        request.inherit = vec![extra];
        let processes = SystemProcesses::new();
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        drop(request);
        drop(leak_write);
        let mut text = String::new();
        out_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "out\n");
        text.clear();
        extra_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "extra\n");
    }

    // CLAUDE.md "Concurrency": a descriptor another thread created without `FD_CLOEXEC` yet (macOS has no `pipe2`,
    // so std sets the flag in a second step) must not reach the child, or the child holds a stranger's pipe open.
    #[test]
    fn does_not_leak_descriptors_caught_without_close_on_exec() {
        use std::io::Read;

        let (mut out_read, out_write) = std::io::pipe().unwrap();
        let out = SharedFd::new(out_write.into());
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let (_raced_read, raced_write) = std::io::pipe().unwrap();
        let raced_fd = raced_write.as_raw_fd();
        // SAFETY: `fcntl` on a descriptor this test owns; it touches no memory. This is the state a concurrent
        // thread's descriptor is in between `pipe()` and setting `FD_CLOEXEC`.
        assert_eq!(unsafe { libc::fcntl(raced_fd, libc::F_SETFD, 0) }, 0);
        let mut request = SpawnRequest::new("/bin/sh").arg("-c").arg(format!(
            "if [ -e /dev/fd/{raced_fd} ]; then echo leaked; else echo closed; fi"
        ));
        request.stdio = Stdio::Passed(Box::new([null.clone(), out, null]));
        let processes = SystemProcesses::new();
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(0)));
        drop(request);
        let mut text = String::new();
        out_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "closed\n");
    }

    /// Spawns `/bin/sh -c script` with stdin `/dev/null`, stdout and stderr on two pipes and `placements`; returns
    /// (exit status, stdout, stderr).
    fn run_placed(script: &str, placements: Vec<Placement>) -> (ExitStatus, String, String) {
        use std::io::Read;

        let (mut out_read, out_write) = std::io::pipe().unwrap();
        let (mut err_read, err_write) = std::io::pipe().unwrap();
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let mut request = SpawnRequest::new("/bin/sh").arg("-c").arg(script);
        request.stdio = Stdio::Passed(Box::new([
            null,
            SharedFd::new(out_write.into()),
            SharedFd::new(err_write.into()),
        ]));
        request.placements = placements;
        let processes = SystemProcesses::new();
        let group = processes.spawn(&request).unwrap();
        let status = processes.wait(group).unwrap();
        drop(request);
        let (mut out, mut err) = (String::new(), String::new());
        out_read.read_to_string(&mut out).unwrap();
        err_read.read_to_string(&mut err).unwrap();
        (status, out, err)
    }

    fn placed(target: i32, source: PlacementSource) -> Placement {
        Placement {
            target,
            source: Some(source),
        }
    }

    // KNSH-099: placements put descriptors at the numbers asked for; every source is read before any target is
    // written, so `1>&2 2>&1` swaps standard output and error.
    #[test]
    fn placements_swap_standard_descriptors() {
        let (status, out, err) = run_placed(
            "echo to-one; echo to-two >&2",
            vec![
                placed(1, PlacementSource::Stdio(2)),
                placed(2, PlacementSource::Stdio(1)),
            ],
        );
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!((out.as_str(), err.as_str()), ("to-two\n", "to-one\n"));
    }

    // KNSH-099: a shared descriptor placed above stdio keeps that number in the child (even one whose source number
    // is itself a target), a closed number is closed, and nothing else leaks.
    #[test]
    fn placements_set_numbers_above_stdio_and_close() {
        use std::io::Read;

        let (mut three_read, three_write) = std::io::pipe().unwrap();
        let three = SharedFd::new(three_write.into());
        let (_leak_read, leak_write) = std::io::pipe().unwrap();
        let leak_fd = leak_write.as_raw_fd();
        // The pipe's own number is a target too: it receives `/dev/null`, after the pipe was read for 250. (Test
        // descriptors stay far below 250.)
        let own = three.as_raw_fd();
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let script = format!(
            "echo seven >&250; [ -e /dev/fd/{leak_fd} ] && echo leaked; echo x >&251 2>/dev/null || echo closed; \
             [ -e /dev/fd/{own} ] && echo own-placed"
        );
        let (status, out, _) = run_placed(
            &script,
            vec![
                placed(250, PlacementSource::Shared(three.clone())),
                placed(own, PlacementSource::Shared(null)),
                Placement {
                    target: 251,
                    source: None,
                },
            ],
        );
        drop(three);
        drop(leak_write);
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(out, "closed\nown-placed\n");
        let mut text = String::new();
        three_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "seven\n");
    }

    // KNSH-099: a source's copy never lands on a target number. The lowest free number is made a target, which is
    // where a plain `F_DUPFD(source, 3)` would put the copy (and then close it with the copies); it must still hold
    // standard output, and 255 (`MAX_PLACED_FD`) can be given even though copies above every target would need
    // descriptor 256, past macOS's default soft limit.
    #[test]
    fn placement_copies_avoid_target_numbers() {
        let free = std::fs::File::open("/dev/null").unwrap().as_raw_fd();
        let script = format!("echo low >&{free}; echo top >&255");
        let (status, out, err) = run_placed(
            &script,
            vec![
                placed(free, PlacementSource::Stdio(1)),
                placed(MAX_PLACED_FD, PlacementSource::Stdio(1)),
            ],
        );
        assert_eq!(status, ExitStatus::Exited(0), "{err}");
        assert_eq!(out, "low\ntop\n");
    }

    // KNSH-099: with a placement above stdio the child executes the program itself, so a program that cannot be
    // executed ends with bash's status (127 missing, 126 refused) instead of std's report landing in a placed file.
    #[test]
    fn placed_spawn_of_missing_program_exits_127() {
        let null = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let processes = SystemProcesses::new();
        let mut request = SpawnRequest::new("/nonexistent/knsh-placed");
        request.placements = vec![placed(3, PlacementSource::Shared(null.clone()))];
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(127)));
        let mut request = SpawnRequest::new("/etc");
        request.placements = vec![placed(3, PlacementSource::Shared(null))];
        let group = processes.spawn(&request).unwrap();
        assert_eq!(processes.wait(group), Ok(ExitStatus::Exited(126)));
    }

    // KNSH-099: a target out of range, repeated, or a standard source other than 0 to 2 is refused before forking.
    #[test]
    fn refuses_invalid_placements() {
        let processes = SystemProcesses::new();
        for placements in [
            vec![placed(MAX_PLACED_FD + 1, PlacementSource::Stdio(1))],
            vec![placed(-1, PlacementSource::Stdio(1))],
            vec![
                placed(4, PlacementSource::Stdio(1)),
                placed(4, PlacementSource::Stdio(2)),
            ],
            vec![placed(4, PlacementSource::Stdio(3))],
        ] {
            let mut request = SpawnRequest::new("/usr/bin/true");
            request.placements = placements;
            assert_eq!(
                processes.spawn(&request),
                Err(PlatformError::Os {
                    operation: Operation::Spawn,
                    errno: libc::EINVAL
                })
            );
        }
    }

    #[test]
    fn spawn_refuses_relative_program_and_reports_missing_one() {
        let processes = SystemProcesses::new();
        assert_eq!(
            processes.spawn(&SpawnRequest::new("sh")),
            Err(PlatformError::InvalidPath)
        );
        let error = processes.spawn(&SpawnRequest::new("/nonexistent/knsh")).unwrap_err();
        assert!(error.is_not_found(), "{error:?}");
    }

    /// The process group of `pid`.
    fn group_of(pid: i32) -> i32 {
        // SAFETY: `getpgid` takes a plain integer and touches no memory.
        unsafe { libc::getpgid(pid) }
    }

    fn options(group: GroupMembership) -> ChildOptions {
        ChildOptions {
            group,
            terminal: None,
            signals: ChildSignals::Default,
        }
    }

    // KNSH-100: a child stays in the caller's group, leads its own, or joins a held one; joining a group with no
    // held member is refused.
    #[test]
    fn spawn_child_places_children_in_groups() {
        let processes = SystemProcesses::new();
        let sleep = SpawnRequest::new("/bin/sleep").arg("5");
        let inherit = processes.spawn_child(&sleep, &ChildOptions::default()).unwrap();
        assert_eq!(inherit.group(), None);
        // SAFETY: `getpgrp` has no preconditions and touches no memory.
        assert_eq!(group_of(inherit.pid()), unsafe { libc::getpgrp() });
        let leader = processes.spawn_child(&sleep, &options(GroupMembership::Lead)).unwrap();
        let group = leader.group().unwrap();
        assert_eq!(group.as_raw(), leader.pid());
        assert_eq!(group_of(leader.pid()), leader.pid());
        let member = processes
            .spawn_child(&sleep, &options(GroupMembership::Join(group)))
            .unwrap();
        assert_eq!(member.group(), Some(group));
        assert_eq!(group_of(member.pid()), leader.pid());
        // The leader ends; the member still holds the group, so it can be signalled.
        processes.signal_job(group, Signal::Kill).unwrap();
        assert_eq!(
            processes.wait_child(leader).unwrap(),
            ChildEvent::Exited(ExitStatus::Signalled(libc::SIGKILL))
        );
        assert_eq!(
            processes.wait_child(member).unwrap(),
            ChildEvent::Exited(ExitStatus::Signalled(libc::SIGKILL))
        );
        // CLAUDE.md "Concurrency": no member held, so neither signalling nor joining the old id is allowed.
        assert_eq!(
            processes.signal_job(group, Signal::Kill),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(
            processes.spawn_child(&sleep, &options(GroupMembership::Join(group))),
            Err(PlatformError::UnknownProcessGroup)
        );
        assert_eq!(processes.wait_child(leader), Err(PlatformError::UnknownProcessGroup));
        // A child in the caller's group is no job group: never signalled through it.
        // SAFETY: as above.
        let own = ProcessGroupId::from_raw(unsafe { libc::getpgrp() });
        assert_eq!(
            processes.signal_job(own, Signal::Continue),
            Err(PlatformError::UnknownProcessGroup)
        );
        // SAFETY: `kill` on a child this test started and has not reaped (its id cannot be reused).
        unsafe { libc::kill(inherit.pid(), libc::SIGKILL) };
        assert!(matches!(processes.wait_child(inherit).unwrap(), ChildEvent::Exited(_)));
    }

    // KNSH-100: stops and continues are reported, then the exit; a stop is never mistaken for an exit.
    #[test]
    fn wait_child_reports_stops_and_continues() {
        let processes = SystemProcesses::new();
        let child = processes
            .spawn_child(
                &SpawnRequest::new("/bin/sleep").arg("5"),
                &options(GroupMembership::Lead),
            )
            .unwrap();
        let group = child.group().unwrap();
        processes.signal_job(group, Signal::Stop).unwrap();
        assert_eq!(processes.wait_child(child).unwrap(), ChildEvent::Stopped(libc::SIGSTOP));
        processes.signal_job(group, Signal::Continue).unwrap();
        assert_eq!(processes.wait_child(child).unwrap(), ChildEvent::Continued);
        processes.signal_job(group, Signal::Terminate).unwrap();
        assert_eq!(
            processes.wait_child(child).unwrap(),
            ChildEvent::Exited(ExitStatus::Signalled(libc::SIGTERM))
        );
        let ends = processes
            .spawn_child(&SpawnRequest::new("/usr/bin/true"), &ChildOptions::default())
            .unwrap();
        assert_eq!(
            processes.wait_child(ends).unwrap(),
            ChildEvent::Exited(ExitStatus::Exited(0))
        );
    }

    // KNSH-100: an asynchronous command without job control ignores SIGINT; a job-control child has it at default.
    #[test]
    fn child_signals_are_set_before_exec() {
        let processes = SystemProcesses::new();
        let sleep = SpawnRequest::new("/bin/sleep").arg("5");
        let ignoring = processes
            .spawn_child(
                &sleep,
                &ChildOptions {
                    group: GroupMembership::Lead,
                    terminal: None,
                    signals: ChildSignals::IgnoreInterrupt,
                },
            )
            .unwrap();
        let group = ignoring.group().unwrap();
        processes.signal_job(group, Signal::Interrupt).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        processes.signal_job(group, Signal::Terminate).unwrap();
        assert_eq!(
            processes.wait_child(ignoring).unwrap(),
            ChildEvent::Exited(ExitStatus::Signalled(libc::SIGTERM)),
            "SIGINT was ignored"
        );
        let default = processes.spawn_child(&sleep, &options(GroupMembership::Lead)).unwrap();
        processes
            .signal_job(default.group().unwrap(), Signal::Interrupt)
            .unwrap();
        assert_eq!(
            processes.wait_child(default).unwrap(),
            ChildEvent::Exited(ExitStatus::Signalled(libc::SIGINT))
        );
    }
}
