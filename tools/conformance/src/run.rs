//! Running one shell once: a fresh run directory, a fixed environment, a Seatbelt sandbox, a deadline, captured
//! streams and a snapshot of what the run left behind.
//!
//! Every suite runs untrusted command lines for real (the corpus holds `rm -rf`, `git push --force`, `curl … | sh`,
//! `kill -9`), so every run is confined by [`sandbox_profile`]: no network at all, no writes outside the run's own
//! directory (and `/dev/null`, `/dev/tty`, `/dev/fd/*`, and the temporary files of macOS `diff`), no preference
//! writes (`defaults write`), no signals to processes outside the sandbox, and no `sudo`, `su`, `launchctl`,
//! `osascript`, `open`, `shutdown`, `reboot`, `halt`, `security`, `diskutil` or `tmutil`. The reference and the
//! candidate get the same profile, so a refusal is the same refusal on both sides and the comparison stays fair.
//!
//! Each run is the leader of its own process group, so a run past its deadline is killed with everything it started
//! (before it is reaped, while its group id cannot have been reused). After a run exits, what it left running in its
//! group (`nohup … &`, `sleep 100 &`) gets [`STREAM_GRACE`] to end, so its writes are in the snapshot, and is then
//! killed; this dev-only tool accepts the small window in which that group may have emptied and its id been reused,
//! which the engine itself never does.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::ConformanceError;
use crate::observe::{Ending, FileState, Observation, Snapshot, fnv1a, normalise};

/// At most this many bytes of each stream are kept; the rest is read and dropped (and makes the stream differ from
/// any shorter one, since the cut-off marker is kept).
pub const MAX_STREAM: usize = 1024 * 1024;

/// How long a run's streams may stay open after it exited before its process group is killed.
pub const STREAM_GRACE: Duration = Duration::from_secs(2);

/// Programs no run may execute, whatever the line says: privilege changes and system-wide side effects.
const DENIED_PROGRAMS: [&str; 12] = [
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/login",
    "/bin/launchctl",
    "/usr/bin/osascript",
    "/usr/bin/open",
    "/sbin/shutdown",
    "/sbin/reboot",
    "/sbin/halt",
    // These act through system daemons outside the sandbox (the keychain, disks, Time Machine), so the file-write
    // rule does not hold them back.
    "/usr/bin/security",
    "/usr/sbin/diskutil",
    "/usr/bin/tmutil",
];

/// The Seatbelt profile every run is confined by: writes only under `run_dir`.
///
/// # Errors
///
/// [`ConformanceError::Shell`] when `run_dir` holds a character the profile language cannot quote safely.
pub fn sandbox_profile(run_dir: &Path) -> Result<String, ConformanceError> {
    let dir = run_dir
        .to_str()
        .filter(|dir| !dir.contains(['"', '\\', '\n']))
        .ok_or_else(|| ConformanceError::shell(run_dir, "the run directory cannot be named in a sandbox profile"))?;
    let mut profile = String::from("(version 1)(allow default)(deny network*)(deny file-write*)");
    // Writing to a `String` cannot fail.
    let _ = write!(
        profile,
        "(allow file-write* (subpath \"{dir}\") (literal \"/dev/null\") (literal \"/dev/zero\") \
         (literal \"/dev/dtracehelper\") (regex #\"^/dev/fd/\") (literal \"/dev/tty\"))"
    );
    // macOS `diff` copies a pipe operand (`diff <(…) <(…)`, `… | diff - f`) to `/tmp/diff.XXXXXXXX` whatever
    // `TMPDIR` says; without this the line fails under every shell, which is not what agents see.
    profile.push_str("(allow file-write* (regex #\"^/private/tmp/diff\\.\"))");
    profile.push_str("(deny signal)(allow signal (target same-sandbox))");
    // `defaults write` and every `CFPreferences` write go through `cfprefsd`, outside the sandbox, into the real
    // user's `~/Library/Preferences` whatever `HOME` says; the file-write rule does not see them.
    profile.push_str("(deny user-preference-write)");
    for program in DENIED_PROGRAMS {
        let _ = write!(profile, "(deny process-exec (literal \"{program}\"))");
    }
    Ok(profile)
}

/// One process to run.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// The working directory.
    pub cwd: PathBuf,
    /// The whole environment (nothing is inherited).
    pub env: Vec<(OsString, OsString)>,
    /// Standard input, or `/dev/null` when `None`.
    pub stdin: Option<Vec<u8>>,
    /// The deadline.
    pub timeout: Duration,
    /// The run's directory: the sandbox confines writes to it, and it is replaced by `$RUN` in the streams.
    pub run_dir: PathBuf,
}

/// How a process ended, and its normalised streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// How it ended.
    pub ending: Ending,
    /// Standard output, normalised.
    pub stdout: Vec<u8>,
    /// Standard error, normalised.
    pub stderr: Vec<u8>,
}

/// Runs `invocation` under the sandbox and waits for it, up to its deadline.
///
/// # Errors
///
/// [`ConformanceError::Shell`] when the program cannot be started or waited for.
pub fn execute(invocation: &Invocation) -> Result<Captured, ConformanceError> {
    let profile = sandbox_profile(&invocation.run_dir)?;
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-p")
        .arg(profile)
        .arg(&invocation.program)
        .args(&invocation.args)
        .current_dir(&invocation.cwd)
        .env_clear()
        .envs(invocation.env.iter().map(|(name, value)| (name, value)))
        .stdin(if invocation.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| ConformanceError::shell(&invocation.program, format!("cannot start: {e}")))?;
    let feeder = child
        .stdin
        .take()
        .zip(invocation.stdin.clone())
        .map(|(mut pipe, input)| {
            // A shell that stops reading early closes the pipe; that write error is not the run's failure.
            thread::spawn(move || {
                let _ = pipe.write_all(&input);
            })
        });
    let (sender, streams) = mpsc::channel();
    let readers = [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    for (index, stream) in readers.into_iter().enumerate() {
        let sender = sender.clone();
        let Some(stream) = stream else { continue };
        thread::spawn(move || {
            let _ = sender.send((index, read_capped(stream)));
        });
    }
    drop(sender);
    let ending = wait(&mut child, invocation)?;
    let mut collected: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut received = [false; 2];
    let mut pending = 2;
    let mut killed = ending == Ending::TimedOut;
    while pending > 0 {
        match streams.recv_timeout(STREAM_GRACE) {
            Ok((index, bytes)) => {
                collected[index] = bytes;
                received[index] = true;
                pending -= 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) if !killed => {
                kill_group(child.id());
                killed = true;
            }
            // A descendant that left the group (`setsid`) still holds a stream: what was read so far is lost, and
            // the marker makes the stream differ from any finished one, so the run cannot pass by it.
            Err(_) => {
                for (stream, _) in collected.iter_mut().zip(received).filter(|(_, received)| !received) {
                    stream.extend_from_slice(b"[knsh-conformance: stream left open]\n");
                }
                break;
            }
        }
    }
    if let Some(feeder) = feeder {
        let _ = feeder.join();
    }
    if !killed {
        settle_group(child.id());
    }
    let run_dir = invocation.run_dir.as_os_str().as_encoded_bytes();
    let canonical = fs::canonicalize(&invocation.run_dir).unwrap_or_else(|_| invocation.run_dir.clone());
    let paths = [run_dir, canonical.as_os_str().as_encoded_bytes()];
    let [stdout, stderr] = collected;
    Ok(Captured {
        ending,
        stdout: normalise(&stdout, &paths),
        stderr: normalise(&stderr, &paths),
    })
}

/// Waits for `child` up to the deadline. Past it, kills the child's whole group before reaping the child, so the
/// group id is still the child's when it is signalled.
fn wait(child: &mut Child, invocation: &Invocation) -> Result<Ending, ConformanceError> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(match (status.code(), status.signal()) {
                    (Some(code), _) => Ending::Exited(u8::try_from(code & 0xff).unwrap_or(u8::MAX)),
                    (None, Some(signal)) => Ending::Signaled(signal),
                    (None, None) => Ending::Signaled(0),
                });
            }
            Ok(None) if start.elapsed() < invocation.timeout => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                kill_group(child.id());
                let _ = child.wait();
                return Ok(Ending::TimedOut);
            }
            Err(e) => {
                kill_group(child.id());
                let _ = child.wait();
                return Err(ConformanceError::shell(
                    &invocation.program,
                    format!("cannot wait: {e}"),
                ));
            }
        }
    }
}

/// Waits up to [`STREAM_GRACE`] for every process left in the group `group` (a background job the line started,
/// `nohup … &`) to end, so the snapshot sees what it wrote whichever shell ran it; then kills what is left.
fn settle_group(group: u32) {
    let start = Instant::now();
    let members = || {
        Command::new("/usr/bin/pgrep")
            .args(["-g", &group.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            // pgrep exits 0 when a process matched, 1 when none did.
            .is_ok_and(|status| status.success())
    };
    while members() {
        if start.elapsed() >= STREAM_GRACE {
            kill_group(group);
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Sends `SIGKILL` to the process group `group` with `/bin/kill` (this crate has no `unsafe` and no `libc`).
fn kill_group(group: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{group}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Reads `stream` to its end, keeping at most [`MAX_STREAM`] bytes (then a cut-off marker).
fn read_capped(mut stream: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = MAX_STREAM.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(room)]);
                truncated |= n > room;
            }
        }
    }
    if truncated {
        kept.extend_from_slice(b"\n[knsh-conformance: output cut off]\n");
    }
    kept
}

/// The fixed modification time of every fixture entry (2024-01-01T00:00:00Z), so `ls -l` and `find -newer` give
/// the same answer in every run.
fn fixture_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_hours(473_352)
}

/// A fresh run directory: `<parent>/<name>/` with `work/` (a copy of `fixture`, when given), `home/` and `tmp/`,
/// every entry's modification time fixed. Removed with [`RunDir::remove`] (or when dropped).
#[derive(Debug)]
pub struct RunDir {
    root: PathBuf,
}

impl RunDir {
    /// Creates the run directory, replacing a stale one of the same name.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Io`] when it cannot be created or the fixture cannot be copied.
    pub fn create(parent: &Path, name: &str, fixture: Option<&Path>) -> Result<Self, ConformanceError> {
        let root = parent.join(name);
        if root.exists() {
            remove_tree(&root)?;
        }
        fs::create_dir_all(&root).map_err(|e| ConformanceError::io(&root, e))?;
        let root = fs::canonicalize(&root).map_err(|e| ConformanceError::io(&root, e))?;
        let run = Self { root };
        let work = run.work();
        match fixture {
            Some(fixture) => copy_tree(fixture, &work)?,
            None => fs::create_dir(&work).map_err(|e| ConformanceError::io(&work, e))?,
        }
        for dir in [run.home(), run.tmp()] {
            fs::create_dir(&dir).map_err(|e| ConformanceError::io(&dir, e))?;
        }
        set_times(&run.root)?;
        Ok(run)
    }

    /// The run directory itself (canonical).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `work/`, the working directory.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// `home/`, the run's `HOME`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// `tmp/`, the run's `TMPDIR`.
    #[must_use]
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Every entry under the run directory, normalised.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Io`] when an entry cannot be read.
    pub fn snapshot(&self) -> Result<Snapshot, ConformanceError> {
        let mut snapshot = Snapshot::new();
        let root = self.root.as_os_str().as_encoded_bytes();
        walk(&self.root, &self.root, root, &mut snapshot)?;
        Ok(snapshot)
    }

    /// Removes the run directory.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Io`] when it cannot be removed.
    pub fn remove(self) -> Result<(), ConformanceError> {
        let root = self.root.clone();
        std::mem::forget(self);
        remove_tree(&root)
    }

    /// Builds the [`Observation`] of a run from what it printed and what it left behind.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Io`] when the snapshot cannot be taken.
    pub fn observe(&self, captured: Captured, files: bool) -> Result<Observation, ConformanceError> {
        Ok(Observation {
            ending: captured.ending,
            stdout: captured.stdout,
            stderr: captured.stderr,
            files: if files { self.snapshot()? } else { Snapshot::new() },
        })
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = remove_tree(&self.root);
    }
}

/// Removes `path` and everything under it, first making every directory writable again (a run may `chmod -w`).
fn remove_tree(path: &Path) -> Result<(), ConformanceError> {
    fn unlock(path: &Path) {
        if let Ok(meta) = fs::symlink_metadata(path)
            && meta.is_dir()
        {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    unlock(&entry.path());
                }
            }
        }
    }
    unlock(path);
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ConformanceError::io(path, e)),
    }
}

/// Copies the directory `from` to `to` (which must not exist): files with their permission bits, directories and
/// symbolic links.
///
/// # Errors
///
/// [`ConformanceError::Io`] on any failure.
pub fn copy_tree(from: &Path, to: &Path) -> Result<(), ConformanceError> {
    fs::create_dir(to).map_err(|e| ConformanceError::io(to, e))?;
    let mut entries: Vec<_> = fs::read_dir(from)
        .map_err(|e| ConformanceError::io(from, e))?
        .collect::<Result<_, _>>()
        .map_err(|e| ConformanceError::io(from, e))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source = entry.path();
        let target = to.join(entry.file_name());
        let meta = fs::symlink_metadata(&source).map_err(|e| ConformanceError::io(&source, e))?;
        if meta.file_type().is_symlink() {
            let link = fs::read_link(&source).map_err(|e| ConformanceError::io(&source, e))?;
            std::os::unix::fs::symlink(link, &target).map_err(|e| ConformanceError::io(&target, e))?;
        } else if meta.is_dir() {
            copy_tree(&source, &target)?;
        } else {
            fs::copy(&source, &target).map_err(|e| ConformanceError::io(&target, e))?;
        }
    }
    Ok(())
}

/// Sets the modification time of every file and directory under `dir` (and `dir` itself) to [`fixture_time`],
/// children first, since creating an entry changes its directory's time.
fn set_times(dir: &Path) -> Result<(), ConformanceError> {
    let entries = fs::read_dir(dir).map_err(|e| ConformanceError::io(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| ConformanceError::io(dir, e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| ConformanceError::io(&path, e))?;
        if kind.is_dir() {
            set_times(&path)?;
        } else if kind.is_file() {
            let file = fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .or_else(|_| fs::File::open(&path))
                .map_err(|e| ConformanceError::io(&path, e))?;
            file.set_modified(fixture_time())
                .map_err(|e| ConformanceError::io(&path, e))?;
        }
    }
    fs::File::open(dir)
        .and_then(|handle| handle.set_modified(fixture_time()))
        .map_err(|e| ConformanceError::io(dir, e))
}

/// Records every entry under `dir` into `snapshot`, by path relative to `root`, contents normalised.
fn walk(root: &Path, dir: &Path, root_bytes: &[u8], snapshot: &mut Snapshot) -> Result<(), ConformanceError> {
    let Ok(entries) = fs::read_dir(dir) else {
        // A directory the run made unreadable is recorded (by its parent) but not entered.
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| ConformanceError::io(dir, e))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| ConformanceError::io(&path, e))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
        let mode = meta.mode() & 0o7777;
        let state = if meta.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|e| ConformanceError::io(&path, e))?;
            FileState::Symlink {
                target: fnv1a(&normalise(target.as_os_str().as_encoded_bytes(), &[root_bytes])),
            }
        } else if meta.is_dir() {
            walk(root, &path, root_bytes, snapshot)?;
            FileState::Dir { mode }
        } else if meta.is_file() {
            // The length is the normalised one: runs' directories differ in length (`c1-bash52-a`, `c1-knsh`), so a
            // file holding its own path would otherwise differ between shells that wrote the same. An unreadable
            // file (the run did `chmod 000`) is compared by its mode and length.
            match fs::read(&path) {
                Ok(contents) => {
                    let contents = normalise(&contents, &[root_bytes]);
                    FileState::File {
                        mode,
                        len: u64::try_from(contents.len()).unwrap_or(u64::MAX),
                        hash: fnv1a(&contents),
                    }
                }
                Err(_) => FileState::File {
                    mode,
                    len: meta.len(),
                    hash: fnv1a(b""),
                },
            }
        } else {
            FileState::Other
        };
        snapshot.insert(relative, state);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("knsh-conformance-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(dir).unwrap()
    }

    fn invocation(run: &RunDir, script: &str) -> Invocation {
        Invocation {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), script.into()],
            cwd: run.work(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            stdin: None,
            timeout: Duration::from_secs(10),
            run_dir: run.root().to_owned(),
        }
    }

    #[test]
    fn profile_confines_writes_to_the_run_directory() {
        let profile = sandbox_profile(Path::new("/private/tmp/run")).unwrap();
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(subpath \"/private/tmp/run\")"));
        assert!(profile.contains("/usr/bin/sudo"));
        assert!(profile.contains("(deny user-preference-write)"));
        assert!(!profile.contains("^/dev/tty"));
        assert!(sandbox_profile(Path::new("/tmp/a\"b")).is_err());
    }

    // The sandbox refuses writes outside the run directory; the streams are captured and normalised.
    #[test]
    fn runs_confined_and_captures_normalised_streams() {
        let parent = scratch("exec");
        let run = RunDir::create(&parent, "one", None).unwrap();
        let outside = parent.join("outside");
        let script = format!("pwd; echo inside > made; echo x > '{}'; exit 3", outside.display());
        let captured = execute(&invocation(&run, &script)).unwrap();
        assert_eq!(captured.ending, Ending::Exited(3));
        assert_eq!(captured.stdout, b"$RUN/work\n");
        assert_ne!(captured.stderr, b"");
        assert!(!outside.exists());
        let snapshot = run.snapshot().unwrap();
        assert!(matches!(
            snapshot.get("work/made"),
            Some(FileState::File { len: 7, .. })
        ));
        assert!(matches!(snapshot.get("home"), Some(FileState::Dir { .. })));
        // A file holding the run's own path compares equal across runs whose directories differ in length.
        let longer = RunDir::create(&parent, "a-longer-name", None).unwrap();
        for dir in [&run, &longer] {
            fs::write(dir.work().join("where"), format!("{}\n", dir.work().display())).unwrap();
        }
        assert_eq!(
            run.snapshot().unwrap().get("work/where"),
            longer.snapshot().unwrap().get("work/where")
        );
        longer.remove().unwrap();
        run.remove().unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn deadline_kills_the_whole_group() {
        let parent = scratch("deadline");
        let run = RunDir::create(&parent, "one", None).unwrap();
        let mut slow = invocation(&run, "sleep 30 & sleep 30");
        slow.timeout = Duration::from_millis(300);
        let start = Instant::now();
        assert_eq!(execute(&slow).unwrap().ending, Ending::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(10));
        // A background job that keeps stdout open after the shell exited is killed after the grace period.
        let lingering = invocation(&run, "sleep 30 & echo started");
        let captured = execute(&lingering).unwrap();
        assert_eq!(
            (captured.ending, captured.stdout.as_slice()),
            (Ending::Exited(0), &b"started\n"[..])
        );
        // A background job's writes after the shell exited are in place before the run is observed.
        let late = invocation(&run, "(sleep 0.3; echo late > late.txt) > /dev/null 2>&1 &");
        assert_eq!(execute(&late).unwrap().ending, Ending::Exited(0));
        assert_eq!(fs::read_to_string(run.work().join("late.txt")).unwrap(), "late\n");
        drop(run);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn fixture_copies_get_fixed_times() {
        let parent = scratch("fixture");
        let fixture = parent.join("fixture");
        fs::create_dir_all(fixture.join("src")).unwrap();
        fs::write(fixture.join("src/a.txt"), "a").unwrap();
        let first = RunDir::create(&parent, "first", Some(&fixture)).unwrap();
        let meta = fs::metadata(first.work().join("src/a.txt")).unwrap();
        assert_eq!(meta.modified().unwrap(), fixture_time());
        assert_eq!(fs::metadata(first.work()).unwrap().modified().unwrap(), fixture_time());
        let second = RunDir::create(&parent, "second", Some(&fixture)).unwrap();
        assert_eq!(first.snapshot().unwrap(), second.snapshot().unwrap());
        drop((first, second));
        fs::remove_dir_all(parent).unwrap();
    }
}
