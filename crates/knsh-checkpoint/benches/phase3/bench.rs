//! The phase 3 runs: the rig that wires checkpoints as `knshd` does, the two measurements, their statistics and the
//! report (crate documentation in `main.rs`).

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use knsh_checkpoint::{
    Captures, Change, Checkpoint, FLUSH_DEADLINE, HeldScan, History, Ledger, LineClose, LineProcesses,
    PlatformShadowFiles, SHADOW_BUDGET, SHADOW_THREADS, STREAM_LATENCY, ShadowFiles, ShadowPlan, ShadowStatus,
    StoredPreImage, WatchPlan, WatchReport, Watcher, held_dir, held_in_roots, marker_dir, shadow_dir, start_shadow,
    start_watch,
};
use knsh_core::{CanonicalPath, RecordId, SessionId, TornReason, Ulid, UncertainReason};
use knsh_platform::macos::{FsEventStreams, RealFs, SystemClock, SystemRandom, SystemVolumes, SystemWriteHolders};
use knsh_platform::{Clock, FileSystemKind, Fs, Random, Volumes};

type BenchResult<T> = Result<T, Box<dyn Error>>;

/// Changed files per line (NFR-PERF-05, `performance-validation.md`).
const SIZES: [usize; 4] = [0, 1, 100, 10_000];

/// Files of the NFR-PERF-05 root: 100 folders of 100, so the largest line changes every one of them.
const LINE_ROOT_FOLDERS: usize = 100;
const LINE_ROOT_FILES_PER_FOLDER: usize = 100;

/// The NFR-PERF-06 root: 100,000 files in 100 × 40 folders of 25 (decision 15 measured 100,000 files in 3,906).
const SHADOW_TOP: usize = 100;
const SHADOW_MIDDLE: usize = 40;
const SHADOW_FILES_PER_FOLDER: usize = 25;
const SHADOW_FILES: u64 = 100_000;

/// The diagnostic configuration's flush deadline: long enough that no line of 10,000 files is cut short.
const DIAGNOSTIC_DEADLINE: Duration = Duration::from_secs(60);

/// How long the rig waits, between lines, for the watcher to settle.
const SETTLE_LIMIT: Duration = Duration::from_secs(300);

/// One line: appends a line to each of the first `$2` files of the root `$1` (`d<i / 100>/f<i % 100>`).
const WRITER: &str = r#"
r="$1"; n="$2"; i=0
while [ "$i" -lt "$n" ]; do printf 'line\n' >> "$r/d$((i / 100))/f$((i % 100))"; i=$((i + 1)); done
"#;

/// What the runs are told by the environment (crate documentation).
struct Settings {
    rounds: usize,
    rounds_large: usize,
    shadow_runs: usize,
    purge: bool,
    /// Working folder; decides the volume measured.
    work: PathBuf,
    /// Where the report goes.
    out: PathBuf,
}

impl Settings {
    fn from_env() -> BenchResult<Self> {
        let workspace = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
        let count = |name: &str, default: usize| -> BenchResult<usize> {
            match std::env::var(name) {
                Ok(text) => match text.parse::<usize>() {
                    Ok(value) if value > 0 => Ok(value),
                    _ => Err(format!("{name} must be a positive whole number").into()),
                },
                Err(_) => Ok(default),
            }
        };
        let out = if let Some(dir) = std::env::var_os("KNSH_QUALIFICATION_DIR") {
            PathBuf::from(dir)
        } else {
            let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            workspace.join(format!(".build/qualification/phase3-{secs}"))
        };
        let work =
            std::env::var_os("KNSH_BENCH_DIR").map_or_else(|| workspace.join(".build/phase3-work"), PathBuf::from);
        Ok(Self {
            rounds: count("KNSH_BENCH_ROUNDS", 20)?,
            rounds_large: count("KNSH_BENCH_ROUNDS_LARGE", 5)?,
            shadow_runs: count("KNSH_BENCH_SHADOW_RUNS", 3)?,
            purge: std::env::var("KNSH_BENCH_PURGE").is_ok_and(|value| value == "1"),
            work,
            out,
        })
    }
}

/// A temporary folder, removed on drop (also on an early error).
struct TempDir(PathBuf);

impl TempDir {
    fn new(base: &Path, name: &str) -> BenchResult<Self> {
        fs::create_dir_all(base)?;
        let path = base.join(format!("{name}-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(fs::canonicalize(&path)?))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One measured series.
struct Series {
    requirement: &'static str,
    name: String,
    unit: &'static str,
    /// Every sample in the order taken, with why it is invalid if it is (it did not do what it claims to measure).
    values: Vec<(f64, Option<String>)>,
}

impl Series {
    fn new(requirement: &'static str, name: impl Into<String>, unit: &'static str) -> Self {
        Self {
            requirement,
            name: name.into(),
            unit,
            values: Vec::new(),
        }
    }

    fn push(&mut self, value: f64, problem: Option<String>) {
        self.values.push((value, problem));
    }

    /// The valid samples, ascending.
    fn sorted_valid(&self) -> Vec<f64> {
        let mut sorted: Vec<f64> = self
            .values
            .iter()
            .filter(|(_, problem)| problem.is_none())
            .map(|(value, _)| *value)
            .collect();
        sorted.sort_by(f64::total_cmp);
        sorted
    }

    fn invalid_count(&self) -> usize {
        self.values.iter().filter(|(_, problem)| problem.is_some()).count()
    }

    /// The largest figure, valid or not: what a target is judged on.
    fn max_all(&self) -> Option<f64> {
        self.values.iter().map(|(value, _)| *value).reduce(f64::max)
    }
}

/// The nearest-rank `p`th percentile of `sorted` (non-empty, ascending).
fn percentile(sorted: &[f64], p: usize) -> f64 {
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Attribution, capture and history of one session's root, wired as `knshd`'s `shadows` module wires them
/// (`Attributor` and `SessionReport` there): ledger lock, then the captures; the history is written with no other
/// lock held, before the call that finished the checkpoint returns.
struct Attributor {
    ledger: Mutex<Ledger>,
    captures: Captures,
    history: Mutex<History>,
    session: SessionId,
    store: PathBuf,
    /// Checkpoints the history refused: each makes the line's sample invalid.
    record_errors: AtomicU64,
}

impl Attributor {
    fn with<R>(&self, change: impl FnOnce(&mut Ledger, &Captures) -> R) -> R {
        let (result, finished) = {
            let mut ledger = lock(&self.ledger);
            let result = change(&mut ledger, &self.captures);
            for edge in ledger.take_missed() {
                self.captures.mark_uncertain(edge, UncertainReason::CaptureFailed);
            }
            let closed = ledger.take_closed();
            let finished = if closed.is_empty() {
                Vec::new()
            } else {
                self.captures.closed(&closed)
            };
            (result, finished)
        };
        self.record(finished);
        result
    }

    fn record(&self, finished: Vec<Checkpoint>) {
        if finished.is_empty() {
            return;
        }
        let mut history = lock(&self.history);
        for checkpoint in finished {
            if history.record(checkpoint).is_err() {
                self.record_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl WatchReport for Attributor {
    fn changed(&self, root: &CanonicalPath, change: Change) {
        let ticket = self.with(|ledger, captures| ledger.changed(root, &change.path).map(|edge| captures.begin(edge)));
        match ticket {
            Some(ticket) => {
                let finished = self.captures.add(ticket, self.session, &self.store, root, change);
                self.record(finished);
            }
            None => self.captures.discard(change),
        }
    }

    fn uncertain(&self, root: &CanonicalPath, reason: UncertainReason) {
        self.with(|ledger, captures| {
            if let Some(edge) = ledger.edge_of(root) {
                captures.mark_uncertain(edge, reason);
            }
        });
    }
}

/// A shadowed, watched root of 10,000 files for NFR-PERF-05.
struct Rig {
    root: CanonicalPath,
    watcher: Arc<Watcher>,
    attributor: Arc<Attributor>,
    /// Record identifiers handed out so far.
    lines: u128,
    /// Holds the root and the store; removed last.
    _dir: TempDir,
}

impl Rig {
    fn new(base: &Path, name: &str, flush_deadline: Duration, files: &Arc<dyn ShadowFiles>) -> BenchResult<Self> {
        let dir = TempDir::new(base, name)?;
        let root_path = dir.0.join("root");
        let store = dir.0.join("store");
        fs::create_dir(&store)?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
        for folder in 0..LINE_ROOT_FOLDERS {
            let folder_path = root_path.join(format!("d{folder}"));
            fs::create_dir_all(&folder_path)?;
            for file in 0..LINE_ROOT_FILES_PER_FOLDER {
                fs::write(folder_path.join(format!("f{file}")), format!("file {folder}/{file}\n"))?;
            }
        }
        let root = CanonicalPath::new(&root_path)?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let random: Arc<dyn Random> = Arc::new(SystemRandom::new());
        let session = SessionId::from_ulid(Ulid::from_u128(1));
        let attributor = Arc::new(Attributor {
            ledger: Mutex::new(Ledger::new()),
            captures: Captures::new(Arc::clone(files), Arc::clone(&clock), Arc::clone(&random)),
            history: Mutex::new(History::new(Arc::clone(files), Arc::clone(&clock), random)),
            session,
            store: store.clone(),
            record_errors: AtomicU64::new(0),
        });
        // Not an envelope session: changes between lines are `external` and never land in a line's checkpoint.
        attributor.with(|ledger, _| ledger.watch(&root, session, false));
        let session_name = session.to_string();
        let (shadow, parents) = shadow_dir(&store, &session_name, 0);
        let (markers, marker_parents) = marker_dir(&store, &session_name, 0);
        let (held, held_parents) = held_dir(&store, &session_name, 0);
        let report: Arc<dyn WatchReport> = attributor.clone();
        // The watcher first, then the build, as `knshd` starts them (KNSH-080).
        let watcher = start_watch(
            &FsEventStreams::new(),
            Arc::clone(files),
            Arc::clone(&clock),
            report,
            WatchPlan {
                root: root.clone(),
                shadow: shadow.clone(),
                markers,
                marker_parents,
                held,
                held_parents,
                exclude: Vec::new(),
                skip: vec![store.clone()],
                latency: STREAM_LATENCY,
                flush_deadline,
            },
        )?;
        let build = start_shadow(
            Arc::clone(files),
            clock,
            ShadowPlan {
                root: root.clone(),
                dir: shadow,
                parents,
                exclude: Vec::new(),
                skip: vec![store],
                threads: SHADOW_THREADS,
            },
        );
        watcher.follow(Arc::clone(&build));
        match build.wait(Duration::from_secs(300)) {
            ShadowStatus::Complete(_) => {}
            other => {
                watcher.stop();
                // Stopped and waited for before the folder is removed, so no build thread writes into it after.
                build.cancel();
                let _ = build.wait(Duration::from_secs(60));
                return Err(format!("the line root's shadow did not complete: {other:?}").into());
            }
        }
        let rig = Self {
            root,
            watcher,
            attributor,
            lines: 0,
            _dir: dir,
        };
        rig.settle()?;
        Ok(rig)
    }

    /// Lets the watcher apply whatever is left, outside any measurement: flushes until a flush is certain, so a
    /// rescan forced by an earlier uncertain line is over and none of its changes lands in the next line.
    fn settle(&self) -> BenchResult<()> {
        let start = Instant::now();
        while !self.watcher.flush() {
            if start.elapsed() > SETTLE_LIMIT {
                return Err(format!("the watcher did not settle within {SETTLE_LIMIT:?}").into());
            }
        }
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// Runs one line changing `n` files and returns the checkpoint work after it, and why the sample is invalid if
    /// it is. The steps after the reap are those of `knshd`'s `close_lines`.
    fn line(&mut self, n: usize) -> BenchResult<(f64, Option<String>)> {
        self.lines += 1;
        let record = RecordId::from_ulid(Ulid::from_u128(self.lines));
        let session = self.attributor.session;
        let roots = std::slice::from_ref(&self.root);
        let errors_before = self.attributor.record_errors.load(Ordering::Relaxed);
        self.attributor
            .with(|ledger, _| ledger.line_started(record, session, roots));
        let mark = self.watcher.open_line();
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(WRITER)
            .arg("writer")
            .arg(self.root.as_path())
            .arg(n.to_string())
            .process_group(0)
            .spawn()?;
        let group = i32::try_from(child.id())?;
        let status = child.wait()?;

        // The line has been reaped: from here on is the work its answer waits for.
        let start = Instant::now();
        let close = self.watcher.close_line(mark);
        let held = held_in_roots(
            &SystemWriteHolders::new(),
            &LineProcesses {
                group: Some(group),
                envelopes: Vec::new(),
            },
            roots,
        );
        let ended = self.attributor.with(|ledger, captures| {
            if let Some(edge) = ledger.running_edge(record) {
                if let LineClose::Uncertain(reason) = close {
                    captures.mark_uncertain(edge.id, reason);
                }
                match &held {
                    HeldScan::Held(paths) => {
                        for (path, reason) in paths {
                            captures.mark_possibly_torn(edge.id, path.clone(), *reason);
                        }
                    }
                    HeldScan::Unchecked => captures.mark_all_possibly_torn(edge.id, TornReason::Unchecked),
                }
            }
            ledger.line_ended(record)
        });
        let summary = ended.and_then(|ended| self.attributor.captures.summary(ended.edge));
        let elapsed = millis(start.elapsed());

        let mut problems = Vec::new();
        if !status.success() {
            problems.push(format!("writer exited with {status}"));
        }
        if let LineClose::Uncertain(reason) = close {
            problems.push(format!("line closed uncertain ({reason:?})"));
        }
        if matches!(held, HeldScan::Unchecked) {
            // The scan gave up early: the figure is that of the failure path, and every file is marked torn.
            problems.push("the held-file scan could not check the line's processes".to_owned());
        }
        if ended.is_none() {
            problems.push("the ledger did not know the line".to_owned());
        }
        if self.attributor.record_errors.load(Ordering::Relaxed) != errors_before {
            problems.push("the history refused a checkpoint".to_owned());
        }
        match (n, &summary) {
            (0, None) => {}
            (0, Some(summary)) => problems.push(format!("a line changing nothing has {} paths", summary.count)),
            (_, None) => problems.push("no checkpoint".to_owned()),
            (_, Some(summary)) => {
                if summary.count != n as u64 {
                    problems.push(format!("checkpoint holds {} of {n} changed files", summary.count));
                }
                if summary.uncertain {
                    problems.push("checkpoint uncertain".to_owned());
                }
                match lock(&self.attributor.history).checkpoint(summary.id) {
                    None => problems.push("checkpoint not in the history".to_owned()),
                    Some(checkpoint) => problems.extend(contents_problem(checkpoint, &self.root, n)),
                }
            }
        }
        self.settle()?;
        let problem = (!problems.is_empty()).then(|| problems.join("; "));
        Ok((elapsed, problem))
    }
}

/// Why `checkpoint` is not the one a line appending to the first `n` files of `root` must leave, if it is not: it
/// holds exactly those paths, each with its pre-image kept (they existed before), and none possibly torn (the writer
/// had exited). A count alone could hide a wrong path or a pre-image recorded as something it was not.
fn contents_problem(checkpoint: &Checkpoint, root: &CanonicalPath, n: usize) -> Option<String> {
    let expected: BTreeSet<PathBuf> = (0..n)
        .map(|i| root.as_path().join(format!("d{}/f{}", i / 100, i % 100)))
        .collect();
    let mut held: BTreeSet<PathBuf> = BTreeSet::new();
    for (in_root, paths) in &checkpoint.paths {
        if in_root != root {
            return Some(format!(
                "checkpoint holds paths of another root {}",
                in_root.as_path().display()
            ));
        }
        for (path, captured) in paths {
            if !matches!(captured.pre, StoredPreImage::Kept(_)) {
                return Some(format!("pre-image of {} not kept", path.as_path().display()));
            }
            held.insert(path.as_path().to_path_buf());
        }
    }
    if held != expected {
        let missing = expected.difference(&held).count();
        let extra = held.difference(&expected).count();
        return Some(format!(
            "checkpoint paths differ: {missing} missing, {extra} unexpected"
        ));
    }
    if !checkpoint.possibly_torn.is_empty() {
        return Some(format!("{} paths possibly torn", checkpoint.possibly_torn.len()));
    }
    None
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.watcher.stop();
    }
}

/// NFR-PERF-05 under one flush deadline: one series per size, lines interleaved by size so drift spreads evenly,
/// after one discarded warm-up line of each size.
fn checkpoint_lines(
    settings: &Settings,
    files: &Arc<dyn ShadowFiles>,
    name: &str,
    deadline: Duration,
) -> BenchResult<Vec<Series>> {
    // The folder gets a plain name; the series keep the readable one.
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let mut rig = Rig::new(&settings.work, &slug, deadline, files)?;
    let mut series: Vec<Series> = SIZES
        .iter()
        .map(|n| Series::new("NFR-PERF-05", format!("{name}: {n} changed files"), "ms"))
        .collect();
    for n in SIZES {
        let _ = rig.line(n)?;
    }
    let rounds = settings.rounds.max(settings.rounds_large);
    for round in 0..rounds {
        for (index, n) in SIZES.into_iter().enumerate() {
            let wanted = if n >= 10_000 {
                settings.rounds_large
            } else {
                settings.rounds
            };
            if round >= wanted {
                continue;
            }
            let (value, problem) = rig.line(n)?;
            series[index].push(value, problem);
        }
        eprintln!("phase3: {name}: round {} of {rounds}", round + 1);
    }
    Ok(series)
}

/// Whether `sudo -n /usr/sbin/purge` emptied the file cache; `Err` says why not.
fn purge() -> Result<(), String> {
    match Command::new("/usr/bin/sudo").args(["-n", "/usr/sbin/purge"]).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("`sudo -n /usr/sbin/purge` exited with {status}")),
        Err(error) => Err(format!("`sudo -n /usr/sbin/purge` did not start: {error}")),
    }
}

/// NFR-PERF-06: the real builder on a 100,000-file root, warm, and cold when purging works. Also returns the time
/// to remove each shadow (diagnostic) and why the cold cache was not measured, if it was not.
fn initial_shadows(settings: &Settings, files: &Arc<dyn ShadowFiles>) -> BenchResult<(Vec<Series>, Option<String>)> {
    let dir = TempDir::new(&settings.work, "shadow")?;
    let root_path = dir.0.join("root");
    let store = dir.0.join("store");
    fs::create_dir(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
    for top in 0..SHADOW_TOP {
        for middle in 0..SHADOW_MIDDLE {
            let folder = root_path.join(format!("d{top}")).join(format!("e{middle}"));
            fs::create_dir_all(&folder)?;
            for file in 0..SHADOW_FILES_PER_FOLDER {
                fs::write(folder.join(format!("f{file}")), format!("{top}/{middle}/{file}\n"))?;
            }
        }
    }
    let root = CanonicalPath::new(&root_path)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let mut warm = Series::new("NFR-PERF-06", "100,000 files, warm cache", "s");
    let mut cold = Series::new("NFR-PERF-06", "100,000 files, cold cache (after purge)", "s");
    let mut removal = Series::new("NFR-PERF-06", "diagnostic: removing a 100,000-file shadow", "s");
    let mut cold_missing = (!settings.purge).then(|| "KNSH_BENCH_PURGE=1 was not set".to_owned());
    let build = |tag: &str, run: usize, series: &mut Series, removal: &mut Series| -> BenchResult<()> {
        let (shadow, parents) = shadow_dir(&store, &format!("{tag}{run}"), 0);
        let started = start_shadow(
            Arc::clone(files),
            Arc::clone(&clock),
            ShadowPlan {
                root: root.clone(),
                dir: shadow.clone(),
                parents,
                exclude: Vec::new(),
                skip: vec![store.clone()],
                threads: SHADOW_THREADS,
            },
        );
        let status = started.wait(Duration::from_secs(600));
        match status {
            ShadowStatus::Complete(summary) => {
                let problem = (summary.files != SHADOW_FILES)
                    .then(|| format!("{} files shadowed, not {SHADOW_FILES}", summary.files));
                series.push(summary.duration.as_secs_f64(), problem);
                eprintln!(
                    "phase3: {}: {:.2} s for {} files in {} folders",
                    series.name,
                    summary.duration.as_secs_f64(),
                    summary.files,
                    summary.folders
                );
            }
            other => {
                // Stopped and waited for before the folder is removed, so no build thread writes into it after.
                started.cancel();
                let _ = started.wait(Duration::from_secs(60));
                return Err(format!("shadow build did not complete: {other:?}").into());
            }
        }
        let start = Instant::now();
        fs::remove_dir_all(&shadow)?;
        removal.push(start.elapsed().as_secs_f64(), None);
        Ok(())
    };
    for run in 0..settings.shadow_runs {
        if cold_missing.is_none() {
            match purge() {
                Ok(()) => build("cold", run, &mut cold, &mut removal)?,
                Err(why) => cold_missing = Some(why),
            }
        }
        build("warm", run, &mut warm, &mut removal)?;
    }
    Ok((vec![warm, cold, removal], cold_missing))
}

/// The output of a command, trimmed; `None` if it fails.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The machine, macOS, commit and volume, for the report.
fn environment(work: &Path, volumes: &dyn Volumes) -> Vec<(&'static str, String)> {
    let unknown = || "unknown".to_owned();
    let sysctl = |name: &str| output("/usr/sbin/sysctl", &["-n", name]).unwrap_or_else(unknown);
    let memory = sysctl("hw.memsize")
        .parse::<u64>()
        .map_or_else(|_| unknown(), |bytes| format!("{} GiB", bytes >> 30));
    let machine = format!(
        "{}, {} ({} CPUs, {memory})",
        sysctl("hw.model"),
        sysctl("machdep.cpu.brand_string"),
        sysctl("hw.ncpu")
    );
    let macos = format!(
        "{} ({})",
        output("/usr/bin/sw_vers", &["-productVersion"]).unwrap_or_else(unknown),
        output("/usr/bin/sw_vers", &["-buildVersion"]).unwrap_or_else(unknown)
    );
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace = workspace.to_string_lossy();
    let commit = output("git", &["-C", &workspace, "rev-parse", "--short", "HEAD"]).unwrap_or_else(unknown);
    let dirty = output("git", &["-C", &workspace, "status", "--porcelain"]).is_some_and(|text| !text.is_empty());
    let commit = if dirty {
        format!("{commit} + uncommitted changes")
    } else {
        commit
    };
    let volume = match volumes.volume_of(work) {
        Ok(volume) => format!("{:?} at {}", volume.kind, volume.mount_point.display()),
        Err(error) => format!("unknown ({error})"),
    };
    vec![
        (
            "Date (UTC)",
            output("/bin/date", &["-u", "+%Y-%m-%d %H:%M:%S"]).unwrap_or_else(unknown),
        ),
        ("Machine", machine),
        ("macOS", macos),
        ("Commit", commit),
        ("Build", "release (`cargo bench`, bench profile)".to_owned()),
        ("Volume", volume),
    ]
}

/// One judged target: what it is, its figure and its result.
struct Verdict {
    requirement: &'static str,
    measure: String,
    target: String,
    figure: String,
    met: Option<bool>,
}

fn judge(series: &Series, budget: f64, target: String) -> Verdict {
    let figure = match series.max_all() {
        None => "not measured".to_owned(),
        Some(max) => {
            let sorted = series.sorted_valid();
            let mut text = format!("max {max:.2} {}", series.unit);
            if !sorted.is_empty() {
                let _ = write!(
                    text,
                    " (p50 {:.2}, p95 {:.2}, n {})",
                    percentile(&sorted, 50),
                    percentile(&sorted, 95),
                    sorted.len()
                );
            }
            let invalid = series.invalid_count();
            if invalid > 0 {
                let _ = write!(text, ", {invalid} invalid");
            }
            text
        }
    };
    let met = series.max_all().map(|max| series.invalid_count() == 0 && max < budget);
    Verdict {
        requirement: series.requirement,
        measure: series.name.clone(),
        target,
        figure,
        met,
    }
}

fn render(
    environment: &[(&'static str, String)],
    settings: &Settings,
    verdicts: &[Verdict],
    series: &[Series],
    open: &[String],
) -> String {
    let mut md = String::from("# Phase 3 performance qualification (KNSH-095)\n\n");
    md.push_str(
        "Method: `specs/07-testing/performance-validation.md`, \"Phase 3 qualification\". Every bound is strict; ",
    );
    md.push_str(
        "a target holds when every sample is valid and the largest is under it. Percentiles are nearest rank.\n\n",
    );
    md.push_str("| | |\n| --- | --- |\n");
    for (name, value) in environment {
        let _ = writeln!(md, "| {name} | {value} |");
    }
    let _ = writeln!(
        md,
        "| Settings | {} lines per size ({} of 10,000 files) after one warm-up each, {} shadow runs, purge {} |",
        settings.rounds,
        settings.rounds_large,
        settings.shadow_runs,
        if settings.purge { "on" } else { "off" }
    );
    md.push_str(
        "\n## Results\n\n| Requirement | Measure | Target | Figure | Result |\n| --- | --- | --- | --- | --- |\n",
    );
    for verdict in verdicts {
        let result = match verdict.met {
            Some(true) => "**met**",
            Some(false) => "**missed**",
            None => "**not measured**",
        };
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {result} |",
            verdict.requirement, verdict.measure, verdict.target, verdict.figure
        );
    }
    md.push_str("\n## Series\n\n| Requirement | Series | n | invalid | min | p50 | p95 | p99 | max | unit |\n");
    md.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for one in series {
        let sorted = one.sorted_valid();
        let cells = if sorted.is_empty() {
            "– | – | – | – | –".to_owned()
        } else {
            format!(
                "{:.2} | {:.2} | {:.2} | {:.2} | {:.2}",
                sorted[0],
                percentile(&sorted, 50),
                percentile(&sorted, 95),
                percentile(&sorted, 99),
                sorted[sorted.len() - 1]
            )
        };
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {cells} | {} |",
            one.requirement,
            one.name,
            sorted.len(),
            one.invalid_count(),
            one.unit
        );
    }
    let invalid: Vec<String> = series
        .iter()
        .flat_map(|one| {
            one.values.iter().enumerate().filter_map(|(index, (value, problem))| {
                let why = problem.as_ref()?;
                Some(format!(
                    "- {}, sample {index}: {value:.2} {}: {why}",
                    one.name, one.unit
                ))
            })
        })
        .collect();
    if !invalid.is_empty() {
        md.push_str("\n## Invalid samples\n\n");
        for line in invalid.iter().take(200) {
            md.push_str(line);
            md.push('\n');
        }
        if invalid.len() > 200 {
            let _ = writeln!(md, "- … and {} more (see the samples file)", invalid.len() - 200);
        }
    }
    md.push_str("\n## Open items\n\n");
    if open.is_empty() {
        md.push_str("None.\n");
    }
    for item in open {
        let _ = writeln!(md, "- {item}");
    }
    md
}

fn samples_csv(series: &[Series]) -> String {
    let mut csv = String::from("requirement,series,index,value,unit,valid\n");
    for one in series {
        for (index, (value, problem)) in one.values.iter().enumerate() {
            let _ = writeln!(
                csv,
                "{},\"{}\",{index},{value:.4},{},{}",
                one.requirement,
                one.name,
                one.unit,
                problem.is_none()
            );
        }
    }
    csv
}

fn run() -> BenchResult<bool> {
    let settings = Settings::from_env()?;
    fs::create_dir_all(&settings.work)?;
    let volumes = SystemVolumes::new();
    let kind = volumes.volume_of(&settings.work)?.kind;
    if kind != FileSystemKind::Apfs {
        return Err(format!(
            "{} is not on APFS ({kind:?}): checkpoints need clones",
            settings.work.display()
        )
        .into());
    }
    let real: Arc<dyn Fs> = Arc::new(RealFs::new());
    let files: Arc<dyn ShadowFiles> = Arc::new(PlatformShadowFiles::new(real, Arc::new(SystemVolumes::new())));
    let environment = environment(&settings.work, &volumes);

    let production = checkpoint_lines(&settings, &files, "production deadline (1 s)", FLUSH_DEADLINE)?;
    let diagnostic = checkpoint_lines(&settings, &files, "diagnostic: 60 s deadline", DIAGNOSTIC_DEADLINE)?;
    let (shadows, cold_missing) = initial_shadows(&settings, &files)?;

    let mut verdicts: Vec<Verdict> = SIZES
        .iter()
        .zip(&production)
        .map(|(n, series)| {
            // At most 10,000: exact in an f64.
            let budget = 20.0 + f64::from(u32::try_from(*n).unwrap_or(u32::MAX));
            judge(series, budget, format!("< {budget:.0} ms (20 ms + {n} × 1 ms)"))
        })
        .collect();
    let budget = SHADOW_BUDGET.as_secs_f64();
    verdicts.push(judge(&shadows[0], budget, format!("< {budget:.0} s")));
    verdicts.push(judge(&shadows[1], budget, format!("< {budget:.0} s")));

    let mut open = Vec::new();
    for verdict in &verdicts {
        match verdict.met {
            Some(true) => {}
            Some(false) => open.push(format!(
                "{} missed: {}: {} against {}.",
                verdict.requirement, verdict.measure, verdict.figure, verdict.target
            )),
            None => open.push(format!("{} not measured: {}.", verdict.requirement, verdict.measure)),
        }
    }
    if let Some(why) = &cold_missing {
        open.push(format!("NFR-PERF-06 cold cache not measured: {why}."));
    }
    let all: Vec<Series> = production.into_iter().chain(diagnostic).chain(shadows).collect();
    let report = render(&environment, &settings, &verdicts, &all, &open);
    fs::create_dir_all(&settings.out)?;
    fs::write(settings.out.join("phase-3-performance.md"), &report)?;
    fs::write(settings.out.join("phase-3-performance-samples.csv"), samples_csv(&all))?;
    println!("{report}");
    println!("Report: {}", settings.out.display());
    Ok(open.is_empty())
}

pub(crate) fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("phase3: {error}");
            ExitCode::from(1)
        }
    }
}
