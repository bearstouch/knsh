//! Start-up benchmark for integration mode (KNSH-024, NFR-PERF-04, `specs/07-testing/performance-validation.md`).
//!
//! Measures the time to first prompt of plain `/bin/zsh -i` and of `knsh`-hosted zsh with human recording off and on,
//! on a pseudo-terminal, and checks that `knsh` adds less than [`TARGET`] at p95. Dev-only: never shipped.
//!
//! # Method
//!
//! - Each run starts `script -q /dev/null <shell>` (so the shell sits on a real pseudo-terminal, as at a terminal
//!   window) and times from just before the spawn until the prompt marker appears on the terminal. `script(1)`'s own
//!   cost is in every variant alike, so it cancels out of the added time. The shell is then told `exit`.
//! - Every variant shares one temporary `HOME` per recording state (never the user's own) whose `.zshrc` sets the
//!   prompt to `KNSHBENCH<r>> `, where `<r>` is `$KNSH_RECORDING` or `0`. The digit proves which state the run was in:
//!   a recording-on run whose prompt says `0` aborts the benchmark rather than being counted.
//! - Variants are interleaved and their order rotates each round, so drift (thermal, background work) hits all of them.
//!   Warm-up rounds are discarded.
//! - Added time at a percentile is the `knsh` variant's percentile minus plain zsh's (nearest-rank percentiles).
//! - Recording on runs with no `knshd` listening: `knsh` reaches `knshd` only from a worker thread after the shell has
//!   started (KNSH-021, NFR-REL-02), so the daemon is off the path to the first prompt. The report says so.
//!
//! # Output
//!
//! `<out>/<UTC stamp>/report.md` (machine, method, results, verdict) and `samples.csv` (every timed run), and a copy
//! of the report at `<out>/latest.md`. Exit status 0 when the target is met on an Apple silicon machine; 1 when it is
//! not met or the machine does not qualify (the report then lists it as an open item, never as passed); 2 on a usage
//! error; 3 when the benchmark itself failed.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::fmt::{self, Write as _};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// NFR-PERF-04: start-up time added to a human session stays under this at p95.
const TARGET: Duration = Duration::from_millis(50);

/// The prompt text set by the benchmark's `.zshrc`; followed by the recording digit and `> `.
const MARKER: &[u8] = b"KNSHBENCH";

/// The `.zshrc` of every benchmark home: a recognisable prompt carrying the recording state, and nothing else.
const ZSHRC: &str = "PS1=\"KNSHBENCH${KNSH_RECORDING:-0}> \"\n";

/// The user settings file under a home (`specs/09-reference/file-locations.md`).
const CONFIG_FILE: &str = ".config/knsh/config.toml";

/// The `PATH` of the minimal environment every shell starts with.
const BENCH_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The zsh measured, plainly and as `knsh`'s hosted shell.
const ZSH: &str = "/bin/zsh";

/// How long one run may take to show its prompt, and then to exit, before the benchmark fails.
const RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timed rounds (each round runs every variant once).
const DEFAULT_RUNS: usize = 50;

/// Default discarded warm-up rounds.
const DEFAULT_WARMUP: usize = 3;

/// Fewest timed rounds accepted: below 20 samples the nearest-rank p95 is just the maximum, which says nothing about
/// a 95th percentile.
const MIN_RUNS: usize = 20;

/// Default results directory, relative to where the benchmark is started (the workspace root, from the script).
const DEFAULT_OUT: &str = ".build/startup-bench";

/// Why the benchmark could not produce a result.
#[derive(Debug)]
enum BenchError {
    /// The command line was wrong; the text says how.
    Usage(String),
    /// A file or process operation failed: what was being done, and the error.
    Io(&'static str, std::io::Error),
    /// A run did not show its prompt, or did not exit, in time.
    Timeout(Variant),
    /// The terminal output ended before the prompt marker appeared.
    NoPrompt(Variant),
    /// The prompt showed the wrong recording state, so the run did not measure what it claims to.
    WrongRecording(Variant, u8),
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(text) => f.write_str(text),
            Self::Io(doing, error) => write!(f, "{doing}: {error}"),
            Self::Timeout(variant) => write!(f, "{}: no prompt or no exit within {RUN_TIMEOUT:?}", variant.name()),
            Self::NoPrompt(variant) => write!(f, "{}: the terminal closed before the prompt", variant.name()),
            Self::WrongRecording(variant, digit) => write!(
                f,
                "{}: prompt reported recording state {:?}, expected {:?}",
                variant.name(),
                char::from(*digit),
                char::from(variant.recording_digit())
            ),
        }
    }
}

impl std::error::Error for BenchError {}

/// What one run starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// `/bin/zsh -i`, without `knsh`.
    PlainZsh,
    /// `knsh` hosting zsh, recording off.
    KnshRecordingOff,
    /// `knsh` hosting zsh, recording on.
    KnshRecordingOn,
}

impl Variant {
    /// Every variant, in their base order.
    const ALL: [Self; 3] = [Self::PlainZsh, Self::KnshRecordingOff, Self::KnshRecordingOn];

    /// The name used in the report and the samples file.
    const fn name(self) -> &'static str {
        match self {
            Self::PlainZsh => "plain zsh",
            Self::KnshRecordingOff => "knsh, recording off",
            Self::KnshRecordingOn => "knsh, recording on",
        }
    }

    /// The variant's name in the samples file: no commas or spaces.
    const fn slug(self) -> &'static str {
        match self {
            Self::PlainZsh => "plain-zsh",
            Self::KnshRecordingOff => "knsh-recording-off",
            Self::KnshRecordingOn => "knsh-recording-on",
        }
    }

    /// The digit the prompt must show: `$KNSH_RECORDING` is `1` only in a recorded session.
    const fn recording_digit(self) -> u8 {
        match self {
            Self::PlainZsh | Self::KnshRecordingOff => b'0',
            Self::KnshRecordingOn => b'1',
        }
    }
}

/// The benchmark's settings, from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    /// The `knsh` binary measured (a release build).
    knsh: PathBuf,
    /// Timed rounds.
    runs: usize,
    /// Discarded warm-up rounds.
    warmup: usize,
    /// Where results go.
    out: PathBuf,
}

/// The usage text.
const USAGE: &str = "usage: startup_bench --knsh <path> [--runs <n>] [--warmup <n>] [--out <dir>]";

/// Parses the command line (without `argv[0]`). Every option takes a value; anything unknown or repeated is refused.
fn parse_options(args: &[String]) -> Result<Options, BenchError> {
    let usage = |why: &str| BenchError::Usage(format!("{why}\n{USAGE}"));
    let mut knsh = None;
    let mut runs = None;
    let mut warmup = None;
    let mut out = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| usage(&format!("{flag} needs a value")))?;
        let count = || {
            value
                .parse::<usize>()
                .map_err(|_| usage(&format!("{flag} needs a whole number")))
        };
        let slot_taken = match flag.as_str() {
            "--knsh" => knsh.replace(PathBuf::from(value)).is_some(),
            "--runs" => runs.replace(count()?).is_some(),
            "--warmup" => warmup.replace(count()?).is_some(),
            "--out" => out.replace(PathBuf::from(value)).is_some(),
            _ => return Err(usage(&format!("unknown option {flag}"))),
        };
        if slot_taken {
            return Err(usage(&format!("{flag} given more than once")));
        }
    }
    let runs = runs.unwrap_or(DEFAULT_RUNS);
    if runs < MIN_RUNS {
        return Err(usage(&format!("--runs must be at least {MIN_RUNS}")));
    }
    Ok(Options {
        knsh: knsh.ok_or_else(|| usage("--knsh is required"))?,
        runs,
        warmup: warmup.unwrap_or(DEFAULT_WARMUP),
        out: out.unwrap_or_else(|| PathBuf::from(DEFAULT_OUT)),
    })
}

/// The nearest-rank `percent` percentile of `sorted` (ascending, non-empty): the smallest sample with at least
/// `percent`% of the samples at or below it.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    // ceil(percent * n / 100), at least 1: the 1-based rank of the sample.
    let rank = (percent * sorted.len()).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

/// Summary of one variant's samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stats {
    /// Fastest run.
    min: Duration,
    /// Median.
    p50: Duration,
    /// 95th percentile.
    p95: Duration,
    /// Slowest run.
    max: Duration,
}

impl Stats {
    /// Summarises `samples`; `None` when there are none.
    fn of(samples: &[Duration]) -> Option<Self> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Some(Self {
            min: *sorted.first()?,
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            max: *sorted.last()?,
        })
    }
}

/// The time `knsh` adds over plain zsh at the median and at p95, in milliseconds (negative when it is faster, which
/// noise can make it).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Added {
    /// At the median.
    p50_ms: f64,
    /// At p95: the figure NFR-PERF-04 bounds.
    p95_ms: f64,
}

impl Added {
    /// `knsh`'s figures minus plain zsh's.
    fn between(plain: Stats, knsh: Stats) -> Self {
        Self {
            p50_ms: ms(knsh.p50) - ms(plain.p50),
            p95_ms: ms(knsh.p95) - ms(plain.p95),
        }
    }

    /// Whether the added p95 is under the target.
    fn meets_target(self) -> bool {
        self.p95_ms < ms(TARGET)
    }
}

/// A duration in milliseconds.
fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// The recording digit right after the first prompt marker in `terminal`; `None` until the digit has arrived.
fn find_prompt(terminal: &[u8]) -> Option<u8> {
    let at = terminal.windows(MARKER.len()).position(|window| window == MARKER)?;
    terminal.get(at + MARKER.len()).copied()
}

/// The machine the benchmark ran on, as recorded in the report.
#[derive(Debug, Default)]
struct Machine {
    /// `hw.model`, e.g. `Mac15,6`.
    model: String,
    /// `machdep.cpu.brand_string`, e.g. `Apple M3 Pro`.
    cpu: String,
    /// `uname -m`.
    arch: String,
    /// Logical CPUs.
    cpus: String,
    /// Memory in GiB.
    memory_gib: String,
    /// `sw_vers -productVersion`.
    macos: String,
    /// `/bin/zsh --version`.
    zsh: String,
    /// `knsh --version`, first line.
    knsh: String,
    /// The commit measured, with `-dirty` when the tree had changes.
    commit: String,
}

impl Machine {
    /// Whether this is an Apple silicon Mac, the machine NFR-PERF-04 is validated on.
    fn is_apple_silicon(&self) -> bool {
        self.arch == "arm64" && self.cpu.starts_with("Apple ")
    }
}

/// The trimmed standard output of `program args`, or `unknown` when it cannot be run. Only for describing the machine.
fn probe(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Describes this machine and what is measured.
fn describe_machine(knsh: &Path) -> Machine {
    let memory_gib = probe("/usr/sbin/sysctl", &["-n", "hw.memsize"])
        .parse::<u64>()
        .map_or_else(|_| "unknown".to_owned(), |bytes| (bytes >> 30).to_string());
    let knsh_version = probe(&knsh.to_string_lossy(), &["--version"]);
    let mut commit = probe("git", &["rev-parse", "--short", "HEAD"]);
    // A measurement of uncommitted code says so. `probe` maps git's empty "clean" answer to `unknown`, so read the
    // status directly.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| output.status.success() && !output.stdout.is_empty());
    if dirty {
        commit.push_str("-dirty");
    }
    Machine {
        model: probe("/usr/sbin/sysctl", &["-n", "hw.model"]),
        cpu: probe("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"]),
        arch: probe("/usr/bin/uname", &["-m"]),
        cpus: probe("/usr/sbin/sysctl", &["-n", "hw.ncpu"]),
        memory_gib,
        macos: probe("/usr/bin/sw_vers", &["-productVersion"]),
        zsh: probe(ZSH, &["--version"]),
        knsh: knsh_version.lines().next().unwrap_or("unknown").to_owned(),
        commit,
    }
}

/// A temporary home for the benchmark's shells, removed when dropped. Short and under `/private/tmp`, so that the
/// engine socket path under it stays within the 104-byte limit.
struct BenchHome(PathBuf);

impl BenchHome {
    /// Creates the home with the benchmark `.zshrc` and the given recording switch.
    fn new(tag: &str, recording: bool) -> Result<Self, BenchError> {
        let dir = PathBuf::from(format!("/private/tmp/knsh-bench-{}-{tag}", std::process::id()));
        // A leftover from an earlier run with the same PID would carry its own settings; start from nothing. A
        // missing directory is the usual case, so the error is ignored.
        let _ = fs::remove_dir_all(&dir);
        // `/private/tmp` is shared and the name is predictable: create the home itself exclusively and owner-only, so
        // a directory another user planted under this name (after the removal above) fails the benchmark instead of
        // receiving a `.zshrc` that the shells then run.
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| BenchError::Io("creating the benchmark home", e))?;
        }
        let home = Self(dir);
        let config = home.0.join(CONFIG_FILE);
        if let Some(parent) = config.parent() {
            fs::create_dir_all(parent).map_err(|e| BenchError::Io("creating the benchmark home", e))?;
        }
        fs::write(home.0.join(".zshrc"), ZSHRC).map_err(|e| BenchError::Io("writing .zshrc", e))?;
        fs::write(&config, format!("[recording]\nhuman = {recording}\n"))
            .map_err(|e| BenchError::Io("writing config.toml", e))?;
        Ok(home)
    }
}

impl Drop for BenchHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Kills and reaps a child when dropped, so no run outlives the benchmark whatever path it leaves by.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Times one run of `variant`: spawn to prompt marker. The shell is then told to exit and reaped.
fn time_once(variant: Variant, knsh: &Path, home: &Path) -> Result<Duration, BenchError> {
    let mut command = Command::new("/usr/bin/script");
    command.args(["-q", "/dev/null"]);
    match variant {
        Variant::PlainZsh => command.args([ZSH, "-i"]),
        Variant::KnshRecordingOff | Variant::KnshRecordingOn => command.arg(knsh),
    };
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", BENCH_PATH)
        .env("SHELL", ZSH)
        .env("TERM", "xterm-256color")
        .env("LANG", "en_US.UTF-8")
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let started = Instant::now();
    let mut child = Reaped(command.spawn().map_err(|e| BenchError::Io("starting script(1)", e))?);
    let stdin = child.0.stdin.take();
    let stdout = child.0.stdout.take();
    let (Some(mut stdin), Some(stdout)) = (stdin, stdout) else {
        return Err(BenchError::Io(
            "taking the pipes",
            std::io::Error::other("missing pipe"),
        ));
    };
    let chunks = read_in_background(stdout);

    let elapsed = wait_for_prompt(variant, &chunks, started)?;

    // Standard input stays open until the shell has gone, as at a real terminal.
    stdin
        .write_all(b"exit\n")
        .map_err(|e| BenchError::Io("typing exit", e))?;
    // The exit is not timed, only bounded: a shell that never leaves would otherwise hang the benchmark.
    let deadline = Instant::now() + RUN_TIMEOUT;
    loop {
        match child.0.try_wait() {
            Ok(Some(_)) => return Ok(elapsed),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => return Err(BenchError::Timeout(variant)),
            Err(e) => return Err(BenchError::Io("waiting for the shell", e)),
        }
    }
}

/// Reads `stdout` on a thread, sending each chunk; the channel closes at end of file.
fn read_in_background(mut stdout: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if sender.send(buffer[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });
    receiver
}

/// Accumulates terminal output until the prompt marker and its recording digit arrive; returns the time since
/// `started`. A wrong digit, a closed terminal or the timeout is an error.
fn wait_for_prompt(variant: Variant, chunks: &Receiver<Vec<u8>>, started: Instant) -> Result<Duration, BenchError> {
    let deadline = started + RUN_TIMEOUT;
    let mut terminal = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match chunks.recv_timeout(left) {
            Ok(chunk) => {
                terminal.extend_from_slice(&chunk);
                if let Some(digit) = find_prompt(&terminal) {
                    let elapsed = started.elapsed();
                    // A wrong digit means the run measured another recording state; counting it would skew the
                    // comparison, so the whole benchmark fails instead.
                    if digit != variant.recording_digit() {
                        return Err(BenchError::WrongRecording(variant, digit));
                    }
                    return Ok(elapsed);
                }
            }
            Err(RecvTimeoutError::Timeout) => return Err(BenchError::Timeout(variant)),
            Err(RecvTimeoutError::Disconnected) => return Err(BenchError::NoPrompt(variant)),
        }
    }
}

/// Every timed sample: the round and the variant with its time.
type Samples = Vec<(usize, Variant, Duration)>;

/// Runs the warm-up and timed rounds, rotating the variant order each round.
fn measure(options: &Options) -> Result<Samples, BenchError> {
    let off = BenchHome::new("off", false)?;
    let on = BenchHome::new("on", true)?;
    let mut samples = Vec::with_capacity(options.runs * Variant::ALL.len());
    for round in 0..options.warmup + options.runs {
        for slot in 0..Variant::ALL.len() {
            let variant = Variant::ALL[(round + slot) % Variant::ALL.len()];
            let home = if variant == Variant::KnshRecordingOn { &on } else { &off };
            let elapsed = time_once(variant, &options.knsh, &home.0)?;
            if round >= options.warmup {
                samples.push((round - options.warmup, variant, elapsed));
            }
        }
    }
    Ok(samples)
}

/// The samples of one variant.
fn samples_of(samples: &Samples, variant: Variant) -> Vec<Duration> {
    samples
        .iter()
        .filter(|(_, v, _)| *v == variant)
        .map(|(_, _, d)| *d)
        .collect()
}

/// The benchmark's conclusion.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Verdict {
    /// Added time with recording off.
    off: Added,
    /// Added time with recording on.
    on: Added,
    /// Whether the machine is the one the target is defined on.
    apple_silicon: bool,
}

impl Verdict {
    /// Passed only when both recording states meet the target on an Apple silicon machine.
    fn passed(self) -> bool {
        self.apple_silicon && self.off.meets_target() && self.on.meets_target()
    }

    /// The open items this result leaves: one per unmet condition. Empty when it passed.
    fn open_items(self) -> Vec<String> {
        let mut items = Vec::new();
        if !self.apple_silicon {
            items.push("not measured on an Apple silicon Mac: this result does not qualify NFR-PERF-04".to_owned());
        }
        for (state, added) in [("off", self.off), ("on", self.on)] {
            if !added.meets_target() {
                items.push(format!(
                    "recording {state}: added p95 {:.1} ms is not under the {} ms target (NFR-PERF-04)",
                    added.p95_ms,
                    TARGET.as_millis()
                ));
            }
        }
        items
    }
}

/// Renders the report. Pure, so its wording is tested.
fn render_report(
    machine: &Machine,
    options: &Options,
    stamp: &str,
    stats: &[(Variant, Stats)],
    verdict: Verdict,
) -> String {
    let mut r = String::new();
    // `write!` to a String cannot fail.
    let _ = writeln!(r, "# knsh start-up benchmark — {stamp}\n");
    let _ = writeln!(
        r,
        "NFR-PERF-04: start-up time added to a human session, under {} ms at p95.\n",
        TARGET.as_millis()
    );
    let _ = writeln!(r, "## Machine\n");
    let _ = writeln!(r, "| Field | Value |\n| --- | --- |");
    for (field, value) in [
        ("Model", &machine.model),
        ("CPU", &machine.cpu),
        ("Architecture", &machine.arch),
        ("Logical CPUs", &machine.cpus),
        ("Memory (GiB)", &machine.memory_gib),
        ("macOS", &machine.macos),
        ("zsh", &machine.zsh),
        ("knsh", &machine.knsh),
        ("Commit", &machine.commit),
    ] {
        let _ = writeln!(r, "| {field} | {value} |");
    }
    let _ = writeln!(r, "\n## Method\n");
    let _ = writeln!(
        r,
        "Time from spawning `script -q /dev/null <shell>` to the prompt marker on the pseudo-terminal. {} timed rounds \
         after {} warm-up rounds; each round runs every variant once, in a rotating order. Temporary `HOME` with a \
         `.zshrc` that only sets the prompt. Added time = knsh percentile − plain zsh percentile (nearest rank). \
         Recording on runs without a `knshd` listening: knsh reaches it only from a worker thread after the shell has \
         started, so the daemon is off the path to the first prompt (KNSH-021, NFR-REL-02).",
        options.runs, options.warmup
    );
    let _ = writeln!(r, "\n## Results (ms)\n");
    let _ = writeln!(
        r,
        "| Variant | min | p50 | p95 | max |\n| --- | --- | --- | --- | --- |"
    );
    for (variant, s) in stats {
        let _ = writeln!(
            r,
            "| {} | {:.1} | {:.1} | {:.1} | {:.1} |",
            variant.name(),
            ms(s.min),
            ms(s.p50),
            ms(s.p95),
            ms(s.max)
        );
    }
    let _ = writeln!(
        r,
        "\n| Added by knsh | p50 | p95 | Under {} ms at p95 |\n| --- | --- | --- | --- |",
        TARGET.as_millis()
    );
    for (state, added) in [("recording off", verdict.off), ("recording on", verdict.on)] {
        let met = if added.meets_target() { "yes" } else { "**no**" };
        let _ = writeln!(r, "| {state} | {:.1} | {:.1} | {met} |", added.p50_ms, added.p95_ms);
    }
    let _ = writeln!(r, "\n## Verdict\n");
    let open = verdict.open_items();
    if open.is_empty() {
        let _ = writeln!(
            r,
            "PASSED: the added time is under {} ms at p95 with recording off and on.",
            TARGET.as_millis()
        );
    } else {
        let _ = writeln!(r, "NOT PASSED. Open items:\n");
        for item in open {
            let _ = writeln!(r, "- {item}");
        }
    }
    r
}

/// Renders every timed sample as CSV: round, variant, milliseconds.
fn render_samples(samples: &Samples) -> String {
    let mut csv = String::from("round,variant,ms\n");
    for (round, variant, elapsed) in samples {
        let _ = writeln!(csv, "{round},{},{:.3}", variant.slug(), ms(*elapsed));
    }
    csv
}

/// Writes `text` to `path`, creating its directory.
fn write_file(path: &Path, text: &str) -> Result<(), BenchError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| BenchError::Io("creating the results directory", e))?;
    }
    fs::write(path, text).map_err(|e| BenchError::Io("writing results", e))
}

/// Runs the benchmark and writes its results; `Ok(true)` when the target was met.
fn run(options: &Options) -> Result<bool, BenchError> {
    // Absolute: every run starts in its temporary home, where a relative path would name nothing.
    let knsh = fs::canonicalize(&options.knsh)
        .ok()
        .filter(|path| path.is_file())
        .ok_or_else(|| BenchError::Usage(format!("no knsh binary at {}\n{USAGE}", options.knsh.display())))?;
    let options = &Options {
        knsh,
        ..options.clone()
    };
    let machine = describe_machine(&options.knsh);
    let samples = measure(options)?;
    // A variant without samples cannot happen after `measure` succeeds (`--runs` is at least `MIN_RUNS`), but is
    // reported rather than unwrapped.
    let summarise = |variant| Stats::of(&samples_of(&samples, variant)).ok_or(BenchError::NoPrompt(variant));
    let plain = summarise(Variant::PlainZsh)?;
    let off = summarise(Variant::KnshRecordingOff)?;
    let on = summarise(Variant::KnshRecordingOn)?;
    let stats = [
        (Variant::PlainZsh, plain),
        (Variant::KnshRecordingOff, off),
        (Variant::KnshRecordingOn, on),
    ];
    let verdict = Verdict {
        off: Added::between(plain, off),
        on: Added::between(plain, on),
        apple_silicon: machine.is_apple_silicon(),
    };
    let stamp = probe("/bin/date", &["-u", "+%Y%m%dT%H%M%SZ"]);
    let report = render_report(&machine, options, &stamp, &stats, verdict);
    let dir = options.out.join(&stamp);
    write_file(&dir.join("report.md"), &report)?;
    write_file(&dir.join("samples.csv"), &render_samples(&samples))?;
    write_file(&options.out.join("latest.md"), &report)?;
    print!("{report}");
    println!("\nResults: {}", dir.display());
    Ok(verdict.passed())
}

/// Entry point: see the module docs for the exit statuses.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_options(&args).and_then(|options| run(&options)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(BenchError::Usage(text)) => {
            eprintln!("{text}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("startup_bench: {error}");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let sorted: Vec<Duration> = (1..=20).map(d).collect();
        assert_eq!(percentile(&sorted, 50), d(10));
        assert_eq!(percentile(&sorted, 95), d(19));
        assert_eq!(percentile(&sorted, 100), d(20));
        assert_eq!(percentile(&[d(7)], 95), d(7));
        assert_eq!(percentile(&sorted, 0), d(1));
    }

    #[test]
    fn stats_sort_their_samples() {
        let stats = Stats::of(&[d(30), d(10), d(20)]).unwrap();
        assert_eq!((stats.min, stats.p50, stats.max), (d(10), d(20), d(30)));
        assert!(Stats::of(&[]).is_none());
    }

    // NFR-PERF-04: the bound is strict ("under 50 ms").
    #[test]
    fn target_is_strictly_under_fifty_ms() {
        let plain = Stats::of(&[d(100)]).unwrap();
        assert!(Added::between(plain, Stats::of(&[d(149)]).unwrap()).meets_target());
        assert!(!Added::between(plain, Stats::of(&[d(150)]).unwrap()).meets_target());
    }

    #[test]
    fn prompt_needs_marker_and_digit() {
        assert_eq!(find_prompt(b"\x1b]133;A\x07KNSHBENCH1> "), Some(b'1'));
        assert_eq!(find_prompt(b"noise KNSHBENCH"), None, "digit not yet arrived");
        assert_eq!(find_prompt(b"KNSHBENC"), None);
        assert_eq!(find_prompt(b"xKNSHBENCH0> "), Some(b'0'));
    }

    #[test]
    fn recording_digit_matches_variant() {
        assert_eq!(Variant::PlainZsh.recording_digit(), b'0');
        assert_eq!(Variant::KnshRecordingOff.recording_digit(), b'0');
        assert_eq!(Variant::KnshRecordingOn.recording_digit(), b'1');
    }

    // KNSH-024: a target not met, or a machine that does not qualify, is an open item and never a pass.
    #[test]
    fn unmet_target_or_wrong_machine_is_an_open_item() {
        let fast = Added {
            p50_ms: 5.0,
            p95_ms: 10.0,
        };
        let slow = Added {
            p50_ms: 40.0,
            p95_ms: 50.0,
        };
        let passed = Verdict {
            off: fast,
            on: fast,
            apple_silicon: true,
        };
        assert!(passed.passed());
        assert_eq!(passed.open_items(), Vec::<String>::new());

        let slow_on = Verdict { on: slow, ..passed };
        assert!(!slow_on.passed());
        let items = slow_on.open_items();
        assert_eq!(items.len(), 1);
        assert!(
            items[0].contains("recording on") && items[0].contains("50.0"),
            "{items:?}"
        );

        let intel = Verdict {
            apple_silicon: false,
            ..passed
        };
        assert!(!intel.passed());
        assert!(intel.open_items()[0].contains("Apple silicon"));
    }

    #[test]
    fn report_records_machine_results_and_open_items() {
        let machine = Machine {
            model: "Mac15,6".into(),
            cpu: "Apple M3 Pro".into(),
            arch: "arm64".into(),
            commit: "abc1234".into(),
            ..Machine::default()
        };
        assert!(machine.is_apple_silicon());
        let options = parse_options(&args(&["--knsh", "k"])).unwrap();
        let stats = Stats::of(&[d(100)]).unwrap();
        let verdict = Verdict {
            off: Added {
                p50_ms: 1.0,
                p95_ms: 2.0,
            },
            on: Added {
                p50_ms: 60.0,
                p95_ms: 70.0,
            },
            apple_silicon: true,
        };
        let report = render_report(
            &machine,
            &options,
            "20260101T000000Z",
            &[(Variant::PlainZsh, stats)],
            verdict,
        );
        for needle in [
            "Apple M3 Pro",
            "Mac15,6",
            "abc1234",
            "| plain zsh | 100.0",
            "| recording on | 60.0 | 70.0 | **no** |",
            "NOT PASSED",
            "70.0 ms is not under the 50 ms target",
        ] {
            assert!(report.contains(needle), "missing {needle:?} in\n{report}");
        }
        assert!(!report.contains("PASSED: the added time"));
    }

    #[test]
    fn options_are_strict() {
        let options = parse_options(&args(&["--knsh", "k", "--runs", "30", "--warmup", "0", "--out", "o"])).unwrap();
        assert_eq!(
            options,
            Options {
                knsh: "k".into(),
                runs: 30,
                warmup: 0,
                out: "o".into()
            }
        );
        assert_eq!(parse_options(&args(&["--knsh", "k"])).unwrap().runs, DEFAULT_RUNS);
        for bad in [
            &[][..],
            &["--knsh"],
            &["--knsh", "k", "--runs", "x"],
            &["--knsh", "k", "--runs", "19"],
            &["--knsh", "k", "--knsh", "j"],
            &["--knsh", "k", "--bogus", "1"],
        ] {
            assert!(
                matches!(parse_options(&args(bad)), Err(BenchError::Usage(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn samples_csv_has_one_row_per_sample() {
        let csv = render_samples(&vec![
            (0, Variant::PlainZsh, d(12)),
            (0, Variant::KnshRecordingOn, d(15)),
        ]);
        assert_eq!(
            csv,
            "round,variant,ms\n0,plain-zsh,12.000\n0,knsh-recording-on,15.000\n"
        );
    }
}
