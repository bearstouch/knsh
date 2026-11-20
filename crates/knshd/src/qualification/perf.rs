//! The phase 2 performance measurements (KNSH-076; NFR-PERF-01, NFR-PERF-02, NFR-PERF-03, NFR-PERF-07,
//! NFR-PERF-08; `specs/07-testing/performance-validation.md`).
//!
//! [`phase_2_performance`] measures each target in turn and writes `performance.md` and `performance-samples.csv`
//! (module [`super::report`]). It is `#[ignore]`d: the figures depend on the machine and the build, so it runs on
//! purpose, in release, through `scripts/qualify-phase2.sh`, never as part of `cargo test`.
//!
//! Every measurement but idle memory drives the threat-model suite's miniature `knshd` ([`Stack`]): the parts `main`
//! wires, with the real record store, event hub, profile loader, supervisor and sockets. Idle memory needs the real
//! `knshd` process, so it is started by launchd under a test job, as `tests/launchd_agent.rs` does.
//!
//! # What each figure includes
//!
//! - **Decision** (NFR-PERF-01): from handing a line to the supervisor to the verdict, over the agent-command corpus,
//!   with no hooks and no authority. A line that is allowed is timed to the moment the supervisor hands it to the
//!   spawner, which here is [`TimingSpawner`] and starts nothing. A refused line is timed until it is answered, so its
//!   figure also holds the record write and `command.denied`: an upper bound. Every round opens a new session, so the
//!   repeated-denial limiter (FR-HOOK-20) never shortens a refusal.
//! - **Spawn overhead** (NFR-PERF-02): what an agent pays for a trivial line run through Kinetic Shell, compared with
//!   running it with plain `bash -c`. Inside a real envelope, a timer ([`KTIME_C`]) runs `"$SHELL" -c <line>` (the
//!   `knsh` client: `agent.sock`, `hello`, `exec.run`, the decision, the record, `knsh-exec`, `sandbox-exec` and
//!   `bash`); outside any envelope the same timer runs `/bin/bash -c <line>`. Overhead is the difference of the p95s.
//! - **Hooks** (NFR-PERF-03): every record of a line a hook matched lists that hook with its run time, no run time
//!   exceeds its hook's timeout, and a hook that hangs is killed at its timeout so its line is decided shortly after.
//! - **Event delivery** (NFR-PERF-07): a subscriber on the real `user.sock` (as an authority or `knsh events`
//!   subscribes) compares each event's `ts`, stamped by the hub with the system clock as it publishes, with the system
//!   clock when the notification has been read and parsed, while the corpus runs.
//! - **Idle memory** (NFR-PERF-08): the resident size of a real `knshd` that served one `hello` and then had no
//!   connection and no session for the idle period.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use knsh_core::{HookResult, Timestamp};
use knsh_json::{Frame, FrameReader, FrameWriter, Value};
use knsh_proto::{ErrorCode, LineStatus};

use super::report::{self, Machine, Measurement, Series, Target, Unit};
use super::stats::{Summary, ms};
use crate::supervisor::{LineEvents, Ran, SpawnPlan, SpawnReport, Spawner};
use crate::threat_model::harness::{Binaries, Stack, Wiring, built, built_binaries};

/// NFR-PERF-01.
const DECISION: Target = Target {
    requirement: "NFR-PERF-01",
    text: "Supervisor decision without hooks or authority: p95 under 5 ms over the corpus",
    unit: Unit::Ms,
    bound: Some(5.0),
};

/// NFR-PERF-02.
const SPAWN: Target = Target {
    requirement: "NFR-PERF-02",
    text: "Spawn overhead versus plain `bash -c`: p95 under 15 ms for trivial commands",
    unit: Unit::Ms,
    bound: Some(15.0),
};

/// NFR-PERF-03: a property, decided by its checks.
const HOOKS: Target = Target {
    requirement: "NFR-PERF-03",
    text: "Hook time reported per record, bounded by its timeout",
    unit: Unit::Ms,
    bound: None,
};

/// NFR-PERF-07.
const EVENTS: Target = Target {
    requirement: "NFR-PERF-07",
    text: "Event delivery: p95 under 10 ms",
    unit: Unit::Ms,
    bound: Some(10.0),
};

/// NFR-PERF-08.
const MEMORY: Target = Target {
    requirement: "NFR-PERF-08",
    text: "`knshd` idle memory under 50 MB",
    unit: Unit::Mb,
    bound: Some(50.0),
};

/// Timed rounds, overridden by `KNSH_QUALIFICATION_ROUNDS` (at least 1).
const DEFAULT_ROUNDS: usize = 5;

/// Discarded warm-up rounds before the timed ones: the first lines pay for cold caches and lazily built state.
const WARMUP_ROUNDS: usize = 1;

/// Runs of each trivial line per round, in the spawn measurement.
const SPAWN_RUNS: usize = 20;

/// How long `knshd` idles before its memory is read, overridden by `KNSH_QUALIFICATION_IDLE_S`.
const DEFAULT_IDLE: Duration = Duration::from_secs(60);

/// How many times, a second apart, the idle `knshd`'s resident size is read at the end of the idle period.
const MEMORY_SAMPLES: usize = 10;

/// The profile every measured line runs under.
const PROFILE: &str = "perf";

/// How the measurements are repeated.
#[derive(Debug, Clone, Copy)]
struct Settings {
    /// Timed rounds, after [`WARMUP_ROUNDS`].
    rounds: usize,
    /// How long `knshd` idles before its memory is read.
    idle: Duration,
}

impl Settings {
    /// The defaults, with the environment's overrides. A value that is not a positive whole number is refused
    /// loudly: a run must measure what it says it did.
    fn from_env() -> Self {
        let number = |var: &str| {
            std::env::var(var).ok().map(|text| {
                text.parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .unwrap_or_else(|| panic!("{var} must be a positive whole number, not {text:?}"))
            })
        };
        Self {
            rounds: number("KNSH_QUALIFICATION_ROUNDS").map_or(DEFAULT_ROUNDS, |n| usize::try_from(n).unwrap()),
            idle: number("KNSH_QUALIFICATION_IDLE_S").map_or(DEFAULT_IDLE, Duration::from_secs),
        }
    }

    /// Every round, warm-up included.
    fn total(self) -> usize {
        WARMUP_ROUNDS + self.rounds
    }
}

/// The profile of every measured line: everything allowed and nothing asked, so each line is decided by the rules
/// alone (no authority, no person), and the timer may run inside the envelope.
fn perf_profile(tools: &Path) -> String {
    format!(
        "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\ndefault = \"allow\"\nproject_executables = \"allow\"\n\
         trusted_folders = [\"{}\"]\n[approvals]\nirreversible = \"allow\"\n",
        tools.display()
    )
}

/// The profile of the refusal pass: every line denied by the rules (`exec.default = "deny"`), so the refused path of
/// the decision is measured over the same corpus.
const DENY_PROFILE: &str = "perf-deny";

/// The text of [`DENY_PROFILE`].
const DENY_PROFILE_TEXT: &str = "[exec]\ndefault = \"deny\"\nproject_executables = \"deny\"\n";

/// A spawner that starts nothing: it notes when the supervisor handed it the line, and reports a clean exit.
#[derive(Default)]
struct TimingSpawner {
    handed: Mutex<Option<Instant>>,
}

impl TimingSpawner {
    /// When the last line was handed over, clearing it.
    fn take(&self) -> Option<Instant> {
        self.handed.lock().unwrap().take()
    }
}

impl Spawner for TimingSpawner {
    fn spawn(&self, _plan: SpawnPlan, _events: &dyn LineEvents) -> SpawnReport {
        // First thing: everything the supervisor did before this call is the decision.
        *self.handed.lock().unwrap() = Some(Instant::now());
        SpawnReport {
            sandbox_profile: None,
            outcome: Ok(Ran {
                status: LineStatus::Exited(0),
                timed_out: false,
            }),
            output: None,
            network: Vec::new(),
        }
    }
}

/// A miniature `knshd` whose lines are decided and recorded but never started, with `wiring` otherwise.
fn deciding_stack(tag: &str, bins: &Binaries, wiring: &Wiring) -> (Stack, Arc<TimingSpawner>) {
    let timer = Arc::new(TimingSpawner::default());
    let stack = Stack::start_with(
        tag,
        bins,
        Wiring {
            spawner: Some(Arc::clone(&timer) as Arc<dyn Spawner>),
            hooks: wiring.hooks,
            real_clock: wiring.real_clock,
            redactors: None,
        },
    );
    stack.profile(PROFILE, &perf_profile(&stack.tools));
    (stack, timer)
}

/// Whole milliseconds as recorded (`latency_ms`, `duration_ms`), saturating at `u32::MAX`, which no run reaches.
fn whole_ms(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

/// Every command of the agent-command corpus (`tests/corpus/*.txt`, `specs/07-testing/agent-command-corpus.md`), in
/// file order, unescaped.
fn corpus() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    let mut lines = Vec::new();
    for file in files {
        for entry in std::fs::read_to_string(&file).unwrap().lines() {
            if entry.starts_with('#') || entry.is_empty() {
                continue;
            }
            // source, licence, tags, command: the command is the last field and may not hold a raw tab.
            let command = entry.splitn(4, '\t').nth(3).unwrap();
            lines.push(unescape(command));
        }
    }
    assert!(!lines.is_empty(), "the corpus is empty");
    lines
}

/// Undoes the corpus escapes: `\\`, `\n`, `\t`, `\r`.
fn unescape(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            // `\\`, or a lone backslash at the end.
            Some('\\') | None => out.push('\\'),
            // The corpus gate refuses any other escape; kept as written rather than guessed.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// NFR-PERF-01 (module documentation).
fn decision(bins: &Binaries, settings: Settings) -> Measurement {
    let (stack, timer) = deciding_stack("qdec", bins, &Wiring::default());
    stack.profile(DENY_PROFILE, DENY_PROFILE_TEXT);
    let lines = corpus();
    let (mut allowed, mut refused, mut latency) = (Vec::new(), Vec::new(), Vec::new());
    let mut excluded: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed_checks = Vec::new();
    // Each round runs the corpus twice: under the allow-everything profile (every line reaches the spawner), then
    // under the deny-everything one (every line is refused and recorded).
    let passes = (0..settings.total()).flat_map(|round| [(round, PROFILE), (round, DENY_PROFILE)]);
    for (round, profile) in passes {
        let counted = round >= WARMUP_ROUNDS;
        let session = stack.session(profile);
        for line in &lines {
            let _ = timer.take();
            let started = Instant::now();
            let answer = stack.line(session, line, &[]);
            let answered = started.elapsed();
            match answer {
                Ok(_) => match timer.take() {
                    Some(handed) if counted => allowed.push(ms(handed.duration_since(started))),
                    Some(_) => {}
                    None => failed_checks.push(format!("an allowed line never reached the spawner: {line:?}")),
                },
                Err(error) if error.code == ErrorCode::Denied => {
                    if counted {
                        refused.push(ms(answered));
                    }
                }
                // An ask or any other answer is not a decision by rules alone: excluded, and said so.
                Err(error) => *excluded.entry(format!("{:?}", error.code)).or_default() += 1,
            }
        }
        if counted {
            latency.extend(
                stack
                    .records(session)
                    .iter()
                    .filter_map(|record| record.details.decision.as_ref())
                    .map(|decision| whole_ms(decision.latency_ms)),
            );
        }
    }
    let all: Vec<f64> = allowed.iter().chain(&refused).copied().collect();
    let mut notes = vec![
        format!(
            "{} corpus lines × {} timed rounds (after {WARMUP_ROUNDS} warm-up) × 2 profiles: {} allowed, {} refused.",
            lines.len(),
            settings.rounds,
            allowed.len(),
            refused.len()
        ),
        "Profiles: one with `exec.default`, `exec.project_executables` and `approvals.irreversible` all `allow`, \
         one with `exec.default` and `exec.project_executables` `deny`; no hooks, no authority, no grants."
            .to_owned(),
        "The `record latency_ms` series is the supervisor's own figure in each record (whole milliseconds, rounded \
         down): a cross-check of the wall-clock series, not the figure judged."
            .to_owned(),
    ];
    if !excluded.is_empty() {
        notes.push(format!("Excluded (not decided by rules alone): {excluded:?}"));
    }
    Measurement {
        figure_label: "p95 over every timed line".to_owned(),
        figure: Summary::of(&all).map(|s| s.p95),
        method: "Each corpus line is handed to the supervisor (`exec.run`'s path, without the socket) of a \
                 miniature `knshd`. An allowed line is timed until the supervisor hands it to the spawner (which \
                 starts nothing); a refused line until it is answered, record write included (an upper bound). \
                 Every round uses a new session, so the repeated-denial limiter never shortens a refusal."
            .to_owned(),
        series: vec![
            Series::new("all lines", all),
            Series::new("allowed: to spawner hand-off", allowed),
            Series::new("refused: to answer (record written)", refused),
            Series::new("record latency_ms (whole ms)", latency),
        ],
        notes,
        failed_checks,
        ..Measurement::new(DECISION)
    }
    .judge()
}

/// A timer run inside and outside envelopes: `ktime <label> <runs> <program> [args…]` starts `program` `runs`
/// times, one after another, with stdin, stdout and stderr on `/dev/null`, and prints `<label> <nanoseconds>` for
/// each run from `posix_spawn` to `waitpid` on the monotonic clock. A run that does not exit 0 prints
/// `<label> fail <status>` and stops: a line that was refused must never count as a fast one.
const KTIME_C: &str = "#include <spawn.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <fcntl.h>\n\
    #include <sys/wait.h>\n#include <time.h>\nextern char **environ;\n\
    int main(int argc, char **argv) { if (argc < 4) return 2; const char *label = argv[1];\n\
    int n = atoi(argv[2]); if (n < 1) return 2; long long *ns = calloc((size_t)n, sizeof *ns); if (!ns) return 2;\n\
    posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);\n\
    posix_spawn_file_actions_addopen(&fa, 0, \"/dev/null\", O_RDONLY, 0);\n\
    posix_spawn_file_actions_addopen(&fa, 1, \"/dev/null\", O_WRONLY, 0);\n\
    posix_spawn_file_actions_addopen(&fa, 2, \"/dev/null\", O_WRONLY, 0);\n\
    for (int i = 0; i < n; i++) { struct timespec a, b; pid_t pid; int status = 0;\n\
    clock_gettime(CLOCK_MONOTONIC, &a);\n\
    if (posix_spawn(&pid, argv[3], &fa, NULL, argv + 3, environ) != 0) { printf(\"%s fail spawn\\n\", label); \
    return 1; }\n\
    if (waitpid(pid, &status, 0) != pid) { printf(\"%s fail wait\\n\", label); return 1; }\n\
    clock_gettime(CLOCK_MONOTONIC, &b);\n\
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) { printf(\"%s fail %d\\n\", label, status); return 1; }\n\
    ns[i] = (long long)(b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec); }\n\
    for (int i = 0; i < n; i++) printf(\"%s %lld\\n\", label, ns[i]); return 0; }\n";

/// The trivial lines of NFR-PERF-02: a label (no spaces) and the line.
const TRIVIAL: [(&str, &str); 2] = [("true", "true"), ("echo", "echo hi")];

/// Reads `ktime` output into `into` (label → milliseconds); each failure line becomes a failed check.
fn read_ktime(out: &str, prefix: &str, into: &mut BTreeMap<String, Vec<f64>>, failed: &mut Vec<String>) {
    for line in out.lines() {
        let Some((label, value)) = line.split_once(' ') else {
            continue;
        };
        if !TRIVIAL.iter().any(|(known, _)| *known == label) {
            continue;
        }
        match value.parse::<f64>() {
            Ok(ns) => into.entry(format!("{prefix}{label}")).or_default().push(ns / 1e6),
            Err(_) => failed.push(format!("{prefix}{label}: {value}")),
        }
    }
}

/// NFR-PERF-02 (module documentation).
fn spawn_overhead(bins: &Binaries, settings: Settings) -> Measurement {
    let stack = Stack::start("qspawn", bins);
    stack.profile(PROFILE, &perf_profile(&stack.tools));
    let ktime = stack.build_probe("ktime", KTIME_C);
    let mut samples: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut failed_checks = Vec::new();
    for round in 0..settings.total() {
        // Warm-up samples are read into a throw-away map.
        let mut warmup = BTreeMap::new();
        let into = if round >= WARMUP_ROUNDS {
            &mut samples
        } else {
            &mut warmup
        };
        for (label, line) in TRIVIAL {
            let plain = Command::new(&ktime)
                .args([label, &SPAWN_RUNS.to_string(), "/bin/bash", "-c", line])
                .output()
                .unwrap();
            if !plain.status.success() {
                failed_checks.push(format!("plain bash -c {line:?} failed"));
            }
            read_ktime(
                &String::from_utf8_lossy(&plain.stdout),
                "plain: ",
                into,
                &mut failed_checks,
            );
        }
        // Only `knsh` may be timed as the supervised side: an envelope whose `SHELL` were plain bash would time plain
        // bash and pass.
        let mut script = format!(
            "[ \"$SHELL\" = '{}' ] || {{ echo 'SHELL is not knsh'; exit 3; }}\n",
            bins.knsh.as_path().display()
        );
        for (label, line) in TRIVIAL {
            let _ = writeln!(
                script,
                "'{}' {label} {SPAWN_RUNS} \"$SHELL\" -c '{line}'",
                ktime.display()
            );
        }
        let (status, out) = stack.envelope(PROFILE, &script);
        if status != LineStatus::Exited(0) {
            failed_checks.push(format!("the envelope ended {status:?}: {}", out.trim()));
        }
        read_ktime(&out, "knsh: ", into, &mut failed_checks);
        diagnose_spawn(&stack, &ktime, into, &mut failed_checks);
    }
    let mut figure: Option<f64> = None;
    let mut notes = Vec::new();
    for (label, line) in TRIVIAL {
        let summary = |prefix: &str| samples.get(&format!("{prefix}{label}")).and_then(|s| Summary::of(s));
        match (summary("plain: "), summary("knsh: ")) {
            (Some(plain), Some(knsh)) => {
                let added = knsh.p95 - plain.p95;
                notes.push(format!(
                    "`{line}`: added p95 {added:.2} ms (knsh {:.2} − plain {:.2}); added p50 {:.2} ms.",
                    knsh.p95,
                    plain.p95,
                    knsh.p50 - plain.p50
                ));
                figure = Some(figure.map_or(added, |worst| worst.max(added)));
            }
            _ => failed_checks.push(format!("no samples for `{line}`")),
        }
    }
    notes.push(format!(
        "{SPAWN_RUNS} runs of each line per round, {} timed rounds after {WARMUP_ROUNDS} warm-up; plain and \
         supervised runs alternate each round.",
        settings.rounds
    ));
    notes.push(format!(
        "Diagnostic series (not judged), to show where the time goes: `{DIAG_SANDBOX}` is `sandbox-exec` with an \
         allow-everything profile running `bash -c true` (the floor any sandboxed line pays); `{DIAG_SUPERVISOR}` is \
         the supervisor's own path for `true` in-process, without the `knsh` client or the socket (decision, \
         record, profile file, `knsh-exec`, `sandbox-exec`, `bash`, reaping)."
    ));
    notes.push(
        "Supervised = `\"$SHELL\" -c <line>` inside a real envelope: the `knsh` client starts, connects to \
         `agent.sock`, says `hello`, sends `exec.run`; the supervisor decides, records, writes the line's profile and \
         starts it through `knsh-exec` and `sandbox-exec`; `bash` runs the line. Plain = `/bin/bash -c <line>` \
         outside any envelope."
            .to_owned(),
    );
    Measurement {
        figure_label: "worst added p95 (supervised p95 − plain p95)".to_owned(),
        figure,
        method: "A small C timer (`posix_spawn` to `waitpid`, monotonic clock) runs each trivial line repeatedly, \
                 outside any envelope with plain `bash -c`, and inside an envelope through the `knsh` client. The \
                 overhead is the difference of the nearest-rank p95s."
            .to_owned(),
        series: samples
            .into_iter()
            .map(|(name, values)| Series::new(&name, values))
            .collect(),
        notes,
        failed_checks,
        ..Measurement::new(SPAWN)
    }
    .judge()
}

/// Diagnostic series of the spawn measurement: `sandbox-exec` alone.
const DIAG_SANDBOX: &str = "diag: sandbox-exec alone: true";

/// Diagnostic series of the spawn measurement: the supervisor in-process, without the client.
const DIAG_SUPERVISOR: &str = "diag: supervisor in-process: true";

/// Times the parts of a supervised line that the spawn measurement's figure lumps together, into `into`: the floor
/// cost of `sandbox-exec`, and the supervisor's own path in-process (no `knsh` client, no socket).
fn diagnose_spawn(stack: &Stack, ktime: &Path, into: &mut BTreeMap<String, Vec<f64>>, failed: &mut Vec<String>) {
    let floor = Command::new(ktime)
        .args([
            "true",
            &SPAWN_RUNS.to_string(),
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1)(allow default)",
            "/bin/bash",
            "-c",
            "true",
        ])
        .output()
        .unwrap();
    let mut by_label = BTreeMap::new();
    read_ktime(&String::from_utf8_lossy(&floor.stdout), "", &mut by_label, failed);
    into.entry(DIAG_SANDBOX.to_owned())
        .or_default()
        .extend(by_label.remove("true").unwrap_or_default());
    let session = stack.session(PROFILE);
    for _ in 0..SPAWN_RUNS {
        let started = Instant::now();
        match stack.line(session, "true", &[]) {
            Ok(finished) if finished.status == LineStatus::Exited(0) => {
                into.entry(DIAG_SUPERVISOR.to_owned())
                    .or_default()
                    .push(ms(started.elapsed()));
            }
            other => failed.push(format!("in-process `true` did not run cleanly: {other:?}")),
        }
    }
}

/// One registered hook of the hook measurement: the binary it matches, what it does, its timeout.
struct HookCase {
    /// `hooks[N]`.
    name: &'static str,
    /// The line it is measured with; its first word is the binary the hook matches.
    line: &'static str,
    /// The hook's body (after `#!/bin/sh`).
    body: &'static str,
    timeout_ms: u64,
    /// What the record must report.
    result: HookResult,
    /// Lines per round.
    per_round: usize,
}

/// The hooks measured: one that answers at once, one that takes 100 ms, and one that hangs past its timeout.
const HOOK_CASES: [HookCase; 3] = [
    HookCase {
        name: "hooks[0]",
        line: "echo hooked",
        body: "exec /bin/cat >/dev/null\n",
        timeout_ms: 2000,
        result: HookResult::Allow,
        per_round: 10,
    },
    HookCase {
        name: "hooks[1]",
        line: "printf x",
        body: "/bin/cat >/dev/null\n/bin/sleep 0.1\n",
        timeout_ms: 2000,
        result: HookResult::Allow,
        per_round: 10,
    },
    HookCase {
        name: "hooks[2]",
        line: "date",
        body: "/bin/sleep 30\n",
        timeout_ms: 500,
        result: HookResult::Timeout,
        per_round: 2,
    },
];

/// How long after its hook's timeout a line may still be undecided: the runner kills the hook's group at the
/// timeout and allows its stdout 250 ms to drain (`hooks::DRAIN_TIMEOUT`); the rest is process exit and slack.
const HOOK_GRACE_MS: f64 = 500.0;

/// Registers [`HOOK_CASES`] in the stack's configuration file, with each hook's executable inside the
/// configuration directory, owner-only, as the runner requires (FR-HOOK-07).
fn register_hooks(stack: &Stack) {
    let config = stack.paths.config_file();
    let hooks_dir = config.parent().unwrap().join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    std::fs::set_permissions(&hooks_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut toml = String::new();
    for (index, case) in HOOK_CASES.iter().enumerate() {
        let file = hooks_dir.join(format!("hook{index}"));
        std::fs::write(&file, format!("#!/bin/sh\n{}", case.body)).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary = case.line.split(' ').next().unwrap();
        let _ = write!(
            toml,
            "[[hooks]]\nevent = \"command.proposed\"\nmatch = {{ binary = [\"{binary}\"] }}\nrun = \"{}\"\n\
             timeout_ms = {}\n\n",
            file.display(),
            case.timeout_ms
        );
    }
    std::fs::write(&config, toml).unwrap();
}

/// NFR-PERF-03 (module documentation).
fn hook_time(bins: &Binaries, settings: Settings) -> Measurement {
    let (stack, _timer) = deciding_stack(
        "qhook",
        bins,
        &Wiring {
            hooks: true,
            ..Wiring::default()
        },
    );
    register_hooks(&stack);
    let mut reported: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    let mut hanging_lines = Vec::new();
    let mut failed_checks = Vec::new();
    for round in 0..settings.total() {
        let counted = round >= WARMUP_ROUNDS;
        // A new session each round: the hanging hook's denials must stay under the repeated-denial limit.
        let session = stack.session(PROFILE);
        for case in &HOOK_CASES {
            for _ in 0..case.per_round {
                let started = Instant::now();
                let _ = stack.line(session, case.line, &[]);
                if counted && case.result == HookResult::Timeout {
                    hanging_lines.push(ms(started.elapsed()));
                }
            }
        }
        if !counted {
            continue;
        }
        for record in stack.records(session) {
            let Some(case) = HOOK_CASES
                .iter()
                .find(|case| case.line == record.command.expose().as_str())
            else {
                failed_checks.push(format!("unexpected record {:?}", record.command.expose().as_str()));
                continue;
            };
            let runs = record
                .details
                .decision
                .as_ref()
                .map(|decision| decision.hooks.clone())
                .unwrap_or_default();
            // FR-HOOK-05: exactly the matching hook, with its run time, bounded by its timeout.
            match runs.as_slice() {
                [run] if run.hook == case.name && run.result == case.result && run.duration_ms <= case.timeout_ms => {
                    reported.entry(case.name).or_default().push(whole_ms(run.duration_ms));
                }
                _ => failed_checks.push(format!("{}: the record reports {runs:?}", case.line)),
            }
        }
    }
    let hang = &HOOK_CASES[2];
    let limit = f64::from(u32::try_from(hang.timeout_ms).unwrap()) + HOOK_GRACE_MS;
    let figure = Summary::of(&hanging_lines).map(|s| s.max);
    if let Some(slowest) = figure
        && slowest >= limit
    {
        failed_checks.push(format!(
            "a line whose hook hangs took {slowest:.2} ms, not under its {} ms timeout + {HOOK_GRACE_MS} ms",
            hang.timeout_ms
        ));
    }
    let mut series: Vec<Series> = HOOK_CASES
        .iter()
        .map(|case| {
            Series::new(
                &format!(
                    "{} reported duration_ms ({}; timeout {} ms)",
                    case.name, case.line, case.timeout_ms
                ),
                reported.remove(case.name).unwrap_or_default(),
            )
        })
        .collect();
    series.push(Series::new("hanging hook: line decided after (wall)", hanging_lines));
    Measurement {
        figure_label: format!(
            "slowest decision of a line whose hook hangs (timeout {} ms; must be under timeout + {HOOK_GRACE_MS} ms)",
            hang.timeout_ms
        ),
        figure,
        method: "Three hooks are registered in the configuration file and run by the real hook runner: one answers \
                 at once, one sleeps 100 ms, one hangs past its 500 ms timeout. Each record of a matching line must \
                 list exactly its hook, with the expected result and a `duration_ms` no larger than the hook's \
                 timeout; a line whose hook hangs must be decided shortly after the timeout."
            .to_owned(),
        series,
        notes: vec![
            "Hook time is the hook's own run time, not a target: it is reported per record (FR-HOOK-05) and \
             bounded by the hook's `timeout_ms` (at most 60 s)."
                .to_owned(),
        ],
        failed_checks,
        ..Measurement::new(HOOKS)
    }
    .judge()
}

/// A subscriber on `user.sock`, as an authority or `knsh events` subscribes: `hello`, then `events.subscribe` for
/// every session. A reader thread notes each event's delivery delay.
struct EventWatcher {
    stream: UnixStream,
    /// Delivery delays in milliseconds, in arrival order.
    delays: Arc<Mutex<Vec<f64>>>,
    /// `events.lost` notifications received.
    lost: Arc<Mutex<usize>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl EventWatcher {
    /// Connects to `socket`, says `hello` and subscribes, panicking if either is refused, then starts the reader.
    fn connect(socket: &Path) -> Self {
        let stream = UnixStream::connect(socket).unwrap();
        let request = |id: u32, method: &str, params: &str| {
            let text = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#);
            let mut writer = FrameWriter::new(&stream);
            writer
                .write_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
                .unwrap();
            writer.flush().unwrap();
            let Some(Frame::Json(answer)) = FrameReader::new(&stream).read_frame().unwrap() else {
                panic!("no answer to {method}");
            };
            let answer = knsh_json::parse(&answer, 1 << 20).unwrap();
            assert!(
                answer.as_object().unwrap().contains_key("result"),
                "{method} refused: {answer:?}"
            );
        };
        request(
            1,
            "hello",
            r#"{"client":"knsh-qualification","client_version":"1","protocols":[1],"binary_frames":false}"#,
        );
        request(2, "events.subscribe", "{}");
        let (delays, lost) = (Arc::default(), Arc::default());
        let reader = {
            let stream = stream.try_clone().unwrap();
            let (delays, lost) = (Arc::clone(&delays), Arc::clone(&lost));
            std::thread::spawn(move || read_events(&stream, &delays, &lost))
        };
        Self {
            stream,
            delays,
            lost,
            reader: Some(reader),
        }
    }

    /// How many events have arrived so far.
    fn count(&self) -> usize {
        self.delays.lock().unwrap().len()
    }

    /// Waits until no event has arrived for half a second (at most 30 s), and answers how many arrived.
    fn settle(&self) -> usize {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut seen = self.count();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = self.count();
            if now == seen || Instant::now() > deadline {
                return now;
            }
            seen = now;
        }
    }

    /// Closes the connection and answers the delays and the `events.lost` count.
    fn finish(mut self) -> (Vec<f64>, usize) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let delays = std::mem::take(&mut *self.delays.lock().unwrap());
        let lost = *self.lost.lock().unwrap();
        (delays, lost)
    }
}

/// Microseconds since the Unix epoch on the system clock: the clock the hub stamps `ts` with.
fn now_micros() -> i128 {
    i128::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// Reads notifications until the connection closes: each event's delay from its `ts` to now.
fn read_events(stream: &UnixStream, delays: &Mutex<Vec<f64>>, lost: &Mutex<usize>) {
    let mut reader = FrameReader::new(stream);
    while let Ok(Some(Frame::Json(payload))) = reader.read_frame() {
        let Ok(message) = knsh_json::parse(&payload, 1 << 24) else {
            continue;
        };
        // Parsed first, then timed: the delay covers what a subscriber must do before it can use the event.
        let received = now_micros();
        let Some(object) = message.as_object() else { continue };
        if object.get("method").and_then(Value::as_str) == Some("events.lost") {
            *lost.lock().unwrap() += 1;
            continue;
        }
        let ts = object
            .get("params")
            .and_then(Value::as_object)
            .and_then(|params| params.get("ts"))
            .and_then(Value::as_str)
            .and_then(|ts| ts.parse::<Timestamp>().ok());
        if let Some(ts) = ts {
            let delay_us = received - i128::from(ts.as_unix_micros());
            #[allow(clippy::cast_precision_loss)]
            delays.lock().unwrap().push(delay_us as f64 / 1000.0);
        }
    }
}

/// NFR-PERF-07 (module documentation).
fn event_delivery(bins: &Binaries, settings: Settings) -> Measurement {
    let (stack, _timer) = deciding_stack(
        "qevt",
        bins,
        &Wiring {
            real_clock: true,
            ..Wiring::default()
        },
    );
    let watcher = EventWatcher::connect(&stack.paths.user_socket());
    let lines = corpus();
    let mut warmup_events = 0;
    for round in 0..settings.total() {
        let session = stack.session(PROFILE);
        for line in &lines {
            let _ = stack.line(session, line, &[]);
        }
        if round + 1 == WARMUP_ROUNDS {
            warmup_events = watcher.settle();
        }
    }
    watcher.settle();
    let (mut delays, lost) = watcher.finish();
    let timed = delays.split_off(warmup_events.min(delays.len()));
    let mut failed_checks = Vec::new();
    if lost > 0 {
        failed_checks.push(format!("{lost} events.lost notifications: the subscriber fell behind"));
    }
    if timed.iter().any(|delay| *delay < -1.0) {
        // An event received before it was stamped means the clocks disagree, and every figure is suspect.
        failed_checks.push("an event arrived more than 1 ms before its `ts`: the clock stepped".to_owned());
    }
    Measurement {
        figure_label: "p95 of `ts` to receipt".to_owned(),
        figure: Summary::of(&timed).map(|s| s.p95),
        method: "A subscriber connects to the real `user.sock`, says `hello` and subscribes to every session \
                 (`events.subscribe`). The corpus then runs through the supervisor (decided and recorded, nothing \
                 started), publishing `command.proposed`, `command.finished`, `command.denied` and the session \
                 events. Delay = the system clock when a notification has been read and parsed − its `ts`, which \
                 the hub stamps with the system clock as it publishes."
            .to_owned(),
        series: vec![Series::new("ts to receipt", timed)],
        notes: vec![format!(
            "{} corpus lines × {} timed rounds after {WARMUP_ROUNDS} warm-up; events of the warm-up are discarded. \
             `events.lost` notifications: {lost}.",
            lines.len(),
            settings.rounds
        )],
        failed_checks,
        ..Measurement::new(EVENTS)
    }
    .judge()
}

/// A `knshd` started by launchd under a test job, with its own label, Mach service and home under `/private/tmp`
/// (never the user's agent). Unloaded and removed on drop.
struct LaunchedKnshd {
    agent: knsh_platform::LaunchAgent,
    home: PathBuf,
    uid: u32,
}

impl LaunchedKnshd {
    /// Installs the job for `knshd` (copied out of the source tree: launchd-started processes need consent to read
    /// `~/Desktop` and the like).
    fn install(knshd: &Path) -> Result<Self, String> {
        use knsh_platform::macos::{Launchctl, RealFs, effective_uid};
        let pid = std::process::id();
        let home = PathBuf::from(format!("/private/tmp/knsh-qm-{pid}"));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir(&home).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        let paths = knsh_platform::EnginePaths::for_home(&home).map_err(|e| e.to_string())?;
        let program = home.join("knshd");
        std::fs::copy(knshd, &program).map_err(|e| e.to_string())?;
        let agent = knsh_platform::LaunchAgent::new(&format!("knsh.qualification.{pid}"), &program, &paths)
            .and_then(|agent| agent.with_control_service(&format!("knsh.qualification.{pid}.control")))
            .map_err(|e| e.to_string())?;
        let uid = effective_uid();
        let installed = Self { agent, home, uid };
        knsh_platform::install_agent(&RealFs::new(), &Launchctl::new(), &installed.agent, uid)
            .map_err(|e| format!("the launchd job could not be loaded (is there a GUI login session?): {e}"))?;
        Ok(installed)
    }

    /// The running `knshd`'s pid, as launchd reports it.
    fn pid(&self) -> Option<u32> {
        let target = format!("gui/{}/{}", self.uid, self.agent.label());
        let output = Command::new("/bin/launchctl").args(["print", &target]).output().ok()?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = ")?.parse().ok())
    }
}

impl Drop for LaunchedKnshd {
    fn drop(&mut self) {
        use knsh_platform::ServiceManager as _;
        let _ = knsh_platform::macos::Launchctl::new().bootout(self.uid, self.agent.label());
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// The resident size of `pid` in megabytes (10^6 bytes), from `ps` (which reports KiB).
fn rss_mb(pid: u32) -> Option<f64> {
    let output = Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let kib: f64 = String::from_utf8_lossy(&output.stdout).trim().parse().ok()?;
    Some(kib * 1024.0 / 1e6)
}

/// NFR-PERF-08 (module documentation).
fn idle_memory(settings: Settings) -> Measurement {
    let Some(knshd) = built("knshd") else {
        return Measurement::not_measured(MEMORY, "knshd is not built beside the test binary");
    };
    let launched = match LaunchedKnshd::install(&knshd) {
        Ok(launched) => launched,
        Err(reason) => return Measurement::not_measured(MEMORY, &reason),
    };
    // First contact starts it: `hello`, answered, then the connection closes. No session is opened.
    {
        let stream = UnixStream::connect(launched.agent.paths().user_socket()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut writer = FrameWriter::new(&stream);
        let hello = br#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"knsh-qualification","client_version":"1","protocols":[1]}}"#;
        writer.write_json(&knsh_json::parse(hello, 1 << 16).unwrap()).unwrap();
        writer.flush().unwrap();
        assert!(
            matches!(FrameReader::new(&stream).read_frame(), Ok(Some(Frame::Json(_)))),
            "knshd did not answer hello"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let pid = loop {
        if let Some(pid) = launched.pid() {
            break pid;
        }
        assert!(Instant::now() < deadline, "launchd did not start knshd");
        std::thread::sleep(Duration::from_millis(200));
    };
    let started = Instant::now();
    // Idle: no connection and no session; then the samples, a second apart.
    // The whole idle period first, then the samples: the figure is the size after the idle period, as the target says.
    std::thread::sleep(settings.idle);
    let mut samples = Vec::new();
    let mut failed_checks = Vec::new();
    for _ in 0..MEMORY_SAMPLES {
        match rss_mb(pid) {
            Some(mb) => samples.push(mb),
            None => failed_checks.push("ps could not read knshd's resident size".to_owned()),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if launched.pid() != Some(pid) {
        failed_checks.push("knshd exited or was restarted during the idle period".to_owned());
    }
    let figure = Summary::of(&samples).map(|s| s.max);
    Measurement {
        figure_label: "largest resident size over the last samples".to_owned(),
        figure,
        method: format!(
            "The release `knshd` is started by launchd under a test job (own label, Mach service and home under \
             `/private/tmp`), as `tests/launchd_agent.rs` does. One connection says `hello` and closes; no session \
             is opened. After {:.0} s idle, `ps -o rss=` is then read {MEMORY_SAMPLES} times a second apart. MB = 10^6 \
             bytes (stricter than MiB).",
            started.elapsed().as_secs_f64().max(settings.idle.as_secs_f64())
        ),
        series: vec![Series::new("knshd RSS at idle", samples)],
        notes: vec![
            "Not measured here: memory after a long busy period. A real `knshd` runs agent lines only for profiles \
             signed after Touch ID or a password, which an unattended run cannot provide."
                .to_owned(),
        ],
        failed_checks,
        ..Measurement::new(MEMORY)
    }
    .judge()
}

/// Runs `measure`, turning a panic into "not measured" with its message, so one failed measurement still leaves a
/// report of the others.
fn guarded(target: Target, measure: impl FnOnce() -> Measurement) -> Measurement {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(measure)).unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_else(|| "a panic without a message".to_owned());
        Measurement::not_measured(
            target,
            &format!("the measurement failed: {}", message.replace('\n', " ")),
        )
    })
}

/// KNSH-076: measures the phase 2 targets and writes `performance.md` and `performance-samples.csv` to
/// `target/qualification/` (or `KNSH_QUALIFICATION_DIR`). Fails when a target is missed or not measured, or the
/// machine or build does not qualify, after writing the report.
#[test]
#[ignore = "machine-dependent qualification run: scripts/qualify-phase2.sh"]
fn phase_2_performance() {
    let settings = Settings::from_env();
    let bins = built_binaries();
    let with_bins = |target: Target, measure: fn(&Binaries, Settings) -> Measurement| match &bins {
        Some(bins) => guarded(target, || measure(bins, settings)),
        None => Measurement::not_measured(target, "knsh-exec or knsh is not built beside the test binary"),
    };
    let measurements = vec![
        with_bins(DECISION, decision),
        with_bins(SPAWN, spawn_overhead),
        with_bins(HOOKS, hook_time),
        with_bins(EVENTS, event_delivery),
        guarded(MEMORY, || idle_memory(settings)),
    ];
    let machine = Machine::describe();
    let text = report::render(&machine, &measurements);
    let path = report::write("performance.md", &text);
    report::write("performance-samples.csv", &report::render_samples(&measurements));
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{text}\nReport: {}", path.display());
    let open = report::open_items(&machine, &measurements);
    assert!(open.is_empty(), "open items: {open:#?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_escapes_are_undone() {
        assert_eq!(unescape(r"a\nb\tc\\n\r"), "a\nb\tc\\n\r");
        assert_eq!(unescape(r"x\q"), r"x\q");
    }

    // The decision is measured over the real corpus: every line read, multi-line ones unescaped.
    #[test]
    fn corpus_is_read_whole() {
        let lines = corpus();
        assert!(lines.len() >= 200, "{}", lines.len());
        assert!(lines.iter().any(|line| line.contains("<<'EOF'\n")));
    }

    #[test]
    fn ktime_output_is_read_by_label() {
        let mut into = BTreeMap::new();
        let mut failed = Vec::new();
        read_ktime(
            "true 2000000\necho 3500000\nnoise\ntrue fail 256\n",
            "knsh: ",
            &mut into,
            &mut failed,
        );
        assert_eq!(into["knsh: true"], vec![2.0]);
        assert_eq!(into["knsh: echo"], vec![3.5]);
        assert_eq!(failed, vec!["knsh: true: fail 256".to_owned()]);
    }
}
