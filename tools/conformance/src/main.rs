//! `knsh-conformance`: the dev-only phase 4 conformance gate (KNSH-109). Never shipped.
//!
//! ```text
//! knsh-conformance --bash PATH [--bash32 PATH] [--corpus DIR] [--fixture DIR] [--known FILE] [--compat FILE]
//!                  [--oils DIR] [--bash-tests DIR] [--work DIR] [--report FILE] [--jobs N] [--timeout SECS]
//!                  [--enforce]
//! knsh-conformance native ARG...        # the native interpreter as a shell (also as `knsh-native`)
//! ```
//!
//! `--bash` names bash 5.2, the reference (required, and checked). `--bash32` defaults to `/bin/bash` when it is
//! present. The corpus always runs; the Oils subset runs with `--oils` (a checkout), the bash test suite with
//! `--bash-tests` (the `tests` directory of the bash 5.2 source, with its helpers built). The Markdown report goes to
//! standard output and, with `--report`, to `FILE`. `--enforce` (release runs) makes the gate decide the exit status.
//!
//! Exit status: 0 when the gate passes (or is report-only and the corpus ran), 1 when it fails or the run cannot
//! complete, 2 on a usage error.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use knsh_conformance::report::{self, Report, Suite, SuiteReport};
use knsh_conformance::{ConformanceError, Context, Gate, Shell, bash_suite, corpus, known, oils};

const USAGE: &str = "knsh-conformance --bash PATH [--bash32 PATH] [--corpus DIR] [--fixture DIR] [--known FILE] \
                     [--compat FILE] [--oils DIR] [--bash-tests DIR] [--work DIR] [--report FILE] [--jobs N] \
                     [--timeout SECS] [--enforce]\n       knsh-conformance native ARG...";

/// Where macOS keeps bash 3.2.
const SYSTEM_BASH: &str = "/bin/bash";

#[derive(Debug, Default)]
struct Args {
    bash: Option<PathBuf>,
    bash32: Option<PathBuf>,
    corpus: Option<PathBuf>,
    fixture: Option<PathBuf>,
    known: Option<PathBuf>,
    compat: Option<PathBuf>,
    oils: Option<PathBuf>,
    bash_tests: Option<PathBuf>,
    work: Option<PathBuf>,
    report: Option<PathBuf>,
    jobs: Option<usize>,
    timeout: Option<u64>,
    enforce: bool,
}

fn parse_args(mut words: impl Iterator<Item = String>) -> Result<Args, ConformanceError> {
    let mut args = Args::default();
    while let Some(arg) = words.next() {
        let mut value = |name: &str| {
            words
                .next()
                .ok_or_else(|| ConformanceError::Usage(format!("{name} needs a value")))
        };
        let number = |name: &str, text: String| {
            text.parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| ConformanceError::Usage(format!("{name} needs a positive number")))
        };
        match arg.as_str() {
            "--bash" => args.bash = Some(value("--bash")?.into()),
            "--bash32" => args.bash32 = Some(value("--bash32")?.into()),
            "--corpus" => args.corpus = Some(value("--corpus")?.into()),
            "--fixture" => args.fixture = Some(value("--fixture")?.into()),
            "--known" => args.known = Some(value("--known")?.into()),
            "--compat" => args.compat = Some(value("--compat")?.into()),
            "--oils" => args.oils = Some(value("--oils")?.into()),
            "--bash-tests" => args.bash_tests = Some(value("--bash-tests")?.into()),
            "--work" => args.work = Some(value("--work")?.into()),
            "--report" => args.report = Some(value("--report")?.into()),
            "--jobs" => {
                let jobs = number("--jobs", value("--jobs")?)?;
                args.jobs = Some(usize::try_from(jobs).unwrap_or(usize::MAX));
            }
            "--timeout" => args.timeout = Some(number("--timeout", value("--timeout")?)?),
            "--enforce" => args.enforce = true,
            other => return Err(ConformanceError::Usage(format!("unexpected argument {other}"))),
        }
    }
    if args.bash.is_none() {
        return Err(ConformanceError::Usage("--bash (bash 5.2) is required".to_owned()));
    }
    Ok(args)
}

/// An absolute, canonical path for `path` (the runs change directory, so relative paths would not resolve).
fn absolute(path: &Path) -> Result<PathBuf, ConformanceError> {
    std::fs::canonicalize(path).map_err(|e| ConformanceError::io(path, e))
}

/// The candidate shell: this binary, linked as `knsh-native` under the work directory so that `$SH` and `$THIS_SH`
/// name it as a single program.
fn candidate(work: &Path) -> Result<Shell, ConformanceError> {
    let exe = std::env::current_exe().map_err(|e| ConformanceError::io("current_exe", e))?;
    let bin = work.join("bin");
    std::fs::create_dir_all(&bin).map_err(|e| ConformanceError::io(&bin, e))?;
    let link = bin.join(knsh_conformance::native::NATIVE_NAME);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&exe, &link).map_err(|e| ConformanceError::io(&link, e))?;
    Ok(Shell {
        program: link,
        version: format!(
            "knsh native interpreter (knsh-interp {}, unsupervised)",
            env!("CARGO_PKG_VERSION")
        ),
    })
}

fn main_inner(args: &Args) -> Result<bool, ConformanceError> {
    let work = args
        .work
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/conformance/work"));
    std::fs::create_dir_all(&work).map_err(|e| ConformanceError::io(&work, e))?;
    let work = absolute(&work)?;
    let reference = Shell::probe(&absolute(args.bash.as_deref().unwrap_or(Path::new("")))?)?;
    let bash32 = match &args.bash32 {
        Some(path) => Some(Shell::probe(&absolute(path)?)?),
        None if Path::new(SYSTEM_BASH).is_file() => Some(Shell::probe(Path::new(SYSTEM_BASH))?),
        None => None,
    };
    let context = Context {
        candidate: candidate(&work)?,
        reference,
        bash32,
        work: work.join("runs"),
        timeout: Duration::from_secs(args.timeout.unwrap_or(10)),
        jobs: args
            .jobs
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, std::num::NonZero::get)),
    };
    context.check_reference()?;
    std::fs::create_dir_all(&context.work).map_err(|e| ConformanceError::io(&context.work, e))?;

    let known_path = args.known.clone().unwrap_or_else(known::default_path);
    let compat = args.compat.clone().unwrap_or_else(known::default_page);
    let known = known::load(&known_path, &compat)?;

    let corpus_dir = args.corpus.clone().unwrap_or_else(|| PathBuf::from("tests/corpus"));
    let fixture = absolute(&args.fixture.clone().unwrap_or_else(corpus::default_fixture))?;
    let lines = corpus::load(&corpus_dir)?;
    eprintln!("knsh-conformance: corpus, {} line(s)", lines.len());
    let results = corpus::run(&lines, &context, Some(&fixture))?;
    let (corpus_report, bash32) = report::corpus_report(&results, &known);

    let oils_report = match &args.oils {
        Some(checkout) => {
            let checkout = absolute(checkout)?;
            let cases = oils::load(&checkout)?;
            eprintln!("knsh-conformance: Oils subset, {} case(s)", cases.len());
            report::oils_report(&oils::run(&cases, &context, &checkout)?, &known)
        }
        None => SuiteReport::not_run(Suite::Oils, "no Oils checkout given (--oils)"),
    };
    let bash_report = match &args.bash_tests {
        Some(tests) => {
            let tests = absolute(tests)?;
            let drivers = bash_suite::drivers(&tests)?;
            eprintln!("knsh-conformance: bash test suite, {} driver(s)", drivers.len());
            report::bash_suite_report(&bash_suite::run(&drivers, &context, &tests)?, &known)
        }
        None => SuiteReport::not_run(Suite::BashSuite, "no bash test directory given (--bash-tests)"),
    };

    let mut shells = vec![
        ("reference".to_owned(), context.reference.clone()),
        ("candidate".to_owned(), context.candidate.clone()),
    ];
    if let Some(bash32) = &context.bash32 {
        shells.push(("bash 3.2 (difference list)".to_owned(), bash32.clone()));
    }
    let mut full = Report {
        shells,
        suites: vec![corpus_report, oils_report, bash_report],
        bash32,
        stale_known: Vec::new(),
    };
    full.find_stale(&known);
    let gate = if args.enforce { Gate::Enforce } else { Gate::ReportOnly };
    let text = report::render(&full, gate);
    print!("{text}");
    if let Some(path) = &args.report {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| ConformanceError::io(parent, e))?;
        }
        std::fs::write(path, &text).map_err(|e| ConformanceError::io(path, e))?;
    }
    Ok(full.passed(gate))
}

fn main() -> ExitCode {
    let mut argv: Vec<OsString> = std::env::args_os().collect();
    let argv0 = argv.first().cloned().unwrap_or_default();
    let is_native = Path::new(&argv0)
        .file_name()
        .is_some_and(|name| name == knsh_conformance::native::NATIVE_NAME);
    if is_native {
        return ExitCode::from(knsh_conformance::native::run(&argv0, &argv[1..]));
    }
    if argv.get(1).is_some_and(|arg| arg == "native") {
        argv.remove(1);
        return ExitCode::from(knsh_conformance::native::run(&argv0, &argv[1..]));
    }
    let words = argv.into_iter().skip(1).map(|arg| arg.to_string_lossy().into_owned());
    match parse_args(words).and_then(|args| main_inner(&args)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("knsh-conformance: the conformance gate is not met (see the report)");
            ExitCode::FAILURE
        }
        Err(ConformanceError::Usage(message)) => {
            eprintln!("knsh-conformance: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("knsh-conformance: {error}");
            ExitCode::FAILURE
        }
    }
}
