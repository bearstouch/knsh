//! `knsh-difftest`: the dev-only differential harness for the phase 2 parser exit criterion (KNSH-034). Never
//! shipped.
//!
//! ```text
//! knsh-difftest [--corpus DIR] [--bash PATH]... [--reference PATH]... [--report FILE] [--enforce-exact]
//! ```
//!
//! `DIR` defaults to `tests/corpus`. Without `--bash`, it compares with `/bin/bash` and every newer bash found in
//! the usual Homebrew places. `--reference` adds a non-gating shell such as brush. The Markdown report goes to
//! standard output and, with `--report`, to `FILE` too (for the CI artefact). The verdict gate always decides the
//! exit status; the 95% exact gate does only with `--enforce-exact` (release runs), and is reported either way.
//!
//! Exit status: 0 when both gates pass, 1 when a gate fails or the run cannot complete, 2 on a usage error.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use knsh_difftest::harness::{load_corpus, run};
use knsh_difftest::oracle::{Oracle, Role, ShellOracle, default_bashes};
use knsh_difftest::report::render;
use knsh_difftest::{DiffError, ExactGate, Summary};

/// The default corpus directory, relative to the workspace root.
const DEFAULT_CORPUS: &str = "tests/corpus";

const USAGE: &str =
    "knsh-difftest [--corpus DIR] [--bash PATH]... [--reference PATH]... [--report FILE] [--enforce-exact]";

#[derive(Default)]
struct Args {
    corpus: Option<PathBuf>,
    bashes: Vec<PathBuf>,
    references: Vec<PathBuf>,
    report: Option<PathBuf>,
    enforce_exact: bool,
}

fn parse_args(mut words: impl Iterator<Item = String>) -> Result<Args, DiffError> {
    let mut args = Args::default();
    while let Some(arg) = words.next() {
        let mut value = |name: &str| {
            words
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| DiffError::Usage(format!("{name} needs a value")))
        };
        match arg.as_str() {
            "--corpus" => args.corpus = Some(value("--corpus")?),
            "--bash" => args.bashes.push(value("--bash")?),
            "--reference" => args.references.push(value("--reference")?),
            "--report" => args.report = Some(value("--report")?),
            "--enforce-exact" => args.enforce_exact = true,
            other => return Err(DiffError::Usage(format!("unexpected argument {other}"))),
        }
    }
    Ok(args)
}

/// Probes every shell, dropping a bash that is the same file as one already listed (`/usr/local/bin/bash` may be a
/// link to the Homebrew one), so a line is not compared twice with the same binary.
fn probe_all(args: &Args) -> Result<Vec<ShellOracle>, DiffError> {
    let bashes = if args.bashes.is_empty() {
        default_bashes()
    } else {
        args.bashes.clone()
    };
    let shells = bashes
        .into_iter()
        .map(|path| (path, Role::Gate))
        .chain(args.references.iter().cloned().map(|path| (path, Role::Reference)));
    let mut seen = Vec::new();
    let mut oracles = Vec::new();
    for (path, role) in shells {
        // A path that does not resolve is kept, so the probe reports it as an error instead of skipping it.
        let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&canonical) {
            continue;
        }
        seen.push(canonical);
        oracles.push(ShellOracle::probe(&path, role)?);
    }
    Ok(oracles)
}

fn main_inner(args: &Args) -> Result<bool, DiffError> {
    let corpus = args.corpus.clone().unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS));
    let lines = load_corpus(&corpus)?;
    let oracles = probe_all(args)?;
    let oracles: Vec<&dyn Oracle> = oracles.iter().map(|oracle| oracle as &dyn Oracle).collect();
    let run = run(lines, &oracles)?;
    let summary = Summary::of(&run);
    let exact_gate = if args.enforce_exact {
        ExactGate::Enforce
    } else {
        ExactGate::ReportOnly
    };
    let report = render(&run, &summary, exact_gate);
    print!("{report}");
    if let Some(path) = &args.report {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| DiffError::Io {
                path: parent.to_owned(),
                source,
            })?;
        }
        fs::write(path, &report).map_err(|source| DiffError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(summary.passed(exact_gate))
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)).and_then(|args| main_inner(&args)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("knsh-difftest: phase 2 parser exit criterion not met (see the report)");
            ExitCode::FAILURE
        }
        Err(DiffError::Usage(message)) => {
            eprintln!("knsh-difftest: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("knsh-difftest: {error}");
            ExitCode::FAILURE
        }
    }
}
