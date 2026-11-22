//! The corpus suite: every agent-command corpus line run for real, as `bash -c` runs it, under bash 5.2 (twice),
//! the native interpreter and `/bin/bash` (3.2), each in a fresh copy of the fixture (`tests/conformance/fixture/`).
//!
//! The environment of every run is fixed and nothing is inherited (`specs/07-testing/conformance.md`,
//! "Comparison"): `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `HOME` and `TMPDIR` inside the run's directory, `LC_ALL` and
//! `LANG` `C`, `TZ=UTC`, `TERM=dumb`, `USER` and `LOGNAME` `conformance`; standard input is `/dev/null`; `$0` is
//! `shell`. The first two bash 5.2 runs give the line's [`Volatility`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use knsh_corpus::CorpusError;
use knsh_corpus::check::{corpus_files, read_bounded};
use knsh_corpus::entry::{Entry, Tag, parse_file};

use crate::observe::{Aspects, Difference, Observation, Volatility, compare};
use crate::run::{Invocation, RunDir, execute};
use crate::{ConformanceError, Context, Shell, parallel_map};

/// The `$0` of every corpus run, so the shells' own messages (`shell: line 1: …`) have the same speaker.
pub const SCRIPT_NAME: &str = "shell";

/// The largest corpus file read.
const MAX_FILE_LEN: u64 = 64 * 1024 * 1024;

/// One corpus line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusLine {
    /// The corpus file's name.
    pub file: String,
    /// The 1-based line number in it.
    pub line: usize,
    /// The entry.
    pub entry: Entry,
}

/// The outcome of one corpus line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineResult {
    /// The line.
    pub line: CorpusLine,
    /// What bash 5.2 does not reproduce for it.
    pub volatile: Volatility,
    /// How the native interpreter differs from bash 5.2: empty when it behaves as bash 5.2.
    pub knsh: Vec<Difference>,
    /// How bash 3.2 differs from bash 5.2, when bash 3.2 was run.
    pub bash32: Option<Vec<Difference>>,
}

/// Reads every corpus file in `dir` (`*.txt`, sorted), in file order.
///
/// # Errors
///
/// [`ConformanceError::Corpus`] when the directory or a file cannot be read, or a line is malformed.
pub fn load(dir: &Path) -> Result<Vec<CorpusLine>, ConformanceError> {
    let mut lines = Vec::new();
    for path in corpus_files(dir)? {
        let text = read_bounded(&path, MAX_FILE_LEN)?;
        let entries = parse_file(&text).map_err(|(line, error)| CorpusError::At {
            path: path.clone(),
            line,
            error,
        })?;
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        lines.extend(entries.into_iter().map(|(line, entry)| CorpusLine {
            file: file.clone(),
            line,
            entry,
        }));
    }
    Ok(lines)
}

/// The environment of a corpus run in `run`.
fn environment(run: &RunDir) -> Vec<(OsString, OsString)> {
    let fixed = [
        ("PATH", OsString::from("/usr/bin:/bin:/usr/sbin:/sbin")),
        ("HOME", run.home().into_os_string()),
        ("TMPDIR", run.tmp().into_os_string()),
        ("LC_ALL", OsString::from("C")),
        ("LANG", OsString::from("C")),
        ("TZ", OsString::from("UTC")),
        ("TERM", OsString::from("dumb")),
        ("USER", OsString::from("conformance")),
        ("LOGNAME", OsString::from("conformance")),
    ];
    fixed
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value))
        .collect()
}

/// Runs `command` once under `shell` in a fresh run directory named `name`, and observes it.
///
/// # Errors
///
/// [`ConformanceError`] when the run directory cannot be prepared or the shell cannot be started.
pub fn observe(
    context: &Context,
    fixture: Option<&Path>,
    shell: &Shell,
    command: &str,
    name: &str,
) -> Result<Observation, ConformanceError> {
    let run = RunDir::create(&context.work, name, fixture)?;
    let invocation = Invocation {
        program: shell.program.clone(),
        args: vec!["-c".into(), command.into(), SCRIPT_NAME.into()],
        cwd: run.work(),
        env: environment(&run),
        stdin: None,
        timeout: context.timeout,
        run_dir: run.root().to_owned(),
    };
    let captured = execute(&invocation)?;
    let observation = run.observe(captured, true)?;
    run.remove()?;
    Ok(observation)
}

/// Runs every line and compares.
///
/// # Errors
///
/// The first run that could not be prepared or started: a corpus run is never partly measured.
pub fn run(
    lines: &[CorpusLine],
    context: &Context,
    fixture: Option<&Path>,
) -> Result<Vec<LineResult>, ConformanceError> {
    parallel_map(lines, context.jobs, |index, line| {
        let command = &line.entry.command;
        let first = observe(
            context,
            fixture,
            &context.reference,
            command,
            &format!("c{index}-bash52-a"),
        )?;
        let second = observe(
            context,
            fixture,
            &context.reference,
            command,
            &format!("c{index}-bash52-b"),
        )?;
        let volatile = Volatility::between(&first, &second);
        let knsh = observe(context, fixture, &context.candidate, command, &format!("c{index}-knsh"))?;
        let bash32 = match &context.bash32 {
            Some(bash32) => {
                let old = observe(context, fixture, bash32, command, &format!("c{index}-bash32"))?;
                Some(compare(&first, &old, &volatile, Aspects::ALL))
            }
            None => None,
        };
        Ok(LineResult {
            line: line.clone(),
            knsh: compare(&first, &knsh, &volatile, Aspects::ALL),
            volatile,
            bash32,
        })
    })
}

/// Whether a line is tagged as a known bash 3.2 vs 5.2 difference (`b32-missing` or `b32-differs`).
#[must_use]
pub fn tagged_bash32(line: &CorpusLine) -> bool {
    line.entry.has(Tag::B32Missing) || line.entry.has(Tag::B32Differs)
}

/// The default fixture directory, relative to the workspace root.
#[must_use]
pub fn default_fixture() -> PathBuf {
    PathBuf::from("tests/conformance/fixture")
}
