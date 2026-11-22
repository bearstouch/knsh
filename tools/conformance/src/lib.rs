//! Dev-only phase 4 conformance gate (KNSH-109). Never shipped.
//!
//! Measures how closely `knsh`'s native interpreter behaves as bash 5.2, over three suites, and writes the report
//! the phase 4 release waits for (`specs/07-testing/conformance.md`):
//!
//! - [`corpus`]: every agent-command corpus line, run for real under bash 5.2 (twice, to learn what it does not
//!   reproduce), under the native interpreter and under `/bin/bash` (3.2); at least [`MIN_CORPUS_PERCENT`] must
//!   behave as in bash 5.2 ([`observe`] defines "behaves as"), and every line that does not must be documented
//!   ([`known`]). The bash 3.2 runs give the 3.2 vs 5.2 difference list (NFR-COMPAT-05).
//! - [`oils`]: the bash-compatible subset of the Oils project's cross-shell spec tests, each case compared with
//!   bash 5.2 on status and standard output.
//! - [`bash_suite`]: bash's own test suite (`tests/run-*`), each driver run with `THIS_SH` set to bash 5.2 and to
//!   the native interpreter; the drivers' output (their differences from the expected `.right` files) must match.
//!
//! The candidate shell is this binary itself under the name [`native::NATIVE_NAME`] ([`native`]). Every run is
//! confined by a Seatbelt sandbox with no network and writes only in its own fresh directory ([`run`]).
//!
//! # Boundaries
//!
//! A dev-only tool with one binary, `knsh-conformance`. It depends on `knsh-corpus`, `knsh-bash`, `knsh-interp` and
//! `knsh-platform`, and nothing may depend on it (enforced by `xtask/tests/dependency_policy.rs`). It runs corpus
//! lines for real, so it never runs one outside the sandbox. macOS only, as the platform backend it runs on.
//!
//! # Specification
//!
//! - `specs/07-testing/conformance.md` ("Phase 4 native mode")
//! - `specs/04-non-functional-requirements/compatibility.md`, NFR-COMPAT-02, NFR-COMPAT-05, NFR-COMPAT-07,
//!   NFR-COMPAT-11
//! - `specs/00-stories/KNSH-109-conformance-gate-bash-test-suite-oils-subset-99-corpus.md`

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

pub mod bash_suite;
pub mod corpus;
mod error;
pub mod known;
#[cfg(target_os = "macos")]
pub mod native;
pub mod observe;
pub mod oils;
pub mod report;
pub mod run;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub use error::ConformanceError;
pub use report::{Gate, MIN_CORPUS_PERCENT, Report};

/// A shell the suites run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    /// Its program.
    pub program: PathBuf,
    /// The first line of its `--version` output, or a description for the native interpreter.
    pub version: String,
}

impl Shell {
    /// Runs `program --version` and keeps the first line.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Shell`] when it cannot be run or prints no version.
    pub fn probe(program: &Path) -> Result<Self, ConformanceError> {
        let mut child = Command::new(program)
            .arg("--version")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ConformanceError::shell(program, format!("cannot start: {e}")))?;
        let mut output = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(64 * 1024).read_to_string(&mut output);
        }
        let status = child
            .wait()
            .map_err(|e| ConformanceError::shell(program, format!("cannot wait: {e}")))?;
        let version = output.lines().next().unwrap_or_default().trim().to_owned();
        if !status.success() || version.is_empty() {
            return Err(ConformanceError::shell(program, "`--version` gave no version"));
        }
        Ok(Self {
            program: program.to_owned(),
            version,
        })
    }

    /// The `major.minor` bash version this shell reports (`(5, 2)` for `GNU bash, version 5.2.37(1)-release`).
    #[must_use]
    pub fn bash_version(&self) -> Option<(u32, u32)> {
        let rest = self.version.split_once("bash, version ")?.1;
        let mut parts = rest.split(['.', '(', '-']);
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some((major, minor))
    }
}

/// What every suite needs: the shells, where runs happen, the deadline and the number of workers.
#[derive(Debug, Clone)]
pub struct Context {
    /// The reference: bash 5.2.
    pub reference: Shell,
    /// The candidate: the native interpreter.
    pub candidate: Shell,
    /// `/bin/bash` (3.2), for the corpus's version-difference list, when present.
    pub bash32: Option<Shell>,
    /// The directory under which every run gets its own directory.
    pub work: PathBuf,
    /// The deadline of one run.
    pub timeout: Duration,
    /// How many runs go on at once.
    pub jobs: usize,
}

impl Context {
    /// Checks that the reference is bash 5.2: the gate's contract is bash 5.2 (NFR-COMPAT-11), and measuring
    /// against another version would pass or fail lines for the wrong reasons.
    ///
    /// # Errors
    ///
    /// [`ConformanceError::Shell`] when the reference is not bash 5.2.
    pub fn check_reference(&self) -> Result<(), ConformanceError> {
        match self.reference.bash_version() {
            Some((5, 2)) => Ok(()),
            _ => Err(ConformanceError::shell(
                &self.reference.program,
                format!("the reference must be bash 5.2, not {:?}", self.reference.version),
            )),
        }
    }
}

/// Applies `work` to every item on `jobs` threads, keeping the order of `items`. The first error stops the
/// remaining work and is returned: a run is never partly measured.
///
/// # Errors
///
/// The first error `work` returned.
pub fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    jobs: usize,
    work: impl Fn(usize, &T) -> Result<R, ConformanceError> + Sync,
) -> Result<Vec<R>, ConformanceError> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    let failure: Mutex<Option<ConformanceError>> = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= items.len() || failure.lock().is_ok_and(|failure| failure.is_some()) {
                        break;
                    }
                    match work(index, &items[index]) {
                        Ok(result) => {
                            if let Ok(mut results) = results.lock() {
                                results[index] = Some(result);
                            }
                        }
                        Err(error) => {
                            if let Ok(mut failure) = failure.lock() {
                                failure.get_or_insert(error);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });
    if let Some(error) = failure.into_inner().ok().flatten() {
        return Err(error);
    }
    let results = results
        .into_inner()
        .map_err(|_| ConformanceError::Usage("a worker panicked".to_owned()))?;
    results
        .into_iter()
        .collect::<Option<Vec<R>>>()
        .ok_or_else(|| ConformanceError::Usage("a worker stopped before its work was done".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bash_version() {
        let shell = |version: &str| Shell {
            program: PathBuf::from("/bin/bash"),
            version: version.to_owned(),
        };
        assert_eq!(
            shell("GNU bash, version 5.2.37(1)-release (aarch64-apple-darwin25.6.0)").bash_version(),
            Some((5, 2))
        );
        assert_eq!(
            shell("GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)").bash_version(),
            Some((3, 2))
        );
        assert_eq!(shell("knsh native").bash_version(), None);
    }

    #[test]
    fn reference_must_be_bash_5_2() {
        let shell = |version: &str| Shell {
            program: PathBuf::from("/bin/bash"),
            version: version.to_owned(),
        };
        let mut context = Context {
            reference: shell("GNU bash, version 5.3.0(1)-release"),
            candidate: shell("knsh native"),
            bash32: None,
            work: PathBuf::from("/tmp"),
            timeout: Duration::from_secs(1),
            jobs: 1,
        };
        assert!(context.check_reference().is_err());
        context.reference = shell("GNU bash, version 5.2.37(1)-release");
        assert!(context.check_reference().is_ok());
    }

    #[test]
    fn parallel_map_keeps_order_and_stops_on_error() {
        let items: Vec<usize> = (0..50).collect();
        assert_eq!(
            parallel_map(&items, 4, |_, n| Ok(n * 2)).unwrap(),
            items.iter().map(|n| n * 2).collect::<Vec<_>>()
        );
        let failed = parallel_map(&items, 4, |_, n| {
            if *n == 7 {
                Err(ConformanceError::Usage("seven".into()))
            } else {
                Ok(*n)
            }
        });
        assert!(matches!(failed, Err(ConformanceError::Usage(message)) if message == "seven"));
        assert_eq!(
            parallel_map(&Vec::<usize>::new(), 4, |_, n| Ok(*n)).unwrap(),
            Vec::<usize>::new()
        );
    }
}
