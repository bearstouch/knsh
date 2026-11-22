//! The bash test suite: the `tests/run-*` drivers of the pinned bash 5.2 source (`scripts/conformance.sh`).
//!
//! Each driver runs its `.tests` scripts with `${THIS_SH}` and prints how their output differs from the expected
//! `.right` files (bash's own rule: "any output from any test indicates a possible anomaly"). Every driver is run
//! twice, as `run-all` runs it (`sh run-X`, from a fresh copy of the `tests` directory that also holds the
//! `recho`, `zecho`, `printenv` and `xcase` helpers): with `THIS_SH` naming bash 5.2, and naming the native
//! interpreter. A driver passes when both runs print the same and end the same, so a test that is not clean even for
//! bash 5.2 on this host (a locale it lacks) does not count against the native interpreter. `run-all`,
//! `run-minimal` and `run-gprof` are not tests.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::observe::{Aspects, Difference, Observation, Volatility, compare};
use crate::run::{Invocation, RunDir, execute};
use crate::{ConformanceError, Context, Shell, parallel_map};

/// A driver runs many scripts: its deadline is this many times the per-run deadline (120 s for the default 10 s).
const DRIVER_TIMEOUT_FACTOR: u32 = 12;

/// Drivers that are not tests.
const NOT_TESTS: [&str; 3] = ["run-all", "run-minimal", "run-gprof"];

/// Every test driver in `tests`, sorted.
///
/// # Errors
///
/// [`ConformanceError::Io`] when the directory cannot be read.
pub fn drivers(tests: &Path) -> Result<Vec<String>, ConformanceError> {
    let mut drivers: Vec<String> = fs::read_dir(tests)
        .map_err(|e| ConformanceError::io(tests, e))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            name.starts_with("run-")
                && !NOT_TESTS.contains(&name.as_str())
                && !Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("orig"))
                && !name.ends_with('~')
        })
        .collect();
    drivers.sort();
    Ok(drivers)
}

/// The outcome of one driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverResult {
    /// The driver's name (`run-arith`).
    pub driver: String,
    /// Whether bash 5.2 itself runs it clean (no output, status 0).
    pub reference_clean: bool,
    /// How the native interpreter's run differs from bash 5.2's; empty when it passes.
    pub differences: Vec<Difference>,
}

fn run_driver(
    context: &Context,
    tests: &Path,
    shell: &Shell,
    driver: &str,
    name: &str,
) -> Result<Observation, ConformanceError> {
    let run = RunDir::create(&context.work, name, Some(tests))?;
    let work = run.work();
    let mut path = work.clone().into_os_string();
    path.push(":/usr/bin:/bin");
    let env: Vec<(OsString, OsString)> = vec![
        ("PATH".into(), path),
        ("THIS_SH".into(), shell.program.clone().into_os_string()),
        ("BUILD_DIR".into(), work.clone().into_os_string()),
        ("BASH_TSTOUT".into(), run.tmp().join("bashtst").into_os_string()),
        ("TMPDIR".into(), run.tmp().into_os_string()),
        ("HOME".into(), run.home().into_os_string()),
    ];
    let invocation = Invocation {
        program: "/bin/sh".into(),
        args: vec![driver.into()],
        cwd: work,
        env,
        stdin: None,
        timeout: context.timeout.saturating_mul(DRIVER_TIMEOUT_FACTOR),
        run_dir: run.root().to_owned(),
    };
    let captured = execute(&invocation)?;
    let observation = run.observe(captured, false)?;
    run.remove()?;
    Ok(observation)
}

/// Runs every driver with bash 5.2 and with the native interpreter and compares them.
///
/// # Errors
///
/// The first run that could not be prepared or started.
pub fn run(drivers: &[String], context: &Context, tests: &Path) -> Result<Vec<DriverResult>, ConformanceError> {
    parallel_map(drivers, context.jobs, |index, driver| {
        let bash = run_driver(context, tests, &context.reference, driver, &format!("b{index}-bash52"))?;
        let knsh = run_driver(context, tests, &context.candidate, driver, &format!("b{index}-knsh"))?;
        Ok(DriverResult {
            driver: driver.clone(),
            reference_clean: bash.stdout.is_empty() && bash.ending == crate::observe::Ending::Exited(0),
            differences: compare(&bash, &knsh, &Volatility::none(), Aspects::STATUS_AND_STDOUT),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_test_drivers_only() {
        let dir = std::env::temp_dir().join(format!("knsh-conformance-drivers-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for name in [
            "run-arith",
            "run-all",
            "run-minimal",
            "run-gprof",
            "run-array",
            "run-x.orig",
            "arith.tests",
        ] {
            fs::write(dir.join(name), "").unwrap();
        }
        assert_eq!(
            drivers(&dir).unwrap(),
            vec!["run-arith".to_owned(), "run-array".to_owned()]
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
