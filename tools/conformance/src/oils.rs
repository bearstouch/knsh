//! The Oils subset: the bash-compatible cases of the Oils project's cross-shell spec tests (`spec/*.test.sh` of a
//! pinned checkout, `scripts/conformance.sh`).
//!
//! A spec file is bash-compatible when its `## compare_shells:` line names `bash`. In such a file every case
//! (`#### name`, up to the next one) is in the subset except those the file marks as not implemented by bash
//! (`## N-I bash …`). A case's code is its lines without the `##` assertions and their `## STDOUT:` … `## END`
//! blocks.
//!
//! Each case runs as the Oils runner (`test/sh_spec.py`) runs it: the code on standard input of the shell, in a
//! fresh directory that is also `$TMP`, with `SH` naming the shell under test, `REPO_ROOT` the checkout, `PATH` its
//! `spec/bin` helpers then `/usr/bin:/bin`, and `LC_ALL=C.UTF-8`. Status and standard output are compared with
//! bash 5.2's, which is what the spec files assert; the files' own expectations are not read.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::observe::{Aspects, Difference, Volatility, compare};
use crate::run::{Invocation, RunDir, execute};
use crate::{ConformanceError, Context, Shell, parallel_map};

/// One case of the subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OilsCase {
    /// The spec file's stem (`arith` for `arith.test.sh`): the failure category.
    pub file: String,
    /// The case's name.
    pub name: String,
    /// The code the shell runs.
    pub code: String,
}

/// What one spec file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFile {
    /// Whether its `## compare_shells:` line names `bash`.
    pub compares_bash: bool,
    /// Every case, with whether the file marks it as not implemented by bash.
    pub cases: Vec<(String, String, bool)>,
}

/// Reads a spec file's cases.
#[must_use]
pub fn parse_spec(text: &str) -> SpecFile {
    let mut compares_bash = false;
    let mut cases: Vec<(String, String, bool)> = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        if in_block {
            in_block = line.trim_end() != "## END";
            continue;
        }
        if let Some(name) = line.strip_prefix("####") {
            cases.push((name.trim().to_owned(), String::new(), false));
            continue;
        }
        if let Some(assertion) = line.strip_prefix("## ") {
            let assertion = assertion.trim_end();
            if let Some(shells) = assertion.strip_prefix("compare_shells:") {
                compares_bash = shells.split_whitespace().any(|shell| shell == "bash");
            } else if let Some(rest) = assertion.strip_prefix("N-I ") {
                let shells = rest.split_whitespace().next().unwrap_or_default();
                if let Some(case) = cases.last_mut() {
                    case.2 |= shells.split('/').any(|shell| shell == "bash");
                }
            }
            in_block = assertion.ends_with("STDOUT:") || assertion.ends_with("STDERR:");
            continue;
        }
        if let Some(case) = cases.last_mut() {
            case.1.push_str(line);
            case.1.push('\n');
        }
    }
    SpecFile { compares_bash, cases }
}

/// The subset: every case of every bash-compatible spec file under `checkout/spec`, in file order.
///
/// # Errors
///
/// [`ConformanceError::Io`] when the directory or a file cannot be read.
pub fn load(checkout: &Path) -> Result<Vec<OilsCase>, ConformanceError> {
    let spec = checkout.join("spec");
    let mut files: Vec<PathBuf> = fs::read_dir(&spec)
        .map_err(|e| ConformanceError::io(&spec, e))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".test.sh"))
        .collect();
    files.sort();
    let mut cases = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path).map_err(|e| ConformanceError::io(&path, e))?;
        let parsed = parse_spec(&text);
        if !parsed.compares_bash {
            continue;
        }
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().trim_end_matches(".test.sh").to_owned())
            .unwrap_or_default();
        cases.extend(
            parsed
                .cases
                .into_iter()
                .filter(|(_, _, not_in_bash)| !not_in_bash)
                .map(|(name, code, _)| OilsCase {
                    file: file.clone(),
                    name,
                    code,
                }),
        );
    }
    Ok(cases)
}

/// How the native interpreter differs from bash 5.2 on `case`; empty when it behaves the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// The case.
    pub case: OilsCase,
    /// The differences.
    pub differences: Vec<Difference>,
}

fn run_case(
    context: &Context,
    checkout: &Path,
    shell: &Shell,
    case: &OilsCase,
    name: &str,
) -> Result<crate::observe::Observation, ConformanceError> {
    let run = RunDir::create(&context.work, name, None)?;
    let spec_bin = checkout.join("spec/bin");
    let mut path = spec_bin.into_os_string();
    path.push(":/usr/bin:/bin");
    let env: Vec<(OsString, OsString)> = vec![
        ("PATH".into(), path),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("SH".into(), shell.program.clone().into_os_string()),
        ("REPO_ROOT".into(), checkout.as_os_str().to_owned()),
        ("TMP".into(), run.work().into_os_string()),
        ("HOME".into(), run.home().into_os_string()),
    ];
    let invocation = Invocation {
        program: shell.program.clone(),
        args: Vec::new(),
        cwd: run.work(),
        env,
        stdin: Some(case.code.clone().into_bytes()),
        timeout: context.timeout,
        run_dir: run.root().to_owned(),
    };
    let captured = execute(&invocation)?;
    let observation = run.observe(captured, false)?;
    run.remove()?;
    Ok(observation)
}

/// Runs every case under bash 5.2 and the native interpreter and compares them.
///
/// # Errors
///
/// The first run that could not be prepared or started.
pub fn run(cases: &[OilsCase], context: &Context, checkout: &Path) -> Result<Vec<CaseResult>, ConformanceError> {
    parallel_map(cases, context.jobs, |index, case| {
        let bash = run_case(context, checkout, &context.reference, case, &format!("o{index}-bash52"))?;
        let knsh = run_case(context, checkout, &context.candidate, case, &format!("o{index}-knsh"))?;
        Ok(CaseResult {
            case: case.clone(),
            differences: compare(&bash, &knsh, &Volatility::none(), Aspects::STATUS_AND_STDOUT),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "## compare_shells: dash bash mksh\n\
                        ## oils_failures_allowed: 1\n\
                        \n\
                        #### Add one\n\
                        i=1\n\
                        echo $((i+1))\n\
                        ## stdout: 2\n\
                        \n\
                        #### Block output\n\
                        echo a\n\
                        # a comment stays code\n\
                        ## STDOUT:\n\
                        a\n\
                        ## END\n\
                        ## N-I dash STDOUT:\n\
                        b\n\
                        ## END\n\
                        #### Not in bash\n\
                        echo ${x@P}\n\
                        ## N-I bash/zsh status: 1\n";

    #[test]
    fn reads_cases_without_assertions() {
        let spec = parse_spec(SPEC);
        assert!(spec.compares_bash);
        assert_eq!(
            spec.cases,
            vec![
                ("Add one".to_owned(), "i=1\necho $((i+1))\n\n".to_owned(), false),
                (
                    "Block output".to_owned(),
                    "echo a\n# a comment stays code\n".to_owned(),
                    false
                ),
                ("Not in bash".to_owned(), "echo ${x@P}\n".to_owned(), true),
            ]
        );
        assert!(!parse_spec("## compare_shells: dash mksh\n#### x\necho\n").compares_bash);
        assert!(!parse_spec("## compare_shells: bash-4.4 zsh\n").compares_bash);
    }

    #[test]
    fn loads_only_bash_compatible_files_and_cases() {
        let dir = std::env::temp_dir().join(format!("knsh-conformance-oils-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("spec")).unwrap();
        fs::write(dir.join("spec/arith.test.sh"), SPEC).unwrap();
        fs::write(
            dir.join("spec/ysh-x.test.sh"),
            "## compare_shells: dash\n#### a\necho\n",
        )
        .unwrap();
        fs::write(dir.join("spec/README.md"), "#### not a spec\n").unwrap();
        let cases = load(&dir).unwrap();
        let names: Vec<_> = cases
            .iter()
            .map(|case| (case.file.as_str(), case.name.as_str()))
            .collect();
        assert_eq!(names, vec![("arith", "Add one"), ("arith", "Block output")]);
        fs::remove_dir_all(dir).unwrap();
    }
}
