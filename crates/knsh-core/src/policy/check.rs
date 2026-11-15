//! Dry runs: what policy would decide for a line, without running it (KNSH-043; FR-POL-70).
//!
//! [`check_line`] is the whole decision path short of running anything: parse the line, resolve each command name
//! against the caller's `PATH` and working directory ([`LineResolver`], KNSH-035), classify it with the profile's
//! interpreter table (KNSH-036), and decide it with [`evaluate_line`] (KNSH-041). It is pure: the filesystem is
//! reached only through [`BinaryLookup`], read-only, so a dry run writes nothing, emits nothing and spawns nothing.
//!
//! Hooks, the authority and grants are not consulted: the answer is what the profile's rules say. A line the rules
//! would ask about is reported as `ask`, even if a live grant or the authority would later allow it.
//!
//! # `source`
//!
//! A file read by `source` or `.` is trusted only when it is outside every write root of the session and in a
//! trusted location (FR-LC-05). The write roots are the supervisor's (KNSH-050); until then [`LineResolver`] trusts
//! no sourced file, so every `source` is reported as dynamic code. This only ever errs towards a stricter answer.

use knsh_bash::{Classification, Lookup, Program, Resolver, SourceFile, classify, parse_line};

use super::line::{LineDecision, evaluate_line};
use super::model::Profile;
use crate::path::CanonicalPath;
use crate::resolve::{BinaryLookup, CommandName, Resolution, TrustedFolders, resolve};

/// Resolves command names as bash would run them for one caller: its `PATH`, its working directory and the
/// profile's trusted folders, through a read-only [`BinaryLookup`]. The bridge from [`resolve`] (KNSH-035) to the
/// classifier's [`Resolver`].
pub struct LineResolver<'a, L: ?Sized> {
    env_path: &'a str,
    cwd: &'a CanonicalPath,
    trusted: &'a TrustedFolders,
    lookup: &'a L,
}

impl<'a, L: BinaryLookup + ?Sized> LineResolver<'a, L> {
    /// A resolver searching `env_path` (a `PATH` value) from `cwd`, trusting the binaries in `trusted`.
    #[must_use]
    pub const fn new(env_path: &'a str, cwd: &'a CanonicalPath, trusted: &'a TrustedFolders, lookup: &'a L) -> Self {
        Self {
            env_path,
            cwd,
            trusted,
            lookup,
        }
    }
}

impl<L: BinaryLookup + ?Sized> Resolver for LineResolver<'_, L> {
    fn resolve(&self, name: &str, lookup: Lookup) -> Program {
        let name = match lookup {
            Lookup::Shell => CommandName::Lookup(name),
            // A wrapper program or `exec` runs its command with `execvp`, which never reaches a builtin.
            Lookup::Program => CommandName::Program(name),
        };
        match resolve(name, self.env_path, self.cwd, self.trusted, self.lookup) {
            Resolution::Trusted(path) => Program::Trusted(path.into_path_buf()),
            Resolution::ProjectExecutable(path) => Program::ProjectExecutable(path.into_path_buf()),
            Resolution::Builtin => Program::Builtin,
            // Only `CommandName::Function` resolves to a function, and the classifier never asks for one (function
            // calls are marked by the parser). Should it happen, nothing is run: the line fails with 127.
            Resolution::Function | Resolution::NotFound => Program::NotFound,
        }
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        // Fail closed until the session's write roots are known (module documentation, "`source`").
        SourceFile::Unresolved
    }
}

/// A line checked against a profile: how it was classified and what the rules decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineCheck {
    /// Every command of the line, its class, and the line's dynamic parts.
    pub classification: Classification,
    /// The verdict, the deciding rule, every matched rule and what the line could receive.
    pub decision: LineDecision,
}

/// Decides `line` against `profile` without running it (module documentation): names are resolved on `env_path` (the
/// caller's `PATH`) from `cwd`, against the profile's trusted folders, through `lookup`.
///
/// Pure and total, like [`evaluate_line`]: a line the parser cannot read is dynamic code and decided as such, and an
/// evaluation that fails is a deny.
#[must_use]
pub fn check_line<L: BinaryLookup + ?Sized>(
    profile: &Profile,
    line: &str,
    env_path: &str,
    cwd: &CanonicalPath,
    lookup: &L,
) -> LineCheck {
    let resolver = LineResolver::new(env_path, cwd, &profile.exec.trusted_folders, lookup);
    let classification = classify(&parse_line(line), line, &resolver, &profile.exec.interpreters);
    let decision = evaluate_line(profile, &classification);
    LineCheck {
        classification,
        decision,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use knsh_bash::{CommandClass, DynamicReason};

    use super::*;
    use crate::policy::paths::testing::FakeFs;
    use crate::policy::{
        DecisionSource, LookupError, PathContext, ProfileSource, RuleAction, RuleId, load_profile_text,
    };
    use crate::session::ProfileName;

    /// Executable files by canonical path; nothing is a symlink.
    struct Binaries(BTreeSet<PathBuf>);

    impl BinaryLookup for Binaries {
        fn canonicalise(&self, path: &Path) -> Option<CanonicalPath> {
            // `./x` is joined onto the working directory as `cwd/./x`; drop the `.` as `realpath` would.
            let path: PathBuf = path
                .components()
                .filter(|part| *part != std::path::Component::CurDir)
                .collect();
            self.0.contains(&path).then(|| CanonicalPath::new(path).ok()).flatten()
        }

        fn is_executable_file(&self, path: &CanonicalPath) -> bool {
            self.0.contains(path.as_path())
        }
    }

    fn binaries() -> Binaries {
        Binaries(
            [
                "/usr/bin/git",
                "/usr/bin/env",
                "/bin/ls",
                "/bin/echo",
                "/bin/bash",
                "/Users/u/app/run.sh",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        )
    }

    struct NoParents;

    impl ProfileSource for NoParents {
        fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
            Err(LookupError::NotFound)
        }
    }

    fn profile(text: &str) -> Profile {
        let mut fs = FakeFs::new();
        fs.add("/Users/u/app").add("/tmp").add("/bin/bash");
        let context = PathContext {
            home: PathBuf::from("/Users/u"),
            tmpdir: PathBuf::from("/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        let text = format!("name = \"t\"\n{text}");
        load_profile_text(text.as_bytes(), &NoParents, &context, &fs).unwrap()
    }

    fn check(profile: &Profile, line: &str) -> LineCheck {
        let cwd = CanonicalPath::new("/Users/u/app").unwrap();
        check_line(profile, line, "/usr/bin:/bin", &cwd, &binaries())
    }

    // FR-POL-70: `git push` asked by the profile is reported as `ask`, named by its rule.
    #[test]
    fn asks_for_git_push_by_its_rule() {
        let profile = profile("[exec]\nallow = [\"git status\"]\nask = [\"git push\"]\n");
        let check = check(&profile, "git push origin main");
        assert_eq!(check.decision.verdict, RuleAction::Ask);
        assert_eq!(check.decision.source, DecisionSource::Rule);
        assert_eq!(check.decision.rule_id, Some(RuleId::Ask(0)));
        let [command] = check.classification.commands() else {
            panic!("one command");
        };
        assert_eq!(command.class, CommandClass::Static);
        assert_eq!(command.program, Some(Program::Trusted(PathBuf::from("/usr/bin/git"))));
    }

    // FR-POL-20: interpreter code is dynamic, and the reason is reported.
    #[test]
    fn reports_interpreter_code_as_dynamic() {
        let profile = profile("[exec]\nallow = [\"bash\"]\ndefault = \"deny\"\n");
        let check = check(&profile, "bash -c \"$x\"");
        assert!(check.decision.capabilities.dynamic);
        assert_eq!(
            check.classification.commands()[0].class.dynamic_reason(),
            Some(DynamicReason::InterpreterCode)
        );
    }

    // A name found outside the trusted folders is a project executable, and a wrapper's program skips builtins.
    #[test]
    fn resolves_against_path_cwd_and_trusted_folders() {
        let profile = profile("");
        let check = check(&profile, "./run.sh; env echo hi; missing");
        let found: Vec<_> = check
            .classification
            .commands()
            .iter()
            .map(|command| (command.name.as_deref(), command.program.clone()))
            .collect();
        assert_eq!(
            found,
            [
                (
                    Some("./run.sh"),
                    Some(Program::ProjectExecutable(PathBuf::from("/Users/u/app/run.sh")))
                ),
                (Some("env"), Some(Program::Trusted(PathBuf::from("/usr/bin/env")))),
                (Some("echo"), Some(Program::Trusted(PathBuf::from("/bin/echo")))),
                (Some("missing"), Some(Program::NotFound)),
            ]
        );
    }

    // FR-LC-05, fail closed: without the session's write roots, no sourced file is trusted.
    #[test]
    fn sourced_files_are_dynamic_until_write_roots_are_known() {
        let profile = profile("");
        let check = check(&profile, "source /bin/ls");
        assert!(
            check
                .classification
                .dynamic_parts()
                .iter()
                .any(|part| part.reason == DynamicReason::Source)
        );
    }
}
