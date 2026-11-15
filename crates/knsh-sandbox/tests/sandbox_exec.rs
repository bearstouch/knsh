//! Compiled file rules under the real kernel (KNSH-044 integration test; FR-SBX-01, FR-SBX-02, FR-SBX-10).
//!
//! A test home and project live in a temporary directory, which is the profile's only write root, so every write
//! refused below is refused by a fixed or `fs.deny` rule, not by the default deny. The commands run through
//! `/usr/bin/sandbox-exec -f`, as `knsh-exec` will run them. File rules alone cannot start a process, so the test
//! appends `(allow process-exec process-fork)`: executables are KNSH-045's, and the extra line allows no file access.

#![cfg(target_os = "macos")]
// Test helpers outside `#[test]` functions: a failed step should stop the test.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use knsh_core::{
    CanonicalPath, FixedDenies, LookupError, PathContext, PolicyFs, ProfileName, ProfileSource, RecordId, SessionId,
    Ulid, load_profile_text,
};
use knsh_sandbox::{CommandTag, ProfileInput, compile};

/// The real filesystem, as the loader sees it.
struct RealPaths;

impl PolicyFs for RealPaths {
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, LookupError> {
        let resolved = std::fs::canonicalize(path).map_err(|_| LookupError::NotFound)?;
        CanonicalPath::new(resolved).map_err(|_| LookupError::Failed)
    }
}

struct NoParents;

impl ProfileSource for NoParents {
    fn read_profile(&self, _name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        Err(LookupError::NotFound)
    }
}

/// A temporary directory, canonical, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("knsh-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        Self(std::fs::canonicalize(base).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `script` under `profile` with `/bin/sh`, its operands as `$1`, `$2`, …; whether it succeeded.
fn run(profile: &Path, script: &str, operands: &[&Path]) -> bool {
    Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(profile)
        .args(["/bin/sh", "-c", script, "sh"])
        .args(operands)
        .output()
        .unwrap()
        .status
        .success()
}

// KNSH-044: under the compiled profile, writing `${PROJECT}/.git/hooks/pre-commit` and `~/.zshrc` fails, writing
// `${PROJECT}/src/x` succeeds; so do the other fixed denies, the engine paths and `fs.deny`.
#[test]
fn compiled_file_rules_hold_under_sandbox_exec() {
    let dir = TempDir::new();
    let home = dir.0.join("home");
    let project = home.join("app");
    // The engine directories, from the one source of their location (no path literals here).
    let canonical_home = CanonicalPath::new(home.clone()).unwrap();
    let denies = FixedDenies::for_home(&canonical_home);
    let [engine_data, engine_config] = denies.paths() else {
        panic!("two engine directories");
    };
    let (engine_data, engine_config) = (engine_data.as_path(), engine_config.as_path());
    for path in [
        project.join("src"),
        project.join(".git/hooks"),
        home.join(".ssh"),
        home.join("Library/LaunchAgents"),
        engine_data.to_path_buf(),
        engine_config.to_path_buf(),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(engine_config.join("policy.toml"), "engine").unwrap();
    std::fs::write(home.join("secret"), "secret").unwrap();

    let write_root = dir.0.to_str().unwrap();
    let text = format!("name = \"t\"\n[fs]\nwrite = [\"{write_root}\"]\ndeny = [\"~/secret\"]\n");
    let context = PathContext {
        home: home.clone(),
        tmpdir: dir.0.clone(),
        start_dir: project.clone(),
    };
    let profile = load_profile_text(text.as_bytes(), &NoParents, &context, &RealPaths).unwrap();
    let mut sbpl = compile(&ProfileInput {
        session: SessionId::from_ulid(Ulid::from_u128(1)),
        command: CommandTag::Line(RecordId::from_ulid(Ulid::from_u128(2))),
        profile: &profile,
        home: &canonical_home,
    })
    .into_bytes();
    sbpl.extend_from_slice(b"(allow process-exec process-fork)\n");
    let profile_file = dir.0.join("profile.sb");
    std::fs::write(&profile_file, sbpl).unwrap();

    let write = "echo x > \"$1\"";
    let allowed = |path: PathBuf| assert!(run(&profile_file, write, &[&path]), "{} not writable", path.display());
    let refused = |path: PathBuf| assert!(!run(&profile_file, write, &[&path]), "{} writable", path.display());

    allowed(project.join("src/x"));
    allowed(project.join(".git/HEAD"));
    refused(project.join(".git/hooks/pre-commit"));
    refused(project.join(".git/config"));
    refused(home.join(".zshrc"));
    refused(home.join(".zshenv"));
    refused(home.join(".ssh/authorized_keys"));
    refused(home.join("Library/LaunchAgents/evil.plist"));
    refused(engine_config.join("policy.toml"));
    refused(engine_data.join("records.db"));

    // A planted git directory cannot be renamed into place, and the real one cannot be moved away.
    let plant = "mkdir -p \"$1/hooks\" && echo x > \"$1/hooks/pre-commit\" && mkdir -p \"$2\" && mv \"$1\" \"$2/.git\"";
    assert!(!run(
        &profile_file,
        plant,
        &[&project.join("evil"), &project.join("sub")]
    ));
    assert!(!run(
        &profile_file,
        "mv \"$1\" \"$2\"",
        &[&project.join(".git"), &project.join(".git-old")]
    ));

    // Git takes hooks and configuration from the directory `commondir` names and from submodule git directories;
    // neither can be written, and a submodule git directory cannot be renamed out of `.git` and back.
    refused(project.join(".git/commondir"));
    std::fs::create_dir_all(project.join(".git/modules/lib/hooks")).unwrap();
    refused(project.join(".git/modules/lib/config"));
    refused(project.join(".git/modules/lib/hooks/post-checkout"));
    allowed(project.join(".git/modules/lib/index"));
    assert!(!run(
        &profile_file,
        "mv \"$1\" \"$2\"",
        &[&project.join(".git/modules/lib"), &project.join("lib-git")]
    ));

    // A directory above an engine path, a fixed deny or `fs.deny` cannot be renamed away (and its contents edited
    // at the new place); files inside it can still be created.
    let engine_parent = engine_config.parent().unwrap();
    for ancestor in [engine_parent, &home.join("Library"), &home] {
        let moved = ancestor.with_extension("moved");
        assert!(
            !run(&profile_file, "mv \"$1\" \"$2\"", &[ancestor, &moved]),
            "{} renamable",
            ancestor.display()
        );
    }
    allowed(engine_parent.join("other"));
    allowed(home.join("Library/other"));

    // Engine files and `fs.deny` are unreadable too; other files are readable.
    let read = "cat \"$1\" > /dev/null";
    assert!(!run(&profile_file, read, &[&engine_config.join("policy.toml")]));
    assert!(!run(&profile_file, read, &[&home.join("secret")]));
    assert!(run(&profile_file, read, &[&project.join("src/x")]));
}
