//! Binary lookup over the filesystem trait (KNSH-035; FR-LC-03, FR-POL-11).
//!
//! [`knsh_core::resolve`] is pure and reaches the filesystem only through [`knsh_core::BinaryLookup`]. This module
//! implements that trait for every [`Fs`], so the supervisor resolves against the real filesystem (`RealFs`) and
//! tests against the in-memory fake (`MemFs`), with the same code. Pass the filesystem as `&dyn Fs`.

use std::path::Path;

use knsh_core::{BinaryLookup, CanonicalPath};

use crate::fs::{FileKind, Fs};

/// Any execute bit (owner, group or other). Bash checks execute access for the current user; a file executable only
/// by someone else is still taken here, and running it then fails with 126, as bash reports for it.
const ANY_EXECUTE: u32 = 0o111;

impl BinaryLookup for dyn Fs + '_ {
    fn canonicalise(&self, path: &Path) -> Option<CanonicalPath> {
        // Every error counts as "not here": bash skips a PATH entry it cannot use, and `NotFound` fails the line.
        Fs::canonicalise(self, path).ok()
    }

    fn is_executable_file(&self, path: &CanonicalPath) -> bool {
        // `metadata` does not follow a final symlink, which is why callers pass the canonical path: it has none.
        self.metadata(path.as_path())
            .is_ok_and(|metadata| metadata.kind == FileKind::File && metadata.mode & ANY_EXECUTE != 0)
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::{CommandName, Resolution, TrustedFolders, resolve};

    use super::*;
    use crate::Operation;
    use crate::testing::MemFs;

    const PATH: &str = "/usr/local/bin:/usr/bin:/bin";

    fn canonical(path: &str) -> CanonicalPath {
        CanonicalPath::new(path).unwrap()
    }

    /// A fake filesystem with the trusted folders and a project at `/work/project`.
    fn fs() -> MemFs {
        let fs = MemFs::new();
        for dir in [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
            "/work/project/node_modules/.bin",
            "/work/project/scripts",
        ] {
            fs.add_dir_all(Path::new(dir)).unwrap();
        }
        fs
    }

    fn add_binary(fs: &MemFs, path: &str) {
        fs.write(Path::new(path), b"#!/bin/sh\n", 0o755).unwrap();
    }

    fn resolve_in(fs: &MemFs, name: &str, env_path: &str, trusted: &TrustedFolders) -> Resolution {
        let fs: &dyn Fs = fs;
        resolve(
            CommandName::Lookup(name),
            env_path,
            &canonical("/work/project"),
            trusted,
            fs,
        )
    }

    // FR-POL-13: a name rule such as `git` may match a binary resolved from a trusted folder.
    #[test]
    fn resolves_git_from_usr_bin_as_trusted() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/git");
        assert_eq!(
            resolve_in(&fs, "git", PATH, &TrustedFolders::defaults()),
            Resolution::Trusted(canonical("/usr/bin/git"))
        );
    }

    // FR-POL-14: a binary from an agent-writable place is a project executable, even invoked by bare name and even
    // when it shadows a trusted binary of the same name.
    #[test]
    fn classifies_node_modules_bin_as_project_executable() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/git");
        add_binary(&fs, "/work/project/node_modules/.bin/git");
        let path = format!("node_modules/.bin:{PATH}");
        assert_eq!(
            resolve_in(&fs, "git", &path, &TrustedFolders::defaults()),
            Resolution::ProjectExecutable(canonical("/work/project/node_modules/.bin/git"))
        );
        let path = format!("/work/project/node_modules/.bin:{PATH}");
        assert_eq!(
            resolve_in(&fs, "git", &path, &TrustedFolders::defaults()),
            Resolution::ProjectExecutable(canonical("/work/project/node_modules/.bin/git"))
        );
    }

    // FR-POL-11: a symlink in a trusted folder is classified by its canonical target, not by where the link sits.
    #[test]
    fn follows_symlink_to_canonical_target_outside_trusted() {
        let fs = fs();
        add_binary(&fs, "/work/project/scripts/deploy");
        fs.add_symlink(
            Path::new("/usr/local/bin/deploy"),
            Path::new("/work/project/scripts/deploy"),
        )
        .unwrap();
        assert_eq!(
            resolve_in(&fs, "deploy", PATH, &TrustedFolders::defaults()),
            Resolution::ProjectExecutable(canonical("/work/project/scripts/deploy"))
        );
        // A link to a binary in another trusted folder stays trusted, under its target's path.
        add_binary(&fs, "/bin/ls");
        fs.add_symlink(Path::new("/usr/local/bin/ls"), Path::new("../../../bin/ls"))
            .unwrap();
        assert_eq!(
            resolve_in(&fs, "ls", PATH, &TrustedFolders::defaults()),
            Resolution::Trusted(canonical("/bin/ls"))
        );
    }

    // FR-LC-03: a name with `/` is a path relative to the working directory, canonicalised, never searched on PATH.
    #[test]
    fn relative_path_command_resolved_against_cwd() {
        let fs = fs();
        add_binary(&fs, "/work/project/scripts/x");
        add_binary(&fs, "/usr/bin/x");
        for name in [
            "./scripts/x",
            "scripts/x",
            "scripts/../scripts/./x",
            "/work/project/scripts/x",
        ] {
            assert_eq!(
                resolve_in(&fs, name, PATH, &TrustedFolders::defaults()),
                Resolution::ProjectExecutable(canonical("/work/project/scripts/x")),
                "{name}"
            );
        }
        // A path out of the project into a trusted folder is trusted by where it lands.
        assert_eq!(
            resolve_in(&fs, "../../usr/bin/x", PATH, &TrustedFolders::defaults()),
            Resolution::Trusted(canonical("/usr/bin/x"))
        );
        // A path name is run as written: a builtin's name with `/` is not the builtin.
        assert_eq!(
            resolve_in(&fs, "./cd", PATH, &TrustedFolders::defaults()),
            Resolution::NotFound
        );
    }

    // FR-LC-03: builtins run inside bash and are never looked up, even with a binary of the same name on PATH.
    #[test]
    fn builtins_are_not_resolved_on_path() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/cd");
        add_binary(&fs, "/work/project/node_modules/.bin/export");
        let path = format!("node_modules/.bin:{PATH}");
        for name in ["cd", "export", "echo", "[", "."] {
            assert_eq!(
                resolve_in(&fs, name, &path, &TrustedFolders::defaults()),
                Resolution::Builtin,
                "{name}"
            );
        }
    }

    // FR-LC-03: a program run by a wrapper or `exec` is looked up as `execvp` does, so a builtin's name finds the
    // binary on PATH (`env echo` runs `/bin/echo`), and a name with no binary is not found rather than a builtin.
    #[test]
    fn program_lookup_skips_builtins() {
        let fs = fs();
        add_binary(&fs, "/bin/echo");
        let fs: &dyn Fs = &fs;
        let program = |name| {
            resolve(
                CommandName::Program(name),
                PATH,
                &canonical("/work/project"),
                &TrustedFolders::defaults(),
                fs,
            )
        };
        assert_eq!(program("echo"), Resolution::Trusted(canonical("/bin/echo")));
        assert_eq!(program("cd"), Resolution::NotFound);
    }

    // FR-POL-13: folders the profile adds are trusted like the defaults; without them the same binary is not.
    #[test]
    fn profile_added_trusted_folder_is_honoured() {
        let fs = fs();
        fs.add_dir_all(Path::new("/nix/var/profile/bin")).unwrap();
        add_binary(&fs, "/nix/var/profile/bin/jq");
        let path = format!("/nix/var/profile/bin:{PATH}");
        assert_eq!(
            resolve_in(&fs, "jq", &path, &TrustedFolders::defaults()),
            Resolution::ProjectExecutable(canonical("/nix/var/profile/bin/jq"))
        );
        let mut trusted = TrustedFolders::defaults();
        trusted.add(canonical("/nix/var/profile/bin"));
        assert_eq!(
            resolve_in(&fs, "jq", &path, &trusted),
            Resolution::Trusted(canonical("/nix/var/profile/bin/jq"))
        );
    }

    // FR-LC-03: nothing found is carried through as NotFound (127), never allowed as unknown.
    #[test]
    fn missing_binary_is_not_found() {
        let fs = fs();
        let trusted = TrustedFolders::defaults();
        assert_eq!(resolve_in(&fs, "nope", PATH, &trusted), Resolution::NotFound);
        assert_eq!(resolve_in(&fs, "./nope", PATH, &trusted), Resolution::NotFound);
        assert_eq!(resolve_in(&fs, "/usr/bin/nope", PATH, &trusted), Resolution::NotFound);
        assert_eq!(resolve_in(&fs, "", PATH, &trusted), Resolution::NotFound);
        assert_eq!(resolve_in(&fs, "nope", "", &trusted), Resolution::NotFound);
    }

    // Bash takes the first PATH entry holding an executable regular file: directories, non-executable files,
    // dangling links and entries that fail to resolve are skipped.
    #[test]
    fn path_search_skips_unusable_candidates() {
        let fs = fs();
        fs.add_dir_all(Path::new("/usr/local/bin/tool")).unwrap();
        fs.write(Path::new("/usr/bin/tool"), b"data", 0o644).unwrap();
        fs.add_symlink(Path::new("/work/project/scripts/tool"), Path::new("/gone"))
            .unwrap();
        add_binary(&fs, "/bin/tool");
        let path = format!("/work/project/scripts:{PATH}");
        assert_eq!(
            resolve_in(&fs, "tool", &path, &TrustedFolders::defaults()),
            Resolution::Trusted(canonical("/bin/tool"))
        );
        // Only non-executable matches: not found (bash would try it and fail with 126; both fail the line).
        fs.write(Path::new("/usr/bin/data"), b"data", 0o644).unwrap();
        assert_eq!(
            resolve_in(&fs, "data", PATH, &TrustedFolders::defaults()),
            Resolution::NotFound
        );
    }

    // A lookup error never resolves the name to something else silently: the failing entry is skipped, and if it
    // was the only one the line fails closed.
    #[test]
    fn lookup_errors_fail_closed() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/git");
        fs.inject_fault(Operation::Canonicalise, libc::EACCES);
        assert_eq!(
            resolve_in(&fs, "git", "/usr/bin", &TrustedFolders::defaults()),
            Resolution::NotFound
        );
        fs.inject_fault(Operation::Metadata, libc::EIO);
        assert_eq!(
            resolve_in(&fs, "git", "/usr/bin", &TrustedFolders::defaults()),
            Resolution::NotFound
        );
    }

    // An empty PATH entry (leading, trailing or `::`) is the working directory, as in bash.
    #[test]
    fn empty_path_entry_searches_cwd() {
        let fs = fs();
        add_binary(&fs, "/work/project/build");
        add_binary(&fs, "/usr/bin/build");
        for path in [":/usr/bin", "/nowhere::/usr/bin", "", "."] {
            assert_eq!(
                resolve_in(&fs, "build", path, &TrustedFolders::defaults()),
                Resolution::ProjectExecutable(canonical("/work/project/build")),
                "{path:?}"
            );
        }
    }

    // A call the parser marked as a function runs the function body and is not looked up, even if a binary exists.
    #[test]
    fn marked_function_call_is_function() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/git");
        let fs: &dyn Fs = &fs;
        assert_eq!(
            resolve(
                CommandName::Function("git"),
                PATH,
                &canonical("/work/project"),
                &TrustedFolders::defaults(),
                fs
            ),
            Resolution::Function
        );
    }

    // Quoted keywords reach the resolver as ordinary names and are looked up as bash does (`"time" ls`).
    #[test]
    fn quoted_keyword_names_are_looked_up_on_path() {
        let fs = fs();
        add_binary(&fs, "/usr/bin/time");
        assert_eq!(
            resolve_in(&fs, "time", PATH, &TrustedFolders::defaults()),
            Resolution::Trusted(canonical("/usr/bin/time"))
        );
        assert_eq!(
            resolve_in(&fs, "if", PATH, &TrustedFolders::defaults()),
            Resolution::NotFound
        );
    }
}
