//! The file rules of a compiled profile (KNSH-044; FR-SBX-01, FR-SBX-02, FR-SBX-06, FR-SBX-10, NFR-SEC-03).
//!
//! [`compile`] writes, in this order:
//!
//! 1. `(deny default …)`: deny by default (FR-SBX-01).
//! 2. **Reads**: everything (`fs.read = "all"`), or only the listed paths.
//! 3. **Writes**: the write roots (`fs.write`), and the standard streams and null devices, which every command
//!    writes to (`2>/dev/null`, `> /dev/stdout`) and which reach no file.
//! 4. **`fs.deny`**: each path denied for reading and writing, one tagged rule per entry.
//! 5. **Fixed write denies**, in every profile whatever the input says: the `.git` entry itself and, inside any
//!    `.git` directory, `hooks/`, `config` and `commondir` at any depth, and the submodule and worktree git
//!    directories' own entries; shell startup files; `~/Library/LaunchAgents`; `~/.ssh`.
//! 6. **Ancestors**: the directory entries above every fixed, engine and `fs.deny` path, so none of them can be
//!    renamed away (with the protected path inside it), edited there and renamed back.
//! 7. **Engine paths** ([`FixedDenies`]), denied for reading and writing (FR-SBX-10).
//!
//! Seatbelt applies the last rule that matches an operation, so each deny written after the allows wins over them:
//! a write root that contains `~/.ssh`, an engine directory or a `.git/hooks` folder still cannot reach it, and
//! nothing in [`ProfileInput`] can remove steps 5 to 7.
//!
//! # `.git`
//!
//! The git rules are regexes that hold for every git directory, wherever it is: writes are only allowed under the
//! write roots, so they cover exactly the git directories there (and are harmless elsewhere). Denying `hooks/` and
//! `config` alone is not enough: an agent could build a directory holding `hooks/pre-commit` and rename it to
//! `.git`, or rename the real `.git` away and put its own in place. Denying writes to the `.git` entry itself stops
//! both (observed on macOS 26.6.2, KNSH-044), while `git commit`, `git checkout -b` and `git gc` still work: they
//! write inside `.git`, not to it. `git init` and `git clone` already fail, since they write `.git/config`.
//!
//! Git also takes hooks and configuration from other git directories: a `commondir` file in any git directory names
//! the directory whose `hooks/` and `config` git uses (observed with git 2.54: writing `.git/commondir` alone makes
//! `git commit` run a planted `pre-commit`), and submodules keep their own git directories in `.git/modules/<name>`
//! (`config` there can set `core.fsmonitor`, run by the superproject's `git status`). So `hooks/`, `config`,
//! `config.worktree` and `commondir` are denied at any depth inside `.git`, and so are the `modules` and `worktrees`
//! entries and the entries directly below them, so a submodule or worktree git directory cannot be renamed out of
//! `.git`, edited and renamed back. Commits inside existing submodules and worktrees still work; `git worktree add`
//! and `git submodule add` fail, like `git init`. A submodule whose name holds `/` keeps its root renamable.
//!
//! On a case-insensitive volume Seatbelt matches these rules without regard to case (`.GIT/HOOKS/x` is denied by
//! the lower-case regex, observed on macOS 26.6.2), so no case variant needs spelling out.
//!
//! # Tags
//!
//! Every deny carries `(with message "knsh:<session>:<command>:<rule>")` (FR-SBX-06), so the violation reader
//! (KNSH-047) can trace a denial to its session, command and rule: `<command>` is the record ID of a supervised line
//! or `env` for the envelope, and `<rule>` names the deny (`default`, `fs.deny[N]`, `fixed.git`,
//! `fixed.shell-startup`, `fixed.launch-agents`, `fixed.ssh`, `fixed.ancestors`, `fixed.engine`).

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use knsh_core::{CanonicalPath, FixedDenies, Profile, ReadScope, RecordId, SessionId};

use crate::sbpl::{SbplText, Writer};

/// The SBPL version every profile declares.
const VERSION: &str = "(version 1)";

/// Writes every command may make although they reach no file: the null devices and the process's own standard
/// streams, which only name descriptors it already holds.
const DEVICE_LITERALS: [&str; 4] = ["/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr"];

/// `/dev/fd/N`: one of the process's own open descriptors.
const DEVICE_REGEX: &str = r#"(regex #"^/dev/fd/[0-9]+$")"#;

/// The git rules (module documentation, "`.git`"): the `.git` entry itself; at any depth inside `.git`, `hooks/`
/// (and everything in it), `config`, `config.worktree` and `commondir`; and the `modules` and `worktrees` entries and
/// the git directories directly below them.
const GIT_REGEXES: [&str; 4] = [
    r#"(regex #"/\.git$")"#,
    r#"(regex #"/\.git/(.+/)?hooks(/|$)")"#,
    r#"(regex #"/\.git/(.+/)?(config|config\.worktree|commondir)$")"#,
    r#"(regex #"/\.git/(.+/)?(modules|worktrees)(/[^/]+)?$")"#,
];

/// Shell startup files in the home directory, which bash and zsh run outside any sandbox: the spec's list, plus the
/// zsh and bash files it leaves out that run as often (`.zshenv` runs for every zsh, even non-interactive ones).
const SHELL_STARTUP: [&str; 10] = [
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".bash_logout",
    ".profile",
];

/// Trees in the home directory whose files run outside any sandbox (launchd agents) or grant access elsewhere
/// (SSH keys, `authorized_keys`, `config`'s `ProxyCommand`), by rule name.
const HOME_TREES: [(&str, &[&str]); 2] = [
    ("fixed.launch-agents", &["Library", "LaunchAgents"]),
    ("fixed.ssh", &[".ssh"]),
];

/// What runs under the profile: the supervised line, or the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandTag {
    /// The agent CLI and everything it starts directly.
    Envelope,
    /// A supervised line, by its record.
    Line(RecordId),
}

impl fmt::Display for CommandTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope => f.write_str("env"),
            Self::Line(record_id) => write!(f, "{record_id}"),
        }
    }
}

/// Everything a profile is compiled from.
#[derive(Debug, Clone, Copy)]
pub struct ProfileInput<'a> {
    /// The session, named in every tag.
    pub session: SessionId,
    /// What runs under the profile, named in every tag.
    pub command: CommandTag,
    /// The resolved profile: its `fs` keys decide the file rules.
    pub profile: &'a Profile,
    /// The user's canonical home directory: the fixed denies lie below it.
    pub home: &'a CanonicalPath,
}

/// Compiles the file rules of `input` into profile text (module documentation).
///
/// Pure and deterministic: the same input always gives the same bytes, and rules follow the order of the profile's
/// lists. Total: every canonical path can be written as an escaped string literal, so there is nothing to refuse.
#[must_use]
pub fn compile(input: &ProfileInput<'_>) -> SbplText {
    let tag = Tag {
        session: input.session,
        command: input.command,
    };
    let fs = &input.profile.fs;
    let home = input.home;
    let mut out = Writer::default();
    out.raw(VERSION).newline();
    out.raw("(deny default").end_tagged(&tag, "default");

    // Reads: everything, or only what the profile lists. An empty list allows no reads at all.
    match &fs.read {
        ReadScope::All => {
            out.raw("(allow file-read*)").newline();
        }
        ReadScope::Paths(paths) if paths.is_empty() => {}
        ReadScope::Paths(paths) => {
            out.raw("(allow file-read*");
            for path in paths {
                out.subpath(path);
            }
            out.end();
        }
    }

    // Writes: the write roots, then the devices every command writes to.
    if !fs.write.is_empty() {
        out.raw("(allow file-write*");
        for root in &fs.write {
            out.subpath(root);
        }
        out.end();
    }
    out.raw("(allow file-write*");
    for device in DEVICE_LITERALS {
        out.literal(device);
    }
    out.raw(" ").raw(DEVICE_REGEX).end();

    // Everything below is a deny, after every allow, so it wins.
    for (index, path) in fs.deny.iter().enumerate() {
        out.raw("(deny file-read* file-write*")
            .subpath(path)
            .end_tagged(&tag, &format!("fs.deny[{index}]"));
    }

    out.raw("(deny file-write*");
    for regex in GIT_REGEXES {
        out.raw(" ").raw(regex);
    }
    out.end_tagged(&tag, "fixed.git");

    let startup: Vec<PathBuf> = SHELL_STARTUP.iter().map(|name| home.as_path().join(name)).collect();
    out.raw("(deny file-write*");
    for path in &startup {
        out.literal(path);
    }
    out.end_tagged(&tag, "fixed.shell-startup");

    let engine = FixedDenies::for_home(home);
    let mut trees = Vec::new();
    for (rule, components) in HOME_TREES {
        let mut path = home.as_path().to_path_buf();
        path.extend(components);
        out.raw("(deny file-write*").subpath(&path).end_tagged(&tag, rule);
        trees.push(path);
    }

    // Renaming a directory moves everything below it without touching those paths, so an ancestor of a protected
    // path could be renamed away, the path edited at its new place, and the directory renamed back. Denying writes
    // to each ancestor's own entry stops that; files can still be created and removed inside it (KNSH-044,
    // observed on macOS 26.6.2). Sorted and deduplicated, so the output stays deterministic.
    let protected = fs
        .deny
        .iter()
        .chain(engine.paths())
        .map(CanonicalPath::as_path)
        .chain(startup.iter().map(PathBuf::as_path))
        .chain(trees.iter().map(PathBuf::as_path));
    let ancestors: BTreeSet<&Path> = protected.flat_map(|path| path.ancestors().skip(1)).collect();
    if !ancestors.is_empty() {
        out.raw("(deny file-write*");
        for ancestor in ancestors {
            out.literal(ancestor);
        }
        out.end_tagged(&tag, "fixed.ancestors");
    }

    // Engine paths last: no rule of any profile can come after them.
    out.raw("(deny file-read* file-write*");
    for path in engine.paths() {
        out.subpath(path);
    }
    out.end_tagged(&tag, "fixed.engine");

    out.finish()
}

/// The session and command every tag names.
struct Tag {
    session: SessionId,
    command: CommandTag,
}

impl Writer {
    /// ` (subpath "<path>")`: `path` and everything below it.
    fn subpath(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.filter("subpath", path.as_ref())
    }

    /// ` (literal "<path>")`: `path` itself only.
    fn literal(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.filter("literal", path.as_ref())
    }

    /// ` (<filter> "<path>")`, with the path's raw bytes as the kernel matches them, through the escaping writer.
    fn filter(&mut self, filter: &str, path: &Path) -> &mut Self {
        self.raw(" (")
            .raw(filter)
            .raw(" ")
            .path(path.as_os_str().as_encoded_bytes())
            .raw(")")
    }

    /// Closes the current rule and ends its line.
    fn end(&mut self) -> &mut Self {
        self.raw(")").newline()
    }

    /// Tags the current deny with `rule` ([`Writer::tag`]), then closes it and ends its line.
    fn end_tagged(&mut self, tag: &Tag, rule: &str) -> &mut Self {
        self.tag(tag, rule).end()
    }

    /// ` (with message "knsh:<session>:<command>:<rule>")`. Every part is an ID or a constant rule name, so none
    /// holds `"` or `\`; the text still goes through the escaping writer.
    fn tag(&mut self, tag: &Tag, rule: &str) -> &mut Self {
        let message = format!("knsh:{}:{}:{rule}", tag.session, tag.command);
        self.raw(" (with message ").path(message.as_bytes()).raw(")")
    }
}
