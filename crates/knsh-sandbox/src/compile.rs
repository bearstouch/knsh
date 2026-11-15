//! The compiled profile (KNSH-044, KNSH-045; FR-SBX-01 to FR-SBX-06, FR-SBX-10, FR-LC-15, FR-NET-08, FR-SEC-05,
//! NFR-SEC-03).
//!
//! [`compile`] writes, in this order:
//!
//! 1. `(version 1)`, the header comment naming the profile and its known gaps ([`GAPS`]), and `(deny default …)`:
//!    deny by default (FR-SBX-01).
//! 2. **Reads**: everything (`fs.read = "all"`), or only the listed paths.
//! 3. **Writes**: the write roots (`fs.write`), and the standard streams and null devices, which every command
//!    writes to (`2>/dev/null`, `> /dev/stdout`) and which reach no file.
//! 4. **Executables** (FR-SBX-04, FR-LC-15): `fork`, and `exec` of binaries in the trusted folders, the system tool
//!    folders ([`SYSTEM_TOOL_FOLDERS`]), `exec.bash`, the binaries the supervisor names
//!    ([`ProfileInput::executables`]) and, when `exec.project_executables = "allow"`, the write roots.
//! 5. **System**: Mach services (all but the denies of step 9), POSIX shared memory and semaphores, descriptor
//!    `ioctl`s, `sysctl` reads, and system settings read-only (`user-preference-read`, never `-write`).
//! 6. **Processes** (decision 8, FR-SEC-05): signals and process information only within this sandbox. `(deny
//!    default)` does not cover process information (KNSH-025, C8), so it is denied explicitly before the narrower
//!    allow.
//! 7. **Network**: outbound only to the proxy's loopback port ([`ProfileInput::proxy_port`]) and the
//!    `network.loopback` ports, which may also be served; Unix sockets may be bound under the write roots; an
//!    envelope may connect to `agent.sock` and nothing else, a command to no Unix socket at all (FR-SBX-05).
//! 8. **File denies**: `fs.deny` for reading and writing; the fixed write denies: the `.git` entry itself and,
//!    inside any `.git` directory, `hooks/`, `config` and `commondir` at any depth, and the submodule and worktree
//!    git directories' own entries; shell startup files; `~/Library/LaunchAgents`; `~/.ssh`.
//! 9. **Service denies** (FR-NET-08): `LaunchServices`, Apple Events, launchd job submission, the DNS resolver, the
//!    knsh control service; then the other processes' arguments, environment and list (`sysctl`), and the Docker
//!    socket.
//! 10. **Ancestors**: the directory entries above every fixed, engine and `fs.deny` path, so none of them can be
//!     renamed away (with the protected path inside it), edited there and renamed back.
//! 11. **Engine sockets and paths** ([`FixedDenies`]): binding a socket in an engine directory, connecting to
//!     `user.sock`, and last, reading, writing or executing any engine path (FR-SBX-05, FR-SBX-10).
//!
//! Seatbelt applies the last rule that matches an operation, so each deny written after the allows wins over them:
//! a write root that contains `~/.ssh`, an engine directory or a `.git/hooks` folder still cannot reach it, a
//! broad Mach-service allow still cannot reach the control service, and nothing in [`ProfileInput`] can remove
//! steps 8 to 11. The one deny written before an allow is step 6's, which the allow narrows to this sandbox.
//!
//! # Executables
//!
//! Seatbelt checks the path an `exec` really runs, after every symlink (observed on macOS 26.6.2, KNSH-045): a rule
//! for `/opt/homebrew/bin` does not cover `/opt/homebrew/bin/node`, a link into `/opt/homebrew/Cellar`, and Apple's
//! `/usr/bin/git` is a stub that runs the git of the active developer directory. So trusted folders are allowed with
//! everything below them (as the kernel sees it, `subpath`), the developer directories are allowed as system tool
//! folders, and the supervisor names the canonical binaries it resolved for a line ([`ProfileInput::executables`]):
//! a binary resolved through a link runs, while one swapped in elsewhere afterwards does not (FR-LC-15).
//!
//! `exec.project_executables` maps to the sandbox as: `allow` lets anything under the write roots run; `ask` and
//! `deny` allow none, and an approved project executable reaches the profile only as a binary the supervisor names.
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
//! `fixed.shell-startup`, `fixed.launch-agents`, `fixed.ssh`, `services.launch-services`, `services.apple-events`,
//! `services.launchd-jobs`, `services.dns`, `fixed.control`, `process.info`, `process.sysctl`, `sockets.docker`,
//! `fixed.ancestors`, `fixed.engine-bind`, `fixed.user-sock`, `fixed.engine`). Decision 9: every operation knsh
//! relies on has its own tagged deny, never only the default's.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use knsh_core::{CanonicalPath, FixedDenies, Profile, ReadScope, RecordId, RuleAction, SessionId};

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

/// The header comment's list of what the profile cannot enforce, as specified (`sandbox-profiles.md`, KNSH-025 C8
/// results). Each line is a constant: no input reaches a comment.
pub const GAPS: [&str; 7] = [
    "signals and process information are limited to this sandbox instance, not a process group (decision 8)",
    "the system-wide process list is denied as a whole: proc_listpids has no per-target filter",
    "signal denials are never logged",
    "Mach services: all are allowed but the named denies; the short list command-line tools need is not measured",
    "a tool that sends DNS over UDP itself bypasses the resolver deny; only the network rules stop it",
    "setuid binaries (ps) cannot run under any profile",
    "a script given to an interpreter (sh x.sh, node x.js) is read, not executed: exec rules do not stop it",
];

/// Folders whose binaries `/usr/bin` stubs run (`git`, `clang`, `python3`, `make` run the active developer
/// directory's copy) or that macOS tools run themselves. `/usr/libexec` is sealed in the system volume; the
/// developer directories are installed by an admin (a user-installed Xcode belongs to that user), and agents still
/// cannot write them without a write root there. Another developer directory chosen with `xcode-select`
/// (`Xcode-beta.app`) is not covered.
pub const SYSTEM_TOOL_FOLDERS: [&str; 3] = [
    "/usr/libexec",
    "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app/Contents/Developer",
];

/// `LaunchServices` (`open`, app launches). App bundles that need it run only as trusted tools (decision 10).
const LAUNCH_SERVICES: [&str; 4] = [
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.lsd.modifydb",
    "com.apple.CoreServices.coreservicesd",
];

/// Apple Events: scripting other applications (`osascript`).
const APPLE_EVENTS: &str = "com.apple.coreservices.appleevents";

/// The system DNS resolver's Mach service (FR-NET-08): names are resolved by the proxy, never in the sandbox.
const DNS_SERVICE: &str = "com.apple.dnssd.service";

/// The resolver's Unix socket, canonical (`/var/run` is a link to `/private/var/run`).
const DNS_SOCKET: &str = "/private/var/run/mDNSResponder";

/// The Docker daemon socket, system-wide (canonical). Docker Desktop's own socket lies below the home directory
/// ([`DOCKER_HOME_SOCKET`]); `/private/var/run/docker.sock` is often a link to it. No profile key allows either.
const DOCKER_SOCKET: &str = "/private/var/run/docker.sock";

/// Docker Desktop's socket, relative to the home directory.
const DOCKER_HOME_SOCKET: [&str; 3] = [".docker", "run", "docker.sock"];

/// The `sysctl` names that read other processes: arguments and environment (`kern.procargs*`) and `kinfo_proc`
/// (`kern.proc.*`). Either one with process information allowed exposes them (KNSH-025, C8), so both are denied; a
/// process still reads itself.
const PROCESS_SYSCTLS: [&str; 2] = ["kern.procargs", "kern.proc."];

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
    /// What runs under the profile, named in every tag. It also decides the Unix sockets: an envelope may connect
    /// to `agent.sock`, a supervised line to none (FR-SBX-05).
    pub command: CommandTag,
    /// The resolved profile: its `fs`, `exec` and `network` keys decide the rules.
    pub profile: &'a Profile,
    /// The user's canonical home directory: the fixed denies and the endpoint sockets lie below it.
    pub home: &'a CanonicalPath,
    /// Canonical binaries the supervisor allows besides the trusted and system tool folders: the binaries it
    /// resolved for a line (including an approved project executable), or the agent CLI and the `knsh` shims for an
    /// envelope. Each is allowed exactly (`literal`), so a binary resolved through a link runs.
    pub executables: &'a [CanonicalPath],
    /// The loopback port the network proxy listens on for this profile (TCP, `localhost`). `None` when no proxy
    /// serves it: then only the `network.loopback` ports are reachable.
    pub proxy_port: Option<NonZeroU16>,
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
    let engine = FixedDenies::for_home(home);
    let mut out = Writer::default();
    out.raw(VERSION).newline();
    header(&mut out, input);
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

    executables(&mut out, input);
    system(&mut out, &tag);
    network(&mut out, input, &engine);

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

    let mut trees = Vec::new();
    for (rule, components) in HOME_TREES {
        let mut path = home.as_path().to_path_buf();
        path.extend(components);
        out.raw("(deny file-write*").subpath(&path).end_tagged(&tag, rule);
        trees.push(path);
    }

    service_denies(&mut out, &tag, &engine, home);

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

    // No socket can be bound in an engine directory, so none can squat an endpoint while `knshd` is not running,
    // even from a write root above it (`~`). Connecting to `user.sock` is denied whatever came before (FR-SBX-05).
    out.raw("(deny network-bind");
    for path in engine.paths() {
        out.raw(" (local unix-socket").subpath(path).raw(")");
    }
    out.end_tagged(&tag, "fixed.engine-bind");
    out.raw("(deny network-outbound")
        .unix_socket(engine.user_socket())
        .end_tagged(&tag, "fixed.user-sock");

    // Engine paths last: no rule of any profile can come after them. `process-exec*` too, so a write root above
    // them with project executables allowed still cannot run anything there.
    out.raw("(deny file-read* file-write* process-exec*");
    for path in engine.paths() {
        out.subpath(path);
    }
    out.end_tagged(&tag, "fixed.engine");

    out.finish()
}

/// The header comment: the profile's name and the gaps it cannot close ([`GAPS`]). Profile names are
/// `[A-Za-z0-9._-]` only, so neither part can end the comment.
fn header(out: &mut Writer, input: &ProfileInput<'_>) {
    let kind = match input.command {
        CommandTag::Envelope => "envelope",
        CommandTag::Line(_) => "command",
    };
    out.raw(";; knsh ")
        .raw(kind)
        .raw(" profile ")
        .raw(input.profile.name.as_str())
        .raw(", compiled by knsh-sandbox. Known gaps:")
        .newline();
    for gap in GAPS {
        out.raw(";; - ").raw(gap).newline();
    }
}

/// Step 4: `fork`, and `exec` of trusted, system and named binaries, and of project executables if allowed.
fn executables(out: &mut Writer, input: &ProfileInput<'_>) {
    let exec = &input.profile.exec;
    out.raw("(allow process-fork)").newline();
    out.raw("(allow process-exec");
    for folder in exec.trusted_folders.folders() {
        out.subpath(folder);
    }
    for folder in SYSTEM_TOOL_FOLDERS {
        out.subpath(folder);
    }
    out.literal(&exec.bash);
    for binary in input.executables {
        out.literal(binary);
    }
    match exec.project_executables {
        RuleAction::Allow => {
            for root in &input.profile.fs.write {
                out.subpath(root);
            }
        }
        // An approved project executable is named in `executables`; nothing else under the write roots runs.
        RuleAction::Ask | RuleAction::Deny => {}
    }
    out.end();
}

/// Steps 5 and 6: system services, settings read-only, and processes limited to this sandbox.
fn system(out: &mut Writer, tag: &Tag) {
    out.raw("(allow mach-lookup)").newline();
    out.raw("(allow ipc-posix-shm* ipc-posix-sem)").newline();
    out.raw("(allow file-ioctl)").newline();
    out.raw("(allow sysctl-read)").newline();
    out.raw("(allow user-preference-read)").newline();
    out.raw("(allow signal (target same-sandbox))").newline();
    // Not covered by `(deny default)` (KNSH-025, C8): denied explicitly, then allowed within the sandbox.
    out.raw("(deny process-info*").end_tagged(tag, "process.info");
    out.raw("(allow process-info* (target same-sandbox))").newline();
}

/// Step 7: the proxy and loopback ports, Unix sockets bound under the write roots, and `agent.sock` for an
/// envelope.
fn network(out: &mut Writer, input: &ProfileInput<'_>, engine: &FixedDenies) {
    // Port 0 allows nothing (the loader refuses it in `network.loopback`), so it is left out.
    let loopback: Vec<u16> = input
        .profile
        .network
        .loopback
        .iter()
        .copied()
        .filter(|port| *port != 0)
        .collect();
    let outbound: Vec<u16> = input
        .proxy_port
        .map(NonZeroU16::get)
        .into_iter()
        .chain(loopback.iter().copied())
        .collect();
    if !outbound.is_empty() {
        out.raw("(allow network-outbound");
        for port in outbound {
            out.localhost(port);
        }
        out.end();
    }
    if !loopback.is_empty() {
        out.raw("(allow network-bind network-inbound");
        for port in &loopback {
            out.raw(" (local ip \"localhost:").raw(&port.to_string()).raw("\")");
        }
        out.end();
    }
    // Serving a socket of one's own is not security-relevant; only connecting is limited (sandbox-profiles.md).
    let roots = &input.profile.fs.write;
    if !roots.is_empty() {
        out.raw("(allow network-bind network-inbound");
        for root in roots {
            out.raw(" (local unix-socket").subpath(root).raw(")");
        }
        out.end();
    }
    match input.command {
        CommandTag::Envelope => {
            out.raw("(allow network-outbound")
                .unix_socket(engine.agent_socket())
                .end();
        }
        // Commands talk to nothing over Unix sockets: the default deny covers every one.
        CommandTag::Line(_) => {}
    }
}

/// Step 9: the system services denied (FR-NET-08), the control service, other processes, and the Docker socket.
fn service_denies(out: &mut Writer, tag: &Tag, engine: &FixedDenies, home: &CanonicalPath) {
    out.raw("(deny mach-lookup")
        .global_names(&LAUNCH_SERVICES)
        .end_tagged(tag, "services.launch-services");
    out.raw("(deny mach-lookup")
        .global_names(&[APPLE_EVENTS])
        .end_tagged(tag, "services.apple-events");
    // `(deny default)` already refuses it, but untagged (decision 9).
    out.raw("(deny job-creation").end_tagged(tag, "services.launchd-jobs");
    out.raw("(deny mach-lookup")
        .global_names(&[DNS_SERVICE])
        .end_tagged(tag, "services.dns");
    out.raw("(deny network-outbound")
        .unix_socket(Path::new(DNS_SOCKET))
        .end_tagged(tag, "services.dns");
    out.raw("(deny mach-lookup")
        .global_names(engine.services())
        .end_tagged(tag, "fixed.control");
    out.raw("(deny sysctl-read");
    for prefix in PROCESS_SYSCTLS {
        out.raw(" (sysctl-name-prefix ").path(prefix.as_bytes()).raw(")");
    }
    out.end_tagged(tag, "process.sysctl");
    let mut docker = home.as_path().to_path_buf();
    docker.extend(DOCKER_HOME_SOCKET);
    out.raw("(deny network-outbound")
        .unix_socket(Path::new(DOCKER_SOCKET))
        .unix_socket(&docker)
        .end_tagged(tag, "sockets.docker");
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

    /// ` (remote unix-socket (path-literal "<path>"))`: a connection to the socket at `path`.
    fn unix_socket(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.raw(" (remote unix-socket (path-literal ")
            .path(path.as_ref().as_os_str().as_encoded_bytes())
            .raw("))")
    }

    /// ` (remote ip "localhost:<port>")`: a TCP or UDP connection to `port` on the loopback interface.
    fn localhost(&mut self, port: u16) -> &mut Self {
        self.raw(" (remote ip \"localhost:").raw(&port.to_string()).raw("\")")
    }

    /// ` (global-name "<a>" "<b>" …)`: Mach services by name. Names are constants of this crate or `knsh-core`.
    fn global_names(&mut self, names: &[&str]) -> &mut Self {
        self.raw(" (global-name");
        for name in names {
            self.raw(" ").path(name.as_bytes());
        }
        self.raw(")")
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
