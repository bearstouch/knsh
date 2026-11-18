//! The developer-tool compatibility list (KNSH-076; FR-SBX-09, FR-NET-12; `specs/08-integrations/developer-tools.md`).
//!
//! [`tool_compatibility`] runs each tool on the list twice, as a supervised line under its compiled per-command
//! profile (the path every shell line of an agent takes) and directly inside an envelope (as an agent CLI that starts
//! the tool itself), and writes `tools.md`: per tool and variant, the version tested, what each context did, and the
//! resulting status (**works**, **blocked**, or **needs a trusted tool**), next to what `developer-tools.md` expects.
//!
//! The network is real: the miniature `knshd`'s proxy (`knsh-proxy`, with the real host rules and server-name check)
//! connects to the real hosts. Only name resolution is a stand-in: the names a case needs are resolved here, before
//! the run, with the system resolver and handed to the proxy, as `knshd` would resolve them itself. A tool that
//! ignores the proxy has no way out: the profile allows network only to the proxy.
//!
//! A tool that is not installed, or a part of it that cannot be observed unattended (running a self-sandboxing tool as
//! a trusted tool needs an approval or a grant made after Touch ID), is listed as **pending** with its reason, never
//! with a status it was not seen to have. `#[ignore]`d: it needs the network and the installed tools; run it through
//! `scripts/qualify-phase2.sh`.

use std::fmt::Write as _;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use knsh_proto::LineStatus;

use super::report::{self, macos_version, probe};
use crate::threat_model::harness::{PATH, Stack, built_binaries, developer_dir, output};

/// How long one tool may run, in seconds.
const TOOL_TIMEOUT_S: u64 = 60;

/// `ktimeout <seconds> <command>`: runs `/bin/sh -c <command>` in its own process group and kills the whole group
/// after `seconds`, exiting 124 (as `timeout(1)` does); otherwise exits with the command's status. Bounds a tool run
/// directly inside an envelope, where no supervisor timeout applies (a tool whose name lookups are refused may wait
/// forever).
const KTIMEOUT_C: &str = "#include <signal.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n\
    #include <sys/wait.h>\n#include <time.h>\n\
    int main(int argc, char **argv) { if (argc != 3) return 2; int seconds = atoi(argv[1]); pid_t pid = fork();\n\
    if (pid < 0) return 2;\n\
    if (pid == 0) { setpgid(0, 0); execl(\"/bin/sh\", \"sh\", \"-c\", argv[2], (char *)0); _exit(127); }\n\
    setpgid(pid, pid); time_t deadline = time(NULL) + seconds; int status;\n\
    for (;;) { pid_t done = waitpid(pid, &status, WNOHANG); if (done == pid) break;\n\
    if (time(NULL) >= deadline) { kill(-pid, SIGKILL); waitpid(pid, &status, 0);\n\
    fprintf(stderr, \"timed out after %d s\\n\", seconds); return 124; }\n\
    usleep(50000); }\n\
    kill(-pid, SIGKILL);\n\
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status); }\n";

/// The profile every tool runs under.
const PROFILE: &str = "tools";

/// The status a tool has inside envelopes and command profiles (`developer-tools.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// It does its job.
    Works,
    /// Its network traffic is refused (it ignores the proxy, or speaks something the proxy does not carry).
    Blocked,
    /// It applies a sandbox of its own, which an already-sandboxed process cannot: it runs only as a trusted tool
    /// (FR-SBX-09).
    NeedsTrustedTool,
}

impl Status {
    /// The status as `developer-tools.md` and the report write it.
    const fn text(self) -> &'static str {
        match self {
            Self::Works => "works",
            Self::Blocked => "blocked",
            Self::NeedsTrustedTool => "needs a trusted tool",
        }
    }
}

/// One tool and one way of using it.
struct ToolCase {
    /// The tool, as the list names it.
    tool: &'static str,
    /// What is exercised.
    variant: &'static str,
    /// The tool's version, probed outside any sandbox.
    version: String,
    /// The line run, in the project.
    command: String,
    /// Extra environment (on top of what the supervisor or envelope sets).
    env: Vec<(String, String)>,
    /// Folders on `PATH` before the system ones.
    path: Vec<PathBuf>,
    /// Whether the run did the tool's job: exit 0 and this text in its standard output.
    expect_stdout: &'static str,
    /// Whether a non-zero exit still counts when the expected output arrived (Google Chrome renders, then exits 2
    /// from its own teardown watchdog, sandbox or not).
    any_exit: bool,
    /// The status a failure means for this tool.
    on_failure: Status,
    /// The status `developer-tools.md` gives it.
    documented: Status,
    /// Why it cannot be run here, if it cannot.
    pending: Option<String>,
}

/// What one context did with one case.
#[derive(Debug, Clone)]
struct Observed {
    /// Whether it did the tool's job.
    ok: bool,
    /// Exit status, and the last line of error output when it failed (proxy credentials masked).
    detail: String,
}

/// The first line of `text` (a version banner), or `unknown`.
fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("unknown").to_owned()
}

/// `name` resolved by the system resolver, for the proxy's stand-in resolver; empty when it does not resolve.
fn resolve(name: &str) -> Vec<IpAddr> {
    (name, 443)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

/// The hosts the network cases reach.
const HOSTS: [&str; 7] = [
    "example.com",
    "github.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "index.crates.io",
    "static.crates.io",
];

/// Masks `user:password@` in URLs: a tool's error may echo its proxy setting, which carries the line's credentials.
fn mask_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(scheme) = rest.find("://") {
        let (head, tail) = rest.split_at(scheme + 3);
        out.push_str(head);
        let authority_end = tail.find(['/', ' ', '\'', '"']).unwrap_or(tail.len());
        match tail[..authority_end].rfind('@') {
            Some(at) => {
                out.push_str("<credentials>");
                rest = &tail[at..];
            }
            None => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

/// The line of `text` that says what went wrong (the last one mentioning an error, else the last non-empty one),
/// masked and shortened, for the report.
fn last_line(text: &str) -> String {
    let lines = || text.lines().rev().map(str::trim).filter(|line| !line.is_empty());
    let line = lines()
        .find(|line| line.to_ascii_lowercase().contains("error"))
        .or_else(|| lines().next())
        .unwrap_or("");
    let line = mask_credentials(line).replace('|', "/");
    if line.chars().count() > 240 {
        format!("{}…", line.chars().take(240).collect::<String>())
    } else {
        line
    }
}

/// The `PATH` of a case: its own folders, then the system's.
fn case_path(case: &ToolCase) -> String {
    let mut parts: Vec<String> = case.path.iter().map(|dir| dir.display().to_string()).collect();
    parts.push(PATH.to_owned());
    parts.join(":")
}

/// Runs `case` as a supervised line under its per-command profile.
fn as_line(stack: &Stack, case: &ToolCase) -> Observed {
    let session = stack.session(PROFILE);
    let env: Vec<(&str, &str)> = case.env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    match stack.line_with(session, &case.command, &env, &case_path(case), Some(TOOL_TIMEOUT_S)) {
        Ok(finished) => {
            let (stdout, stderr) = output(&finished);
            let exited = finished.status == LineStatus::Exited(0) || case.any_exit;
            let ok = exited && stdout.contains(case.expect_stdout);
            let detail = if ok {
                "exit 0".to_owned()
            } else {
                format!("{:?}: {}", finished.status, last_line(&format!("{stdout}\n{stderr}")))
            };
            Observed { ok, detail }
        }
        Err(error) => Observed {
            ok: false,
            detail: format!("refused {:?}: {}", error.code, last_line(&error.message)),
        },
    }
}

/// Single-quotes `text` for `/bin/sh`.
fn sh_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// A `/bin/sh` script that runs `case` in the project with its environment, bounded by `ktimeout`, its output to
/// `<name>.out` and `<name>.err`, and prints `tool_exit=<status>`.
fn tool_script(stack: &Stack, ktimeout: &Path, case: &ToolCase, name: &str) -> String {
    let mut script = format!(
        "cd {} || exit 97\nexport PATH={}\n",
        sh_quote(&stack.project.display().to_string()),
        sh_quote(&case_path(case))
    );
    for (name, value) in &case.env {
        let _ = writeln!(script, "export {name}={}", sh_quote(value));
    }
    // The tool's output goes to files; only its exit status and the marker reach the caller's stdout.
    let _ = writeln!(
        script,
        "{} {TOOL_TIMEOUT_S} {} >{name}.out 2>{name}.err; echo \"tool_exit=$?\"",
        sh_quote(&ktimeout.display().to_string()),
        sh_quote(&case.command)
    );
    script
}

/// The run of a [`tool_script`] named `name`: whether the tool did its job, and its detail.
fn judge_script(stack: &Stack, case: &ToolCase, name: &str, ran: bool, out: &str) -> Observed {
    let read = |file: &str| std::fs::read_to_string(stack.project.join(file)).unwrap_or_default();
    let (stdout, stderr) = (read(&format!("{name}.out")), read(&format!("{name}.err")));
    let exit = out
        .lines()
        .find_map(|line| line.strip_prefix("tool_exit="))
        .unwrap_or("none");
    let ok = ran && (exit == "0" || case.any_exit) && stdout.contains(case.expect_stdout);
    let detail = if ok {
        "exit 0".to_owned()
    } else {
        format!("exit {exit}: {}", last_line(&format!("{stdout}\n{stderr}")))
    };
    Observed { ok, detail }
}

/// Runs `case` outside any sandbox and without the proxy, with the same `HOME`, `PATH` and environment: the positive
/// control. A tool that fails here too says nothing about Kinetic Shell, and its status is not claimed.
fn unconfined(stack: &Stack, ktimeout: &Path, case: &ToolCase) -> Observed {
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", &tool_script(stack, ktimeout, case, "unconfined")])
        .env_clear()
        .env("HOME", &stack.home)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&output.stdout);
    judge_script(stack, case, "unconfined", output.status.success(), &out)
}

/// Runs `case` directly inside an envelope, as an agent CLI that starts the tool itself.
fn in_envelope(stack: &Stack, ktimeout: &Path, case: &ToolCase) -> Observed {
    let (status, out) = stack.envelope(PROFILE, &tool_script(stack, ktimeout, case, "envelope"));
    let observed = judge_script(stack, case, "envelope", status == LineStatus::Exited(0), &out);
    if status == LineStatus::Exited(0) {
        return observed;
    }
    Observed {
        detail: format!("envelope ended {status:?}; {}", observed.detail),
        ..observed
    }
}

/// `ssh -V`, which prints its version on standard error.
fn ssh_version() -> String {
    std::process::Command::new("/usr/bin/ssh")
        .arg("-V")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// A Node version from `~/.nvm`, if installed: its `bin` folder.
fn nvm_node(version: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let bin = Path::new(&home).join(".nvm/versions/node").join(version).join("bin");
    bin.join("node")
        .is_file()
        .then(|| std::fs::canonicalize(bin).ok())
        .flatten()
}

/// The folder holding the program `name` resolves to on this process's `PATH`, canonical.
fn which(name: &str) -> Option<PathBuf> {
    let found = probe("/usr/bin/which", &[name]);
    (found != "unknown")
        .then(|| std::fs::canonicalize(found).ok()?.parent().map(Path::to_path_buf))
        .flatten()
}

/// Why a case cannot run, when what it needs was not found.
fn pending_if_missing(found: bool, what: &str) -> Option<String> {
    (!found).then(|| format!("{what} is not installed on this machine"))
}

/// A case with no version, environment or extra `PATH` yet, and nothing pending.
fn base(
    tool: &'static str,
    variant: &'static str,
    command: String,
    expect_stdout: &'static str,
    on_failure: Status,
    documented: Status,
) -> ToolCase {
    ToolCase {
        tool,
        variant,
        version: String::new(),
        command,
        env: Vec::new(),
        path: Vec::new(),
        expect_stdout,
        any_exit: false,
        on_failure,
        documented,
        pending: None,
    }
}

/// Every case of the list, with what is needed to run it on this machine.
fn cases(project: &Path) -> Vec<ToolCase> {
    let mut cases = network_cases(project);
    cases.extend(node_cases());
    cases.extend(browser_cases(project));
    cases.extend(build_cases(project));
    cases
}

/// curl and git (HTTPS and ssh) against their real hosts, then the package managers.
fn network_cases(project: &Path) -> Vec<ToolCase> {
    let mut cases = Vec::new();

    cases.push(ToolCase {
        version: first_line(&probe("/usr/bin/curl", &["--version"])),
        ..base(
            "curl",
            "HTTPS through the proxy (`HTTPS_PROXY`)",
            "/usr/bin/curl -sS -m 60 -o /dev/null -w 'status=%{http_code}\\n' https://example.com/".to_owned(),
            "status=200",
            Status::Blocked,
            Status::Works,
        )
    });

    let git_version = probe("/usr/bin/git", &["--version"]);
    cases.push(ToolCase {
        version: git_version.clone(),
        ..base(
            "git",
            "HTTPS remote (`git ls-remote`)",
            "/usr/bin/git ls-remote https://github.com/git/git.git HEAD".to_owned(),
            "HEAD",
            Status::Blocked,
            Status::Works,
        )
    });
    cases.push(ToolCase {
        version: format!("{git_version}; {}", ssh_version()),
        env: vec![(
            "GIT_SSH_COMMAND".to_owned(),
            // ssh finds `~/.ssh` from the password database, not `HOME`: `UserKnownHostsFile=/dev/null` keeps the
            // positive control from adding GitHub's key to the user's real `known_hosts`.
            "/usr/bin/ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null"
                .to_owned(),
        )],
        ..base(
            "git",
            "ssh remote (`git ls-remote git@github.com:…`)",
            "/usr/bin/git ls-remote git@github.com:git/git.git HEAD".to_owned(),
            "HEAD",
            Status::Blocked,
            Status::Blocked,
        )
    });

    cases.extend(package_manager_cases(project));
    cases
}

/// npm, pip and cargo against their registries.
fn package_manager_cases(project: &Path) -> Vec<ToolCase> {
    let mut cases = Vec::new();
    // npm runs on the default Node; its own proxy setting (`npm_config_https_proxy`) is set by the supervisor.
    // `node`'s folder: npm's own path, once canonical, is inside `lib/node_modules/npm/bin`, where no `node` is.
    let npm_node = which("npm").and(which("node"));
    cases.push(ToolCase {
        version: format!(
            "npm {} (node {})",
            probe("npm", &["--version"]),
            probe("node", &["--version"])
        ),
        env: vec![(
            "npm_config_cache".to_owned(),
            project.join(".npm").display().to_string(),
        )],
        path: npm_node.clone().into_iter().collect(),
        pending: pending_if_missing(npm_node.is_some(), "npm"),
        ..base(
            "npm",
            "registry read (`npm view`)",
            "npm view left-pad version --registry https://registry.npmjs.org/".to_owned(),
            "1.3.0",
            Status::Blocked,
            Status::Works,
        )
    });

    let python = which("python3");
    cases.push(ToolCase {
        version: probe("python3", &["-m", "pip", "--version"]),
        path: python.clone().into_iter().collect(),
        pending: pending_if_missing(python.is_some(), "python3"),
        ..base(
            "pip",
            "package download (`pip download`)",
            "python3 -m pip download --no-deps --no-cache-dir --disable-pip-version-check -d pip-dl six==1.16.0 \
             && echo downloaded"
                .to_owned(),
            "downloaded",
            Status::Blocked,
            Status::Works,
        )
    });

    // The toolchain's own cargo, not the rustup proxy: rustup would look for its home under the test `HOME`.
    let cargo = which("rustup")
        .map(|_| probe("rustup", &["which", "cargo"]))
        .filter(|path| path != "unknown")
        .map(PathBuf::from);
    let crate_dir = project.join("fetch");
    cases.push(ToolCase {
        version: probe("cargo", &["--version"]),
        env: vec![(
            "CARGO_HOME".to_owned(),
            project.join(".cargo-home").display().to_string(),
        )],
        path: cargo
            .as_ref()
            .and_then(|c| c.parent().map(Path::to_path_buf))
            .into_iter()
            .collect(),
        pending: pending_if_missing(cargo.is_some(), "a rustup toolchain"),
        ..base(
            "cargo",
            "crates.io sparse index and download (`cargo fetch`)",
            format!(
                "cargo fetch --manifest-path {}/Cargo.toml && echo fetched",
                crate_dir.display()
            ),
            "fetched",
            Status::Blocked,
            Status::Works,
        )
    });

    cases
}

/// Node's built-in HTTP clients on each Node release installed with nvm.
fn node_cases() -> Vec<ToolCase> {
    let mut cases = Vec::new();
    // Node's built-in HTTP clients honour the proxy only with `NODE_USE_ENV_PROXY=1`, which every line's environment
    // sets (proposed decision 14), and only from 22.21.
    let fetch = "node -e \"fetch('https://example.com/').then(r => console.log('status=' + r.status))\
                 .catch(e => { console.error(String(e.cause && e.cause.code || e)); process.exit(1) })\"";
    let https = "node -e \"require('https').get('https://example.com/', r => { console.log('status=' + r.statusCode); process.exit(0) })\
                 .on('error', e => { console.error(String(e.code || e)); process.exit(1) })\"";
    for version in ["v22.20.0", "v22.23.5", "v24.21.0"] {
        let bin = nvm_node(version);
        // 22.20 predates `NODE_USE_ENV_PROXY`: documented blocked. Later releases honour it.
        let documented = if version == "v22.20.0" {
            Status::Blocked
        } else {
            Status::Works
        };
        for (variant, command) in [("`fetch` (undici)", fetch), ("`https.get`", https)] {
            cases.push(ToolCase {
                version: format!("node {version}"),
                path: bin.clone().into_iter().collect(),
                pending: pending_if_missing(bin.is_some(), &format!("Node {version} (~/.nvm)")),
                ..base(
                    "Node HTTP clients",
                    variant,
                    command.to_owned(),
                    "status=200",
                    Status::Blocked,
                    documented,
                )
            });
        }
    }

    cases
}

/// Chromium as Playwright installs it, Google Chrome, and Playwright's driver.
fn browser_cases(project: &Path) -> Vec<ToolCase> {
    let mut cases = Vec::new();
    // Chromium as Playwright installs it (its headless shell), and Google Chrome. Both start a sandbox of their own.
    let playwright_shell = std::env::var_os("HOME").and_then(|home| {
        let cache = Path::new(&home).join("Library/Caches/ms-playwright");
        let mut builds: Vec<PathBuf> = std::fs::read_dir(cache)
            .ok()?
            .filter_map(|entry| Some(entry.ok()?.path()))
            .filter(|path| {
                path.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("chromium_headless_shell-"))
            })
            .collect();
        builds.sort();
        let shell = builds
            .pop()?
            .join("chrome-headless-shell-mac-arm64/chrome-headless-shell");
        shell.is_file().then_some(shell)
    });
    // `--use-mock-keychain`: Chrome otherwise reads (or creates) its "Chrome Safe Storage" item in the user's real
    // login keychain, whatever `HOME` and `--user-data-dir` say.
    let chromium_command = |binary: &Path| {
        format!(
            "{} --headless --disable-gpu --use-mock-keychain --user-data-dir={} --dump-dom \
             'data:text/html,<p>rendered</p>'",
            sh_quote(&binary.display().to_string()),
            project.join("chromium-profile").display()
        )
    };
    let shell_version = playwright_shell.as_ref().map_or_else(
        || "unknown".to_owned(),
        |shell| probe(&shell.display().to_string(), &["--version"]),
    );
    // `chromium_headless_shell-<revision>`: the build Playwright pinned, two levels above the binary.
    let shell_build = playwright_shell
        .as_ref()
        .and_then(|shell| shell.ancestors().nth(2)?.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    cases.push(ToolCase {
        version: format!("{shell_version} ({shell_build})"),
        pending: pending_if_missing(playwright_shell.is_some(), "Playwright's Chromium headless shell"),
        ..base(
            "Chromium (Playwright build)",
            "headless render (`--dump-dom`)",
            playwright_shell.as_deref().map(chromium_command).unwrap_or_default(),
            "rendered",
            Status::NeedsTrustedTool,
            Status::NeedsTrustedTool,
        )
    });
    let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    cases.push(ToolCase {
        any_exit: true,
        version: probe(&chrome.display().to_string(), &["--version"]),
        pending: pending_if_missing(chrome.is_file(), "Google Chrome"),
        ..base(
            "Chromium (Google Chrome)",
            "headless render (`--dump-dom`)",
            chromium_command(&chrome),
            "rendered",
            Status::NeedsTrustedTool,
            Status::NeedsTrustedTool,
        )
    });
    cases.push(ToolCase {
        pending: Some(
            "Playwright's Node driver is not installed here (only its Chromium build, above); installing it from \
             npm is left to a machine set up for it"
                .to_owned(),
        ),
        ..base(
            "Playwright",
            "Node driver launching Chromium",
            String::new(),
            "",
            Status::NeedsTrustedTool,
            Status::NeedsTrustedTool,
        )
    });

    cases
}

/// `swift build` and Bazel, which build inside sandboxes of their own.
fn build_cases(project: &Path) -> Vec<ToolCase> {
    let mut cases = Vec::new();
    let swift_dir = project.join("swiftpkg");
    let swift_version = first_line(&probe("/usr/bin/swift", &["--version"]));
    for (variant, flags) in [
        ("`swift build`", ""),
        // The same build with SwiftPM's own sandbox off: tells a failure of its sandbox from any other.
        ("`swift build --disable-sandbox`", " --disable-sandbox"),
    ] {
        cases.push(ToolCase {
            version: swift_version.clone(),
            ..base(
                "swift build",
                variant,
                format!(
                    "/usr/bin/swift build{flags} --package-path {} --scratch-path {} && echo built",
                    swift_dir.display(),
                    swift_dir.join(".build").display()
                ),
                "built",
                Status::NeedsTrustedTool,
                Status::NeedsTrustedTool,
            )
        });
    }

    let bazel = which("bazel").or_else(|| which("bazelisk"));
    cases.push(ToolCase {
        version: probe("bazel", &["--version"]),
        pending: pending_if_missing(bazel.is_some(), "Bazel (or Bazelisk)"),
        ..base(
            "Bazel",
            "`bazel build` of a one-file target",
            "bazel build //:hello && echo built".to_owned(),
            "built",
            Status::NeedsTrustedTool,
            Status::NeedsTrustedTool,
        )
    });
    cases
}

/// Writes what the cases build: a crate with one dependency for `cargo fetch`, and a one-file Swift package.
fn write_fixtures(project: &Path) {
    let crate_dir = project.join("fetch");
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"fetch\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.11\"\n",
    )
    .unwrap();
    std::fs::write(crate_dir.join("src/lib.rs"), "").unwrap();
    let swift_dir = project.join("swiftpkg");
    std::fs::create_dir_all(swift_dir.join("Sources/hello")).unwrap();
    std::fs::write(
        swift_dir.join("Package.swift"),
        "// swift-tools-version:5.9\nimport PackageDescription\n\
         let package = Package(name: \"hello\", targets: [.executableTarget(name: \"hello\")])\n",
    )
    .unwrap();
    std::fs::write(swift_dir.join("Sources/hello/main.swift"), "print(\"hello\")\n").unwrap();
    // Bazel: a workspace with one shell target, should Bazel be installed.
    std::fs::write(project.join("MODULE.bazel"), "").unwrap();
    std::fs::write(
        project.join("BUILD.bazel"),
        "genrule(name = \"hello\", outs = [\"hello.txt\"], cmd = \"echo hi > $@\")\n",
    )
    .unwrap();
}

/// What a tool run leaves in the project (caches, downloads, build output), removed before each context.
const TOOL_STATE: [&str; 9] = [
    ".npm",
    ".cargo-home",
    "pip-dl",
    "fetch/Cargo.lock",
    "fetch/target",
    "swiftpkg/.build",
    "chromium-profile",
    "bazel-out",
    ".bazel-cache",
];

/// Removes [`TOOL_STATE`] from `project`.
fn reset_state(project: &Path) {
    for name in TOOL_STATE {
        let path = project.join(name);
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_file(&path);
    }
}

/// `items` as the elements of a TOML array of strings: `"a", "b"`.
fn toml_strings<S: AsRef<str>>(items: &[S]) -> String {
    items
        .iter()
        .map(|item| format!("\"{}\"", item.as_ref()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The profile every tool runs under: the project writable, every command allowed without asking, the hosts of
/// [`HOSTS`] open to every command, and the folders the tools live in trusted (as a user's profile would).
fn tools_profile(stack: &Stack, cases: &[ToolCase]) -> String {
    let mut trusted: Vec<String> = vec![developer_dir().display().to_string(), stack.tools.display().to_string()];
    for case in cases {
        for dir in &case.path {
            trusted.push(dir.display().to_string());
            // The whole installation, as a user's profile would trust it: npm's real entry point is in
            // `lib/node_modules/npm/bin`, beside `bin` rather than in it, and an envelope runs only trusted programs.
            if dir.ends_with("bin")
                && let Some(root) = dir.parent()
            {
                trusted.push(root.display().to_string());
            }
        }
    }
    for dir in [
        "/opt/homebrew/Cellar",
        "/opt/homebrew/opt",
        "/Applications/Google Chrome.app",
    ] {
        if Path::new(dir).exists() {
            trusted.push(dir.to_owned());
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let playwright = Path::new(&home).join("Library/Caches/ms-playwright");
        if playwright.exists() {
            trusted.push(std::fs::canonicalize(playwright).unwrap().display().to_string());
        }
    }
    trusted.sort();
    trusted.dedup();
    format!(
        "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\ndefault = \"allow\"\nproject_executables = \"allow\"\n\
         trusted_folders = [{}]\n[approvals]\nirreversible = \"allow\"\n[network]\nmode = \"allowlist\"\nhosts = [{}]\n",
        toml_strings(&trusted),
        toml_strings(&HOSTS)
    )
}

/// The status both contexts give, or how they differ. Without a passing positive control (the same run outside any
/// sandbox) a failure proves nothing about Kinetic Shell, so no status is claimed.
fn status_of(case: &ToolCase, control: &Observed, line: &Observed, envelope: &Observed) -> String {
    let failed_somewhere = !line.ok || !envelope.ok;
    if !control.ok && failed_somewhere {
        return "**inconclusive**: it fails outside any sandbox too".to_owned();
    }
    let one = |observed: &Observed| if observed.ok { Status::Works } else { case.on_failure };
    let (a, b) = (one(line), one(envelope));
    if a == b {
        let mut text = format!("**{}**", a.text());
        if a != case.documented {
            let _ = write!(text, " (differs from the documented {})", case.documented.text());
        }
        text
    } else {
        format!("**differs**: command profile {}, envelope {}", a.text(), b.text())
    }
}

/// The names each case's sandboxed runs asked the proxy for, as a list for the report.
fn render_proxied(proxied: &[(&str, &str, Vec<String>)]) -> String {
    let mut text = String::from(
        "\nNames each case's sandboxed runs asked the proxy to reach (the proxy resolves names; a tool that ignores \
         it asks for none):\n\n",
    );
    for (tool, variant, hosts) in proxied {
        let hosts = if hosts.is_empty() {
            "none".to_owned()
        } else {
            hosts.join(", ")
        };
        let _ = writeln!(text, "- {tool}, {variant}: {hosts}");
    }
    text
}

/// Runs `case` outside any sandbox (the control), as a supervised line and in an envelope, each from a clean
/// project: a cache filled by an earlier context would let a tool succeed without touching the network. Answers what
/// each did and the names the two sandboxed runs asked the proxy for.
fn run_contexts(stack: &Stack, ktimeout: &Path, case: &ToolCase) -> (Observed, Observed, Observed, Vec<String>) {
    reset_state(&stack.project);
    let control = unconfined(stack, ktimeout, case);
    reset_state(&stack.project);
    let asked_before = stack.resolver.asked().len();
    let line = as_line(stack, case);
    reset_state(&stack.project);
    let envelope = in_envelope(stack, ktimeout, case);
    let mut hosts: Vec<String> = stack.resolver.asked().split_off(asked_before);
    hosts.sort();
    hosts.dedup();
    (control, line, envelope, hosts)
}

/// KNSH-076: runs every case of the list and writes `tools.md` to `target/qualification/` (or
/// `KNSH_QUALIFICATION_DIR`). Fails only when the run itself cannot happen (binaries not built, no network); a tool's
/// status, whatever it is, is a result, not a failure.
#[test]
#[ignore = "needs the network and the installed tools: scripts/qualify-phase2.sh"]
fn tool_compatibility() {
    let bins = built_binaries().expect("knsh-exec and knsh must be built beside the test binary");
    let stack = Stack::start("qtools", &bins);
    write_fixtures(&stack.project);
    let mut unresolved = Vec::new();
    for host in HOSTS {
        let addresses = resolve(host);
        if addresses.is_empty() {
            unresolved.push(host);
        }
        stack.resolver.answer(host, &addresses);
    }
    assert!(unresolved.len() < HOSTS.len(), "no host resolves: is the network up?");
    let ktimeout = stack.build_probe("ktimeout", KTIMEOUT_C);
    let cases = cases(&stack.project);
    stack.profile(PROFILE, &tools_profile(&stack, &cases));

    let macos = macos_version();
    let mut table = String::new();
    let mut proxied = Vec::new();
    for case in &cases {
        let (control, line, envelope, status) = if let Some(reason) = &case.pending {
            let none = || "—".to_owned();
            (none(), none(), none(), format!("**pending**: {reason}"))
        } else {
            eprintln!("tool: {} — {}", case.tool, case.variant);
            let (control, line, envelope, hosts) = run_contexts(&stack, &ktimeout, case);
            proxied.push((case.tool, case.variant, hosts));
            let status = status_of(case, &control, &line, &envelope);
            (control.detail, line.detail, envelope.detail, status)
        };
        let _ = writeln!(
            table,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            case.tool,
            case.variant,
            case.version.replace('|', "/"),
            control,
            line,
            envelope,
            status,
            case.documented.text()
        );
    }
    let per_case = render_proxied(&proxied);
    let mut asked: Vec<String> = stack.resolver.asked();
    asked.sort();
    asked.dedup();
    let unexpected: Vec<&str> = asked
        .iter()
        .map(String::as_str)
        .filter(|host| !HOSTS.contains(host))
        .collect();

    let mut text = String::from("# Developer-tool compatibility (KNSH-076)\n\n");
    let _ = writeln!(
        text,
        "Tested on macOS {macos}, {}, on {}. Each tool ran as a supervised line under its per-command profile and \
         directly inside an envelope, through the real proxy to the real hosts (names resolved before the run by the \
         system resolver). Profile: the project writable, every command allowed, `network.hosts` = {}.\n",
        std::env::consts::ARCH,
        probe("/bin/date", &["-u", "+%Y-%m-%d"]),
        HOSTS.join(", ")
    );
    text.push_str(
        "| Tool | Variant | Version tested | Outside any sandbox (control) | Command profile | Envelope | Status | \
         Documented |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    text.push_str(&table);
    text.push_str(&per_case);
    let _ = writeln!(
        text,
        "\nHosts the proxy was asked for: {}.{}",
        asked.join(", "),
        if unexpected.is_empty() {
            String::new()
        } else {
            format!(" Not on the allowlist (refused): {}.", unexpected.join(", "))
        }
    );
    if !unresolved.is_empty() {
        let _ = writeln!(
            text,
            "\nDid not resolve here (their cases cannot reach them): {}.",
            unresolved.join(", ")
        );
    }
    text.push_str(
        "\n**Pending** for every tool marked *needs a trusted tool*: running it as a trusted tool \
         (`exec.trusted_tools`, FR-SBX-09) needs an approval or a grant made after Touch ID or the user's password, \
         which an unattended run cannot give.\n",
    );
    let path = report::write("tools.md", &text);
    println!("{text}\nReport: {}", path.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tool's error may print its proxy URL, which carries the line's own credentials: never into the report.
    #[test]
    fn credentials_are_masked_in_reported_errors() {
        assert_eq!(
            mask_credentials("failed: http://knsh-12:s3cr3t@127.0.0.1:5000/ and https://example.com/x"),
            "failed: http://<credentials>@127.0.0.1:5000/ and https://example.com/x"
        );
        assert_eq!(mask_credentials("no url here"), "no url here");
        assert_eq!(
            last_line("first\nproxy socks5h://u:p@h:1 refused\n\n"),
            "proxy socks5h://<credentials>@h:1 refused"
        );
    }

    #[test]
    fn status_compares_contexts_and_documentation() {
        let case = base("curl", "v", String::new(), "", Status::Blocked, Status::Works);
        let ok = Observed {
            ok: true,
            detail: String::new(),
        };
        let failed = Observed {
            ok: false,
            detail: String::new(),
        };
        assert_eq!(status_of(&case, &ok, &ok, &ok), "**works**");
        assert_eq!(
            status_of(&case, &ok, &failed, &failed),
            "**blocked** (differs from the documented works)"
        );
        assert_eq!(
            status_of(&case, &ok, &ok, &failed),
            "**differs**: command profile works, envelope blocked"
        );
        // A failure that also happens outside any sandbox is not Kinetic Shell's doing: no status is claimed.
        assert_eq!(
            status_of(&case, &failed, &failed, &failed),
            "**inconclusive**: it fails outside any sandbox too"
        );
    }

    #[test]
    fn shell_quoting_survives_single_quotes() {
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }
}
