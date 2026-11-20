//! The end-to-end cases, one or more per threat row (KNSH-075). Each starts its own [`Stack`], so cases run in
//! parallel without sharing state. Every refusal a case asserts is paired, where the machine allows, with a positive
//! control showing the same action succeeds without the mitigation, so the refusal is the mitigation's and not an
//! accident of the test machine.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use knsh_core::{DecisionSource, EventData, Grant, GrantId, GrantScope, NetworkEntry, NetworkResult, Timestamp, Ulid};
use knsh_json::{Frame, FrameReader, FrameWriter, Value};
use knsh_platform::Clock as _;
use knsh_proto::{Denial, ErrorCode, LineStatus, Message, RpcError};

use super::harness::{
    BOOTSTRAP_NOT_PRIVILEGED, LINE_TIMEOUT_S, LOOKUP_C, PATH, PROCARGS_C, Received, Scratch, Stack, binaries,
    compile_c, developer_dir, exists, field, output, recording_tcp, recording_udp, wait_for,
};
use super::report::Case;
use crate::exec::Finished;

/// The denial in `answer`, which must be one.
fn denial(answer: &Result<Finished, RpcError>) -> Denial {
    match answer {
        Err(error) => Denial::from_error(error).unwrap_or_else(|| panic!("not a denial: {error:?}")),
        Ok(finished) => panic!("ran: {:?} {:?}", finished.executed_command.expose(), output(finished)),
    }
}

/// The exit code of a line that ran.
fn exit_code(answer: &Result<Finished, RpcError>) -> i32 {
    match answer {
        Ok(Finished {
            status: LineStatus::Exited(code),
            ..
        }) => i32::from(*code),
        other => panic!("did not exit normally: {other:?}"),
    }
}

/// Runs `script` with `/bin/sh -c` outside any sandbox (a positive control), answering its stdout.
fn unconfined(script: &str) -> String {
    let output = Command::new("/bin/sh").arg("-c").arg(script).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `(echo x > "<path>") 2>/dev/null; echo <key>=$?` for every `(key, path)`: one line each, so a case reads every
/// write's result with [`field`].
fn write_probes(targets: &[(&str, &Path)]) -> String {
    let mut script = String::new();
    for (key, path) in targets {
        let _ = writeln!(
            script,
            "(echo planted > '{}') 2>/dev/null; echo {key}=$?",
            path.display()
        );
    }
    script
}

/// The JSON-RPC requests `frames` encodes, each a length-prefixed JSON frame as `knsh` sends them.
fn frames(requests: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = FrameWriter::new(&mut bytes);
    for request in requests {
        writer
            .write_json(&knsh_json::parse(request.as_bytes(), 1 << 16).unwrap())
            .unwrap();
    }
    writer.flush().unwrap();
    bytes
}

/// Whether `entries` (a line's network record) show `host` contacted.
fn contacted(entries: &[NetworkEntry], host: &str) -> bool {
    entries
        .iter()
        .any(|entry| entry.host.expose() == host && entry.result == NetworkResult::Contacted)
}

/// Whether `entries` (a line's network record) show `host` refused for `reason`.
fn refused_for(entries: &[NetworkEntry], host: &str, reason: &str) -> bool {
    entries
        .iter()
        .any(|entry| entry.host.expose() == host && entry.result == NetworkResult::Refused(reason.to_owned()))
}

/// Waits up to five seconds for a connection to `received` to carry bytes (a positive control's TLS hello), then
/// forgets what arrived so later checks see only what follows.
fn first_bytes_arrive(received: &Received) -> bool {
    let arrived = wait_for(Duration::from_secs(5), || {
        received.lock().unwrap().iter().any(|bytes| !bytes.is_empty())
    });
    received.lock().unwrap().clear();
    arrived
}

/// Every message in `bytes`, a stream of frames as `knshd` writes them.
fn messages(bytes: &[u8]) -> Vec<Message> {
    let mut reader = FrameReader::new(bytes);
    let mut out = Vec::new();
    while let Ok(Some(Frame::Json(payload))) = reader.read_frame() {
        out.push(knsh_proto::decode(&payload).unwrap());
    }
    out
}

// Row "An agent approves its own request" (FR-AUTH-12 – FR-AUTH-16, FR-AUTH-41 – FR-AUTH-43, FR-SBX-05): from inside
// a real envelope, `user.sock` cannot be reached, `knsh.control` cannot be looked up, and on `agent.sock` (which the
// envelope reaches, bound to its own session) `approval.approve`, `approval.deny` and `policy.grant` do not exist.
#[test]
fn agent_cannot_approve_own_request() {
    let Some((mut case, bins)) = binaries(Case::start("agent_cannot_approve_own_request")) else {
        return;
    };
    let stack = Stack::start("approve", &bins);
    let lookup = stack.build_probe("lookup", LOOKUP_C);
    let requests = stack.tools.join("requests.bin");
    std::fs::write(
        &requests,
        frames(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"hello","params":{"client":"t","client_version":"1","protocols":[1],"binary_frames":false}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"approval.approve","params":{"request_id":"01JCZ0000000000000000000AA"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"approval.deny","params":{"request_id":"01JCZ0000000000000000000AA"}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"policy.grant","params":{"rule":"git push","scope":"session","duration_s":60}}"#,
        ]),
    )
    .unwrap();
    stack.profile(
        "it",
        &format!(
            "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\ntrusted_folders = [\"{}\"]\n",
            stack.tools.display()
        ),
    );
    let (user, agent) = (stack.paths.user_socket(), stack.paths.agent_socket());
    let answers = stack.project.join("answers.bin");
    let probes = format!(
        "nc -U -w 1 '{user}' </dev/null >/dev/null 2>&1; echo user_sock=$?\n\
         echo control=$('{lookup}' {control})\n",
        user = user.display(),
        lookup = lookup.display(),
        control = knsh_core::CONTROL_SERVICE,
    );
    // Positive controls: outside any envelope `user.sock` accepts, and the control service lookup is not refused
    // (the name is merely unregistered here).
    let free = unconfined(&probes);
    assert_eq!(field(&free, "user_sock"), Some("0"), "{free}");
    assert_ne!(field(&free, "control"), Some(BOOTSTRAP_NOT_PRIVILEGED), "{free}");

    let script = format!(
        "{probes}nc -U -w 3 '{agent}' < '{requests}' > '{answers}' 2>/dev/null; echo agent_sock=$?\n",
        agent = agent.display(),
        requests = requests.display(),
        answers = answers.display(),
    );
    let (status, out) = stack.envelope("it", &script);
    assert_eq!(status, LineStatus::Exited(0), "{out}");
    assert_eq!(field(&out, "user_sock"), Some("1"), "user.sock reached: {out}");
    assert_eq!(field(&out, "control"), Some(BOOTSTRAP_NOT_PRIVILEGED), "{out}");

    // On agent.sock: `hello` binds the envelope's session by audit token; the approval and grant methods are not
    // listed and are never served, whatever their parameters: a method the catalogue keeps to other endpoints is
    // refused before any handler runs (`-32003`, or `-32601` for one it does not know at all).
    let answered = messages(&std::fs::read(&answers).unwrap());
    assert_eq!(answered.len(), 4, "{answered:?}");
    let Message::Success(hello) = &answered[0] else {
        panic!("hello refused: {:?}", answered[0]);
    };
    let methods = hello
        .result
        .as_object()
        .and_then(|result| result.get("capabilities"))
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("methods"))
        .and_then(Value::as_array)
        .unwrap();
    let methods: Vec<&str> = methods.iter().filter_map(Value::as_str).collect();
    assert!(methods.contains(&"exec.run"), "{methods:?}");
    for method in ["approval.approve", "approval.deny", "policy.grant", "approval.list"] {
        assert!(!methods.contains(&method), "{method} offered on agent.sock");
    }
    for answer in &answered[1..] {
        let Message::Error(error) = answer else {
            panic!("answered on agent.sock: {answer:?}");
        };
        assert!(
            matches!(error.error.code, ErrorCode::NotAllowed | ErrorCode::MethodNotFound),
            "{answer:?}"
        );
    }
    case.pending(
        "a user approval needs Touch ID or the password in the prompt knshd shows (FR-AUTH-41 – FR-AUTH-43): it \
         cannot be passed without a person at the machine",
    );
    case.passed();
}

// Row "An agent slips past command rules", interpreters (FR-POL-20, FR-POL-21, FR-NET-11): `python3 -c` running
// `git push` is dynamic code, so even allowed it reaches `network.hosts` only and never an approval host: the real
// proxy refuses github.com with `dynamic_code` and nothing reaches it. Positive controls: the same Python line
// reaches a host in `network.hosts`, and a plain `git push` is refused for want of an approval, not as dynamic code.
#[test]
fn python_subprocess_git_push_cannot_reach_approval_host() {
    let Some((case, bins)) = binaries(Case::start("python_subprocess_git_push_cannot_reach_approval_host")) else {
        return;
    };
    let stack = Stack::start("python", &bins);
    let developer = developer_dir();
    stack.profile(
        "net",
        &format!(
            "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\nallow = [\"python3\", \"git\"]\ntrusted_folders = [\"{}\"]\n\
             [network]\nmode = \"allowlist\"\nhosts = [\"allowed.test\", \"127.0.0.1\"]\n\
             approval_hosts = [\"github.com\"]\n",
            developer.display()
        ),
    );
    let (server, received) = recording_tcp();
    let localhost = [server.ip()];
    stack.resolver.answer("github.com", &localhost);
    stack.resolver.answer("allowed.test", &localhost);
    let git = |args: &str| {
        let status = Command::new("/usr/bin/git")
            .args(args.split(' '))
            .current_dir(&stack.project)
            .env("HOME", &stack.home)
            .status()
            .unwrap();
        assert!(status.success(), "git {args}");
    };
    git("init -q");
    git("-c user.name=t -c user.email=t@t commit -q --allow-empty -m init");
    let python_push = |host: &str| {
        format!(
            "python3 -c \"import subprocess; subprocess.run(['git', 'push', 'https://{host}:{port}/knsh/none.git', \
             'HEAD:main'])\"",
            port = server.port()
        )
    };
    let env = [("GIT_TERMINAL_PROMPT", "0")];
    let session = stack.session("net");
    let entries = |command: &str| {
        let finished = stack.line(session, command, &env).unwrap();
        stack.record_of(session, &finished).details.network
    };

    // Positive control: the Python line reaches a host in `network.hosts`; its ClientHello arrives.
    let allowed = entries(&python_push("allowed.test"));
    assert!(contacted(&allowed, "allowed.test"), "{allowed:?}");
    assert!(first_bytes_arrive(&received));

    // The attack: dynamic code, allowed by `python3`'s rule, asks for the approval host.
    let pushed = entries(&python_push("github.com"));
    assert!(refused_for(&pushed, "github.com", "dynamic_code"), "{pushed:?}");
    assert!(
        !pushed.iter().any(|entry| entry.result == NetworkResult::Contacted),
        "{pushed:?}"
    );
    // Control: the same push written plainly is refused for the approval it lacks, not as dynamic code.
    let plain = entries(&format!(
        "git push https://github.com:{}/knsh/none.git HEAD:main",
        server.port()
    ));
    assert!(refused_for(&plain, "github.com", "approval_required"), "{plain:?}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        received.lock().unwrap().iter().all(Vec::is_empty),
        "bytes reached the approval host"
    );
    case.passed();
}

// Row "An agent slips past command rules", `eval`, wrappers and absolute paths (FR-LC-05, FR-POL-20, FR-SBX-04): a
// denied program stays denied whatever wrapper or spelling names it, and dynamic code that the profile lets run is
// still confined by the sandbox: it can write its write roots and nothing else.
#[test]
fn eval_and_absolute_path_bypass_stay_inside_profile() {
    let Some((case, bins)) = binaries(Case::start("eval_and_absolute_path_bypass_stay_inside_profile")) else {
        return;
    };
    let stack = Stack::start("eval", &bins);
    stack.profile(
        "rules",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"touch\", \"ls\"]\ndeny = [\"rm\"]\ndefault = \"allow\"\n",
    );
    let session = stack.session("rules");
    let keep = stack.project.join("keep");
    std::fs::write(&keep, "keep").unwrap();
    let victim = stack.outside.join("victim");
    std::fs::write(&victim, "victim").unwrap();

    // Classified: every spelling and wrapper of `rm` is the denied `rm`.
    for command in [
        "rm -f keep",
        "/bin/rm -f keep",
        "env rm -f keep",
        "/usr/bin/env rm -f keep",
        "command rm -f keep",
        "nice rm -f keep",
        "nohup rm -f keep",
        "env -i /bin/rm -f keep",
        "ls; rm -f keep",
        "echo $(rm -f keep)",
    ] {
        let denied = denial(&stack.line(session, command, &[]));
        assert_eq!(denied.rule_id.as_deref(), Some("exec.deny[0]"), "{command}: {denied:?}");
        assert!(exists(&keep), "{command} removed the file");
    }

    // Confined: dynamic code the profile allows runs, inside its write roots only.
    let planted = |name: &str| stack.outside.join(name);
    let outside = stack.outside.display();
    let attempts = [
        format!("eval \"touch {outside}/eval\""),
        format!("eval \"\\$(printf rm) -f {outside}/victim\""),
        format!("sh -c 'touch {outside}/sh'"),
        format!("bash -c 'echo x > {outside}/bash'"),
        format!("x=touch; $x {outside}/var"),
        format!("/usr/bin/touch {outside}/abs"),
    ];
    for command in &attempts {
        let answer = stack.line(session, command, &[]);
        assert_ne!(exit_code(&answer), 0, "{command}: {:?}", answer.as_ref().map(output));
    }
    for name in ["eval", "sh", "bash", "var", "abs"] {
        assert!(!exists(&planted(name)), "{name} wrote outside the profile");
    }
    assert!(exists(&victim), "dynamic code removed a file outside the profile");
    // Positive control: the same dynamic forms run, and write where the profile lets them.
    for command in ["eval \"touch evaled\"", "sh -c 'touch shelled'", "x=touch; $x varied"] {
        assert_eq!(exit_code(&stack.line(session, command, &[])), 0, "{command}");
    }
    for name in ["evaled", "shelled", "varied"] {
        assert!(exists(&stack.project.join(name)), "{name}");
    }
    case.passed();
}

// Row "A binary is swapped between classification and execution" (FR-LC-13, FR-LC-15, FR-SBX-04): a program planted
// after the line was decided cannot be executed (the kernel refuses it at exec), and a name that resolved to a
// trusted binary runs that binary by its absolute path even if one of the same name is planted earlier on `PATH`.
#[test]
fn binary_swapped_after_classification_cannot_exec() {
    let Some((case, bins)) = binaries(Case::start("binary_swapped_after_classification_cannot_exec")) else {
        return;
    };
    let stack = Stack::start("swap", &bins);
    stack.profile(
        "swap",
        &format!(
            "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\nallow = [\"git\", \"printf\", \"chmod\", \"mkdir\"]\n\
             default = \"allow\"\nproject_executables = \"deny\"\ntrusted_folders = [\"{}\"]\n",
            developer_dir().display()
        ),
    );
    let session = stack.session("swap");
    let project = stack.project.display();
    let plant = |path: &str, marker: &str| {
        format!("printf '#!/bin/sh\\ntouch {project}/{marker}\\n' > {path} && chmod +x {path}")
    };

    // Planted after classification: `./tool` did not exist when the line was decided (so `exec.default` decided
    // it); it exists when the line runs, and the kernel refuses to execute it.
    let answer = stack.line(session, &format!("{} && ./tool", plant("tool", "ran")), &[]);
    assert_ne!(exit_code(&answer), 0, "{:?}", answer.as_ref().map(output));
    assert!(!exists(&stack.project.join("ran")), "the planted program ran");
    // Positive control: the planted program itself works outside the sandbox.
    let control = Command::new(stack.project.join("tool")).status().unwrap();
    assert!(control.success() && exists(&stack.project.join("ran")));
    std::fs::remove_file(stack.project.join("ran")).unwrap();
    // Present at classification, it is a project executable, and the profile denies those.
    let denied = denial(&stack.line(session, "./tool", &[]));
    assert_eq!(
        denied.rule_id.as_deref(),
        Some("exec.project_executables"),
        "{denied:?}"
    );

    // Shadowed after classification: `git` resolved to `/usr/bin/git` on the line's `PATH`, so the line runs that
    // path even though a `git` planted first on `PATH` exists by the time the command runs.
    let path = format!("{project}/bin:{PATH}");
    let command = format!("mkdir -p bin && {} && git --version", plant("bin/git", "shadow"));
    let finished = stack
        .line_with(session, &command, &[], &path, Some(LINE_TIMEOUT_S))
        .unwrap();
    let (stdout, stderr) = output(&finished);
    assert_eq!(finished.status, LineStatus::Exited(0), "{stdout} {stderr}");
    assert!(stdout.starts_with("git version"), "{stdout} {stderr}");
    assert!(
        finished.executed_command.expose().contains("/usr/bin/git --version"),
        "{}",
        finished.executed_command.expose()
    );
    assert!(!exists(&stack.project.join("shadow")), "the shadowing git ran");
    case.passed();
}

// Row "An agent escapes through LaunchServices, Apple Events or launchd" (FR-SBX-02): under the built-in
// `unattended` profile `open`, `osascript` and `launchctl` are denied by rule, however they are spelled; under a
// profile that allows them, the sandbox still refuses LaunchServices, Apple Events and launchd job creation.
#[test]
fn open_osascript_launchctl_denied_by_rule_and_profile() {
    let Some((mut case, bins)) = binaries(Case::start("open_osascript_launchctl_denied_by_rule_and_profile")) else {
        return;
    };
    let stack = Stack::start("svc", &bins);
    let label = format!("knsh.threat-model.{}", std::process::id());
    let finder = "osascript -e 'tell application \"Finder\" to get version'";
    let submit = format!("launchctl submit -l {label} -- /usr/bin/true");

    // By rule.
    let unattended = stack.session(knsh_core::UNATTENDED_PROFILE);
    for command in [
        "open -g -a Safari",
        "/usr/bin/open -g -a Safari",
        finder,
        "env osascript -e 1",
        &submit,
        "launchctl list",
    ] {
        let denied = denial(&stack.line(unattended, command, &[]));
        assert!(
            denied
                .rule_id
                .as_deref()
                .is_some_and(|rule| rule.starts_with("exec.deny[")),
            "{command}: {denied:?}"
        );
    }

    // By profile: allowed by rule, refused by the sandbox. `osascript` hangs rather than fails when Apple Events
    // are denied (KNSH-025, C8), so it is killed at its timeout; either way it never got its answer.
    stack.profile(
        "svc",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"open\", \"osascript\", \"launchctl\"]\n",
    );
    let session = stack.session("svc");
    let opened = stack.line(session, "open -g -a Safari", &[]);
    assert_ne!(exit_code(&opened), 0, "LaunchServices opened Safari");
    match stack.line_with(session, finder, &[], PATH, Some(5)) {
        Ok(finished) => assert_ne!(finished.status, LineStatus::Exited(0), "{:?}", output(&finished)),
        Err(error) => assert_eq!(error.code, ErrorCode::LineTimedOut, "{error:?}"),
    }
    let listed = |label: &str| {
        Command::new("/bin/launchctl")
            .args(["list", label])
            .output()
            .unwrap()
            .status
            .success()
    };
    // Never leave a job behind, even when the test fails.
    let remove = |label: &str| {
        let _ = Command::new("/bin/launchctl").args(["remove", label]).output();
    };
    // Positive control: unsandboxed, the same `launchctl submit` creates the job, so its absence below is the
    // sandbox's doing. A runner whose session cannot take jobs at all leaves that part pending, never passed.
    // Under a label of its own, so a slow removal cannot be mistaken for the line's job.
    let control_label = format!("{label}.control");
    let free = Command::new("/bin/launchctl")
        .args(["submit", "-l", &control_label, "--", "/usr/bin/true"])
        .output()
        .unwrap();
    let control = free.status.success() && listed(&control_label);
    remove(&control_label);
    if !control {
        case.pending("launchd job creation could not be observed outside the sandbox on this machine");
    }
    let submitted = stack.line(session, &submit, &[]);
    let created = listed(&label);
    remove(&label);
    assert!(!created, "a launchd job was created from a line");
    assert_ne!(exit_code(&submitted), 0, "launchctl submit succeeded");
    case.passed();
}

// Row "An agent plants code that runs later outside the sandbox" (FR-SBX-02): with the whole home as a write root,
// writes to git hooks and configuration, shell startup files and `~/Library/LaunchAgents` are still refused, from a
// supervised line and from the envelope itself; the `.git` directory cannot be moved away either. Positive control:
// other files in the same directories are written.
#[test]
fn writes_to_git_hooks_config_rc_files_launchagents_denied() {
    let Some((case, bins)) = binaries(Case::start("writes_to_git_hooks_config_rc_files_launchagents_denied")) else {
        return;
    };
    let stack = Stack::start("plant", &bins);
    stack.profile(
        "plant",
        &format!(
            "[fs]\nwrite = [\"{}\"]\n[exec]\ndefault = \"allow\"\n",
            stack.home.display()
        ),
    );
    let status = Command::new("/usr/bin/git")
        .args(["init", "-q"])
        .current_dir(&stack.project)
        .status()
        .unwrap();
    assert!(status.success());
    let launch_agents = stack.home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&launch_agents).unwrap();
    let git = stack.project.join(".git");
    let (hook, config) = (git.join("hooks/pre-commit"), git.join("config"));
    let (zshrc, bashrc, profile, zshenv) = (
        stack.home.join(".zshrc"),
        stack.home.join(".bashrc"),
        stack.home.join(".profile"),
        stack.home.join(".zshenv"),
    );
    let plist = launch_agents.join("evil.plist");
    let (notes, head) = (stack.home.join("notes"), git.join("HEAD"));
    let script = format!(
        "{}mv '{}' '{}' 2>/dev/null; echo moved=$?\n",
        write_probes(&[
            ("hook", &hook),
            ("config", &config),
            ("zshrc", &zshrc),
            ("bashrc", &bashrc),
            ("profile", &profile),
            ("zshenv", &zshenv),
            ("plist", &plist),
            ("notes", &notes),
            ("head", &head),
        ]),
        git.display(),
        stack.project.join("git-old").display(),
    );
    let config_before = std::fs::read(&config).unwrap();
    let check = |who: &str, out: &str| {
        for key in [
            "hook", "config", "zshrc", "bashrc", "profile", "zshenv", "plist", "moved",
        ] {
            assert_eq!(field(out, key), Some("1"), "{who}: {key} written: {out}");
        }
        for key in ["notes", "head"] {
            assert_eq!(field(out, key), Some("0"), "{who}: {key} not written: {out}");
        }
        for path in [&hook, &zshrc, &bashrc, &profile, &zshenv, &plist] {
            assert!(!exists(path), "{who}: {} planted", path.display());
        }
        assert_eq!(
            std::fs::read(&config).unwrap(),
            config_before,
            "{who}: .git/config changed"
        );
        assert!(exists(&git), "{who}: .git moved");
    };

    let session = stack.session("plant");
    let finished = stack.line(session, &script, &[]).unwrap();
    check("line", &output(&finished).0);
    let (status, out) = stack.envelope("plant", &script);
    assert_eq!(status, LineStatus::Exited(0), "{out}");
    check("envelope", &out);
    case.passed();
}

// Row "An agent edits policy, hooks or trust" (FR-POL-40 – FR-POL-42, FR-HOOK-07, FR-AUTH-11, FR-POL-30): the engine
// paths (policies, the configuration file that holds hooks, the record store, the compiled profiles) can be neither
// written nor read from a line or the envelope, even under a write root above them. A policy file changed anyway
// (by something outside every session) is ignored: the line is denied, `policy.invalid` names the profile, and the
// rule the edit removed still holds because nothing runs at all.
#[test]
fn agent_cannot_edit_policy_hooks_or_trust() {
    let Some((mut case, bins)) = binaries(Case::start("agent_cannot_edit_policy_hooks_or_trust")) else {
        return;
    };
    let stack = Stack::start("policy", &bins);
    let profile_text = format!(
        "[fs]\nwrite = [\"{}\"]\n[exec]\nallow = [\"ls\", \"cat\"]\ndeny = [\"rm\"]\ndefault = \"allow\"\n",
        stack.home.display()
    );
    stack.profile("edit", &profile_text);
    let policy = stack.policy_file("edit");
    let config = stack.paths.config_file();
    std::fs::write(&config, "[[hooks]]\n").unwrap();
    let records = stack.paths.data_dir().join("records.db");
    let compiled = stack.paths.profiles_dir().join("planted.sb");
    let new_policy = stack.paths.policies_dir().join("mine.toml");
    let policy_before = std::fs::read(&policy).unwrap();
    let script = format!(
        "{}cat '{}' >/dev/null 2>&1; echo read_policy=$?\nmv '{}' '{}' 2>/dev/null; echo moved=$?\n",
        write_probes(&[
            ("policy", &policy),
            ("new_policy", &new_policy),
            ("hooks", &config),
            ("records", &records),
            ("profiles", &compiled),
        ]),
        policy.display(),
        stack.paths.config_dir().display(),
        stack.home.join("config-moved").display(),
    );
    let check = |who: &str, out: &str| {
        for key in [
            "policy",
            "new_policy",
            "hooks",
            "records",
            "profiles",
            "read_policy",
            "moved",
        ] {
            assert_eq!(field(out, key), Some("1"), "{who}: {key}: {out}");
        }
        assert_eq!(std::fs::read(&policy).unwrap(), policy_before, "{who}: policy changed");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "[[hooks]]\n",
            "{who}: hooks changed"
        );
        assert!(!exists(&new_policy), "{who}: a new policy was written");
    };
    let session = stack.session("edit");
    let finished = stack.line(session, &script, &[]).unwrap();
    check("line", &output(&finished).0);
    let (status, out) = stack.envelope("edit", &script);
    assert_eq!(status, LineStatus::Exited(0), "{out}");
    check("envelope", &out);

    // A tampered file: the deny of `rm` removed, the old signature kept.
    let victim = stack.project.join("victim");
    std::fs::write(&victim, "victim").unwrap();
    assert_eq!(
        denial(&stack.line(session, "rm -f victim", &[])).rule_id.as_deref(),
        Some("exec.deny[0]")
    );
    let tampered = String::from_utf8(policy_before)
        .unwrap()
        .replace("deny = [\"rm\"]", "deny = []");
    std::fs::write(&policy, tampered).unwrap();
    let watcher = stack.watch();
    let denied = denial(&stack.line(session, "rm -f victim", &[]));
    assert!(denied.rule_id.is_none(), "{denied:?}");
    assert!(exists(&victim), "the tampered policy was used");
    let invalid: Vec<String> = watcher
        .take(100)
        .into_iter()
        .filter_map(|(_, delivery)| match delivery {
            knsh_core::Delivery::Event(event) => match &event.data {
                EventData::PolicyInvalid { profile } => Some(profile.as_str().to_owned()),
                _ => None,
            },
            knsh_core::Delivery::Lost(_) | knsh_core::Delivery::Engine(_) | knsh_core::Delivery::EngineLost(_) => None,
        })
        .collect();
    assert_eq!(invalid, ["edit"]);
    // Even `ls`, which the tampered text still allows, does not run: the whole file is ignored.
    assert_eq!(denial(&stack.line(session, "ls", &[])).rule_id, None);

    case.pending(
        "authority trust lives in the Keychain under an item only a Developer ID-signed knshd can read \
         (FR-AUTH-11): its access control cannot be observed with this ad-hoc-signed build",
    );
    case.passed();
}

// Row "An agent kills `knshd` or squats its endpoints" (NFR-REL-01, decision 8): from the envelope and from a line,
// neither `knshd` (this test process stands for it) nor another process outside the sandbox can be signalled, and
// the endpoint sockets cannot be removed or replaced. Lines run through `knsh -c` while `knshd` serves; once it is
// gone, the same line does not run.
#[test]
fn envelope_cannot_signal_knshd_and_lines_stop_when_it_dies() {
    let Some((case, bins)) = binaries(Case::start("envelope_cannot_signal_knshd_and_lines_stop_when_it_dies")) else {
        return;
    };
    let stack = Stack::start("kill", &bins);
    stack.profile(
        "kill",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"touch\", \"kill\"]\ndefault = \"allow\"\n",
    );
    let mut sleeper = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let (knshd, other) = (std::process::id(), sleeper.id());
    // Positive control: unsandboxed, the same user may signal both.
    let free = unconfined(&format!(
        "kill -0 {knshd}; echo knshd=$?\nkill -0 {other}; echo other=$?\n"
    ));
    assert_eq!(
        (field(&free, "knshd"), field(&free, "other")),
        (Some("0"), Some("0")),
        "{free}"
    );

    let agent = stack.paths.agent_socket();
    let signals = format!(
        "kill -0 {knshd} 2>/dev/null; echo knshd=$?\nkill -TERM {other} 2>/dev/null; echo other=$?\n\
         rm -f '{agent}' 2>/dev/null; echo unlink=$?\nmv '{agent}' '{agent}.old' 2>/dev/null; echo moved=$?\n",
        agent = agent.display(),
    );
    let session = stack.session("kill");
    let finished = stack.line(session, &signals, &[]).unwrap();
    let from_line = output(&finished).0;
    for key in ["knshd", "other", "unlink", "moved"] {
        assert_eq!(field(&from_line, key), Some("1"), "line: {key}: {from_line}");
    }

    let flag = stack.outside.join("gone");
    let (before, after) = (stack.project.join("before"), stack.project.join("after"));
    let script = format!(
        "{signals}\"$SHELL\" -c 'touch {before}'; echo before=$?\n\
         while [ ! -f '{flag}' ]; do sleep 0.1; done\n\
         \"$SHELL\" -c 'touch {after}' 2>/dev/null; echo after=$?\n",
        before = before.display(),
        flag = flag.display(),
        after = after.display(),
    );
    let (served, (status, out)) = std::thread::scope(|scope| {
        let envelope = scope.spawn(|| stack.envelope("kill", &script));
        let served = wait_for(Duration::from_secs(30), || exists(&before));
        // Stop and release the envelope before asserting: a panic here would leave the scope waiting forever on an
        // envelope that polls for the flag.
        stack.stop_knshd();
        std::fs::write(&flag, "").unwrap();
        (served, envelope.join().unwrap())
    });
    assert!(served, "no line ran while knshd served: {out}");
    assert_eq!(status, LineStatus::Exited(0), "{out}");
    for key in ["knshd", "other", "unlink", "moved"] {
        assert_eq!(field(&out, key), Some("1"), "envelope: {key}: {out}");
    }
    assert!(agent.exists(), "agent.sock was removed");
    assert_eq!(sleeper.try_wait().unwrap(), None, "the other process was signalled");
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    assert_eq!(field(&out, "before"), Some("0"), "{out}");
    assert_ne!(field(&out, "after"), Some("0"), "a line ran with knshd gone: {out}");
    assert!(!exists(&after), "a line ran with knshd gone");
    case.passed();
}

// Row "An impostor daemon or authority" (FR-AUTH-12 – FR-AUTH-15): an authority signed ad hoc (here, by the linker)
// does not meet the peer requirement `knshd` compiles for the trusted authority, checked by the Security framework;
// the same binary verifies without a requirement, so the refusal is the requirement's. With no authority trusted,
// every peer is refused.
#[test]
fn impostor_authority_refused() {
    use knsh_platform::{
        BundleVersion, CodeSigning, PeerGate, PeerRejection, SignatureFacts, SigningIdentifier, TeamId,
        TrustedAuthority, peer_requirement,
    };

    /// A peer that presents what an ad-hoc-signed process presents.
    struct AdHoc;
    impl CodeSigning<()> for AdHoc {
        fn inspect(&self, (): &()) -> Result<SignatureFacts, knsh_platform::PlatformError> {
            Ok(SignatureFacts {
                requirement_met: false,
                signature_flags: 0x2,
                status: 0x2201_0011,
                bundle_version: Some("9.9".to_owned()),
            })
        }
    }

    let mut case = Case::start("impostor_authority_refused");
    let dir = Scratch::new("impostor");
    let impostor = dir.0.join("authority");
    compile_c("int main(void) { return 0; }\n", &impostor);

    let trusted = TrustedAuthority {
        team_id: TeamId::new("ABCDE12345").unwrap(),
        identifier: SigningIdentifier::new("com.example.authority").unwrap(),
        min_version: BundleVersion::parse("1.0").unwrap(),
    };
    let requirement = peer_requirement(&trusted);
    // The requirement compiles, as knshd compiles it for XPC.
    knsh_platform::macos::SecCodeSigning::new(&requirement).unwrap();
    let codesign = |args: &[&str]| {
        Command::new("/usr/bin/codesign")
            .args(args)
            .arg(&impostor)
            .output()
            .unwrap()
    };
    let shown = codesign(&["-dv"]);
    assert!(
        String::from_utf8_lossy(&shown.stderr).contains("Signature=adhoc"),
        "{shown:?}"
    );
    assert!(
        codesign(&["--verify"]).status.success(),
        "the impostor is validly signed"
    );
    let checked = codesign(&["--verify", &format!("-R={requirement}")]);
    // Exit 3 is "failed to satisfy the requirement"; any other failure (1: a requirement codesign cannot read) would
    // be a refusal for an unrelated reason.
    assert_eq!(
        checked.status.code(),
        Some(3),
        "the ad-hoc authority was not refused by the peer requirement: {checked:?}"
    );

    // The gate refuses such a peer on the facts alone, and refuses everyone while no authority is trusted.
    assert_eq!(
        PeerGate::new(Some(trusted)).admit(&AdHoc, &()),
        Err(PeerRejection::RequirementNotMet)
    );
    assert_eq!(
        PeerGate::new(None).admit(&AdHoc, &()),
        Err(PeerRejection::NoTrustedAuthority)
    );

    case.pending(
        "a Developer ID-signed authority accepted, and an impostor refused, by the launchd-registered control \
         service over XPC, and the authority checking knshd's own signature, need Developer ID-signed builds and a \
         launchd job (FR-AUTH-12 – FR-AUTH-15)",
    );
    case.passed();
}

// Row "An agent leaks a secret" (FR-SEC-03, decision 8): process information is limited to the command's own
// sandbox: a line cannot read another line's arguments (`KERN_PROCARGS2`), where a secret it was given shows, while
// the same read succeeds outside any sandbox.
#[test]
fn secret_not_visible_to_other_process_groups() {
    let Some((mut case, bins)) = binaries(Case::start("secret_not_visible_to_other_process_groups")) else {
        return;
    };
    let stack = Stack::start("secret", &bins);
    let procargs = stack.build_probe("procargs", PROCARGS_C);
    stack.profile(
        "secret",
        &format!(
            "[fs]\nwrite = [\"${{PROJECT}}\"]\n[exec]\ndefault = \"allow\"\ntrusted_folders = [\"{}\"]\n",
            stack.tools.display()
        ),
    );
    let session = stack.session("secret");
    let secret = format!(
        "s3cret-{}-{}",
        std::process::id(),
        Ulid::from_u128(u128::from(std::process::id()))
    );
    let pid_file = stack.project.join("holder.pid");
    // The secret is in the holder's environment and, expanded, in its arguments: recent macOS no longer shows
    // another process's environment even outside a sandbox, but still shows its arguments, so the outside read
    // below finds it there. `; :` keeps `sh` from replacing itself with `sleep`, which would drop the arguments.
    let holder = format!(
        "echo $$ > {}; exec /bin/sh -c 'sleep 8; :' \"$KNSH_TM_SECRET\"",
        pid_file.display()
    );
    std::thread::scope(|scope| {
        let holding = scope.spawn(|| stack.line(session, &holder, &[("KNSH_TM_SECRET", &secret)]));
        assert!(wait_for(Duration::from_secs(20), || std::fs::read_to_string(&pid_file)
            .is_ok_and(|text| text.ends_with('\n'))));
        let pid = std::fs::read_to_string(&pid_file).unwrap().trim().to_owned();
        let probe = format!("'{}' {pid} '{secret}'", procargs.display());
        // Positive control: outside any sandbox the holder's arguments show the secret.
        assert_eq!(unconfined(&probe).trim(), "found");
        let finished = stack.line(session, &probe, &[]).unwrap();
        let (stdout, stderr) = output(&finished);
        assert!(stdout.starts_with("refused "), "{stdout} {stderr}");
        assert_eq!(exit_code(&holding.join().unwrap()), 0);
    });
    case.pending(
        "secret injection and network narrowing (FR-SEC-01 – FR-SEC-04) are tested by \
         injected_secret_reaches_only_its_hosts; this case covers the process-information limit (FR-SEC-05)",
    );
    case.passed();
}

// Row "An agent leaks a secret" (FR-SEC-01 – FR-SEC-04, FR-SEC-06, FR-NET-10; KNSH-092): a granted `curl` matching
// `inject_for` is given the secret, which its output shows only redacted, and reaches the secret's host through the
// real proxy; the same line sending it to another host of `network.hosts` is refused (`secret_hosts`) and no byte
// arrives. Positive control: without the secret (`ls`-only line), that other host is reached.
#[test]
fn injected_secret_reaches_only_its_hosts() {
    let Some((case, bins)) = binaries(Case::start("injected_secret_reaches_only_its_hosts")) else {
        return;
    };
    let token = format!(
        "ghp_tm{}x{}",
        std::process::id(),
        Ulid::from_u128(u128::from(std::process::id()))
    );
    let secrets = crate::redaction::tests::FakeSecrets::default();
    secrets
        .stored
        .lock()
        .unwrap()
        .push(("gh-token", Box::leak(token.clone().into_boxed_str())));
    let stack = Stack::start_with(
        "inject",
        &bins,
        super::harness::Wiring {
            redactors: Some(crate::redaction::Redactors::new(std::sync::Arc::new(secrets))),
            ..super::harness::Wiring::default()
        },
    );
    // The test server is on loopback, so its address is listed in both `network.hosts` and the secret's `hosts`
    // (FR-NET-07); the names decide.
    stack.profile(
        "inject",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"curl\", \"printenv\"]\n[network]\nmode = \"allowlist\"\n\
         hosts = [\"allowed.test\", \"other.test\", \"127.0.0.1\"]\n[secrets.env]\n\
         GH_TOKEN = { secret = \"gh-token\", inject_for = [\"curl\"], hosts = [\"allowed.test\", \"127.0.0.1\"] }\n",
    );
    let (server, received) = recording_tcp();
    stack.resolver.answer("allowed.test", &[server.ip()]);
    stack.resolver.answer("other.test", &[server.ip()]);
    let session = stack.session("inject");
    let now = knsh_platform::macos::SystemClock::new().now().unwrap();
    let expires = Timestamp::from_unix_micros(now.as_unix_micros() + 3_600_000_000).unwrap();
    let grant = Grant::new(
        GrantId::from_ulid(Ulid::from_u128(92)),
        GrantScope::Session(session),
        "curl",
        expires,
    );
    stack.grants.insert(grant.unwrap(), now).unwrap();
    let port = server.port();
    let line = |host: &str| {
        let command = format!("curl -s -m 10 https://{host}:{port}/; printenv GH_TOKEN");
        let finished = stack.line(session, &command, &[]).unwrap();
        let record = stack.record_of(session, &finished);
        (output(&finished).0, record)
    };

    // The secret's host: reached, its ClientHello arrives; the line had the token, shown only redacted.
    let (stdout, record) = line("allowed.test");
    assert!(contacted(&record.details.network, "allowed.test"), "{record:?}");
    assert!(first_bytes_arrive(&received));
    assert_eq!(stdout.trim(), "«redacted:gh-token»");
    assert_eq!(record.details.secrets_injected, ["gh-token"]);
    assert_eq!(record.details.decision.unwrap().source, DecisionSource::Grant);

    // Another host the profile opens: refused to this line, and nothing arrives.
    let (stdout, record) = line("other.test");
    assert!(
        refused_for(&record.details.network, "other.test", "secret_hosts"),
        "{record:?}"
    );
    assert!(
        !record
            .details
            .network
            .iter()
            .any(|entry| entry.result == NetworkResult::Contacted),
        "{record:?}"
    );
    assert_eq!(stdout.trim(), "«redacted:gh-token»");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        received.lock().unwrap().iter().all(Vec::is_empty),
        "bytes reached other.test"
    );
    assert!(!format!("{record:?}").contains(&token));

    // Positive control: the same line under the same network without `[secrets.env]` receives nothing and reaches
    // that host.
    stack.profile(
        "plain",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"curl\", \"printenv\"]\n[network]\nmode = \"allowlist\"\n\
         hosts = [\"allowed.test\", \"other.test\", \"127.0.0.1\"]\n",
    );
    let plain = stack.session("plain");
    let finished = stack
        .line(
            plain,
            &format!("curl -s -m 10 https://other.test:{port}/; printenv GH_TOKEN"),
            &[],
        )
        .unwrap();
    let record = stack.record_of(plain, &finished);
    assert!(contacted(&record.details.network, "other.test"), "{record:?}");
    assert!(first_bytes_arrive(&received));
    assert_eq!(output(&finished).0, "");
    assert_eq!(record.details.secrets_injected, Vec::<String>::new());
    case.passed();
}

// Row "An agent sends data out" (FR-NET-01 – FR-NET-08): through the real proxy, an IP literal, a name resolving to
// a private address and a TLS hello naming another host than the tunnel's are each refused, with the reason in the
// line's record, and no byte reaches the destination; a direct DNS query to a server of the line's choosing and the
// system resolver's socket are refused by the sandbox. Positive controls: a host in `network.hosts` is reached, and
// the DNS query arrives when sent from outside the sandbox.
#[test]
fn exfiltration_blocked_by_host_name_and_address_checks() {
    let Some((case, bins)) = binaries(Case::start("exfiltration_blocked_by_host_name_and_address_checks")) else {
        return;
    };
    let stack = Stack::start("exfil", &bins);
    stack.profile(
        "out",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\ndefault = \"allow\"\n[network]\nmode = \"allowlist\"\n\
         hosts = [\"allowed.test\", \"internal.test\", \"127.0.0.1\"]\n",
    );
    let (server, received) = recording_tcp();
    stack.resolver.answer("allowed.test", &[server.ip()]);
    stack.resolver.answer("internal.test", &["10.0.0.5".parse().unwrap()]);
    let session = stack.session("out");
    let port = server.port();
    let curl = |target: &str| {
        let finished = stack.line(session, &format!("curl -s -m 10 {target}"), &[]).unwrap();
        stack.record_of(session, &finished).details.network
    };
    let refused = |entries: &[NetworkEntry], host: &str, reason: &str| {
        assert!(
            refused_for(entries, host, reason),
            "{host} not refused with {reason}: {entries:?}"
        );
        assert!(
            !entries.iter().any(|entry| entry.result == NetworkResult::Contacted),
            "{entries:?}"
        );
    };

    // Positive control: a listed host is reached; its ClientHello arrives.
    let reached = curl(&format!("https://allowed.test:{port}/"));
    assert!(contacted(&reached, "allowed.test"), "{reached:?}");
    assert!(first_bytes_arrive(&received));

    refused(&curl(&format!("https://1.2.3.4:{port}/")), "1.2.3.4", "ip_literal");
    refused(
        &curl(&format!("https://internal.test:{port}/")),
        "internal.test",
        "address_not_allowed",
    );
    // A tunnel to a listed host carrying a hello for another (domain fronting).
    refused(
        &curl(&format!(
            "--connect-to example.test:{port}:allowed.test:{port} https://example.test:{port}/"
        )),
        "allowed.test",
        "server_name_mismatch",
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        received.lock().unwrap().iter().all(Vec::is_empty),
        "bytes reached a destination after a refusal"
    );

    // No local DNS: a query to a server the line names, and the system resolver's socket.
    let (dns, queries) = recording_udp();
    let dig = format!(
        "dig +time=1 +tries=1 -p {} @{} knsh.test >/dev/null 2>&1",
        dns.port(),
        dns.ip()
    );
    unconfined(&dig);
    assert!(wait_for(Duration::from_secs(5), || !queries.lock().unwrap().is_empty()));
    queries.lock().unwrap().clear();
    let resolver_socket = "nc -U -w 1 /var/run/mDNSResponder </dev/null >/dev/null 2>&1; echo resolver=$?";
    assert_eq!(field(&unconfined(resolver_socket), "resolver"), Some("0"));
    let finished = stack
        .line(session, &format!("{dig}; echo dig=$?\n{resolver_socket}\n"), &[])
        .unwrap();
    let out = output(&finished).0;
    assert_ne!(field(&out, "dig"), Some("0"), "{out}");
    assert_eq!(field(&out, "resolver"), Some("1"), "{out}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(queries.lock().unwrap().is_empty(), "a DNS query left the sandbox");
    case.passed();
}

// Row "Approval fatigue" (FR-HOOK-20, FR-POL-60 – FR-POL-70): five denials of one line within 60 s limit it, so the
// sixth is denied with source `rate_limit` before anything is asked; a grant answers the ask a line would otherwise
// raise, so it runs without one.
#[test]
fn repeated_denials_rate_limited_and_grants_reduce_asks() {
    let Some((mut case, bins)) = binaries(Case::start("repeated_denials_rate_limited_and_grants_reduce_asks")) else {
        return;
    };
    let stack = Stack::start("fatigue", &bins);
    stack.profile(
        "fatigue",
        "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nallow = [\"ls\"]\nask = [\"touch\"]\ndeny = [\"rm\"]\n",
    );
    let session = stack.session("fatigue");
    for attempt in 1..=5 {
        let denied = denial(&stack.line(session, "rm -f keep", &[]));
        assert_eq!(denied.source.as_deref(), Some("rule"), "attempt {attempt}: {denied:?}");
    }
    for _ in 0..2 {
        let limited = denial(&stack.line(session, "rm -f keep", &[]));
        assert_eq!(limited.source.as_deref(), Some("rate_limit"), "{limited:?}");
    }
    // Another line is decided as usual.
    assert_eq!(exit_code(&stack.line(session, "ls", &[])), 0);

    // Without a grant, `touch` asks; nobody answers, so it does not run (`-32002` at the ask's timeout).
    let granted = stack.project.join("granted");
    let asked = stack.line(session, "touch granted", &[]);
    assert_eq!(asked.as_ref().map(drop).unwrap_err().code, ErrorCode::DecisionTimeout);
    assert!(!exists(&granted));
    // With a session grant for `touch`, the same line runs, decided by the grant, without an ask.
    let now = knsh_platform::macos::SystemClock::new().now().unwrap();
    let expires = Timestamp::from_unix_micros(now.as_unix_micros() + 3_600_000_000).unwrap();
    let grant = Grant::new(
        GrantId::from_ulid(Ulid::from_u128(75)),
        GrantScope::Session(session),
        "touch",
        expires,
    )
    .unwrap();
    stack.grants.insert(grant, now).unwrap();
    let ran = stack.line(session, "touch granted", &[]);
    assert_eq!(exit_code(&ran), 0);
    assert!(exists(&granted));
    let decision = stack
        .record_of(session, ran.as_ref().unwrap())
        .details
        .decision
        .unwrap();
    assert_eq!(decision.source, DecisionSource::Grant);
    case.pending(
        "a grant made by the user goes through policy.grant on user.sock after Touch ID (FR-POL-60 – FR-POL-70, \
         KNSH-073); the prompt needs a person, so the grant is placed in the live store as that call would",
    );
    case.passed();
}
