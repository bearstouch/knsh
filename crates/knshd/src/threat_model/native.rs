//! KNSH-108 end to end: a native-mode session's lines through the real supervisor, the sandboxed `knsh` interpreter
//! (`--native-line`), the supervision channel and `knsh-exec`'s program mode, on this machine (FR-LC-50 to FR-LC-58).
//! Skipped when `knsh` and `knsh-exec` are not built beside the test binary (`cargo test -p knshd` alone).

use knsh_core::DecisionSource;

use super::harness::{Stack, built_binaries, exists, output};

/// Shell builtins and the tools the cases run are allowed, `rm` is denied; the project is writable.
const NATIVE: &str = "[fs]\nwrite = [\"${PROJECT}\"]\n[exec]\nmode = \"native\"\nallow = [\"cat\", \"touch\", \"ls\"]\n\
                      deny = [\"rm\"]\ndefault = \"allow\"\n";

// FR-LC-53 to FR-LC-56: every external command of a native-mode line is decided on its own, after expansion, and run
// by the supervisor; a denied one fails with 126 inside the script, its reason on stderr, and the script goes on as
// bash says.
#[test]
fn native_mode_decides_each_command_of_a_line() {
    let Some(bins) = built_binaries() else { return };
    let stack = Stack::start("native", &bins);
    stack.profile("native", NATIVE);
    let session = stack.session("native");
    let keep = stack.project.join("keep");
    std::fs::write(&keep, "keep").unwrap();

    // Builtins, a substitution, a redirection by the interpreter and a command it runs through the supervisor.
    let finished = stack
        .line(session, "x=$(printf hi); echo \"$x there\" > out.txt; cat out.txt", &[])
        .unwrap();
    let (stdout, stderr) = output(&finished);
    assert_eq!(stdout, "hi there\n", "stderr: {stderr}");
    assert_eq!(finished.decision.source, DecisionSource::Native);
    let line_record = finished.record_id.unwrap();
    let records = stack.records(session);
    let cat = records
        .iter()
        .find(|record| record.details.parent_record_id == Some(line_record))
        .unwrap_or_else(|| panic!("no command record: {records:?}"));
    assert!(cat.command.expose().ends_with("/cat out.txt"), "{:?}", cat.command);
    assert_eq!(cat.exit_code, Some(0));

    // `eval` builds `rm`: decided after expansion, denied, 126 in the script, which goes on.
    let finished = stack
        .line(session, "eval \"rm -f keep\"; echo \"status $?\"", &[])
        .unwrap();
    let (stdout, stderr) = output(&finished);
    assert_eq!(stdout, "status 126\n", "stderr: {stderr}");
    assert!(stderr.contains("knsh: rm: denied by rule (exec.deny[0])"), "{stderr}");
    assert!(exists(&keep), "the denied rm ran");

    // `set -e` ends the script at the denial.
    let finished = stack.line(session, "set -e; rm -f keep; echo after", &[]).unwrap();
    assert_eq!(finished.status, knsh_proto::LineStatus::Exited(126));
    assert_eq!(output(&finished).0, "");
    assert!(exists(&keep));
}

// FR-LC-52: what the interpreter does itself is confined by its own profile: a redirection outside the write roots
// fails, and an allowed command still cannot write there under its profile.
#[test]
fn native_interpreter_is_confined_by_its_profile() {
    let Some(bins) = built_binaries() else { return };
    let stack = Stack::start("natconf", &bins);
    stack.profile("native", NATIVE);
    let session = stack.session("native");
    let outside = stack.outside.display().to_string();
    let finished = stack
        .line(
            session,
            &format!("echo x > {outside}/redirected; touch {outside}/touched; touch inside; echo done"),
            &[],
        )
        .unwrap();
    let (stdout, stderr) = output(&finished);
    assert_eq!(stdout, "done\n", "stderr: {stderr}");
    assert!(
        !exists(&stack.outside.join("redirected")),
        "the interpreter wrote outside its profile"
    );
    assert!(
        !exists(&stack.outside.join("touched")),
        "a command wrote outside its profile"
    );
    assert!(exists(&stack.project.join("inside")));
}
