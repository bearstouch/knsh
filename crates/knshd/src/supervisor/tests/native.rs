//! KNSH-108: native-mode lines through the orchestrator, with a fake interpreter that speaks the real supervision
//! channel (FR-LC-50 to FR-LC-58).

use std::ffi::OsString;
use std::path::PathBuf;

use knsh_platform::supervision::Submission;

use super::*;

/// [`WEB`] in native mode.
const WEB_NATIVE: &str = "name = \"web\"\n[exec]\nmode = \"native\"\nallow = [\"git status\", \"ls\", \"echo\"]\n\
                          ask = [\"git push\"]\ndeny = [\"rm\"]\n";

/// A command as the interpreter submits it after expansion, with no descriptors (the fake passes none).
fn submitted(program: &str, args: &[&str]) -> Submission {
    Submission {
        program: PathBuf::from(program),
        argv0: OsString::from(program.rsplit('/').next().unwrap()),
        args: args.iter().map(OsString::from).collect(),
        env: vec![("PATH".into(), "/Users/u/.knsh/shims:/usr/bin:/bin".into())],
        cwd: PathBuf::from(PROJECT),
        umask: Some(0o022),
        descriptors: Vec::new(),
    }
}

fn native_setup(authority: Vec<AskReply>, commands: Vec<Submission>, journal: &Arc<Journal>) -> Setup {
    Setup {
        profiles: Some(vec![("web", WEB_NATIVE)]),
        authority: Some(authority),
        spawner: Some(FakeSpawner {
            native: commands,
            ..FakeSpawner::new(Arc::clone(journal))
        }),
        ..Setup::default()
    }
}

// Integration (story): an agent session in native mode runs `eval "git push"`; the authority is asked about `git
// push` itself, never about the `eval` line, and each command gets its own decision and record, linked to the line
// record (FR-LC-51, FR-LC-53, FR-LC-54).
#[test]
#[allow(clippy::too_many_lines)] // One end-to-end scenario: the decisions, the records and the events of one line.
fn native_line_asks_the_authority_for_the_command_eval_runs() {
    let daemon = Daemon::new();
    let commands = vec![
        submitted("/usr/bin/git", &["status"]),
        submitted("/usr/bin/git", &["push"]),
        submitted("/bin/rm", &["-rf", "build"]),
    ];
    let lifecycle = daemon.lifecycle(native_setup(vec![AskReply::Allow], commands, &daemon.journal));
    let finished = lifecycle
        .run(
            daemon.line("git status; eval \"git push\"; rm -rf build"),
            &StillWaiting,
        )
        .unwrap();
    assert_eq!(finished.status, LineStatus::Exited(0));
    assert_eq!(finished.decision.source, DecisionSource::Native);
    let entries = daemon.journal.entries();
    // The only ask is about `git push`, by the path it resolved to.
    let asks: Vec<&String> = entries.iter().filter(|entry| entry.starts_with("ask ")).collect();
    assert_eq!(asks, ["ask /usr/bin/git push"], "{entries:?}");
    // The line itself was never proposed to hooks or the authority, nor spawned as a stock line.
    assert!(
        !entries
            .iter()
            .any(|entry| entry.contains("eval") && (entry.starts_with("hooks") || entry.starts_with("spawn /"))),
        "{entries:?}"
    );
    assert!(entries.contains(&"spawn native git status; eval \"git push\"; rm -rf build".to_owned()));
    // Allowed commands started by the supervisor, in the line's group; the denied one never.
    let line_record = finished.record_id.unwrap();
    let ran: Vec<&String> = entries.iter().filter(|entry| entry.starts_with("command ")).collect();
    assert_eq!(ran.len(), 2, "{entries:?}");
    assert!(
        ran[0].starts_with("command /usr/bin/git [\"status\"] in group 4242"),
        "{ran:?}"
    );
    assert!(
        ran[1].starts_with("command /usr/bin/git [\"push\"] in group 4242"),
        "{ran:?}"
    );
    assert!(
        entries.contains(&"ran /usr/bin/git: Ok(Exited(7))".to_owned()),
        "{entries:?}"
    );
    let denied = entries
        .iter()
        .find(|entry| entry.starts_with("denied /bin/rm"))
        .unwrap();
    assert!(denied.contains("exec.deny[0]"), "{denied}");
    // FR-LC-58: once the interpreter ended, what was left of its group was killed.
    assert!(entries.contains(&"kill members of 4242".to_owned()), "{entries:?}");

    let records = daemon.records();
    assert_eq!(records.len(), 4);
    let line = records.iter().find(|record| record.record_id == line_record).unwrap();
    assert_eq!(line.details.parent_record_id, None);
    assert_eq!(line.details.decision.as_ref().unwrap().source, DecisionSource::Native);
    assert_eq!(line.details.decision.as_ref().unwrap().verdict, DecisionVerdict::Allow);
    assert!(line.details.argv.is_empty());
    assert_eq!(line.exit_code, Some(0));
    let commands: Vec<&ExecutionRecord> = records
        .iter()
        .filter(|record| record.record_id != line_record)
        .collect();
    assert!(
        commands
            .iter()
            .all(|record| record.details.parent_record_id == Some(line_record))
    );
    let by_command = |text: &str| {
        commands
            .iter()
            .find(|record| record.command.expose() == text)
            .unwrap_or_else(|| panic!("{text}: {commands:?}"))
    };
    let status = by_command("/usr/bin/git status");
    assert_eq!(status.exit_code, Some(7));
    assert_eq!(status.details.decision.as_ref().unwrap().source, DecisionSource::Rule);
    assert_eq!(status.details.attribution, None);
    let push = by_command("/usr/bin/git push");
    assert_eq!(
        push.details.decision.as_ref().unwrap().source,
        DecisionSource::Authority
    );
    let rm = by_command("/bin/rm -rf build");
    assert_eq!(rm.details.decision.as_ref().unwrap().verdict, DecisionVerdict::Deny);
    assert_eq!(rm.exit_code, None);

    // Events per command, linked to the line: started and finished for each that ran, denied for `rm`.
    let events = daemon.events();
    let linked = |name: &str| {
        events
            .iter()
            .filter(|event| event.name() == name)
            .filter(|event| {
                matches!(
                    &event.data,
                    EventData::CommandStarted { parent_record_id: Some(parent), .. }
                    | EventData::CommandFinished { parent_record_id: Some(parent), .. }
                    | EventData::CommandDenied { parent_record_id: Some(parent), .. } if *parent == line_record
                )
            })
            .count()
    };
    assert_eq!(linked("command.started"), 2);
    assert_eq!(linked("command.finished"), 2);
    assert_eq!(linked("command.denied"), 1);
    // The line's own: started and finished, never linked, and no `command.proposed` for it.
    let proposed: Vec<String> = events
        .iter()
        .filter_map(|event| match &event.data {
            EventData::CommandProposed { command, .. } => Some(command.expose().clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        proposed,
        ["/usr/bin/git status", "/usr/bin/git push", "/bin/rm -rf build"]
    );
}

// FR-LC-53: a program the supervisor cannot resolve is answered "not found" (127) and nothing is recorded for it; the
// shims are removed from a command's `PATH` before it is decided (FR-LC-16).
#[test]
fn native_command_that_cannot_be_resolved_is_not_found() {
    let daemon = Daemon::new();
    let commands = vec![submitted("/usr/bin/missing", &[]), submitted("/bin/ls", &[])];
    let lifecycle = daemon.lifecycle(native_setup(Vec::new(), commands, &daemon.journal));
    lifecycle.run(daemon.line("missing; ls"), &StillWaiting).unwrap();
    let entries = daemon.journal.entries();
    assert!(
        entries.contains(&"answer /usr/bin/missing: Ok(NotFound)".to_owned()),
        "{entries:?}"
    );
    assert!(
        entries.iter().any(|entry| entry.starts_with("command /bin/ls")),
        "{entries:?}"
    );
    // The line record and `ls`'s: nothing for the program that does not exist.
    assert_eq!(daemon.records().len(), 2);
}

// FR-LC-56: a hook rewriting one command of a native-mode line denies it: the interpreter already expanded it.
#[test]
fn native_command_rewrite_is_denied() {
    let daemon = Daemon::new();
    let mut setup = native_setup(Vec::new(), vec![submitted("/bin/ls", &[])], &daemon.journal);
    setup.hooks = vec![HookVerdict::Rewrite {
        command: "echo instead".to_owned(),
    }];
    let lifecycle = daemon.lifecycle(setup);
    lifecycle.run(daemon.line("ls"), &StillWaiting).unwrap();
    let entries = daemon.journal.entries();
    assert!(
        entries
            .iter()
            .any(|entry| entry.starts_with("denied /bin/ls") && entry.contains("rewrite")),
        "{entries:?}"
    );
    assert!(
        !entries.iter().any(|entry| entry.starts_with("command ")),
        "{entries:?}"
    );
}

// FR-LC-50: the profile alone chooses native mode; a session in line mode runs its line as before, through a stock
// interpreter, decided as a whole.
#[test]
fn line_mode_sessions_are_unchanged() {
    let daemon = Daemon::new();
    let finished = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("git status"), &StillWaiting)
        .unwrap();
    assert_eq!(finished.decision.source, DecisionSource::Rule);
    let entries = daemon.journal.entries();
    assert!(
        !entries.iter().any(|entry| entry.starts_with("spawn native")),
        "{entries:?}"
    );
    assert_eq!(daemon.spawns(), ["spawn /usr/bin/git status as bash"]);
    assert!(
        daemon
            .records()
            .iter()
            .all(|record| record.details.parent_record_id.is_none())
    );
}
