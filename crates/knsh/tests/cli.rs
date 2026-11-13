//! End-to-end checks of the `knsh` binary's argument handling (KNSH-009): usage errors exit with status 2, name
//! the flag on stderr and run nothing; `--help` prints generated help and exits with 0.

#![cfg(test)]

use std::process::{Command, Output};

fn knsh(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_knsh"))
        .args(args)
        .env_clear()
        .output()
        .expect("run knsh")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// KNSH-009 acceptance: unknown flags exit with status 2, naming the flag; nothing runs (nothing on stdout).
#[test]
fn unknown_flag_exits_2_naming_the_flag() {
    let output = knsh(&["history", "--bogus"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--bogus"));
    assert_eq!(output.stdout, b"");
}

// KNSH-009 acceptance: missing values exit with status 2, naming the flag.
#[test]
fn missing_value_exits_2_naming_the_flag() {
    let output = knsh(&["agent", "--profile"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--profile"));

    let output = knsh(&["-c"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("-c"));
}

#[test]
fn help_prints_generated_text_and_exits_0() {
    let output = knsh(&["agent", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--profile <p>") && stdout.contains("--json"),
        "{stdout}"
    );
}

#[test]
fn valid_invocations_are_not_usage_errors() {
    // Behaviour is not implemented yet, but a valid argv must never be reported as a usage error.
    for args in [
        &["agent", "--profile", "web-app", "--", "claude", "--flag"][..],
        &["-c", "history"],
    ] {
        assert_ne!(knsh(args).status.code(), Some(2), "{args:?}");
    }
}

// KNSH-017 CLI validation: `knsh forget` without a selector, or with a malformed one, is a usage error (exit 2) and
// sends nothing.
#[test]
fn forget_without_a_selector_is_a_usage_error() {
    for args in [
        &["forget"][..],
        &["forget", "--with-checkpoints"],
        &["forget", "--session", "not-an-id"],
        &["forget", "--since", "last week"],
    ] {
        let output = knsh(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(output.stdout, b"", "{args:?}");
        assert!(stderr(&output).contains("forget"), "{args:?}: {}", stderr(&output));
    }
}

// With no reachable knshd (an isolated, empty HOME: never the user's real engine), `knsh forget` fails with 1 and
// says why, rather than reporting a count.
#[test]
fn forget_without_knshd_fails_with_1() {
    let home = std::env::temp_dir().join(format!("knsh-cli-forget-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_knsh"))
        .args(["forget", "--since", "2026-11-01"])
        .env_clear()
        .env("HOME", &home)
        .output()
        .expect("run knsh");
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("cannot reach knshd"), "{}", stderr(&output));
    assert_eq!(output.stdout, b"");
}
