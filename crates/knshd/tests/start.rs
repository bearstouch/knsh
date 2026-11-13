//! `knshd` start-up integration tests: the binary prepares the engine directories in the `HOME` it is given
//! (KNSH-011), refuses to run without a usable one, and refuses to serve without sockets from launchd (KNSH-012).
//! Uses a temporary home, never the user's real one. Started directly, not by launchd, so it never gets sockets.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use knsh_platform::EnginePaths;

/// A temporary home directory, removed on drop.
struct TempHome(PathBuf);

impl TempHome {
    fn new(tag: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("knshd-home-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn knshd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_knshd"))
}

// NFR-SEC-08: starting the daemon leaves every engine directory owner-only, even when it then stops for lack of
// launchd sockets.
#[test]
fn start_prepares_engine_directories() {
    let home = TempHome::new("ok");
    let status = knshd().env("HOME", &home.0).status().unwrap();
    assert!(!status.success());
    for dir in EnginePaths::for_home(&home.0).unwrap().private_dirs() {
        let mode = fs::symlink_metadata(&dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "{}", dir.display());
    }
}

// Fail closed: no usable home, or an engine path that cannot be used, stops the daemon with a reason on stderr.
#[test]
fn start_fails_without_a_usable_home() {
    let output = knshd().env_remove("HOME").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("HOME is not set"));

    let output = knshd().env("HOME", "relative").output().unwrap();
    assert!(!output.status.success());

    let home = TempHome::new("blocked");
    let data_dir = EnginePaths::for_home(&home.0).unwrap().data_dir().to_path_buf();
    fs::create_dir_all(data_dir.parent().unwrap()).unwrap();
    // A file where the data directory belongs.
    fs::write(&data_dir, b"").unwrap();
    let output = knshd().env("HOME", &home.0).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot prepare engine directories"), "{stderr}");
    assert!(
        !stderr.contains(home.0.to_str().unwrap()),
        "stderr names a path: {stderr}"
    );
}

// KNSH-012: started outside launchd, `knshd` exits with an error and never binds a socket of its own.
#[test]
fn refuses_to_start_without_launchd_sockets() {
    let home = TempHome::new("nolaunchd");
    let output = knshd().env("HOME", &home.0).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no sockets from launchd"), "{stderr}");
    let paths = EnginePaths::for_home(&home.0).unwrap();
    assert!(!paths.user_socket().exists(), "knshd bound user.sock itself");
    assert!(!paths.agent_socket().exists(), "knshd bound agent.sock itself");
}
