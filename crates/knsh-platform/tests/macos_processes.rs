//! macOS backend integration test for process groups (KNSH-007).
//!
//! Spawns a real shell in a new process group, signals the group and observes that the leader ended by that signal.

#![cfg(all(test, target_os = "macos"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use knsh_platform::macos::SystemProcesses;
use knsh_platform::{ExitStatus, PlatformError, Processes, Signal, SpawnRequest};

// CLAUDE.md "Concurrency": signal by group, using a handle this instance holds.
#[test]
fn signalling_a_spawned_group_ends_its_leader_by_that_signal() {
    let processes = SystemProcesses::new();
    let group = processes
        .spawn(&SpawnRequest::new("/bin/sh").arg("-c").arg("sleep 10"))
        .unwrap();
    assert!(group.as_raw() > 1);
    assert_eq!(processes.try_wait(group), Ok(None), "exited before being signalled");

    let started = Instant::now();
    processes.signal(group, Signal::Terminate).unwrap();
    assert_eq!(processes.wait(group), Ok(ExitStatus::Signalled(libc::SIGTERM)));
    assert!(started.elapsed() < Duration::from_secs(5), "group was not signalled");

    // Reaped: the id may now be reused by the system, so it is refused.
    assert_eq!(
        processes.signal(group, Signal::Kill),
        Err(PlatformError::UnknownProcessGroup)
    );
}

// The signal reaches the whole group, not just the leader: a background child in the same group dies too.
#[test]
fn signal_reaches_every_member_of_the_group() {
    let dir = std::env::temp_dir().join(format!("knsh-platform-group-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("child.pid");
    let processes = SystemProcesses::new();
    let script = format!("sleep 10 & echo $! > '{}'; wait", pid_file.display());
    let group = processes
        .spawn(&SpawnRequest::new("/bin/sh").arg("-c").arg(script))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let child_pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "background child never started");
        std::thread::sleep(Duration::from_millis(10));
    };
    processes.signal(group, Signal::Kill).unwrap();
    assert_eq!(processes.wait(group), Ok(ExitStatus::Signalled(libc::SIGKILL)));

    // Observe the background child with `ps` (read-only; this test never signals a bare pid). Once orphaned it is
    // reaped by launchd, so allow a moment for it to disappear.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let listed = std::process::Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &child_pid.to_string()])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&listed.stdout);
        // Gone, or a zombie waiting to be reaped: either way it is no longer running.
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            break;
        }
        assert!(Instant::now() < deadline, "background child survived the group signal");
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Waiting in one thread while another signals: `wait` must not block `signal`.
#[test]
fn signal_while_another_thread_waits() {
    let processes = Arc::new(SystemProcesses::new());
    let group = processes
        .spawn(&SpawnRequest::new("/bin/sh").arg("-c").arg("sleep 10"))
        .unwrap();
    let waiter = {
        let processes = Arc::clone(&processes);
        std::thread::spawn(move || processes.wait(group))
    };
    std::thread::sleep(Duration::from_millis(100));
    processes.signal(group, Signal::Terminate).unwrap();
    assert_eq!(waiter.join().unwrap(), Ok(ExitStatus::Signalled(libc::SIGTERM)));
}
