//! macOS backend integration test for the sandbox violation reader (KNSH-047, decision 9).
//!
//! Streams real sandbox denials with `log stream` as the current user (no `sudo`), causes canary denials until one
//! comes back through the stream, and checks that stopping the stream ends a blocked read. The canary file lives in
//! a temporary directory, never in the user's engine directories.

#![cfg(all(test, target_os = "macos"))]

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use knsh_platform::macos::UnifiedLogDenials;
use knsh_platform::violation::parse_entry;
use knsh_platform::{CanaryNonce, DenialLog, LogEntry};

/// `log stream` took from 0.27 s to over 2 s to attach in KNSH-025; this leaves ample room.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(20);

// KNSH-047 (FR-SBX-08, decision 9): the reader runs as the user, sees its own canary come back, and stops cleanly.
#[test]
fn canary_comes_back_through_the_real_log_stream() {
    // A private temporary directory for the canary file, never the user's engine directories.
    let dir = std::env::temp_dir().join(format!("knsh-denials-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = UnifiedLogDenials::new(&dir).unwrap();
    let mut stream = log.open().unwrap();
    let stopper = stream.stopper();
    let nonce = CanaryNonce::new(*b"knsh-047-canary!");

    // Read on a second thread, so this one can keep causing canaries until the stream is attached.
    let (seen, received) = mpsc::channel();
    let reader = thread::spawn(move || {
        while let Ok(Some(entry)) = stream.next_entry() {
            if let Some(LogEntry::Canary(found)) = parse_entry(&entry) {
                let _ = seen.send(found);
            }
        }
    });
    let started = Instant::now();
    let found = loop {
        log.trigger_canary(&nonce).unwrap();
        if let Ok(found) = received.recv_timeout(Duration::from_millis(300)) {
            break Some(found);
        }
        if started.elapsed() > ATTACH_TIMEOUT {
            break None;
        }
    };
    stopper.stop();
    reader.join().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(found, Some(nonce), "no canary arrived through log stream");
}
