//! macOS integration test for engine directories (KNSH-011) on the real filesystem.
//!
//! Each test uses a temporary `HOME` under this crate's directory, never the user's real one. It is not under the
//! system temp directory or `target/`, because both are already excluded from Time Machine there, which would make
//! the `tmutil isexcluded` cross-check pass whatever the engine did.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};

use knsh_platform::engine_dirs::{
    BACKUP_EXCLUDE_ATTRIBUTE, BACKUP_EXCLUDE_VALUE, DIR_MODE, FILE_MODE, SPOTLIGHT_MARKER,
};
use knsh_platform::macos::{RealFs, effective_uid};
use knsh_platform::{EnginePaths, FileKind, Fs, PlatformError, ensure_engine_dirs};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A temporary home directory, removed on drop (also when a test panics).
struct TempHome(PathBuf);

impl TempHome {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".knsh-test-home-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn paths(&self) -> EnginePaths {
        EnginePaths::for_home(&self.0).unwrap()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `tmutil isexcluded` for one path: `Some(true)` if Time Machine reports it excluded, `None` if `tmutil` is
/// unavailable or its output is not understood.
fn tmutil_excluded(path: &Path) -> Option<bool> {
    let output = Command::new("/usr/bin/tmutil")
        .arg("isexcluded")
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    if text.starts_with("[Excluded]") {
        Some(true)
    } else if text.starts_with("[Included]") {
        Some(false)
    } else {
        None
    }
}

fn assert_prepared(home: &TempHome) {
    let real = RealFs::new();
    for dir in home.paths().private_dirs() {
        let meta = real.metadata(&dir).unwrap();
        assert_eq!(
            (meta.kind, meta.mode, meta.uid),
            (FileKind::Directory, DIR_MODE, effective_uid())
        );
        let marker = real.metadata(&dir.join(SPOTLIGHT_MARKER)).unwrap();
        assert_eq!(
            (marker.kind, marker.mode, marker.uid),
            (FileKind::File, FILE_MODE, effective_uid())
        );
        assert_eq!(
            real.xattr(&dir, BACKUP_EXCLUDE_ATTRIBUTE, 256).unwrap().as_deref(),
            Some(BACKUP_EXCLUDE_VALUE)
        );
    }
}

// NFR-PRIV-04, NFR-SEC-08: on a fresh home, every engine directory is 0700 with a 0600 Spotlight marker and carries
// the Time Machine exclusion, which `tmutil` itself (no admin rights) reports as excluded.
#[test]
fn prepares_engine_dirs_and_time_machine_reports_them_excluded() {
    let home = TempHome::new();
    // Only a home that Time Machine includes makes the cross-check meaningful.
    let baseline = tmutil_excluded(&home.0);
    ensure_engine_dirs(&RealFs::new(), &home.paths(), effective_uid()).unwrap();
    assert_prepared(&home);

    match baseline {
        Some(false) => {
            for dir in home.paths().private_dirs() {
                assert_eq!(tmutil_excluded(&dir), Some(true), "{}", dir.display());
            }
            assert_eq!(
                tmutil_excluded(&home.0),
                Some(false),
                "exclusion leaked to the home directory"
            );
        }
        Some(true) | None => {
            eprintln!("tmutil cross-check skipped: temporary home is already excluded or tmutil is unavailable");
        }
    }
}

// NFR-SEC-08 and idempotence on the real filesystem: wide modes are reset, a second run changes nothing.
#[test]
fn tightens_existing_wide_permissions_on_disk() {
    let home = TempHome::new();
    let paths = home.paths();
    ensure_engine_dirs(&RealFs::new(), &paths, effective_uid()).unwrap();
    fs::set_permissions(paths.data_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        paths.run_dir().join(SPOTLIGHT_MARKER),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(paths.checkpoints_dir(), fs::Permissions::from_mode(0o777)).unwrap();
    ensure_engine_dirs(&RealFs::new(), &paths, effective_uid()).unwrap();
    assert_prepared(&home);
}

// A symlink planted at an engine path is refused; its target gains nothing and keeps its mode.
#[test]
fn refuses_symlink_at_engine_path_on_disk() {
    let home = TempHome::new();
    let paths = home.paths();
    let target = home.0.join("elsewhere");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(paths.config_dir().parent().unwrap()).unwrap();
    symlink(&target, paths.config_dir()).unwrap();
    assert_eq!(
        ensure_engine_dirs(&RealFs::new(), &paths, effective_uid()),
        Err(PlatformError::UnexpectedKind)
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0, "wrote through the symlink");
    assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o7777, 0o755);
}

// Several processes (here threads, which race on the same system calls) preparing the same home at once all succeed.
#[test]
fn concurrent_runs_all_succeed() {
    const RUNNERS: usize = 8;
    let home = TempHome::new();
    let barrier = Arc::new(Barrier::new(RUNNERS));
    let handles: Vec<_> = (0..RUNNERS)
        .map(|_| {
            let paths = home.paths();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                ensure_engine_dirs(&RealFs::new(), &paths, effective_uid())
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), Ok(()));
    }
    assert_prepared(&home);
}
