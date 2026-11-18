//! macOS integration test for the shadow builder (KNSH-079): a 10,000-file tree cloned through the real clone service
//! on the volume the checkout is on (normally the home APFS volume), compared file by file with the source.
//!
//! Files live in a temporary folder under this crate's directory, never in the user's real data.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use knsh_checkpoint::{PlatformShadowFiles, SHADOW_THREADS, ShadowPlan, ShadowStatus, shadow_dir, start_shadow};
use knsh_core::CanonicalPath;
use knsh_platform::macos::{RealFs, SystemClock, SystemVolumes};
use knsh_platform::{FileSystemKind, Volumes};

/// A temporary folder, removed on drop (also when a test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".knsh-test-shadow-{name}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(&path).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Every path below `dir`, relative to it, sorted.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(folder) = pending.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            found.push(path.strip_prefix(dir).unwrap().to_path_buf());
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                pending.push(path);
            }
        }
    }
    found.sort();
    found
}

// FR-CKP-01, FR-CKP-31: a 10,000-file root shadowed through the real clone service has every file with identical
// contents and its own inode; excluded folders, special files and the target of an outward symlink are left out.
#[test]
fn ten_thousand_file_tree_is_shadowed_with_identical_contents() {
    let volumes = SystemVolumes::new();
    let temp = TempDir::new("tree");
    if volumes.volume_of(&temp.0).unwrap().kind != FileSystemKind::Apfs {
        eprintln!("skipped: the checkout is not on APFS");
        return;
    }
    let root = temp.0.join("root");
    let store = temp.0.join("store");
    let outside = temp.0.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), b"not in the root").unwrap();
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    // 10,000 files in 100 folders, two levels deep, of varied sizes.
    for folder in 0..100 {
        let dir = root.join(format!("d{}", folder % 10)).join(format!("e{folder}"));
        fs::create_dir_all(&dir).unwrap();
        for file in 0..100 {
            let size = (folder * 100 + file) % 4099;
            let contents: Vec<u8> = (0..size).map(|i| u8::try_from((i + file) % 251).unwrap()).collect();
            fs::write(dir.join(format!("f{file}")), contents).unwrap();
        }
    }
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), b"excluded").unwrap();
    symlink(&outside, root.join("escape")).unwrap();
    // A FIFO stands for every special file (a socket path here would pass `sun_path`'s 104 bytes).
    let fifo = std::process::Command::new("/usr/bin/mkfifo")
        .arg(root.join("app.fifo"))
        .status()
        .unwrap();
    assert!(fifo.success());

    let (dir, parents) = shadow_dir(&store, "01SESSION", 0);
    let plan = ShadowPlan {
        root: CanonicalPath::new(&root).unwrap(),
        dir: dir.clone(),
        parents,
        exclude: vec!["node_modules".to_owned()],
        skip: vec![store.clone()],
        threads: SHADOW_THREADS,
    };
    let files = Arc::new(PlatformShadowFiles::new(Arc::new(RealFs::new()), Arc::new(volumes)));
    let shadow = start_shadow(files, Arc::new(SystemClock::new()), plan);
    let summary = match shadow.wait(Duration::from_secs(300)) {
        ShadowStatus::Complete(summary) => summary,
        other => panic!("shadow did not complete: {other:?}"),
    };
    eprintln!("10,000 files shadowed in {:?}", summary.duration);
    // 10,000 files and the symlink.
    assert_eq!(summary.files, 10_001);
    assert_eq!(summary.excluded_folders, 1);
    assert_eq!(summary.special, [root.join("app.fifo")]);

    let mut expected: Vec<PathBuf> = walk(&root)
        .into_iter()
        .filter(|path| !path.starts_with("node_modules") && path != Path::new("app.fifo"))
        .collect();
    expected.sort();
    assert_eq!(walk(&dir), expected);
    for path in &expected {
        let (source, clone) = (root.join(path), dir.join(path));
        let (source_meta, clone_meta) = (
            fs::symlink_metadata(&source).unwrap(),
            fs::symlink_metadata(&clone).unwrap(),
        );
        assert_eq!(source_meta.file_type(), clone_meta.file_type(), "{}", path.display());
        if source_meta.is_file() {
            assert_eq!(
                fs::read(&source).unwrap(),
                fs::read(&clone).unwrap(),
                "{}",
                path.display()
            );
            assert_ne!(
                std::os::unix::fs::MetadataExt::ino(&source_meta),
                std::os::unix::fs::MetadataExt::ino(&clone_meta)
            );
        }
    }
    // The outward symlink is cloned as a link to the same text and its target is not copied.
    assert_eq!(fs::read_link(dir.join("escape")).unwrap(), outside);
    assert!(
        fs::symlink_metadata(dir.join("escape"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // Shadow folders are owner-only.
    assert_eq!(
        fs::metadata(dir.join("d0")).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
