//! macOS integration test for the file-event watcher (KNSH-080): a real `FSEvents` stream on a temporary root while
//! several writer processes create, append to, rename and remove files at once; after each line's end (the marker
//! procedure of decision 16), the shadow must equal the live tree.
//!
//! Files live in a temporary folder under this crate's directory, never in the user's real data.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use knsh_checkpoint::{
    FLUSH_DEADLINE, LineClose, PlatformShadowFiles, SHADOW_THREADS, STREAM_LATENCY, ShadowFiles, ShadowPlan,
    ShadowStatus, WatchPlan, WatchReport, marker_dir, shadow_dir, start_shadow, start_watch,
};
use knsh_core::{CanonicalPath, UncertainReason};
use knsh_platform::macos::{FsEventStreams, RealFs, SystemClock, SystemVolumes};

/// A temporary folder, removed on drop (also when a test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".knsh-test-watch-{name}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        // Canonical: the stream reports resolved paths.
        Self(fs::canonicalize(&path).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What the watcher reported.
#[derive(Default)]
struct Reports {
    changed: Mutex<Vec<PathBuf>>,
    uncertain: Mutex<Vec<UncertainReason>>,
}

impl WatchReport for Reports {
    fn changed(&self, _root: &CanonicalPath, path: &CanonicalPath) {
        self.changed.lock().unwrap().push(path.as_path().to_path_buf());
    }

    fn uncertain(&self, _root: &CanonicalPath, reason: UncertainReason) {
        self.uncertain.lock().unwrap().push(reason);
    }
}

/// One entry of a tree, as compared.
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    Dir,
    File(Vec<u8>),
    Link(PathBuf),
}

/// Every entry below `dir`, relative to it.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Entry> {
    let mut found = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(folder) = pending.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(dir).unwrap().to_path_buf();
            let entry = if meta.is_dir() {
                pending.push(path.clone());
                Entry::Dir
            } else if meta.file_type().is_symlink() {
                Entry::Link(fs::read_link(&path).unwrap())
            } else {
                Entry::File(fs::read(&path).unwrap())
            };
            found.insert(relative, entry);
        }
    }
    found
}

/// Writer processes per line.
const WRITERS: usize = 4;

/// One writer process for round `round` in folder `dir`: 40 creates, 8 appends to files every round keeps, 10
/// renames, and the removal of the previous round's files.
const WRITER: &str = r#"
d="$1"; r="$2"; p=$((r - 1))
i=0; while [ $i -lt 40 ]; do printf 'round %s file %s\n' "$r" "$i" > "$d/c-$r-$i"; i=$((i + 1)); done
i=0; while [ $i -lt 8 ]; do printf 'more %s\n' "$r" >> "$d/keep-$i"; i=$((i + 1)); done
i=0; while [ $i -lt 40 ]; do mv "$d/c-$r-$i" "$d/c-$r-$i.mv"; i=$((i + 4)); done
if [ "$r" -gt 0 ]; then rm -f "$d"/c-"$p"-*; fi
mkdir -p "$d/sub-$r" && printf 'nested %s\n' "$r" > "$d/sub-$r/n"
if [ "$r" -gt 0 ]; then rm -rf "$d/sub-$p"; fi
"#;

// FR-CKP-03, FR-CKP-04, decision 16: with 4 concurrent writer processes per line, the shadow equals the live tree once
// each line is closed (and, when the system dropped events, once the rescan that forces has run).
#[test]
fn shadow_equals_live_tree_after_each_line_with_concurrent_writers() {
    let dir = TempDir::new("writers");
    let root = dir.0.join("root");
    let store = dir.0.join("store");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&store).unwrap();
    for w in 0..WRITERS {
        let folder = root.join(format!("w{w}"));
        fs::create_dir(&folder).unwrap();
        for k in 0..8 {
            fs::write(folder.join(format!("keep-{k}")), b"start\n").unwrap();
        }
    }
    fs::write(root.join("README"), b"hello").unwrap();
    std::os::unix::fs::symlink("README", root.join("link")).unwrap();

    let real: Arc<dyn knsh_platform::Fs> = Arc::new(RealFs::new());
    let volumes: Arc<dyn knsh_platform::Volumes> = Arc::new(SystemVolumes::new());
    let files: Arc<dyn ShadowFiles> = Arc::new(PlatformShadowFiles::new(real, volumes));
    let clock = Arc::new(SystemClock::new());
    let reports = Arc::new(Reports::default());
    let (shadow, parents) = shadow_dir(&store, "S1", 0);
    let (markers, marker_parents) = marker_dir(&store, "S1", 0);
    let root_path = CanonicalPath::new(&root).unwrap();
    // Started before the build, as `knshd` does, so nothing written during the build is missed.
    let watcher = start_watch(
        &FsEventStreams::new(),
        Arc::clone(&files),
        clock.clone(),
        reports.clone(),
        WatchPlan {
            root: root_path.clone(),
            shadow: shadow.clone(),
            markers,
            marker_parents,
            exclude: vec!["node_modules".to_owned()],
            skip: vec![store.clone()],
            latency: STREAM_LATENCY,
            flush_deadline: FLUSH_DEADLINE,
        },
    )
    .unwrap();
    let build = start_shadow(
        Arc::clone(&files),
        clock,
        ShadowPlan {
            root: root_path,
            dir: shadow.clone(),
            parents,
            exclude: vec!["node_modules".to_owned()],
            skip: vec![store.clone()],
            threads: SHADOW_THREADS,
        },
    );
    watcher.follow(Arc::clone(&build));
    assert!(matches!(build.wait(Duration::from_secs(60)), ShadowStatus::Complete(_)));

    let mut uncertain_lines = 0;
    for round in 0..6 {
        let mark = watcher.open_line();
        let children: Vec<_> = (0..WRITERS)
            .map(|w| {
                Command::new("/bin/sh")
                    .arg("-c")
                    .arg(WRITER)
                    .arg("writer")
                    .arg(root.join(format!("w{w}")))
                    .arg(round.to_string())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let mut close = watcher.close_line(mark);
        if close != LineClose::Certain {
            uncertain_lines += 1;
            // A drop or a missed deadline forces a rescan; an empty line settles it.
            for _ in 0..20 {
                close = watcher.close_line(watcher.open_line());
                if close == LineClose::Certain {
                    break;
                }
            }
        }
        assert_eq!(close, LineClose::Certain, "round {round}");
        let live = snapshot(&root);
        let copy = snapshot(&shadow);
        assert_eq!(live.len(), copy.len(), "round {round}: entry counts");
        assert!(live == copy, "round {round}: the shadow differs from the live tree");
    }
    // Changes by these processes, not agents, were reported (FR-EVT-08).
    let changed = reports.changed.lock().unwrap();
    assert!(
        changed.iter().any(|path| path.ends_with("c-5-1")),
        "{} reported",
        changed.len()
    );
    eprintln!("lines needing a rescan: {uncertain_lines} of 6");
    drop(changed);
    watcher.stop();
}
