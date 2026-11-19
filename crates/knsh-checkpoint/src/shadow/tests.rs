//! Shadow builder and line gate (KNSH-079).

use std::sync::Arc;
use std::time::Duration;

use knsh_core::Timestamp;
use knsh_platform::testing::FakeClock;

use super::*;
use crate::testing::{FakeNode, FakeTree};

const ROOT: &str = "/code/app";
const STORE: &str = "/store";
const EIO: i32 = 5;

/// Long enough for any build in these tests; a hung build fails the test instead of hanging it.
const SETTLE: Duration = Duration::from_secs(20);

fn canonical(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

fn clock() -> Arc<FakeClock> {
    Arc::new(FakeClock::new(
        Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap(),
    ))
}

/// A tree with the store folder and an empty root.
fn tree() -> Arc<FakeTree> {
    let tree = Arc::new(FakeTree::new());
    tree.add_dir(STORE);
    tree.add_dir(ROOT);
    tree
}

fn plan(threads: usize) -> ShadowPlan {
    let (dir, parents) = shadow_dir(Path::new(STORE), "S1", 0);
    ShadowPlan {
        root: canonical(ROOT),
        dir,
        parents,
        exclude: ["node_modules", "target", ".venv", "dist", "build"]
            .into_iter()
            .map(String::from)
            .collect(),
        skip: vec![PathBuf::from(STORE)],
        threads,
    }
}

fn build(tree: &Arc<FakeTree>, plan: ShadowPlan) -> ShadowStatus {
    let files: Arc<dyn ShadowFiles> = Arc::clone(tree) as Arc<dyn ShadowFiles>;
    start_shadow(files, clock(), plan).wait(SETTLE)
}

fn complete(status: ShadowStatus) -> ShadowSummary {
    match status {
        ShadowStatus::Complete(summary) => summary,
        other => panic!("expected a complete shadow, got {other:?}"),
    }
}

fn shadow_root() -> PathBuf {
    shadow_dir(Path::new(STORE), "S1", 0).0
}

// FR-CKP-01: every file of the root, at every depth, has an identical clone in the shadow.
#[test]
fn shadow_holds_a_clone_of_every_file_at_every_depth() {
    let tree = tree();
    for (path, contents) in [
        ("a.txt", &b"a"[..]),
        ("src/main.rs", b"fn main() {}"),
        ("src/deep/er/mod.rs", b"mod x;"),
        ("empty/.keep", b""),
    ] {
        tree.add_file(Path::new(ROOT).join(path), contents);
    }
    tree.add_dir(Path::new(ROOT).join("empty/nothing"));
    for threads in [1, SHADOW_THREADS] {
        let mut plan = plan(threads);
        let (dir, _) = shadow_dir(Path::new(STORE), "S1", threads);
        plan.dir = dir.clone();
        let summary = complete(build(&tree, plan));
        assert_eq!(summary.files, 4, "{threads} threads");
        // The root, src, src/deep, src/deep/er, empty, empty/nothing.
        assert_eq!(summary.folders, 6, "{threads} threads");
        assert_eq!(tree.paths_below(&dir), tree.paths_below(ROOT), "{threads} threads");
        assert_eq!(
            tree.node(dir.join("src/main.rs")),
            Some(FakeNode::File(b"fn main() {}".to_vec()))
        );
    }
}

// FR-CKP-31: excluded folders are not shadowed, at any depth, and not even listed; a file of the same name is.
#[test]
fn excluded_folders_are_not_shadowed() {
    let tree = tree();
    tree.add_file(Path::new(ROOT).join("node_modules/left-pad/index.js"), b"x");
    tree.add_file(Path::new(ROOT).join("crates/core/target/debug/core"), b"x");
    tree.add_file(Path::new(ROOT).join("pkg/.venv/bin/python"), b"x");
    tree.add_file(Path::new(ROOT).join("web/dist/app.js"), b"x");
    tree.add_file(Path::new(ROOT).join("crates/core/src/lib.rs"), b"x");
    // A file named like an excluded folder is still protected.
    tree.add_file(Path::new(ROOT).join("build"), b"#!/bin/sh");

    let summary = complete(build(&tree, plan(SHADOW_THREADS)));
    let shadow = shadow_root();
    assert_eq!(summary.excluded_folders, 4);
    assert_eq!(summary.files, 2);
    assert!(tree.node(shadow.join("crates/core/src/lib.rs")).is_some());
    assert!(tree.node(shadow.join("build")).is_some());
    for excluded in ["node_modules", "crates/core/target", "pkg/.venv", "web/dist"] {
        assert_eq!(tree.node(shadow.join(excluded)), None, "{excluded}");
        assert!(
            !tree.listed().contains(&Path::new(ROOT).join(excluded)),
            "{excluded} was listed"
        );
    }
}

// A symlink is cloned as the link; a link to a folder outside the root is never entered or listed.
#[test]
fn symlink_pointing_outside_root_is_not_followed() {
    let tree = tree();
    tree.add_file("/etc/secret/passwd", b"root:x:0:0");
    tree.add(
        Path::new(ROOT).join("escape"),
        FakeNode::Symlink(PathBuf::from("/etc/secret")),
    );
    tree.add(
        Path::new(ROOT).join("file-link"),
        FakeNode::Symlink(PathBuf::from("/etc/secret/passwd")),
    );
    tree.add_file(Path::new(ROOT).join("real.txt"), b"ok");

    let summary = complete(build(&tree, plan(SHADOW_THREADS)));
    let shadow = shadow_root();
    assert_eq!(summary.files, 3);
    assert_eq!(
        tree.node(shadow.join("escape")),
        Some(FakeNode::Symlink(PathBuf::from("/etc/secret")))
    );
    assert_eq!(tree.node(shadow.join("escape/passwd")), None);
    assert!(
        tree.listed().iter().all(|listed| listed.starts_with(ROOT)),
        "listed outside the root: {:?}",
        tree.listed()
    );
}

// Special files are skipped and listed; the build still completes.
#[test]
fn special_files_are_skipped_and_listed() {
    let tree = tree();
    tree.add(Path::new(ROOT).join("run/app.sock"), FakeNode::Special);
    tree.add(Path::new(ROOT).join("fifo"), FakeNode::Special);
    tree.add_file(Path::new(ROOT).join("run/pid"), b"1");

    let summary = complete(build(&tree, plan(1)));
    assert_eq!(summary.special_count, 2);
    let mut special = summary.special.clone();
    special.sort();
    assert_eq!(
        special,
        [Path::new(ROOT).join("fifo"), Path::new(ROOT).join("run/app.sock")]
    );
    assert_eq!(tree.node(shadow_root().join("fifo")), None);
    assert_eq!(summary.files, 1);
}

// A root that holds its own store (a whole home folder) never clones the shadow into itself.
#[test]
fn the_store_inside_a_root_is_never_shadowed() {
    let tree = Arc::new(FakeTree::new());
    tree.add_file("/home/notes.txt", b"n");
    tree.add_dir("/home/store");
    let (dir, parents) = shadow_dir(Path::new("/home/store"), "S1", 0);
    let plan = ShadowPlan {
        root: canonical("/home"),
        dir: dir.clone(),
        parents,
        exclude: Vec::new(),
        skip: vec![PathBuf::from("/home/store")],
        threads: 2,
    };
    let summary = complete(build(&tree, plan));
    assert_eq!(summary.files, 1);
    assert_eq!(tree.node(dir.join("store")), None);
    assert!(!tree.listed().contains(&PathBuf::from("/home/store")));
}

// Fail closed: a clone error fails the whole build rather than leaving an unreported hole.
#[test]
fn a_clone_error_fails_the_build() {
    let tree = tree();
    for index in 0..50 {
        tree.add_file(Path::new(ROOT).join(format!("d{}/f{index}", index % 5)), b"x");
    }
    tree.fail_clone(Path::new(ROOT).join("d3/f13"), EIO);
    let status = build(&tree, plan(SHADOW_THREADS));
    assert_eq!(
        status,
        ShadowStatus::Failed(ShadowFailure::Platform(PlatformError::Os {
            operation: knsh_platform::Operation::Clone,
            errno: EIO
        }))
    );
}

#[test]
fn a_root_that_is_not_a_folder_fails() {
    let tree = tree();
    tree.add_file("/code/file", b"x");
    let mut plan = plan(1);
    plan.root = canonical("/code/file");
    assert_eq!(build(&tree, plan), ShadowStatus::Failed(ShadowFailure::RootNotAFolder));

    let mut plan = self::plan(1);
    plan.root = canonical("/code/missing");
    assert!(matches!(
        build(&tree, plan),
        ShadowStatus::Failed(ShadowFailure::Platform(_))
    ));
}

// A shadow folder that already exists holds unknown contents: never built into.
#[test]
fn an_existing_shadow_folder_is_never_reused() {
    let tree = tree();
    tree.add_file(shadow_root().join("stale"), b"old");
    assert_eq!(build(&tree, plan(1)), ShadowStatus::Failed(ShadowFailure::ShadowExists));
    // A symlink where a parent folder should be is refused too.
    let tree = self::tree();
    tree.add(
        Path::new(STORE).join(SHADOWS_DIR),
        FakeNode::Symlink(PathBuf::from("/elsewhere")),
    );
    assert_eq!(
        build(&tree, plan(1)),
        ShadowStatus::Failed(ShadowFailure::Platform(PlatformError::UnexpectedKind))
    );
}

// FR-CKP-01: the build runs in the background; its progress is visible while it runs, and cancelling stops it.
#[test]
fn a_build_reports_progress_and_can_be_cancelled() {
    let tree = tree();
    for index in 0..20 {
        tree.add_file(Path::new(ROOT).join(format!("f{index}")), b"x");
    }
    tree.hold();
    let shadow = start_shadow(Arc::clone(&tree) as Arc<dyn ShadowFiles>, clock(), plan(2));
    assert!(matches!(shadow.status(), ShadowStatus::Building(_)));
    assert!(matches!(
        shadow.wait(Duration::from_millis(20)),
        ShadowStatus::Building(_)
    ));
    shadow.cancel();
    tree.release();
    assert_eq!(shadow.wait(SETTLE), ShadowStatus::Cancelled);
}

// Decision 15: the build is timed on the injected clock, and one over the budget is marked.
#[test]
fn a_slow_build_is_marked_over_budget() {
    struct Slow {
        tree: Arc<FakeTree>,
        clock: Arc<FakeClock>,
    }
    impl ShadowFiles for Slow {
        fn kind(&self, path: &Path) -> Result<FileKind, PlatformError> {
            self.tree.kind(path)
        }
        fn list(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError> {
            self.tree.list(path, limit)
        }
        fn make_dir(&self, path: &Path) -> Result<(), PlatformError> {
            self.tree.make_dir(path)
        }
        fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
            self.clock.advance(Duration::from_secs(6));
            self.tree.clone_file(src, dst)
        }
        fn identity(&self, path: &Path) -> Result<FileIdentity, PlatformError> {
            self.tree.identity(path)
        }
        fn remove(&self, path: &Path, folder: bool) -> Result<(), PlatformError> {
            self.tree.remove(path, folder)
        }
        fn create_file(&self, path: &Path) -> Result<(), PlatformError> {
            self.tree.create_file(path)
        }
        fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError> {
            self.tree.rename_new(from, to)
        }
        fn hash(&self, path: &Path, limit: u64) -> Result<Option<knsh_platform::ContentHash>, PlatformError> {
            self.tree.hash(path, limit)
        }
        fn write_in_place(&self, src: &Path, dst: &Path, expect: Option<&FileIdentity>) -> Result<(), PlatformError> {
            self.tree.write_in_place(src, dst, expect)
        }
        fn touch(&self, path: &Path) -> Result<(), PlatformError> {
            self.tree.touch(path)
        }
        fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), PlatformError> {
            self.tree.write_file(path, data)
        }
        fn read_file(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
            self.tree.read_file(path, limit)
        }
    }
    let tree = tree();
    tree.add_file(Path::new(ROOT).join("a"), b"a");
    tree.add_file(Path::new(ROOT).join("b"), b"b");
    let clock = clock();
    let files = Arc::new(Slow {
        tree: Arc::clone(&tree),
        clock: Arc::clone(&clock),
    });
    let summary = complete(start_shadow(files, clock, plan(1)).wait(SETTLE));
    assert_eq!(summary.duration, Duration::from_secs(12));
    assert!(summary.over_budget);

    let summary = complete(build(&self::tree(), plan(1)));
    assert!(!summary.over_budget);
}

#[test]
fn line_touches_a_root_from_its_cwd_or_a_write_path() {
    let root = canonical("/code/app");
    let none: [CanonicalPath; 0] = [];
    assert!(line_touches_root(&root, &canonical("/code/app"), &none));
    assert!(line_touches_root(&root, &canonical("/code/app/src"), &none));
    assert!(!line_touches_root(&root, &canonical("/code/other"), &none));
    // `/code/application` is not inside `/code/app`: components, not text.
    assert!(!line_touches_root(&root, &canonical("/code/application"), &none));
    assert!(line_touches_root(&root, &canonical("/tmp"), &[canonical("/code")]));
    assert!(line_touches_root(
        &root,
        &canonical("/tmp"),
        &[canonical("/code/app/out")]
    ));
    assert!(!line_touches_root(&root, &canonical("/tmp"), &[canonical("/tmp")]));
}

fn building(files: u64) -> RootReadiness {
    RootReadiness::Building(ShadowProgress {
        files,
        folders: 1,
        folders_pending: 2,
    })
}

// FR-CKP-02: a waiting caller waits for a root still being built.
#[test]
fn line_touching_root_waits_until_shadow_complete() {
    let roots = [(canonical("/a"), RootReadiness::Ready), (canonical("/b"), building(3))];
    assert_eq!(gate(true, true, &roots), Gate::Wait { root: canonical("/b") });
    let done = [
        (canonical("/a"), RootReadiness::Ready),
        (canonical("/b"), RootReadiness::Ready),
    ];
    assert_eq!(
        gate(true, true, &done),
        Gate::Run {
            unprotected: Vec::new()
        }
    );
}

// FR-CKP-02: a caller that does not wait gets `-32010` with the root and its progress.
#[test]
fn non_waiting_caller_gets_not_ready_with_progress() {
    let roots = [(canonical("/b"), building(7))];
    assert_eq!(
        gate(true, false, &roots),
        Gate::NotReady {
            root: canonical("/b"),
            progress: ShadowProgress {
                files: 7,
                folders: 1,
                folders_pending: 2
            }
        }
    );
}

// Fail closed: with `required = true`, a root that will never be protected denies the line, before any wait.
#[test]
fn shadow_failure_with_required_true_denies_line() {
    let roots = [
        (canonical("/a"), building(1)),
        (
            canonical("/b"),
            RootReadiness::Unavailable(UnprotectedReason::ShadowFailed),
        ),
    ];
    let denied = Gate::Deny {
        root: canonical("/b"),
        reason: UnprotectedReason::ShadowFailed,
    };
    assert_eq!(gate(true, true, &roots), denied);
    assert_eq!(gate(true, false, &roots), denied);
    assert_eq!(
        RootReadiness::of(&ShadowStatus::Failed(ShadowFailure::Threads)),
        RootReadiness::Unavailable(UnprotectedReason::ShadowFailed)
    );
    assert_eq!(
        RootReadiness::of(&ShadowStatus::Cancelled),
        RootReadiness::Unavailable(UnprotectedReason::ShadowFailed)
    );
}

// With `required = false` nothing waits; roots not ready are listed as not protected.
#[test]
fn required_false_runs_at_once_and_lists_unprotected_roots() {
    let roots = [
        (canonical("/a"), RootReadiness::Ready),
        (canonical("/b"), building(0)),
        (canonical("/c"), RootReadiness::Unavailable(UnprotectedReason::NoShadow)),
    ];
    for wait in [true, false] {
        assert_eq!(
            gate(false, wait, &roots),
            Gate::Run {
                unprotected: vec![
                    (canonical("/b"), UnprotectedReason::ShadowBuilding),
                    (canonical("/c"), UnprotectedReason::NoShadow)
                ]
            }
        );
    }
    assert_eq!(
        gate(true, false, &[]),
        Gate::Run {
            unprotected: Vec::new()
        }
    );
}
