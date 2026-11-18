//! The shadow registry over fake volumes and an in-memory tree (KNSH-079).

use std::path::Path;

use knsh_checkpoint::testing::FakeTree;
use knsh_core::{ProfileName, SessionId, Ulid};
use knsh_platform::testing::{FakeClock, FakeVolumes, MemFs, RecordingLog};
use knsh_platform::{FileSystemKind, ensure_engine_dirs};

use super::*;

pub(crate) const HOME: &str = "/Users/u";
pub(crate) const ROOT: &str = "/Users/u/app";

/// Long enough for any build here; a hung build fails the test instead of hanging it.
pub(crate) const SETTLE: Duration = Duration::from_secs(20);

/// A machine whose home is on one APFS volume, with a non-APFS stick, and the engine directories ready. Returns the
/// shadows over `tree`, which already holds the home store and `ROOT` with a few files.
pub(crate) fn shadows(tree: &Arc<FakeTree>) -> Arc<Shadows> {
    let fs = MemFs::new();
    for dir in [HOME, ROOT, "/Volumes/Stick/code"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    let paths = EnginePaths::for_home(Path::new(HOME)).unwrap();
    ensure_engine_dirs(&fs, &paths, fs.uid()).unwrap();
    let volumes = FakeVolumes::new();
    volumes.add_volume("/", FileSystemKind::Apfs, false);
    volumes.add_volume("/Volumes/Stick", FileSystemKind::Other, false);
    tree.add_dir(paths.checkpoints_dir());
    tree.add_file(Path::new(ROOT).join("src/main.rs"), b"fn main() {}");
    tree.add_file(Path::new(ROOT).join("README"), b"hi");
    tree.add_file(Path::new(ROOT).join("node_modules/x/index.js"), b"excluded");
    let uid = fs.uid();
    Shadows::new(ShadowParts {
        fs: Arc::new(fs),
        volumes: Arc::new(volumes),
        files: Arc::clone(tree) as Arc<dyn ShadowFiles>,
        clock: Arc::new(FakeClock::new(
            knsh_core::Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        )),
        paths,
        uid,
        log: Arc::new(RecordingLog::new()),
    })
}

/// A profile protecting `roots`, loaded as the supervisor loads profiles, with `extra` TOML appended.
pub(crate) fn profile_with(roots: &[&str], required: bool, extra: &str) -> Profile {
    let roots = roots
        .iter()
        .map(|root| format!("\"{root}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!("name = \"ckpt\"\n[checkpoints]\nroots = [{roots}]\nrequired = {required}\n{extra}");
    let fs = MemFs::new();
    for dir in [HOME, ROOT, "/tmp", "/Volumes/Stick/code", "/Users/u/lib"] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    let policies = EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir();
    fs.add_dir_all(&policies).unwrap();
    fs.write(
        &policies.join("ckpt.toml"),
        &crate::policy::tests::signed("ckpt", &text),
        0o600,
    )
    .unwrap();
    crate::policy::tests::loader(fs)
        .load(&ProfileName::new("ckpt").unwrap(), Path::new(ROOT))
        .unwrap()
}

/// [`profile_with`] and nothing else.
pub(crate) fn profile(roots: &[&str], required: bool) -> Profile {
    profile_with(roots, required, "")
}

fn session(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

fn root(path: &str) -> CanonicalPath {
    CanonicalPath::new(path).unwrap()
}

/// Waits until the shadow of `root` for `session_id` has settled.
pub(crate) fn settled(shadows: &Shadows, session_id: SessionId, root: &CanonicalPath) -> RootReadiness {
    shadows.wait(session_id, root, SETTLE)
}

// FR-CKP-01: starting a session starts one background build per root and returns without waiting for any.
#[test]
fn starting_a_session_starts_one_background_build_per_root() {
    let tree = Arc::new(FakeTree::new());
    tree.add_file("/Users/u/lib/a.rs", b"a");
    let shadows = shadows(&tree);
    tree.hold();
    // Returns while every clone is held: nothing in `start` waits for a build.
    shadows.start(session(1), &profile(&[ROOT, "/Users/u/lib"], true));
    for path in [ROOT, "/Users/u/lib"] {
        assert!(
            matches!(shadows.readiness(session(1), &root(path)), RootReadiness::Building(_)),
            "{path}"
        );
    }
    // Building roots are not in the capability report yet.
    assert!(shadows.capability_report().is_empty());
    tree.release();
    for path in [ROOT, "/Users/u/lib"] {
        assert_eq!(
            settled(&shadows, session(1), &root(path)),
            RootReadiness::Ready,
            "{path}"
        );
    }
    // Each root in its own folder of the home store, without the excluded folder.
    let store = EnginePaths::for_home(Path::new(HOME)).unwrap().checkpoints_dir();
    let shadow = store.join("shadows").join(session(1).to_string());
    assert!(tree.node(shadow.join("0/src/main.rs")).is_some());
    assert!(tree.node(shadow.join("0/node_modules")).is_none());
    assert!(tree.node(shadow.join("1/a.rs")).is_some());
    let report = shadows.capability_report();
    assert_eq!(report.get(ROOT), Some(&CheckpointBackend::ApfsClone));
    assert_eq!(report.get("/Users/u/lib"), Some(&CheckpointBackend::ApfsClone));
}

// A failed build is reported as `none`, and the root is not protected.
#[test]
fn a_failed_build_reports_none() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    tree.fail_clone(Path::new(ROOT).join("README"), 5);
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(
        settled(&shadows, session(1), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::ShadowFailed)
    );
    assert_eq!(shadows.capability_report().get(ROOT), Some(&CheckpointBackend::None));
}

// A root on a volume without clones gets no shadow yet: `none`, never a false `plain-copy` claim.
#[test]
fn a_root_without_clones_has_no_shadow_and_reports_none() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&["/Volumes/Stick/code"], false));
    assert_eq!(
        shadows.readiness(session(1), &root("/Volumes/Stick/code")),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
    assert_eq!(
        shadows.capability_report().get("/Volumes/Stick/code"),
        Some(&CheckpointBackend::None)
    );
    // A root the session never had, or a session that does not exist, has no shadow either.
    assert_eq!(
        shadows.readiness(session(1), &root("/elsewhere")),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
    assert_eq!(
        shadows.readiness(session(9), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
}

// Ending a session stops its builds and drops its roots from the report.
#[test]
fn ending_a_session_stops_its_builds() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    tree.hold();
    shadows.start(session(1), &profile(&[ROOT], true));
    let shadow = shadows.shadow_of(session(1), &root(ROOT)).unwrap();
    shadows.end(session(1));
    tree.release();
    assert_eq!(shadow.wait(SETTLE), ShadowStatus::Cancelled);
    assert!(shadows.capability_report().is_empty());
    assert_eq!(
        shadows.readiness(session(1), &root(ROOT)),
        RootReadiness::Unavailable(UnprotectedReason::NoShadow)
    );
}

// Two sessions sharing a root: the report shows the weaker of the two.
#[test]
fn a_shared_root_reports_the_weaker_state() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&[ROOT], true));
    assert_eq!(settled(&shadows, session(1), &root(ROOT)), RootReadiness::Ready);
    tree.fail_clone(Path::new(ROOT).join("README"), 5);
    shadows.start(session(2), &profile(&[ROOT], true));
    let _ = settled(&shadows, session(2), &root(ROOT));
    assert_eq!(shadows.capability_report().get(ROOT), Some(&CheckpointBackend::None));
}

// A session with no roots gets nothing.
#[test]
fn a_session_without_roots_starts_nothing() {
    let tree = Arc::new(FakeTree::new());
    let shadows = shadows(&tree);
    shadows.start(session(1), &profile(&[], true));
    assert!(shadows.table().is_empty());
    assert_eq!(tree.clones(), 0);
}
