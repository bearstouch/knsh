//! The restore engine (KNSH-084) over an in-memory tree: checks, in-place writes, the journal, rollback and recovery.
//! [`Fixture`] is shared with the undo and redo tests.

use std::cell::Cell;
use std::sync::Arc;

use knsh_core::{Attribution, RecordId, SessionId, Ulid};

use super::*;
use crate::attribution::EdgeId;
use crate::identity::post_image;
use crate::testing::{FakeNode, FakeTree};

pub(crate) const ROOT: &str = "/code/app";
pub(crate) const STORE: &str = "/store";

/// `errno` values (macOS).
pub(crate) const ENOSPC: i32 = 28;

pub(crate) fn canonical(path: impl AsRef<Path>) -> CanonicalPath {
    CanonicalPath::new(path.as_ref()).unwrap()
}

pub(crate) fn live(relative: &str) -> PathBuf {
    Path::new(ROOT).join(relative)
}

pub(crate) fn session(n: u128) -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(n))
}

pub(crate) fn record(n: u128) -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(100 + n))
}

/// A tree with a root and a store, and changes taken the way capture takes them (KNSH-082).
pub(crate) struct Fixture {
    pub(crate) tree: Arc<FakeTree>,
    kept: Cell<u64>,
}

/// One change to take with [`Fixture::change`].
pub(crate) struct Taken<'a> {
    /// Its number: names its checkpoint, edge and record.
    pub(crate) n: u128,
    pub(crate) attribution: Attribution,
    pub(crate) session: SessionId,
    /// The paths it changes, relative to [`ROOT`].
    pub(crate) paths: &'a [&'a str],
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let tree = Arc::new(FakeTree::new());
        tree.add_dir(ROOT);
        tree.add_dir(Path::new(STORE).join(CHECKPOINTS_DIR));
        Self {
            tree,
            kept: Cell::new(0),
        }
    }

    pub(crate) fn contents(&self, relative: &str) -> Option<Vec<u8>> {
        match self.tree.node(live(relative)) {
            Some(FakeNode::File(contents)) => Some(contents),
            _ => None,
        }
    }

    pub(crate) fn identity(&self, relative: &str) -> FileIdentity {
        self.tree.identity(&live(relative)).unwrap()
    }

    /// A command line's change of `paths`, made by `edit`: each path's pre-image is set aside first (a clone into the
    /// checkpoint's folder, or a marker), its post-image identity read after, as capture does.
    pub(crate) fn change(&self, taken: &Taken<'_>, edit: impl FnOnce(&FakeTree)) -> Checkpoint {
        let id = CheckpointId::from_ulid(Ulid::from_u128(1000 + taken.n));
        let folder = Path::new(STORE).join(CHECKPOINTS_DIR).join(id.to_string());
        self.tree.add_dir(&folder);
        let mut pres = Vec::new();
        for relative in taken.paths {
            let path = live(relative);
            let pre = match self.tree.node(&path) {
                None => StoredPreImage::NotExisted,
                Some(FakeNode::Dir) => StoredPreImage::Folder,
                Some(_) => {
                    let copy = folder.join(self.kept.get().to_string());
                    self.kept.set(self.kept.get() + 1);
                    self.tree.clone_file(&path, &copy).unwrap();
                    StoredPreImage::Kept(copy)
                }
            };
            pres.push((canonical(&path), pre));
        }
        edit(&self.tree);
        let paths = pres
            .into_iter()
            .map(|(path, pre)| {
                let post = post_image(self.tree.as_ref(), path.as_path());
                (path, CapturedPath { pre, post })
            })
            .collect();
        Checkpoint {
            id,
            edge: EdgeId::for_tests(u64::try_from(taken.n).unwrap()),
            attribution: taken.attribution,
            records: [record(taken.n)].into(),
            sessions: [taken.session].into(),
            paths: [(canonical(ROOT), paths)].into(),
            uncertain: BTreeSet::new(),
            stores: [(canonical(ROOT), PathBuf::from(STORE))].into(),
            excluded: BTreeMap::new(),
            excluded_overflowed: false,
        }
    }

    pub(crate) fn command(&self, n: u128, paths: &[&str], edit: impl FnOnce(&FakeTree)) -> Checkpoint {
        self.change(
            &Taken {
                n,
                attribution: Attribution::Command,
                session: session(1),
                paths,
            },
            edit,
        )
    }

    pub(crate) fn journals(&self) -> Vec<PathBuf> {
        self.tree
            .paths_below(Path::new(STORE).join(RESTORES_DIR))
            .into_iter()
            .filter(|path| !path.as_os_str().is_empty())
            .collect()
    }
}

fn saved_id(n: u128) -> CheckpointId {
    CheckpointId::from_ulid(Ulid::from_u128(5000 + n))
}

fn restore_from(fixture: &Fixture, from: &Checkpoint, force: bool) -> Result<RestoreOutcome, CheckpointError> {
    restore(
        fixture.tree.as_ref(),
        &RestoreRequest {
            from,
            saved: saved_id(1),
            force,
        },
    )
}

fn saved_folder() -> PathBuf {
    Path::new(STORE).join(CHECKPOINTS_DIR).join(saved_id(1).to_string())
}

// FR-CKP-20, FR-CKP-22: a matching file gets its old contents in place, and its current version is saved first.
#[test]
fn restore_writes_in_place_and_saves_current_versions() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    let checkpoint = fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"new"));
    let inode = fixture.identity("a.txt").inode;

    let outcome = restore_from(&fixture, &checkpoint, false).unwrap();

    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(fixture.identity("a.txt").inode, inode);
    assert_eq!(outcome.restored, vec![canonical(live("a.txt"))]);
    assert!(!outcome.forced);
    let saved = &outcome.saved[&canonical(ROOT)][&canonical(live("a.txt"))];
    let StoredPreImage::Kept(copy) = &saved.pre else {
        panic!("the current version is kept: {saved:?}");
    };
    assert!(copy.starts_with(saved_folder()));
    assert_eq!(fixture.tree.node(copy), Some(FakeNode::File(b"new".to_vec())));
    assert_eq!(saved.post, PostImage::Present(post_image_identity(&fixture, "a.txt")));
    assert_eq!(
        fixture.journals(),
        Vec::<PathBuf>::new(),
        "the journal is removed once done"
    );
}

fn post_image_identity(fixture: &Fixture, relative: &str) -> crate::PostImageIdentity {
    match post_image(fixture.tree.as_ref(), &live(relative)) {
        PostImage::Present(identity) => identity,
        other => panic!("{relative} is {other:?}"),
    }
}

// A change that created a file, deleted one and created a folder with a file: undone, each is as before, and the
// deleted file comes back with its time set to now (FR-CKP-23).
#[test]
fn created_deleted_and_folder_paths_are_restored() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("gone.txt"), b"keep me");
    let before = fixture.identity("gone.txt").modified;
    let checkpoint = fixture.command(1, &["new.txt", "gone.txt", "dir", "dir/f"], |tree| {
        tree.add_file(live("new.txt"), b"n");
        tree.remove_all(live("gone.txt"));
        tree.add_dir(live("dir"));
        tree.add_file(live("dir/f"), b"f");
    });

    let outcome = restore_from(&fixture, &checkpoint, false).unwrap();

    assert_eq!(fixture.tree.node(live("new.txt")), None);
    assert_eq!(fixture.tree.node(live("dir")), None);
    assert_eq!(fixture.contents("gone.txt").as_deref(), Some(&b"keep me"[..]));
    assert!(
        fixture.identity("gone.txt").modified > before,
        "a restored file's time is now"
    );
    assert_eq!(outcome.restored.len(), 4);
    let saved = &outcome.saved[&canonical(ROOT)];
    assert_eq!(saved[&canonical(live("dir"))].pre, StoredPreImage::Folder);
    assert_eq!(saved[&canonical(live("gone.txt"))].pre, StoredPreImage::NotExisted);
    assert_eq!(saved[&canonical(live("dir"))].post, PostImage::Deleted);
}

// A folder the change created now holds a file nobody recorded: removing it would delete that work, so it is a
// conflict even with `force`, and nothing changes.
#[test]
fn folder_with_unrecorded_entries_is_a_conflict_even_with_force() {
    let fixture = Fixture::new();
    let checkpoint = fixture.command(1, &["dir", "dir/f"], |tree| tree.add_file(live("dir/f"), b"f"));
    fixture.tree.add_file(live("dir/mine.txt"), b"human work");

    for force in [false, true] {
        let error = restore_from(&fixture, &checkpoint, force).unwrap_err();
        assert_eq!(
            error,
            CheckpointError::Conflicts(vec![RestoreConflict {
                path: canonical(live("dir")),
                reason: ConflictReason::FolderNotEmpty,
            }])
        );
        assert_eq!(fixture.contents("dir/f").as_deref(), Some(&b"f"[..]));
        assert_eq!(fixture.contents("dir/mine.txt").as_deref(), Some(&b"human work"[..]));
        assert!(fixture.tree.paths_below(saved_folder()).is_empty(), "nothing saved");
    }
}

// FR-CKP-21: `force` overrides an identity mismatch, never a lost pre-image.
#[test]
fn force_overrides_identity_but_not_a_lost_pre_image() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    let checkpoint = fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"new"));
    fixture.tree.add_file(live("a.txt"), b"human");

    let outcome = restore_from(&fixture, &checkpoint, true).unwrap();
    assert!(outcome.forced);
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));

    let mut lost = checkpoint.clone();
    for captured in lost.paths.values_mut().flat_map(BTreeMap::values_mut) {
        captured.pre = StoredPreImage::Lost;
    }
    let error = restore(
        fixture.tree.as_ref(),
        &RestoreRequest {
            from: &lost,
            saved: saved_id(2),
            force: true,
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![RestoreConflict {
            path: canonical(live("a.txt")),
            reason: ConflictReason::PreImageLost,
        }])
    );
}

// Never mixed: a write that fails part-way leaves a torn file; every file touched is put back from the saved copies,
// and nothing of the restore is left.
#[test]
fn failure_mid_restore_rolls_back_every_file() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a-old");
    fixture.tree.add_file(live("b.txt"), b"b-old");
    let checkpoint = fixture.command(1, &["a.txt", "b.txt", "c.txt"], |tree| {
        tree.add_file(live("a.txt"), b"a-new");
        tree.add_file(live("b.txt"), b"b-new");
        tree.add_file(live("c.txt"), b"c-new");
    });
    let inode = fixture.identity("b.txt").inode;
    // `a.txt` and `b.txt` come before `c.txt`: one is restored, one torn, one not reached.
    fixture.tree.fail_write_once(live("b.txt"), ENOSPC);
    let calls = fixture.tree.writes().len();

    let error = restore_from(&fixture, &checkpoint, false).unwrap_err();

    assert!(matches!(error, CheckpointError::RolledBack(_)), "{error:?}");
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-new"[..]));
    assert_eq!(
        fixture.contents("b.txt").as_deref(),
        Some(&b"b-new"[..]),
        "the torn file is whole again"
    );
    assert_eq!(fixture.contents("c.txt").as_deref(), Some(&b"c-new"[..]));
    assert_eq!(fixture.identity("b.txt").inode, inode);
    assert!(fixture.tree.writes().len() > calls, "a.txt was restored, then put back");
    assert_eq!(fixture.journals(), Vec::<PathBuf>::new());
    assert_eq!(fixture.tree.node(saved_folder()), None, "the saved copies are removed");
}

// Never mixed, across a stop: when putting back fails too, the journal stays, and recovery puts every listed path
// back to its version before the restore.
#[test]
fn rollback_failure_keeps_journal_for_recovery() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a-old");
    fixture.tree.add_file(live("b.txt"), b"b-old");
    let checkpoint = fixture.command(1, &["a.txt", "b.txt", "new.txt"], |tree| {
        tree.add_file(live("a.txt"), b"a-new");
        tree.add_file(live("b.txt"), b"b-new");
        tree.add_file(live("new.txt"), b"created");
    });
    fixture.tree.fail_write(live("b.txt"), ENOSPC);

    let error = restore_from(&fixture, &checkpoint, false).unwrap_err();

    assert!(matches!(error, CheckpointError::RollbackFailed(_)), "{error:?}");
    assert_eq!(fixture.journals().len(), 1);
    assert_ne!(
        fixture.contents("b.txt").as_deref(),
        Some(&b"b-new"[..]),
        "torn until recovery"
    );

    fixture.tree.allow_write(live("b.txt"));
    assert_eq!(recover_restores(fixture.tree.as_ref(), Path::new(STORE)), Ok(1));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-new"[..]));
    assert_eq!(fixture.contents("b.txt").as_deref(), Some(&b"b-new"[..]));
    assert_eq!(fixture.contents("new.txt").as_deref(), Some(&b"created"[..]));
    assert_eq!(fixture.journals(), Vec::<PathBuf>::new());
    assert_eq!(fixture.tree.node(saved_folder()), None);
    assert_eq!(recover_restores(fixture.tree.as_ref(), Path::new(STORE)), Ok(0));
}

// A journal that cannot be written: the restore does not start, and the saved copies are removed.
#[test]
fn journal_failure_changes_nothing() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    let checkpoint = fixture.command(1, &["a.txt"], |tree| tree.add_file(live("a.txt"), b"new"));
    fixture.tree.add_dir(Path::new(STORE).join(RESTORES_DIR));
    fixture.tree.fail_write(
        Path::new(STORE)
            .join(RESTORES_DIR)
            .join(format!("{}.json", saved_id(1))),
        ENOSPC,
    );

    let error = restore_from(&fixture, &checkpoint, false).unwrap_err();

    assert!(matches!(error, CheckpointError::Platform(_)), "{error:?}");
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
    assert_eq!(fixture.tree.node(saved_folder()), None);
}

#[test]
fn journal_round_trips_and_refuses_anything_else() {
    let steps: BTreeMap<CanonicalPath, Step> = [
        (
            "/code/app/a",
            Want::Copy {
                from: PathBuf::from("/store/checkpoints/x/0"),
                kind: FileKind::File,
            },
        ),
        (
            "/code/app/l",
            Want::Copy {
                from: PathBuf::from("/store/checkpoints/x/1"),
                kind: FileKind::Symlink,
            },
        ),
        ("/code/app/d", Want::Folder),
        ("/code/app/n", Want::Absent),
        ("/code/app/s", Want::Unknown),
    ]
    .into_iter()
    .map(|(path, before)| {
        let step = Step {
            root: canonical(ROOT),
            want: Want::Unknown,
            live: None,
            checked: false,
            before,
        };
        (canonical(path), step)
    })
    .collect();
    let bytes = encode_journal(saved_id(1), steps.iter()).unwrap();
    let (saved, decoded) = decode_journal(&bytes).unwrap();
    assert_eq!(saved, saved_id(1));
    let befores = |steps: &BTreeMap<CanonicalPath, Step>| -> Vec<(CanonicalPath, Want)> {
        steps
            .iter()
            .map(|(path, step)| (path.clone(), step.before.clone()))
            .collect()
    };
    assert_eq!(befores(&decoded), befores(&steps));

    let text = String::from_utf8(bytes).unwrap();
    for corrupt in [
        text.replace(r#""format":1"#, r#""format":2"#),
        text.replace(r#""before":"folder""#, r#""before":"pipe""#),
        text.replace(r#""copy":null"#, r#""copy":"/x""#),
        text.replace(r#""steps":["#, r#""extra":1,"steps":["#),
        text.replace(
            r#""root":"/code/app","path":"/code/app/a""#,
            r#""root":"/other","path":"/code/app/a""#,
        ),
        "{".to_owned(),
    ] {
        assert_eq!(
            decode_journal(corrupt.as_bytes()).unwrap_err(),
            CheckpointError::Journal,
            "{corrupt}"
        );
    }
}

// `knshd` is not sandboxed: a folder an agent swapped for a symlink to somewhere else (here, the user's `.ssh`) never
// lets an undo create, write or remove anything there, with or without `force`.
#[test]
fn folder_swapped_for_a_symlink_is_never_followed() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("keys/authorized_keys"), b"agent key");
    let checkpoint = fixture.command(1, &["keys/authorized_keys"], |tree| {
        tree.remove_all(live("keys/authorized_keys"));
    });
    fixture.tree.add_dir("/Users/me/.ssh");
    fixture.tree.remove_all(live("keys"));
    fixture
        .tree
        .add("/code/app/keys", FakeNode::Symlink(PathBuf::from("/Users/me/.ssh")));

    for force in [false, true] {
        let error = restore_from(&fixture, &checkpoint, force).unwrap_err();
        assert_eq!(
            error,
            CheckpointError::Conflicts(vec![RestoreConflict {
                path: canonical(live("keys/authorized_keys")),
                reason: ConflictReason::ParentMissing,
            }])
        );
        assert_eq!(fixture.tree.node("/Users/me/.ssh/authorized_keys"), None);
    }
}

/// A tree where someone writes `racer` into `path` right before the restore's write into it: between the check of
/// step 1 and the write.
struct Racing {
    tree: Arc<FakeTree>,
    path: PathBuf,
}

impl ShadowFiles for Racing {
    fn kind(&self, path: &Path) -> Result<FileKind, PlatformError> {
        self.tree.kind(path)
    }
    fn list(&self, path: &Path, limit: usize) -> Result<Vec<std::ffi::OsString>, PlatformError> {
        self.tree.list(path, limit)
    }
    fn make_dir(&self, path: &Path) -> Result<(), PlatformError> {
        self.tree.make_dir(path)
    }
    fn clone_file(&self, src: &Path, dst: &Path) -> Result<(), PlatformError> {
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
        if dst == self.path && expect.is_some() {
            self.tree.add_file(dst, b"racer");
        }
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

// FR-CKP-20: a file written by someone else between its check and the restore's write is never overwritten. The
// whole restore is put back, and the conflict names that file, not one the rollback rewrote.
#[test]
fn file_changed_before_its_write_is_a_conflict_naming_it() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a-old");
    fixture.tree.add_file(live("b.txt"), b"b-old");
    let checkpoint = fixture.command(1, &["a.txt", "b.txt"], |tree| {
        tree.add_file(live("a.txt"), b"a-new");
        tree.add_file(live("b.txt"), b"b-new");
    });
    let racing = Racing {
        tree: Arc::clone(&fixture.tree),
        path: live("b.txt"),
    };

    let error = restore(
        &racing,
        &RestoreRequest {
            from: &checkpoint,
            saved: saved_id(1),
            force: false,
        },
    )
    .unwrap_err();

    assert_eq!(
        error,
        CheckpointError::Conflicts(vec![RestoreConflict {
            path: canonical(live("b.txt")),
            reason: ConflictReason::Changed,
        }])
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-new"[..]), "put back");
    assert_eq!(
        fixture.contents("b.txt").as_deref(),
        Some(&b"racer"[..]),
        "never overwritten"
    );
    assert_eq!(fixture.journals(), Vec::<PathBuf>::new());
    assert_eq!(fixture.tree.node(saved_folder()), None);
}

// Never mixed, across a stop: the temporary file of a journal write a crash interrupted is not a journal; recovery
// leaves it and still puts back the real journal's restore.
#[test]
fn recovery_skips_what_is_not_a_journal() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"a-old");
    let checkpoint = fixture.command(1, &["a.txt", "new.txt"], |tree| {
        tree.add_file(live("a.txt"), b"a-new");
        tree.add_file(live("new.txt"), b"created");
    });
    fixture.tree.fail_write(live("a.txt"), ENOSPC);
    let error = restore_from(&fixture, &checkpoint, false).unwrap_err();
    assert!(matches!(error, CheckpointError::RollbackFailed(_)), "{error:?}");
    let stray = Path::new(STORE).join(RESTORES_DIR).join(".knsh.1234.tmp");
    fixture.tree.add_file(&stray, b"{\"format\":1,\"chec");

    fixture.tree.allow_write(live("a.txt"));
    assert_eq!(recover_restores(fixture.tree.as_ref(), Path::new(STORE)), Ok(1));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a-new"[..]));
    assert_eq!(fixture.contents("new.txt").as_deref(), Some(&b"created"[..]));
    assert_eq!(fixture.journals(), vec![PathBuf::from(".knsh.1234.tmp")]);
    assert_eq!(recover_restores(fixture.tree.as_ref(), Path::new(STORE)), Ok(0));
}
