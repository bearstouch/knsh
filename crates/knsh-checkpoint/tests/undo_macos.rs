//! macOS integration test for undo and redo (KNSH-084): a real `sed -i` edit, captured through the public capture API
//! with the real clone service, undone while another process holds the file open.
//!
//! Files live in a temporary folder under this crate's directory, never in the user's real data.

#![cfg(all(test, target_os = "macos"))]
// Setup helpers outside `#[test]` functions: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use knsh_checkpoint::{
    Caller, Captures, Change, History, Ledger, PlatformShadowFiles, PostImage, PreImage, Request, RestoreEvents,
    ShadowFiles, Target, post_image_identity,
};
use knsh_core::{CanonicalPath, EventData, RecordId, SessionId, Ulid};
use knsh_platform::macos::{RealFs, SystemClock, SystemRandom, SystemVolumes};
use knsh_platform::{FileSystemKind, Volumes};

/// A temporary folder, removed on drop (also when a test panics).
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(".knsh-test-undo-{name}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(&path).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<EventData>>);

impl RestoreEvents for Events {
    fn restored(&self, _session_id: SessionId, data: EventData) {
        self.0.lock().unwrap().push(data);
    }
}

// FR-CKP-20, FR-CKP-22, FR-CKP-23: `sed -i` replaces the file with a new one (a new inode). A process that opened the
// edited file holds that inode; undo writes the old contents into it in place, so the open descriptor reads the
// restored contents, the inode stays, and the time is now. Redo brings the edit back the same way.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end scenario: capture, undo, redo, conflict"
)]
fn undo_of_sed_edit_is_seen_through_an_open_descriptor() {
    let volumes = SystemVolumes::new();
    let temp = TempDir::new("sed");
    if volumes.volume_of(&temp.0).unwrap().kind != FileSystemKind::Apfs {
        eprintln!("skipped: the checkout is not on APFS");
        return;
    }
    let root = CanonicalPath::new(temp.0.join("root")).unwrap();
    let store = temp.0.join("store");
    fs::create_dir(root.as_path()).unwrap();
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let file = root.as_path().join("notes.txt");
    fs::write(&file, b"hello world\n").unwrap();
    let path = CanonicalPath::new(&file).unwrap();

    // Capture, as the watcher does: the shadow copy (a clone of the version before) is held, then the edit runs.
    let held = store.join("held-0");
    volumes.clone_file(&file, &held).unwrap();
    let status = Command::new("/usr/bin/sed")
        .args(["-i", "", "s/world/there/"])
        .arg(&file)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read(&file).unwrap(), b"hello there\n");
    let post = post_image_identity(&volumes, &file).unwrap();

    let files: Arc<dyn ShadowFiles> = Arc::new(PlatformShadowFiles::new(Arc::new(RealFs::new()), Arc::new(volumes)));
    let session = SessionId::from_ulid(Ulid::from_u128(1));
    let record = RecordId::from_ulid(Ulid::from_u128(2));
    let mut ledger = Ledger::new();
    let captures = Captures::new(
        Arc::clone(&files),
        Arc::new(SystemClock::new()),
        Arc::new(SystemRandom::new()),
    );
    ledger.watch(&root, session, true);
    ledger.line_started(record, session, std::slice::from_ref(&root));
    let edge = ledger.changed(&root, &path).unwrap();
    let ticket = captures.begin(edge);
    let mut finished = captures.add(
        ticket,
        session,
        &store,
        &root,
        Change {
            path: path.clone(),
            pre: PreImage::Held(held),
            post: PostImage::Present(post),
        },
    );
    ledger.line_ended(record);
    finished.extend(captures.closed(&ledger.take_closed()));
    let checkpoint = finished.pop().unwrap();

    // Another process opens the edited file and waits.
    let mut holder = Command::new("/bin/sh")
        .args(["-c", r#"exec 3<"$1"; echo ready; read _; cat <&3"#, "sh"])
        .arg(&file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(holder.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    assert_eq!(ready, "ready\n");
    let inode = fs::metadata(&file).unwrap().ino();
    let before_undo = SystemTime::now() - Duration::from_secs(1);

    let mut history = History::new(
        Arc::clone(&files),
        Arc::new(SystemClock::new()),
        Arc::new(SystemRandom::new()),
    );
    history.record(checkpoint).unwrap();
    let events = Events::default();
    let request = Request {
        target: Target::Record(record),
        caller: Caller::User,
        force: false,
    };
    let restored = history.undo(&request, &events).unwrap();

    assert_eq!(restored.restored, vec![path]);
    let meta = fs::metadata(&file).unwrap();
    assert_eq!(meta.ino(), inode, "restored in place");
    assert!(meta.modified().unwrap() >= before_undo, "the time is now");
    assert_eq!(fs::read(&file).unwrap(), b"hello world\n");
    holder.stdin.take().unwrap().write_all(b"\n").unwrap();
    let mut through_descriptor = String::new();
    stdout.read_to_string(&mut through_descriptor).unwrap();
    assert!(holder.wait().unwrap().success());
    assert_eq!(
        through_descriptor, "hello world\n",
        "the open descriptor reads the restored contents"
    );
    assert_eq!(events.0.lock().unwrap().len(), 1, "checkpoint.restored");

    // Redo: the edit is back, in the same inode.
    history.redo(&request, &events).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"hello there\n");
    assert_eq!(fs::metadata(&file).unwrap().ino(), inode);

    // A human edit after the redo: undo is a conflict, and the edit is kept.
    fs::write(&file, b"human\n").unwrap();
    assert!(history.undo(&request, &events).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"human\n");
    assert!(
        fs::read_dir(store.join(knsh_checkpoint::RESTORES_DIR))
            .unwrap()
            .next()
            .is_none(),
        "no journal is left behind"
    );
}
