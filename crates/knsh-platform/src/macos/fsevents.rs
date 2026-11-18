//! The macOS [`FileEvents`]: `FSEvents` streams with file-level events, on a private serial dispatch queue (KNSH-080).
//!
//! Hand-written bindings to `CoreServices`, `CoreFoundation` and `libdispatch`, as in the capability probe (KNSH-014).
//! Each stream is created with `kFSEventStreamCreateFlagFileEvents` (one event per file, not per folder) and
//! `kFSEventStreamCreateFlagWatchRoot` (a watched folder moved or removed reports `RootChanged`, decision 16), from
//! now on (`kFSEventStreamEventIdSinceNow`).
//!
//! # Lifetime of the sink
//!
//! The stream's context holds a raw pointer to a boxed `Arc<dyn FileEventSink>`. The callback runs only on the
//! stream's serial queue. Dropping the stream stops and invalidates it (no callback is scheduled after that), then
//! runs an empty function synchronously on the same queue, so a callback already running has returned, and only then
//! frees the sink. A panic in the sink is caught at the callback boundary and the batch is dropped, never unwound into
//! the system's frames.

use std::ffi::{CStr, OsStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::error::{Operation, PlatformError};
use crate::file_events::{FileEvent, FileEventFlags, FileEventSink, FileEventStream, FileEvents};

type CFAllocatorRef = *const c_void;
type CFArrayRef = *const c_void;
type CFStringRef = *const c_void;
type CFIndex = isize;
type FSEventStreamRef = *mut c_void;
type DispatchQueue = *mut c_void;
type FSEventStreamCallback = extern "C" fn(*const c_void, *mut c_void, usize, *mut c_void, *const u32, *const u64);

/// `CFArrayCallBacks`; only its address is used.
#[repr(C)]
struct CFArrayCallBacks {
    version: CFIndex,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

/// `FSEventStreamContext`: version 0, the `info` pointer handed to the callback, and no retain or release functions
/// (the stream's owner keeps `info` alive, module documentation).
#[repr(C)]
struct FSEventStreamContext {
    version: CFIndex,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

const K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW: u64 = u64::MAX;
/// `kFSEventStreamCreateFlagWatchRoot`.
const K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x0000_0004;
/// `kFSEventStreamCreateFlagFileEvents`.
const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;

/// Folders one stream watches at most: a root and its marker folder in `knshd`; the bound keeps a caller from
/// building an unbounded path array.
pub const MAX_WATCHED_PATHS: usize = 64;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: CFArrayCallBacks;
    fn CFStringCreateWithFileSystemRepresentation(allocator: CFAllocatorRef, buffer: *const c_char) -> CFStringRef;
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const *const c_void,
        count: CFIndex,
        callbacks: *const CFArrayCallBacks,
    ) -> CFArrayRef;
    fn CFRelease(object: *const c_void);
}

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: CFAllocatorRef,
        callback: FSEventStreamCallback,
        context: *const FSEventStreamContext,
        paths: CFArrayRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamSetDispatchQueue(stream: FSEventStreamRef, queue: DispatchQueue);
    fn FSEventStreamStart(stream: FSEventStreamRef) -> u8;
    fn FSEventStreamFlushSync(stream: FSEventStreamRef);
    fn FSEventStreamStop(stream: FSEventStreamRef);
    fn FSEventStreamInvalidate(stream: FSEventStreamRef);
    fn FSEventStreamRelease(stream: FSEventStreamRef);
}

// libdispatch is part of libSystem.
unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attributes: *const c_void) -> DispatchQueue;
    fn dispatch_sync_f(queue: DispatchQueue, context: *mut c_void, work: extern "C" fn(*mut c_void));
    fn dispatch_release(object: *mut c_void);
}

/// Starts `FSEvents` streams.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsEventStreams;

impl FsEventStreams {
    /// The backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn file_events_error() -> PlatformError {
    PlatformError::Os {
        operation: Operation::FileEvents,
        // FSEvents reports failure as a null result or `false`, without an errno.
        errno: libc::EIO,
    }
}

/// The sink as the callback sees it: a thin pointer to this box is the stream's `info`.
type SinkBox = Arc<dyn FileEventSink>;

impl FileEvents for FsEventStreams {
    fn watch(
        &self,
        paths: &[PathBuf],
        latency: Duration,
        sink: Arc<dyn FileEventSink>,
    ) -> Result<Box<dyn FileEventStream>, PlatformError> {
        if paths.is_empty() || paths.len() > MAX_WATCHED_PATHS || paths.iter().any(|path| !path.is_absolute()) {
            return Err(PlatformError::InvalidPath);
        }
        let array = path_array(paths)?;
        let info = Box::into_raw(Box::new(sink));
        let context = FSEventStreamContext {
            version: 0,
            info: info.cast(),
            retain: ptr::null(),
            release: ptr::null(),
            copy_description: ptr::null(),
        };
        // SAFETY: a valid callback, context (copied by the stream) and path array; the default allocator (null).
        let stream = unsafe {
            FSEventStreamCreate(
                ptr::null(),
                deliver,
                &raw const context,
                array.0,
                K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
                latency.as_secs_f64(),
                K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS | K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT,
            )
        };
        drop(array);
        if stream.is_null() {
            // SAFETY: `info` came from `Box::into_raw` above and no stream refers to it.
            drop(unsafe { Box::from_raw(info) });
            return Err(file_events_error());
        }
        // SAFETY: a static label; null attributes make a serial queue, so callbacks never run concurrently.
        let queue = unsafe { dispatch_queue_create(c"knsh.watch.fsevents".as_ptr(), ptr::null()) };
        if queue.is_null() {
            // SAFETY: the stream was never scheduled, so it never calls back; released once, then `info` is freed.
            unsafe {
                FSEventStreamRelease(stream);
                drop(Box::from_raw(info));
            }
            return Err(file_events_error());
        }
        let mut running = Stream {
            handle: stream,
            queue,
            info,
            started: false,
            flushing: Mutex::new(()),
        };
        // SAFETY: `stream` and `queue` are valid; the stream is scheduled once.
        running.started = unsafe {
            FSEventStreamSetDispatchQueue(stream, queue);
            FSEventStreamStart(stream) != 0
        };
        if !running.started {
            // Dropping `running` invalidates and releases everything in order.
            return Err(file_events_error());
        }
        Ok(Box::new(running))
    }
}

/// A `CFArray` of `CFString`s, released on drop.
struct CfArray(CFArrayRef);

impl Drop for CfArray {
    fn drop(&mut self) {
        // SAFETY: created by `CFArrayCreate` and released exactly once.
        unsafe { CFRelease(self.0) };
    }
}

/// The paths as a `CFArray` of `CFString`s in the file system's representation.
fn path_array(paths: &[PathBuf]) -> Result<CfArray, PlatformError> {
    let mut strings: Vec<CFStringRef> = Vec::with_capacity(paths.len());
    let release_all = |strings: &[CFStringRef]| {
        for string in strings {
            // SAFETY: each came from a Create call and is released exactly once.
            unsafe { CFRelease(*string) };
        }
    };
    for path in paths {
        let Ok(text) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            release_all(&strings);
            return Err(PlatformError::InvalidPath);
        };
        // SAFETY: a valid NUL-terminated string that outlives the call; the default allocator.
        let string = unsafe { CFStringCreateWithFileSystemRepresentation(ptr::null(), text.as_ptr()) };
        if string.is_null() {
            release_all(&strings);
            return Err(PlatformError::InvalidPath);
        }
        strings.push(string);
    }
    let count = CFIndex::try_from(strings.len()).map_err(|_| PlatformError::InvalidPath)?;
    // SAFETY: `strings` holds `count` valid CFStrings for the duration of the call; the array retains each through
    // `kCFTypeArrayCallBacks`, whose address is taken without reading it.
    let array = unsafe { CFArrayCreate(ptr::null(), strings.as_ptr(), count, &raw const kCFTypeArrayCallBacks) };
    release_all(&strings);
    if array.is_null() {
        return Err(file_events_error());
    }
    Ok(CfArray(array))
}

/// The stream callback: converts the batch and hands it to the sink. Runs on the stream's serial queue.
extern "C" fn deliver(
    _stream: *const c_void,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    _ids: *const u64,
) {
    if info.is_null() || paths.is_null() || flags.is_null() || count == 0 {
        return;
    }
    // SAFETY: without `kFSEventStreamCreateFlagUseCFTypes`, `paths` is an array of `count` C strings and `flags` an
    // array of `count` flags, both valid for the duration of the callback.
    let (paths, flags) = unsafe {
        (
            std::slice::from_raw_parts(paths.cast::<*const c_char>(), count),
            std::slice::from_raw_parts(flags, count),
        )
    };
    let events: Vec<FileEvent> = paths
        .iter()
        .zip(flags)
        .filter(|(path, _)| !path.is_null())
        .map(|(path, flags)| {
            // SAFETY: each non-null entry is a NUL-terminated string valid for the callback.
            let bytes = unsafe { CStr::from_ptr(*path) }.to_bytes();
            FileEvent::new(
                PathBuf::from(OsStr::from_bytes(bytes)),
                FileEventFlags::from_bits(*flags),
            )
        })
        .collect();
    // SAFETY: `info` is the `SinkBox` the stream's owner keeps alive until no callback can run (module
    // documentation).
    let sink = unsafe { &*info.cast::<SinkBox>() };
    // A panic must never unwind into FSEvents' frames; the batch is lost, as if dropped by the system.
    let _ = panic::catch_unwind(AssertUnwindSafe(|| sink.deliver(&events)));
}

/// Does nothing; run synchronously on a stream's queue to wait for a callback in progress.
extern "C" fn barrier(_context: *mut c_void) {}

/// A running stream, its queue and its sink.
struct Stream {
    handle: FSEventStreamRef,
    queue: DispatchQueue,
    info: *mut SinkBox,
    /// Whether `FSEventStreamStart` succeeded, so it must be stopped.
    started: bool,
    /// Serialises flushes from several threads (two lines of one root ending together).
    flushing: Mutex<()>,
}

// SAFETY: the stream, queue and sink pointers are only used through FSEvents and libdispatch calls that may be made
// from any thread (`FSEventStreamFlushSync` from a thread other than the queue's, serialised by `flushing`), and the
// sink itself is `Send + Sync`. The pointers are freed only in `drop`, which has exclusive access.
unsafe impl Send for Stream {}
// SAFETY: as for `Send`; the only method taking `&self` is `flush`, serialised by its mutex.
unsafe impl Sync for Stream {}

impl FileEventStream for Stream {
    fn flush(&self) {
        let _flushing = self.flushing.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: `handle` is a started, valid stream until `drop`, which cannot run concurrently with `&self`.
        unsafe { FSEventStreamFlushSync(self.handle) };
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: each object is valid and released exactly once, in the order FSEvents requires: stop (if started),
        // invalidate, release. After invalidation no callback is scheduled; the barrier then waits for one already
        // running on the serial queue, so `info` is freed only when nothing can use it.
        unsafe {
            if self.started {
                FSEventStreamStop(self.handle);
            }
            FSEventStreamInvalidate(self.handle);
            FSEventStreamRelease(self.handle);
            dispatch_sync_f(self.queue, ptr::null_mut(), barrier);
            dispatch_release(self.queue);
            drop(Box::from_raw(self.info));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Condvar;
    use std::time::Instant;

    use super::*;

    /// Collects every event delivered.
    #[derive(Default)]
    struct Collect {
        events: Mutex<Vec<FileEvent>>,
        arrived: Condvar,
    }

    impl FileEventSink for Collect {
        fn deliver(&self, events: &[FileEvent]) {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(events);
            self.arrived.notify_all();
        }
    }

    impl Collect {
        /// Waits up to 10 s for an event naming `path`; whether one came.
        fn wait_for(&self, path: &Path) -> bool {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut events = self.events.lock().unwrap();
            loop {
                if events.iter().any(|event| event.path == path) {
                    return true;
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                events = self.arrived.wait_timeout(events, deadline - now).unwrap().0;
            }
        }
    }

    /// A temporary folder under this crate, canonical (`FSEvents` reports resolved paths), removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!(".knsh-test-fsevents-{name}-{}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(fs::canonicalize(&path).unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // FR-EVT-08: a file written by this process (any process) under a watched folder is reported, with file-level
    // flags; after the stream is dropped, its sink is released.
    #[test]
    fn reports_a_file_written_under_a_watched_folder() {
        let dir = TempDir::new("write");
        let sink = Arc::new(Collect::default());
        let stream = FsEventStreams::new()
            .watch(
                std::slice::from_ref(&dir.0),
                Duration::from_millis(10),
                Arc::clone(&sink) as Arc<dyn FileEventSink>,
            )
            .unwrap();
        // Events start from now on: give the stream a moment, then write.
        std::thread::sleep(Duration::from_millis(100));
        let file = dir.0.join("hello.txt");
        fs::write(&file, b"hi").unwrap();
        // Flushing repeatedly, as the line-end procedure does, until the event arrives.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sink.events.lock().unwrap().iter().any(|event| event.path == file) && Instant::now() < deadline {
            stream.flush();
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(sink.wait_for(&file));
        let flags = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.path == file)
            .fold(FileEventFlags::NONE, |all, event| all.union(event.flags));
        assert!(flags.contains(FileEventFlags::ITEM_IS_FILE), "{flags:?}");
        drop(stream);
        // The stream held one count of the sink; dropping it gave that back.
        assert_eq!(Arc::strong_count(&sink), 1);
    }

    #[test]
    fn refuses_bad_path_lists() {
        let sink: Arc<dyn FileEventSink> = Arc::new(Collect::default());
        let streams = FsEventStreams::new();
        let latency = Duration::from_millis(10);
        assert_eq!(
            streams.watch(&[], latency, Arc::clone(&sink)).err(),
            Some(PlatformError::InvalidPath)
        );
        assert_eq!(
            streams
                .watch(&[PathBuf::from("relative")], latency, Arc::clone(&sink))
                .err(),
            Some(PlatformError::InvalidPath)
        );
        let many = vec![PathBuf::from("/tmp"); MAX_WATCHED_PATHS + 1];
        assert_eq!(
            streams.watch(&many, latency, sink).err(),
            Some(PlatformError::InvalidPath)
        );
    }
}
