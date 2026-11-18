//! [`ScriptedFileEvents`]: file-event streams whose events the test writes (KNSH-080).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::lock;
use crate::error::{Operation, PlatformError};
use crate::file_events::{FileEvent, FileEventSink, FileEventStream, FileEvents};

/// What a flush delivers: given the stream's watched folders, the events to hand its sink (for example, the event of
/// a marker file the code under test just created).
pub type FlushHook = Box<dyn Fn(&[PathBuf]) -> Vec<FileEvent> + Send + Sync>;

/// One stream as the fake keeps it.
struct Watched {
    paths: Vec<PathBuf>,
    sink: Arc<dyn FileEventSink>,
    /// Shared with the stream handle: cleared when it is dropped.
    live: Arc<Mutex<bool>>,
}

#[derive(Default)]
struct State {
    streams: Vec<Watched>,
    /// Errors the next `watch` calls fail with, first first.
    failures: Vec<PlatformError>,
    flushes: u64,
}

/// The fake's state, shared by its clones and (weakly) by its streams.
#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    hook: Mutex<Option<FlushHook>>,
}

/// File-event streams driven by the test. [`ScriptedFileEvents::emit`] hands events to every live stream watching a
/// folder that contains them, synchronously on the caller's thread; a flush counts itself and delivers what the
/// [`FlushHook`] returns. Nothing is delivered after a stream is dropped. Clones share one set of streams.
#[derive(Default, Clone)]
pub struct ScriptedFileEvents(Arc<Inner>);

impl ScriptedFileEvents {
    /// No stream yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the next `watch` call fail with `error`.
    pub fn fail_next_watch(&self, error: PlatformError) {
        lock(&self.0.state).failures.push(error);
    }

    /// Sets what every later flush delivers.
    pub fn on_flush(&self, hook: FlushHook) {
        *lock(&self.0.hook) = Some(hook);
    }

    /// Hands `events` to each live stream watching a folder that contains them (the folder itself included), one batch
    /// per stream, in order.
    pub fn emit(&self, events: &[FileEvent]) {
        // Collected under the lock, delivered outside it, so a sink may call back into the fake.
        let deliveries: Vec<(Arc<dyn FileEventSink>, Vec<FileEvent>)> = lock(&self.0.state)
            .streams
            .iter()
            .filter(|watched| *lock(&watched.live))
            .filter_map(|watched| {
                let mine: Vec<FileEvent> = events
                    .iter()
                    .filter(|event| watched.paths.iter().any(|path| event.path.starts_with(path)))
                    .cloned()
                    .collect();
                (!mine.is_empty()).then(|| (Arc::clone(&watched.sink), mine))
            })
            .collect();
        for (sink, batch) in deliveries {
            sink.deliver(&batch);
        }
    }

    /// Flushes so far, over every stream.
    #[must_use]
    pub fn flushes(&self) -> u64 {
        lock(&self.0.state).flushes
    }

    /// Streams not dropped yet.
    #[must_use]
    pub fn live_streams(&self) -> usize {
        lock(&self.0.state)
            .streams
            .iter()
            .filter(|watched| *lock(&watched.live))
            .count()
    }

    /// The folders of every stream started so far, in order, dropped or not.
    #[must_use]
    pub fn watched(&self) -> Vec<Vec<PathBuf>> {
        lock(&self.0.state)
            .streams
            .iter()
            .map(|watched| watched.paths.clone())
            .collect()
    }
}

impl FileEvents for ScriptedFileEvents {
    fn watch(
        &self,
        paths: &[PathBuf],
        _latency: Duration,
        sink: Arc<dyn FileEventSink>,
    ) -> Result<Box<dyn FileEventStream>, PlatformError> {
        if paths.is_empty() || paths.iter().any(|path| !Path::is_absolute(path)) {
            return Err(PlatformError::InvalidPath);
        }
        let mut state = lock(&self.0.state);
        if !state.failures.is_empty() {
            return Err(state.failures.remove(0));
        }
        let live = Arc::new(Mutex::new(true));
        state.streams.push(Watched {
            paths: paths.to_vec(),
            sink,
            live: Arc::clone(&live),
        });
        Ok(Box::new(ScriptedStream {
            events: Arc::downgrade(&self.0),
            paths: paths.to_vec(),
            live,
        }))
    }
}

/// A stream of [`ScriptedFileEvents`].
struct ScriptedStream {
    events: Weak<Inner>,
    paths: Vec<PathBuf>,
    live: Arc<Mutex<bool>>,
}

impl FileEventStream for ScriptedStream {
    fn flush(&self) {
        let Some(inner) = self.events.upgrade() else { return };
        lock(&inner.state).flushes += 1;
        let delivered = lock(&inner.hook).as_ref().map(|hook| hook(&self.paths));
        if let Some(delivered) = delivered {
            ScriptedFileEvents(inner).emit(&delivered);
        }
    }
}

impl Drop for ScriptedStream {
    fn drop(&mut self) {
        *lock(&self.live) = false;
    }
}

/// The error a failed `watch` reports on macOS.
#[must_use]
pub fn watch_failure() -> PlatformError {
    PlatformError::Os {
        operation: Operation::FileEvents,
        errno: libc::EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_events::FileEventFlags;

    #[derive(Default)]
    struct Collect(Mutex<Vec<FileEvent>>);

    impl FileEventSink for Collect {
        fn deliver(&self, events: &[FileEvent]) {
            lock(&self.0).extend_from_slice(events);
        }
    }

    #[test]
    fn delivers_to_watching_streams_until_dropped() {
        let events = ScriptedFileEvents::new();
        let sink = Arc::new(Collect::default());
        let stream = events
            .watch(
                &[PathBuf::from("/root")],
                Duration::ZERO,
                Arc::clone(&sink) as Arc<dyn FileEventSink>,
            )
            .unwrap();
        let inside = FileEvent::new("/root/a", FileEventFlags::ITEM_CREATED);
        events.emit(&[inside.clone(), FileEvent::new("/elsewhere/b", FileEventFlags::NONE)]);
        assert_eq!(*lock(&sink.0), std::slice::from_ref(&inside));
        events.on_flush(Box::new(|paths| {
            vec![FileEvent::new(paths[0].join("m"), FileEventFlags::ITEM_CREATED)]
        }));
        stream.flush();
        assert_eq!(events.flushes(), 1);
        assert_eq!(lock(&sink.0).len(), 2);
        assert_eq!(events.live_streams(), 1);
        drop(stream);
        assert_eq!(events.live_streams(), 0);
        events.emit(&[inside]);
        assert_eq!(lock(&sink.0).len(), 2);
        events.fail_next_watch(watch_failure());
        assert!(events.watch(&[PathBuf::from("/root")], Duration::ZERO, sink).is_err());
        assert_eq!(events.watched().len(), 1);
    }
}
