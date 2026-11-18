//! File-event streams: which paths under a watched folder may have changed, by any process (KNSH-080, FR-CKP-03,
//! FR-CKP-04, FR-EVT-08).
//!
//! A stream watches a few folders and hands every batch of events to a [`FileEventSink`] on a thread of its own. The
//! sink must return quickly and never call back into the stream: on macOS it runs on the stream's dispatch queue, and
//! [`FileEventStream::flush`] waits for that queue.
//!
//! **Flags are not a change log** (decision 16, `specs/09-reference/decisions.md`): per-path flags accumulate, so an
//! event only means "this path may have changed". What changed is found by looking at the path. Only the stream-level
//! flags ([`FileEventFlags::needs_rescan`], [`FileEventFlags::ids_wrapped`], [`FileEventFlags::root_changed`]) carry
//! meaning on their own: events were lost, and the path named must be rescanned.
//!
//! | Trait | Effect | macOS backend | Fake ([`testing`](crate::testing)) |
//! | --- | --- | --- | --- |
//! | [`FileEvents`] | Watch folders; flush | `FsEventStreams` (`FSEvents`, file events, `WatchRoot`) | `ScriptedFileEvents` |

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::PlatformError;

/// The flags of one event, as `FSEvents` reports them (`FSEventStreamEventFlags`). Bits the engine does not name are
/// kept, so nothing is lost when a newer system adds one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FileEventFlags(u32);

impl FileEventFlags {
    /// No flag: something about the path changed.
    pub const NONE: Self = Self(0);
    /// The folder named must be rescanned, with everything below it: events for it were coalesced or lost.
    pub const MUST_SCAN_SUB_DIRS: Self = Self(0x0000_0001);
    /// Events were dropped in this process (the stream's client fell behind).
    pub const USER_DROPPED: Self = Self(0x0000_0002);
    /// Events were dropped in the kernel.
    pub const KERNEL_DROPPED: Self = Self(0x0000_0004);
    /// Event identifiers wrapped around: every watched folder must be rescanned.
    pub const EVENT_IDS_WRAPPED: Self = Self(0x0000_0008);
    /// A watched folder itself, or one of its parents, was moved, removed or created (`WatchRoot`).
    pub const ROOT_CHANGED: Self = Self(0x0000_0020);
    /// A volume was unmounted below a watched folder.
    pub const UNMOUNT: Self = Self(0x0000_0080);
    /// The item was created (accumulates: a later event for the same path may still carry it).
    pub const ITEM_CREATED: Self = Self(0x0000_0100);
    /// The item was removed.
    pub const ITEM_REMOVED: Self = Self(0x0000_0200);
    /// The item's inode metadata changed.
    pub const ITEM_INODE_META_MOD: Self = Self(0x0000_0400);
    /// The item was renamed (to or from this path).
    pub const ITEM_RENAMED: Self = Self(0x0000_0800);
    /// The item's contents changed.
    pub const ITEM_MODIFIED: Self = Self(0x0000_1000);
    /// The item's extended attributes changed (every new file gets `com.apple.provenance`).
    pub const ITEM_XATTR_MOD: Self = Self(0x0000_8000);
    /// The item is a regular file.
    pub const ITEM_IS_FILE: Self = Self(0x0001_0000);
    /// The item is a folder.
    pub const ITEM_IS_DIR: Self = Self(0x0002_0000);
    /// The item is a symlink.
    pub const ITEM_IS_SYMLINK: Self = Self(0x0004_0000);

    /// The flags from their raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any bit of `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets of flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Events were lost for the path named (`MustScanSubDirs`, `UserDropped`, `KernelDropped`): it must be
    /// rescanned, with everything below it (decision 16).
    #[must_use]
    pub const fn needs_rescan(self) -> bool {
        self.intersects(Self(
            Self::MUST_SCAN_SUB_DIRS.0 | Self::USER_DROPPED.0 | Self::KERNEL_DROPPED.0,
        ))
    }

    /// Event identifiers wrapped: every watched folder must be rescanned.
    #[must_use]
    pub const fn ids_wrapped(self) -> bool {
        self.intersects(Self::EVENT_IDS_WRAPPED)
    }

    /// A watched folder (or a parent) was moved, removed or recreated, or a volume below it unmounted: the folder
    /// must be looked up again, then rescanned.
    #[must_use]
    pub const fn root_changed(self) -> bool {
        self.intersects(Self(Self::ROOT_CHANGED.0 | Self::UNMOUNT.0))
    }

    /// The item is a folder.
    #[must_use]
    pub const fn is_dir(self) -> bool {
        self.intersects(Self::ITEM_IS_DIR)
    }
}

impl fmt::Debug for FileEventFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileEventFlags({:#010x})", self.0)
    }
}

/// One event: a path that may have changed, and its flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    /// The absolute path the event names, as the system reports it (resolved, so `/private/var`, not `/var`).
    pub path: PathBuf,
    /// What the system says about it.
    pub flags: FileEventFlags,
}

impl FileEvent {
    /// An event for `path` with `flags`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, flags: FileEventFlags) -> Self {
        Self {
            path: path.into(),
            flags,
        }
    }
}

/// Receives a stream's events. Called on the stream's own thread, one batch at a time and never concurrently for one
/// stream; it must not block, and must never call [`FileEventStream::flush`] (which waits for it).
pub trait FileEventSink: Send + Sync {
    /// One batch of events, in the order the system reported them.
    fn deliver(&self, events: &[FileEvent]);
}

/// A running stream. Dropping it stops the stream: once the drop returns, its sink is never called again.
pub trait FileEventStream: Send + Sync {
    /// Asks the system to deliver every event it holds for this stream now, and returns once the sink has received
    /// them (`FSEventStreamFlushSync`). **Not enough to close a line** (decision 16): events still on their way
    /// arrive later. Never call it from the sink.
    fn flush(&self);
}

/// Starts file-event streams.
pub trait FileEvents: Send + Sync {
    /// Starts a stream on `paths` (absolute folders, events from now on) that hands its events to `sink`, at most
    /// `latency` after they happen. Events for the folders themselves being moved or removed are reported as
    /// [`FileEventFlags::ROOT_CHANGED`].
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for an empty list or a relative path; [`PlatformError::Os`] with
    /// [`Operation::FileEvents`](crate::Operation::FileEvents) if the stream cannot be created or started.
    fn watch(
        &self,
        paths: &[PathBuf],
        latency: Duration,
        sink: Arc<dyn FileEventSink>,
    ) -> Result<Box<dyn FileEventStream>, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Decision 16: the drop flags and only they ask for a rescan; item flags never do.
    #[test]
    fn only_stream_level_flags_ask_for_a_rescan() {
        for flag in [
            FileEventFlags::MUST_SCAN_SUB_DIRS,
            FileEventFlags::USER_DROPPED,
            FileEventFlags::KERNEL_DROPPED,
        ] {
            assert!(flag.needs_rescan(), "{flag:?}");
        }
        let item = FileEventFlags::ITEM_CREATED
            .union(FileEventFlags::ITEM_REMOVED)
            .union(FileEventFlags::ITEM_MODIFIED)
            .union(FileEventFlags::ITEM_RENAMED)
            .union(FileEventFlags::ITEM_XATTR_MOD)
            .union(FileEventFlags::ITEM_IS_DIR);
        assert!(!item.needs_rescan());
        assert!(!item.ids_wrapped());
        assert!(!item.root_changed());
        assert!(FileEventFlags::EVENT_IDS_WRAPPED.ids_wrapped());
        assert!(FileEventFlags::ROOT_CHANGED.root_changed());
        assert!(FileEventFlags::UNMOUNT.root_changed());
        assert!(item.is_dir());
        assert!(item.contains(FileEventFlags::ITEM_RENAMED));
        assert!(!item.contains(FileEventFlags::ITEM_IS_FILE));
        assert_eq!(FileEventFlags::from_bits(0x1234).bits(), 0x1234);
    }
}
