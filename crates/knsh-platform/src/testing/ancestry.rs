//! A process table built by the test (KNSH-048).

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::lock;
use crate::ancestry::{ProcessIdentity, ProcessKey, ProcessTree};
use crate::error::{Operation, PlatformError};

/// A process table the test fills: each live process with its parent. A process that [`FakeProcessTree::exit`]s is
/// gone, and [`FakeProcessTree::spawn`] may reuse its pid at a new version, as the kernel does. A process that
/// [`FakeProcessTree::exec`]s keeps its pid and unique id but gets a new pid version, as on macOS.
#[derive(Debug, Default)]
pub struct FakeProcessTree {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Live processes by pid.
    live: BTreeMap<i32, Live>,
    /// The last unique id given out; ids start at 1, so 0 never names a process.
    last_unique: u64,
}

#[derive(Debug, Clone, Copy)]
struct Live {
    identity: ProcessIdentity,
    key: ProcessKey,
    parent: Option<ProcessKey>,
}

impl FakeProcessTree {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the live process `process`, child of `parent` (`None` for a root such as `launchd`), and returns its
    /// key. Replaces whatever process held the pid before, as pid reuse does. A `parent` that is not live (at that
    /// version) is a parent that has already exited: the walk through the new process fails.
    pub fn spawn(&self, process: ProcessIdentity, parent: Option<ProcessIdentity>) -> ProcessKey {
        let mut state = lock(&self.state);
        let parent = parent.map(|parent| match state.live.get(&parent.pid()) {
            Some(live) if live.identity == parent => live.key,
            // Unique id 0 is never given out, so this parent never matches a live process.
            Some(_) | None => ProcessKey::new(parent.pid(), 0),
        });
        state.last_unique += 1;
        let key = ProcessKey::new(process.pid(), state.last_unique);
        state.live.insert(
            process.pid(),
            Live {
                identity: process,
                key,
                parent,
            },
        );
        key
    }

    /// Runs `exec` in `process`: same pid and unique id, next pid version. Returns the new identity, or `None` if
    /// `process` is not live.
    pub fn exec(&self, process: ProcessIdentity) -> Option<ProcessIdentity> {
        let mut state = lock(&self.state);
        let live = state
            .live
            .get_mut(&process.pid())
            .filter(|live| live.identity == process)?;
        live.identity = ProcessIdentity::new(process.pid(), process.version() + 1);
        Some(live.identity)
    }

    /// Removes `process`: it exited and was reaped. Its children keep pointing at it, as a test of re-parenting may
    /// want; a walk through them then fails like the real one.
    pub fn exit(&self, process: ProcessIdentity) {
        let mut state = lock(&self.state);
        if state
            .live
            .get(&process.pid())
            .is_some_and(|live| live.identity == process)
        {
            state.live.remove(&process.pid());
        }
    }
}

impl ProcessTree for FakeProcessTree {
    fn identity(&self, pid: i32) -> Result<ProcessIdentity, PlatformError> {
        lock(&self.state)
            .live
            .get(&pid)
            .map(|live| live.identity)
            .ok_or_else(gone)
    }

    fn resolve(&self, process: ProcessIdentity) -> Result<ProcessKey, PlatformError> {
        match lock(&self.state).live.get(&process.pid()) {
            Some(live) if live.identity == process => Ok(live.key),
            Some(_) | None => Err(gone()),
        }
    }

    fn parent(&self, child: ProcessKey) -> Result<Option<ProcessKey>, PlatformError> {
        let state = lock(&self.state);
        let live = state
            .live
            .get(&child.pid())
            .filter(|live| live.key == child)
            .ok_or_else(gone)?;
        match live.parent {
            // The parent must still be alive, as the real backend checks by unique id.
            Some(parent) if state.live.get(&parent.pid()).is_some_and(|live| live.key == parent) => Ok(Some(parent)),
            Some(_) => Err(gone()),
            None => Ok(None),
        }
    }
}

/// `ESRCH`: no such process.
fn gone() -> PlatformError {
    PlatformError::Os {
        operation: Operation::ProcessInfo,
        errno: libc::ESRCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_live_parents_and_refuses_reused_pids() {
        let tree = FakeProcessTree::new();
        let root = ProcessIdentity::new(1, 1);
        let parent = ProcessIdentity::new(10, 1);
        let child = ProcessIdentity::new(11, 1);
        let root_key = tree.spawn(root, None);
        let parent_key = tree.spawn(parent, Some(root));
        let child_key = tree.spawn(child, Some(parent));
        assert_eq!(tree.resolve(child).unwrap(), child_key);
        assert_eq!(tree.parent(child_key).unwrap(), Some(parent_key));
        assert_eq!(tree.parent(root_key).unwrap(), None);
        assert_eq!(tree.identity(11).unwrap(), child);

        // The child exits and its pid is reused: the old identity and key are refused, the new one is someone else.
        tree.exit(child);
        tree.spawn(ProcessIdentity::new(11, 2), Some(root));
        assert!(tree.resolve(child).is_err());
        assert!(tree.parent(child_key).is_err());
        // The parent exits: its child can no longer be walked through it.
        let grandchild = tree.spawn(ProcessIdentity::new(12, 1), Some(parent));
        tree.exit(parent);
        assert!(tree.parent(grandchild).is_err());
    }

    // As on macOS: exec changes the pid version, not the key.
    #[test]
    fn exec_keeps_the_key() {
        let tree = FakeProcessTree::new();
        let process = ProcessIdentity::new(5, 1);
        let key = tree.spawn(process, None);
        let execd = tree.exec(process).unwrap();
        assert_ne!(execd, process);
        assert!(tree.resolve(process).is_err());
        assert_eq!(tree.resolve(execd).unwrap(), key);
        assert_eq!(tree.exec(process), None);
    }
}
