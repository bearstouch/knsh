//! The process tree on macOS, read with `proc_pidinfo` (KNSH-048).
//!
//! Two flavours are used, both readable for any process without an entitlement:
//!
//! - `PROC_PIDUNIQIDENTIFIERINFO` gives a process's pid version (`p_idversion`, the same value its audit token
//!   carries, and changed by every `exec`), its 64-bit unique id and its parent's unique id. Unique ids survive
//!   `exec` and are never reused while the system runs.
//! - `PROC_PIDT_SHORTBSDINFO` gives its parent pid.
//!
//! Each step is checked against the unique ids, so a pid that was reused between two reads is detected and reported
//! as `ESRCH` rather than followed: the walk can only ever stop early, never wander into an unrelated process.

use std::ffi::{c_int, c_void};
use std::io;

use crate::ancestry::{ProcessIdentity, ProcessKey, ProcessTree};
use crate::error::{Operation, PlatformError};

/// `PROC_PIDUNIQIDENTIFIERINFO` in `<sys/proc_info.h>`; not bound by the libc crate.
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;

/// `struct proc_uniqidentifierinfo` in `<sys/proc_info.h>`: 56 bytes. Fields after `p_idversion` are reserved.
// Field names as in the header, `p_` prefix included, so the struct can be checked against it line by line.
#[allow(clippy::struct_field_names)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UniqueIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_reserve2: u32,
    p_reserve3: u64,
    p_reserve4: u64,
}

/// The kernel's process table.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcessTree;

impl SystemProcessTree {
    /// The live process table.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ProcessTree for SystemProcessTree {
    fn identity(&self, pid: i32) -> Result<ProcessIdentity, PlatformError> {
        let info = unique_info(pid)?;
        Ok(ProcessIdentity::new(pid, info.p_idversion))
    }

    fn resolve(&self, process: ProcessIdentity) -> Result<ProcessKey, PlatformError> {
        // One read gives both, so the unique id is of the very image the version names.
        let info = unique_info(process.pid())?;
        if info.p_idversion != process.version() {
            // Exited (and the pid reused), or exec'd since: not the process the identity named.
            return Err(process_error(libc::ESRCH));
        }
        Ok(ProcessKey::new(process.pid(), info.p_uniqueid))
    }

    fn parent(&self, child: ProcessKey) -> Result<Option<ProcessKey>, PlatformError> {
        let before = unique_info(child.pid())?;
        if before.p_uniqueid != child.unique_id() {
            // The process this key named has exited, and the pid now belongs to another one.
            return Err(process_error(libc::ESRCH));
        }
        let ppid = parent_pid(child.pid())?;
        // The parent pid came from a second read: make sure it was still the same process when it was taken.
        let after = unique_info(child.pid())?;
        if after.p_uniqueid != child.unique_id() {
            return Err(process_error(libc::ESRCH));
        }
        // `launchd` (pid 1) has parent 0, the kernel, which is not followed.
        if ppid <= 0 {
            return Ok(None);
        }
        let parent = unique_info(ppid)?;
        if parent.p_uniqueid != after.p_puniqueid {
            // The parent exited (or the child was re-parented) between the reads and the pid was reused: the pid
            // does not name the parent any more.
            return Err(process_error(libc::ESRCH));
        }
        Ok(Some(ProcessKey::new(ppid, parent.p_uniqueid)))
    }
}

/// The unique-identifier record of `pid`.
fn unique_info(pid: i32) -> Result<UniqueIdentifierInfo, PlatformError> {
    let mut info = UniqueIdentifierInfo::default();
    read_pid_info(pid, PROC_PIDUNIQIDENTIFIERINFO, &mut info)?;
    Ok(info)
}

/// The parent pid of `pid`.
fn parent_pid(pid: i32) -> Result<i32, PlatformError> {
    // SAFETY: `proc_bsdshortinfo` is plain integers and bytes, for which all-zero is a valid value.
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    read_pid_info(pid, libc::PROC_PIDT_SHORTBSDINFO, &mut info)?;
    i32::try_from(info.pbsi_ppid).map_err(|_| process_error(libc::EOVERFLOW))
}

/// Fills `out` with the `flavor` record of `pid`. A short answer is an error: a half-filled record would read as
/// zeros, and a zero pid version or unique id must never be mistaken for a real one.
fn read_pid_info<T>(pid: i32, flavor: c_int, out: &mut T) -> Result<(), PlatformError> {
    let size = c_int::try_from(std::mem::size_of::<T>()).map_err(|_| process_error(libc::EINVAL))?;
    // SAFETY: `out` is a valid, writable buffer of exactly `size` bytes for the duration of the call, and every `T`
    // passed here is a `repr(C)` struct of plain integers, so any bytes the kernel writes form a valid value.
    let written = unsafe { libc::proc_pidinfo(pid, flavor, 0, std::ptr::from_mut(out).cast::<c_void>(), size) };
    if written == size {
        return Ok(());
    }
    if written <= 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(libc::ESRCH);
        // `proc_pidinfo` reports a missing process with 0 and no errno on some releases.
        return Err(process_error(if errno == 0 { libc::ESRCH } else { errno }));
    }
    Err(process_error(libc::EIO))
}

/// A process-information failure with `errno`.
fn process_error(errno: c_int) -> PlatformError {
    PlatformError::Os {
        operation: Operation::ProcessInfo,
        errno,
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    fn own_pid() -> i32 {
        std::process::id().cast_signed()
    }

    #[test]
    fn struct_matches_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<UniqueIdentifierInfo>(), 56);
    }

    // KNSH-048: a live child's parent is this process, at this process's own pid version.
    #[test]
    fn parent_of_a_child_is_this_process() {
        let tree = SystemProcessTree::new();
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let child_key = tree.resolve(tree.identity(child.id().cast_signed()).unwrap()).unwrap();
        let parent = tree.parent(child_key).unwrap();
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(parent, Some(tree.resolve(tree.identity(own_pid()).unwrap()).unwrap()));
    }

    // The walk ends at launchd, which has no parent to follow, within a handful of steps.
    #[test]
    fn walk_from_this_process_ends_at_launchd() {
        let tree = SystemProcessTree::new();
        let mut current = tree.resolve(tree.identity(own_pid()).unwrap()).unwrap();
        for _ in 0..64 {
            let Some(parent) = tree.parent(current).unwrap() else {
                assert_eq!(current.pid(), 1, "the root of the walk is launchd");
                return;
            };
            current = parent;
        }
        panic!("no root within 64 steps");
    }

    // PID reuse: an identity whose version no longer matches the live process is refused, never resolved; a key whose
    // unique id is not the live process's is refused, never followed.
    #[test]
    fn stale_identity_is_refused() {
        let tree = SystemProcessTree::new();
        let own = tree.identity(own_pid()).unwrap();
        let stale = ProcessIdentity::new(own.pid(), own.version().wrapping_add(1));
        assert_eq!(tree.resolve(stale).unwrap_err().errno(), Some(libc::ESRCH));
        let key = tree.resolve(own).unwrap();
        let forged = ProcessKey::new(key.pid(), key.unique_id().wrapping_add(1));
        assert_eq!(tree.parent(forged).unwrap_err().errno(), Some(libc::ESRCH));
        // Once a child is reaped its identity and key are gone: the pid is unreadable, or (reused) is another process.
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id().cast_signed();
        let before = tree.identity(pid).unwrap();
        let key = tree.resolve(before).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_ne!(tree.identity(pid).ok(), Some(before));
        assert!(tree.resolve(before).is_err());
        assert!(tree.parent(key).is_err());
    }

    // KNSH-048: `exec` gives a process a new pid version but keeps its unique id. An identity taken before the exec
    // no longer resolves; the key taken before it still names the process, so an envelope root that execs (as every
    // root does, through `knsh-exec`) stays its envelope's root.
    #[test]
    fn exec_changes_the_version_but_not_the_key() {
        let tree = SystemProcessTree::new();
        // The shell waits on stdin, then execs `sleep`: the pid stays, the image changes.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read line; exec /bin/sleep 30"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id().cast_signed();
        let before = tree.identity(pid).unwrap();
        let key = tree.resolve(before).unwrap();
        let mut stdin = child.stdin.take().unwrap();
        std::io::Write::write_all(&mut stdin, b"go\n").unwrap();
        drop(stdin);
        let mut after = before;
        for _ in 0..200 {
            after = tree.identity(pid).unwrap();
            if after != before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let resolved = tree.resolve(after);
        let parent = tree.parent(key);
        let _ = child.kill();
        let _ = child.wait();
        assert_ne!(after, before, "exec gives a new pid version");
        assert_eq!(resolved.unwrap(), key, "the unique id survives exec");
        assert_eq!(
            parent.unwrap(),
            Some(tree.resolve(tree.identity(own_pid()).unwrap()).unwrap())
        );
    }
}
