//! Files held for writing, read with `proc_pidinfo` (KNSH-085, decision 17).
//!
//! Observed on macOS 26.6 (KNSH-077) to work for a same-user process without privileges:
//!
//! - `PROC_PIDLISTFDS` lists a process's descriptors; for each vnode descriptor, `proc_pidfdinfo` with
//!   `PROC_PIDFDVNODEPATHINFO` gives its open flags (`FWRITE`) and its path.
//! - `PROC_PIDREGIONPATHINFO`, called with an address, gives the first region at or after it with its protection,
//!   inheritance, share mode and, for a file mapping, the file's path; regions are walked from address 0.
//!
//! **Telling a shared mapping from a private one.** The share mode does not: observed on macOS 26.6, a file mapped
//! `MAP_SHARED` by one process reports `SM_PRIVATE`, exactly like a `MAP_PRIVATE` mapping after its first store. The
//! inheritance does: `mmap` gives a `MAP_SHARED` region `VM_INHERIT_SHARE` and a `MAP_PRIVATE` one
//! `VM_INHERIT_COPY`. A region is taken as shared when its inheritance is `VM_INHERIT_SHARE` or its share mode is a
//! shared one (`SM_SHARED`, `SM_TRUESHARED`, `SM_SHARED_ALIASED`); a process that changed a shared region's
//! inheritance with `minherit` is not seen (a limit, recorded in the checkpoint specification).
//!
//! A system-wide search by path (`proc_listpidspath`) took 284 to 620 ms per path, too slow per line, so the
//! processes to ask are chosen by the caller instead.
//!
//! Each process is checked by unique id before and after its files are read, so a pid reused meanwhile is reported
//! as `ESRCH`, never answered with another process's files.

use std::collections::BTreeSet;
use std::ffi::{OsStr, c_int, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::ancestry::ProcessKey;
use crate::error::{Operation, PlatformError};
use crate::holders::{HeldFile, HoldKind, MAX_HELD_FILES, MAX_PROCESSES, ProcessEntry, WriteHolders};

/// `PROC_PIDUNIQIDENTIFIERINFO` in `<sys/proc_info.h>`.
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;
/// `PROC_PIDREGIONPATHINFO` in `<sys/proc_info.h>`.
const PROC_PIDREGIONPATHINFO: c_int = 8;
/// `PROC_PIDFDVNODEPATHINFO` in `<sys/proc_info.h>`.
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
/// `FWRITE` in `<sys/fcntl.h>`: the descriptor was opened for writing.
const FWRITE: u32 = 0x0002;
/// `VREG` in `<sys/vnode.h>`: a regular file.
const VREG: c_int = 1;
/// `VM_INHERIT_SHARE` in `<mach/vm_inherit.h>`: what `mmap` gives a `MAP_SHARED` region (module documentation).
const VM_INHERIT_SHARE: u32 = 0;
/// `SM_SHARED`, `SM_TRUESHARED` and `SM_SHARED_ALIASED` in `<mach/vm_region.h>`: memory shared with another mapping.
const SHARED_SHARE_MODES: [u32; 3] = [4, 5, 7];
/// The most descriptors one process is read with (`kern.maxfilesperproc` is far lower by default).
const MAX_DESCRIPTORS: usize = 1 << 18;
/// The most regions one process is walked through; more is an error (`EOVERFLOW`), never a silent cut.
const MAX_REGIONS: usize = 1 << 20;

/// `struct proc_uniqidentifierinfo` in `<sys/proc_info.h>`: 56 bytes.
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

/// `struct proc_fileinfo` in `<sys/proc_info.h>`: 24 bytes.
#[allow(clippy::struct_field_names)]
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct vnode_fdinfowithpath` in `<sys/proc_info.h>`: 1,200 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: libc::vnode_info_path,
}

/// `struct proc_regioninfo` in `<sys/proc_info.h>`: 96 bytes.
#[allow(clippy::struct_field_names)]
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcRegionInfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
}

/// `struct proc_regionwithpathinfo` in `<sys/proc_info.h>`: 1,272 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcRegionWithPathInfo {
    prp_prinfo: ProcRegionInfo,
    prp_vip: libc::vnode_info_path,
}

/// The kernel's process table and each process's descriptors and mappings.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWriteHolders;

impl SystemWriteHolders {
    /// The live process table.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WriteHolders for SystemWriteHolders {
    fn processes(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        let pids = all_pids()?;
        let mut entries = Vec::with_capacity(pids.len());
        for pid in pids {
            match entry_of(pid) {
                Ok(entry) => entries.push(entry),
                // Exited meanwhile, or a zombie (observed: every flavour answers `ESRCH`): it holds nothing.
                Err(PlatformError::Os { errno: libc::ESRCH, .. }) => {}
                // Any other failure would leave a process, maybe one of the line's, out of the table, and its files
                // would read as not held: the whole table fails instead (FR-CKP-24, fail closed).
                Err(error) => return Err(error),
            }
        }
        Ok(entries)
    }

    fn held_for_writing(&self, process: ProcessKey) -> Result<Vec<HeldFile>, PlatformError> {
        same_process(process)?;
        let mut held = BTreeSet::new();
        open_for_writing(process.pid(), &mut held)?;
        mapped_writable(process.pid(), &mut held)?;
        // Read after the files: had the pid been reused meanwhile, they could be another process's.
        same_process(process)?;
        Ok(held.into_iter().collect())
    }
}

/// Every pid in the process table.
fn all_pids() -> Result<Vec<i32>, PlatformError> {
    // SAFETY: a null buffer of size 0 asks only for the count; nothing is written.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let count = usize::try_from(count).map_err(|_| last_error())?;
    // Room for processes started between the two calls.
    let capacity = (count + 256).min(MAX_PROCESSES + 1);
    let mut pids = vec![0i32; capacity];
    let bytes = c_int::try_from(capacity * size_of::<i32>()).map_err(|_| process_error(libc::EOVERFLOW))?;
    // SAFETY: `pids` is a valid, writable buffer of exactly `bytes` bytes for the duration of the call; any `i32`
    // the kernel writes is a valid value.
    let filled = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), bytes) };
    let filled = usize::try_from(filled).map_err(|_| last_error())?;
    // A full buffer may have cut the table short (more than 256 processes started between the calls): an error,
    // never a silent cut that would leave a line's process unasked.
    if filled > MAX_PROCESSES || filled >= capacity {
        return Err(process_error(libc::EOVERFLOW));
    }
    pids.truncate(filled.min(capacity));
    pids.retain(|pid| *pid > 0);
    Ok(pids)
}

/// The entry of `pid`: unique ids read before and after its group, so the group is the same process's.
fn entry_of(pid: i32) -> Result<ProcessEntry, PlatformError> {
    let before = unique_info(pid)?;
    // SAFETY: `proc_bsdshortinfo` is plain integers and bytes, for which all-zero is a valid value.
    let mut short: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    read_pid_info(pid, libc::PROC_PIDT_SHORTBSDINFO, 0, &mut short)?;
    let after = unique_info(pid)?;
    if before.p_uniqueid != after.p_uniqueid {
        return Err(process_error(libc::ESRCH));
    }
    Ok(ProcessEntry {
        key: ProcessKey::new(pid, after.p_uniqueid),
        parent_unique_id: after.p_puniqueid,
        group: i32::try_from(short.pbsi_pgid).map_err(|_| process_error(libc::EOVERFLOW))?,
    })
}

/// `ESRCH` unless the pid of `process` still names it.
fn same_process(process: ProcessKey) -> Result<(), PlatformError> {
    if unique_info(process.pid())?.p_uniqueid == process.unique_id() {
        Ok(())
    } else {
        Err(process_error(libc::ESRCH))
    }
}

/// Adds the regular files `pid` has descriptors open for writing on.
fn open_for_writing(pid: i32, held: &mut BTreeSet<HeldFile>) -> Result<(), PlatformError> {
    for fd in descriptors(pid)? {
        if u32::try_from(libc::PROX_FDTYPE_VNODE).is_ok_and(|vnode| fd.proc_fdtype != vnode) {
            continue;
        }
        let size = c_int::try_from(size_of::<VnodeFdInfoWithPath>()).map_err(|_| process_error(libc::EINVAL))?;
        // SAFETY: `VnodeFdInfoWithPath` is plain integers and bytes, for which all-zero is a valid value.
        let mut info: VnodeFdInfoWithPath = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable buffer of exactly `size` bytes for the duration of the call.
        let written = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                std::ptr::from_mut(&mut info).cast::<c_void>(),
                size,
            )
        };
        if written != size {
            // Closed since it was listed (`EBADF`): it holds nothing now. A process that exited is caught by the
            // caller's identity check.
            continue;
        }
        if info.pfi.fi_openflags & FWRITE == 0 || info.pvip.vip_vi.vi_type != VREG {
            continue;
        }
        push(held, path_of(&info.pvip), HoldKind::OpenForWriting)?;
    }
    Ok(())
}

/// The descriptors of `pid`.
fn descriptors(pid: i32) -> Result<Vec<libc::proc_fdinfo>, PlatformError> {
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer of size 0 asks only for the size needed; nothing is written.
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(last_error());
    }
    let mut count = usize::try_from(needed).map_err(|_| process_error(libc::EOVERFLOW))? / entry + 64;
    loop {
        if count > MAX_DESCRIPTORS {
            return Err(process_error(libc::EOVERFLOW));
        }
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            count
        ];
        let bytes = c_int::try_from(count * entry).map_err(|_| process_error(libc::EOVERFLOW))?;
        // SAFETY: `fds` is a valid, writable buffer of exactly `bytes` bytes for the duration of the call, and any
        // integers the kernel writes form valid `proc_fdinfo` values.
        let written =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast::<c_void>(), bytes) };
        if written <= 0 {
            return Err(last_error());
        }
        let filled = usize::try_from(written).map_err(|_| process_error(libc::EOVERFLOW))? / entry;
        if filled < count {
            fds.truncate(filled);
            return Ok(fds);
        }
        // Full: descriptors were opened meanwhile, and some may be missing. Read again with more room.
        count *= 2;
    }
}

/// Adds the regular files `pid` has mapped shared and writable.
fn mapped_writable(pid: i32, held: &mut BTreeSet<HeldFile>) -> Result<(), PlatformError> {
    let size = c_int::try_from(size_of::<ProcRegionWithPathInfo>()).map_err(|_| process_error(libc::EINVAL))?;
    let mut address = 0u64;
    for _ in 0..MAX_REGIONS {
        // SAFETY: `ProcRegionWithPathInfo` is plain integers and bytes, for which all-zero is a valid value.
        let mut info: ProcRegionWithPathInfo = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable buffer of exactly `size` bytes for the duration of the call.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                address,
                std::ptr::from_mut(&mut info).cast::<c_void>(),
                size,
            )
        };
        if written != size {
            // `EINVAL` (observed on macOS 26.6): no region at or after `address`, the walk is done. Anything else
            // (`ESRCH` if the process exited, `EPERM`) is an error, never a silent end of the walk that would leave
            // a writable mapping unreported (FR-CKP-24, fail closed).
            if written <= 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(if written <= 0 {
                last_error()
            } else {
                process_error(libc::EIO)
            });
        }
        let region = &info.prp_prinfo;
        let writable = region.pri_protection & u32::try_from(libc::VM_PROT_WRITE).unwrap_or(2) != 0;
        let shared = region.pri_inheritance == VM_INHERIT_SHARE || SHARED_SHARE_MODES.contains(&region.pri_share_mode);
        if writable && shared && info.prp_vip.vip_vi.vi_type == VREG {
            push(held, path_of(&info.prp_vip), HoldKind::MappedWritable)?;
        }
        let next = region.pri_address.saturating_add(region.pri_size);
        if next <= address || region.pri_size == 0 {
            return Ok(());
        }
        address = next;
    }
    Err(process_error(libc::EOVERFLOW))
}

/// Adds `path` held `how`, unless it is empty (a file whose name the kernel no longer has).
fn push(held: &mut BTreeSet<HeldFile>, path: Option<PathBuf>, how: HoldKind) -> Result<(), PlatformError> {
    let Some(path) = path else {
        return Ok(());
    };
    held.insert(HeldFile { path, how });
    if held.len() > MAX_HELD_FILES {
        return Err(process_error(libc::EOVERFLOW));
    }
    Ok(())
}

/// The path in `info`, up to its terminating NUL; `None` if it is empty or not absolute.
fn path_of(info: &libc::vnode_info_path) -> Option<PathBuf> {
    let bytes: Vec<u8> = info
        .vip_path
        .iter()
        .flatten()
        .map(|c| c.cast_unsigned())
        .take_while(|b| *b != 0)
        .collect();
    (bytes.first() == Some(&b'/')).then(|| PathBuf::from(OsStr::from_bytes(&bytes)))
}

/// The unique-identifier record of `pid`.
fn unique_info(pid: i32) -> Result<UniqueIdentifierInfo, PlatformError> {
    let mut info = UniqueIdentifierInfo::default();
    read_pid_info(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &mut info)?;
    Ok(info)
}

/// Fills `out` with the `flavor` record of `pid`; a short answer is an error.
fn read_pid_info<T>(pid: i32, flavor: c_int, arg: u64, out: &mut T) -> Result<(), PlatformError> {
    let size = c_int::try_from(size_of::<T>()).map_err(|_| process_error(libc::EINVAL))?;
    // SAFETY: `out` is a valid, writable buffer of exactly `size` bytes for the duration of the call, and every `T`
    // passed here is a `repr(C)` struct of plain integers, so any bytes the kernel writes form a valid value.
    let written = unsafe { libc::proc_pidinfo(pid, flavor, arg, std::ptr::from_mut(out).cast::<c_void>(), size) };
    if written == size {
        return Ok(());
    }
    if written <= 0 {
        return Err(last_error());
    }
    Err(process_error(libc::EIO))
}

/// The last `errno` as a process-information failure; `ESRCH` when none is set (`proc_pidinfo` reports a missing
/// process with 0 and no errno on some releases).
fn last_error() -> PlatformError {
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(libc::ESRCH);
    process_error(if errno == 0 { libc::ESRCH } else { errno })
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
    use std::fs::OpenOptions;
    use std::process::{Command, Stdio};

    use super::*;

    fn own() -> ProcessKey {
        let pid = std::process::id().cast_signed();
        ProcessKey::new(pid, unique_info(pid).unwrap().p_uniqueid)
    }

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("knsh-holders-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        std::fs::write(&path, vec![0u8; 16_384]).unwrap();
        std::fs::canonicalize(&path).unwrap()
    }

    #[test]
    fn structs_match_the_kernel_layout() {
        assert_eq!(size_of::<ProcFileInfo>(), 24);
        assert_eq!(size_of::<VnodeFdInfoWithPath>(), 1200);
        assert_eq!(size_of::<ProcRegionInfo>(), 96);
        assert_eq!(size_of::<ProcRegionWithPathInfo>(), 1272);
    }

    // FR-CKP-24, decision 17: a descriptor open for writing is reported; one open read-only is not.
    #[test]
    fn open_for_writing_is_reported() {
        let written = temp_file("write");
        let read = temp_file("read");
        let _writer = OpenOptions::new().write(true).open(&written).unwrap();
        let _reader = OpenOptions::new().read(true).open(&read).unwrap();
        let held = SystemWriteHolders::new().held_for_writing(own()).unwrap();
        assert!(held.contains(&HeldFile {
            path: written.clone(),
            how: HoldKind::OpenForWriting
        }));
        assert!(!held.iter().any(|file| file.path == read));
    }

    // FR-CKP-24, decision 17: a shared writable mapping is reported after its descriptor is closed (a write through it
    // moves neither size, time nor events), before and after a store; a private one is not, before or after a store
    // (its pages are then copies), nor a read-only shared one.
    #[test]
    fn writable_shared_mapping_is_reported() {
        let shared = temp_file("shared");
        let private = temp_file("private");
        let read_only = temp_file("read-only");
        let map = |path: &PathBuf, write: bool, flags: c_int| {
            let file = OpenOptions::new().read(true).write(write).open(path).unwrap();
            let protection = if write {
                libc::PROT_READ | libc::PROT_WRITE
            } else {
                libc::PROT_READ
            };
            // SAFETY: a fresh mapping of a valid descriptor, at an address the kernel picks; unmapped below.
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    16_384,
                    protection,
                    flags,
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    0,
                )
            };
            assert_ne!(address, libc::MAP_FAILED);
            address
        };
        let maps = [
            map(&shared, true, libc::MAP_SHARED),
            map(&private, true, libc::MAP_PRIVATE),
            map(&read_only, false, libc::MAP_SHARED),
        ];
        let before = SystemWriteHolders::new().held_for_writing(own()).unwrap();
        for address in &maps[..2] {
            // SAFETY: the first two mappings are writable and 16 KiB long.
            unsafe { address.cast::<u8>().write_volatile(1) };
        }
        let after = SystemWriteHolders::new().held_for_writing(own()).unwrap();
        for address in maps {
            // SAFETY: each address is a 16 KiB mapping made above and not used after this.
            unsafe { libc::munmap(address, 16_384) };
        }
        for held in [before, after] {
            assert!(held.contains(&HeldFile {
                path: shared.clone(),
                how: HoldKind::MappedWritable
            }));
            assert!(!held.iter().any(|file| file.path == private));
            assert!(!held.iter().any(|file| file.path == read_only));
        }
    }

    #[test]
    fn process_table_lists_this_process_with_its_group() {
        let entries = SystemWriteHolders::new().processes().unwrap();
        let me = entries.iter().find(|entry| entry.key == own()).unwrap();
        // SAFETY: `getpgrp` has no preconditions and cannot fail.
        assert_eq!(me.group, unsafe { libc::getpgrp() });
        assert_ne!(me.parent_unique_id, 0);
    }

    // Decision 17: another process of the same user, without privileges, is read too.
    #[test]
    fn child_holding_a_file_is_reported() {
        let path = temp_file("child");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 3>>\"$0\"; echo ready; exec sleep 30")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut ready).unwrap();
        let pid = child.id().cast_signed();
        let key = ProcessKey::new(pid, unique_info(pid).unwrap().p_uniqueid);
        let held = SystemWriteHolders::new().held_for_writing(key);
        let _ = child.kill();
        let _ = child.wait();
        assert!(held.unwrap().contains(&HeldFile {
            path,
            how: HoldKind::OpenForWriting
        }));
    }

    // A reaped child's key is refused, never answered with another process's files.
    #[test]
    fn exited_process_is_refused() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id().cast_signed();
        let key = ProcessKey::new(pid, unique_info(pid).unwrap().p_uniqueid);
        child.kill().unwrap();
        child.wait().unwrap();
        let error = SystemWriteHolders::new().held_for_writing(key).unwrap_err();
        assert_eq!(error.errno(), Some(libc::ESRCH));
    }
}
