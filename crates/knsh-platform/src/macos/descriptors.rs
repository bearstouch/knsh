//! Passing descriptors over a Unix stream socket (`SCM_RIGHTS`), KNSH-049.
//!
//! `knsh -c` hands its stdin, stdout and stderr to the supervisor with the `exec.run` request that names the line,
//! so the line writes straight to the caller's terminal or pipes and its output never crosses the API
//! (`specs/06-api/wire-format.md`, FR-OUT-04). The descriptors ride on the first byte of the request's frame:
//! [`send_with_descriptors`] sends the whole frame with them, and the receiver reads every byte through
//! [`recv_with_descriptors`], which collects whatever descriptors arrive.
//!
//! The receiving side is untrusted input (any process inside an envelope can connect to `agent.sock`), so it is
//! bounded: one read accepts at most [`MAX_PASSED_DESCRIPTORS`], and a sender that passes more or anything other
//! than descriptors gets an error, which closes the connection. Descriptors that did arrive are closed then, never
//! leaked. The receive buffer is sized for the most descriptors the kernel lets one message carry, not for three:
//! when control data is truncated, macOS installs the descriptors that did not fit in the receiver anyway and
//! reports none of them (observed on macOS 26: of six sent into room for three, three stay open and unreachable), so
//! a small buffer would let any sender leak `knshd`'s descriptors until it can accept no more connections.
//!
//! Every received descriptor is marked close-on-exec before it is handed out. macOS has no `MSG_CMSG_CLOEXEC`, so
//! between `recvmsg` and that `fcntl` a process spawned by another thread of the same program could inherit it. In
//! `knshd` that window is a few instructions long and the only children are the engine's own (probes, `knsh-exec`),
//! so the leak would be of the agent's own stdio to an engine process; it is recorded as a known limit rather than
//! solved with a lock around every spawn.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Most descriptors one message may carry: a caller's stdin, stdout and stderr.
pub const MAX_PASSED_DESCRIPTORS: usize = 3;

/// Bytes of one descriptor in the control data.
const FD_LEN: usize = std::mem::size_of::<RawFd>();

/// Bytes of control data for [`MAX_PASSED_DESCRIPTORS`] descriptors in one `SCM_RIGHTS` message, header included.
// `MAX_PASSED_DESCRIPTORS * FD_LEN` is 12: the cast cannot truncate.
#[allow(clippy::cast_possible_truncation)]
// SAFETY: `CMSG_SPACE` is pure arithmetic on its argument; it is `unsafe` only because libc declares it so.
const CONTROL_LEN: usize = unsafe { libc::CMSG_SPACE((MAX_PASSED_DESCRIPTORS * FD_LEN) as libc::c_uint) } as usize;

/// Most descriptors a receive buffer has room for: well above what macOS lets one message carry (one `SCM_RIGHTS`
/// message of at most 254 descriptors, observed on macOS 26; `sendmsg` refuses more with `EINVAL`), so the kernel
/// never truncates what it delivers and every descriptor that arrives is seen, and closed if refused.
const RECV_DESCRIPTORS: usize = 1024;

/// Bytes of control data a receive offers: room for [`RECV_DESCRIPTORS`] descriptors.
// `RECV_DESCRIPTORS * FD_LEN` is 4096: the cast cannot truncate.
#[allow(clippy::cast_possible_truncation)]
// SAFETY: as for `CONTROL_LEN`.
const RECV_CONTROL_LEN: usize = unsafe { libc::CMSG_SPACE((RECV_DESCRIPTORS * FD_LEN) as libc::c_uint) } as usize;

/// A buffer of `N` bytes for control data, aligned for `cmsghdr` (whose fields are 32-bit on macOS).
#[repr(C, align(8))]
struct ControlBuffer<const N: usize>([u8; N]);

/// Sends all of `bytes` on `stream`, with `descriptors` attached to the first byte (`SCM_RIGHTS`). The kernel gives
/// the peer its own copies; the caller keeps its descriptors open.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for more than [`MAX_PASSED_DESCRIPTORS`] descriptors or empty `bytes` (a
/// descriptor needs a byte to ride on); otherwise the error of `sendmsg`, for example `EPIPE` when the peer has
/// closed. `EINTR` is retried.
pub fn send_with_descriptors(stream: &UnixStream, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<()> {
    if descriptors.len() > MAX_PASSED_DESCRIPTORS || bytes.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut control = ControlBuffer::<CONTROL_LEN>([0; CONTROL_LEN]);
    let mut sent = 0;
    while sent < bytes.len() {
        let rest = &bytes[sent..];
        let mut iov = libc::iovec {
            iov_base: rest.as_ptr().cast_mut().cast(),
            iov_len: rest.len(),
        };
        // SAFETY: an all-zero `msghdr` is valid (null pointers, zero lengths); every field used is set below.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &raw mut iov;
        header.msg_iovlen = 1;
        // Only the first `sendmsg` carries the descriptors; a partial send is finished without them, so they are
        // passed exactly once.
        if sent == 0 && !descriptors.is_empty() {
            let data_len = descriptors.len() * FD_LEN;
            // At most 12 bytes (checked above): no truncation.
            #[allow(clippy::cast_possible_truncation)]
            let data_len_c = data_len as libc::c_uint;
            // SAFETY: pure arithmetic, as for `CONTROL_LEN`.
            let space = unsafe { libc::CMSG_SPACE(data_len_c) } as usize;
            header.msg_control = control.0.as_mut_ptr().cast();
            header.msg_controllen = libc::socklen_t::try_from(space).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: `msg_control` points at `control`, which is aligned for `cmsghdr` and at least `space` bytes
            // long, so the first header lies inside it.
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const header) };
            if cmsg.is_null() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // SAFETY: `cmsg` points at the start of `control` (non-null, checked), aligned and large enough for a
            // `cmsghdr` followed by `data_len` bytes of data, since `space` = `CMSG_SPACE(data_len)` fits in it.
            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(data_len_c);
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for (i, descriptor) in descriptors.iter().enumerate() {
                    // The data area is not necessarily aligned for `RawFd`: written unaligned.
                    data.add(i).write_unaligned(descriptor.as_raw_fd());
                }
            }
        }
        // SAFETY: `header` points at `iov` (valid for `rest`) and, on the first send, at `control`; all outlive the
        // call. `sendmsg` only reads them.
        let rc = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const header, 0) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // `rc` is non-negative here and at most `rest.len()`.
        sent += usize::try_from(rc).map_err(|_| io::ErrorKind::InvalidData)?;
    }
    Ok(())
}

/// Reads up to `buf.len()` bytes from `stream` like [`io::Read::read`], and appends to `received` every descriptor
/// that arrived with them, each marked close-on-exec.
///
/// # Errors
///
/// - [`io::ErrorKind::InvalidData`] if more than [`MAX_PASSED_DESCRIPTORS`] descriptors arrived at once, the control
///   data was truncated, or it holds anything but descriptors. Every descriptor that arrived is closed.
/// - The error of `recvmsg` or `fcntl`. `EINTR` is retried.
pub fn recv_with_descriptors(stream: &UnixStream, buf: &mut [u8], received: &mut Vec<OwnedFd>) -> io::Result<usize> {
    loop {
        let mut control = ControlBuffer::<RECV_CONTROL_LEN>([0; RECV_CONTROL_LEN]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: an all-zero `msghdr` is valid (null pointers, zero lengths); every field used is set below.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &raw mut iov;
        header.msg_iovlen = 1;
        header.msg_control = control.0.as_mut_ptr().cast();
        header.msg_controllen = libc::socklen_t::try_from(RECV_CONTROL_LEN).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: `header` points at `iov` (valid and writable for `buf.len()` bytes) and at `control` (writable for
        // `RECV_CONTROL_LEN` bytes); both outlive the call.
        let rc = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut header, 0) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // Owned at once, so that every return below closes what it does not hand out.
        let arrived = take_descriptors(&header);
        let truncated = header.msg_flags & libc::MSG_CTRUNC != 0;
        let mut arrived = match arrived {
            Ok(arrived) if !truncated && arrived.len() <= MAX_PASSED_DESCRIPTORS => arrived,
            // Dropping `arrived` closes whatever did arrive.
            Ok(_) | Err(()) => return Err(io::ErrorKind::InvalidData.into()),
        };
        for descriptor in &arrived {
            set_cloexec(descriptor)?;
        }
        received.append(&mut arrived);
        // `rc` is non-negative here and at most `buf.len()`.
        return usize::try_from(rc).map_err(|_| io::ErrorKind::InvalidData.into());
    }
}

/// Whether the peer of `stream` has closed its end (FR-LC-41): the supervisor asks this while a line it received on
/// `stream` waits for its decision, and cancels the line when the answer is yes.
///
/// Looks at the next byte without taking it and without waiting (`recv` with `MSG_PEEK | MSG_DONTWAIT`): end of
/// stream or a connection error means closed; a byte waiting, or nothing yet, means the peer is still there. Nothing
/// is consumed and the socket's blocking mode is not changed, so the connection's reader is unaffected. A peer that
/// sent more bytes before closing reads as still there until those bytes are read; `knsh -c` sends one request and
/// waits, so its disconnect is always seen.
#[must_use]
pub fn peer_closed(stream: &UnixStream) -> bool {
    let mut byte = [0_u8; 1];
    loop {
        // SAFETY: `byte` is valid and writable for its one byte for the duration of the call; the descriptor is
        // borrowed from `stream`, which outlives the call.
        let rc = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if rc > 0 {
            return false;
        }
        if rc == 0 {
            return true;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => return false,
            // Reset, not connected, or anything else: the caller cannot receive an answer.
            _ => return true,
        }
    }
}

/// The descriptors in the control data `header` received, owned. `Err` (after closing every descriptor found) if
/// the control data holds a message other than `SCM_RIGHTS`.
fn take_descriptors(header: &libc::msghdr) -> Result<Vec<OwnedFd>, ()> {
    let mut found = Vec::new();
    let mut foreign = false;
    // SAFETY: `header` was filled by `recvmsg`: `msg_control` points at the caller's control buffer and
    // `msg_controllen` is the number of bytes the kernel wrote into it, so the first header (if any) lies inside it.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(header) };
    while !cmsg.is_null() {
        // SAFETY: `CMSG_FIRSTHDR` and `CMSG_NXTHDR` return only headers that lie entirely inside the control data.
        let (level, kind, len) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len as usize) };
        // SAFETY: as above; `CMSG_LEN(0)` is pure arithmetic.
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS && len >= header_len {
            // SAFETY: as above: the data area starts inside the control data.
            let data = unsafe { libc::CMSG_DATA(cmsg) }.cast::<RawFd>();
            // A truncated message keeps the length it was sent with, which can run past the buffer: only what lies
            // inside the control data the kernel wrote is read.
            let start = header.msg_control.cast::<u8>().cast_const();
            let offset = (data.cast::<u8>().cast_const() as usize).saturating_sub(start as usize);
            let inside = (header.msg_controllen as usize).saturating_sub(offset);
            let count = (len - header_len).min(inside) / FD_LEN;
            for i in 0..count {
                // SAFETY: `i < count`, inside the data the kernel wrote; read unaligned, as the data area may not be
                // aligned for `RawFd`.
                let raw = unsafe { data.add(i).read_unaligned() };
                if raw >= 0 {
                    // SAFETY: the kernel just installed `raw` in this process for us; nothing else owns it.
                    found.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        } else {
            foreign = true;
        }
        // SAFETY: `cmsg` is a header inside the control data (above).
        cmsg = unsafe { libc::CMSG_NXTHDR(header, cmsg) };
    }
    if foreign {
        // Dropping `found` closes every descriptor it holds.
        drop(found);
        return Err(());
    }
    Ok(found)
}

/// Marks `descriptor` close-on-exec.
fn set_cloexec(descriptor: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fcntl(F_GETFD)` and `fcntl(F_SETFD)` take an open descriptor (owned here) and plain integers.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    /// Reads exactly `len` bytes from `stream`, collecting descriptors.
    fn read_all(stream: &UnixStream, len: usize, received: &mut Vec<OwnedFd>) -> Vec<u8> {
        let mut out = vec![0; len];
        let mut filled = 0;
        while filled < len {
            let n = recv_with_descriptors(stream, &mut out[filled..], received).unwrap();
            assert_ne!(n, 0, "unexpected end of stream");
            filled += n;
        }
        out
    }

    fn cloexec(descriptor: &OwnedFd) -> bool {
        // SAFETY: test-only query of an owned, open descriptor.
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        flags >= 0 && flags & libc::FD_CLOEXEC != 0
    }

    // KNSH-049: three descriptors travel with the bytes, arrive as working copies of the sender's, close-on-exec.
    #[test]
    fn passes_three_descriptors_with_the_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut pipe_read, pipe_write) = std::io::pipe().unwrap();
        let (other, _keep) = UnixStream::pair().unwrap();
        let descriptors = [pipe_write.as_fd(), other.as_fd(), pipe_write.as_fd()];
        send_with_descriptors(&a, b"hello frame", &descriptors).unwrap();
        // The sender's copies stay open and usable.
        drop(pipe_write);
        let mut received = Vec::new();
        assert_eq!(read_all(&b, 11, &mut received), b"hello frame");
        assert_eq!(received.len(), 3);
        assert!(received.iter().all(cloexec));
        // The received stdout is the very pipe the sender passed.
        let mut stdout = std::fs::File::from(received.remove(0));
        stdout.write_all(b"HI").unwrap();
        drop(stdout);
        drop(received);
        let mut text = String::new();
        pipe_read.read_to_string(&mut text).unwrap();
        assert_eq!(text, "HI");
    }

    // Bytes without descriptors read as plain bytes.
    #[test]
    fn plain_bytes_carry_no_descriptors() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"abc").unwrap();
        let mut received = Vec::new();
        assert_eq!(read_all(&b, 3, &mut received), b"abc");
        assert!(received.is_empty());
    }

    // Bounds: more than three descriptors cannot be sent, and nothing rides on no bytes.
    #[test]
    fn refuses_too_many_descriptors_or_no_bytes() {
        let (a, _b) = UnixStream::pair().unwrap();
        let fd = a.as_fd();
        let error = send_with_descriptors(&a, b"x", &[fd, fd, fd, fd]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = send_with_descriptors(&a, b"", &[fd]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// How many descriptors this process has open.
    fn open_descriptors() -> usize {
        // `read_dir` holds one of its own while it lists, each time: counts compare.
        std::fs::read_dir("/dev/fd").unwrap().count()
    }

    // Untrusted sender: one that passes more descriptors than a read accepts (here the most one message may carry)
    // is refused, and none of them stays open in the receiver. Counted, because macOS installs the descriptors that
    // do not fit a short buffer without reporting them.
    #[test]
    fn too_many_descriptors_are_an_error_and_none_leak() {
        let (a, b) = UnixStream::pair().unwrap();
        // Sent by hand: `send_with_descriptors` itself refuses more than three.
        let fds: Vec<RawFd> = vec![a.as_raw_fd(); 254];
        let data_len = u32::try_from(fds.len() * FD_LEN).unwrap();
        // SAFETY: pure arithmetic.
        let space = unsafe { libc::CMSG_SPACE(data_len) } as usize;
        let mut control = vec![0u64; space.div_ceil(8)];
        let mut byte = *b"x";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // SAFETY: test-only `sendmsg` over buffers that outlive the call; the header is built inside `control`.
        unsafe {
            let mut header: libc::msghdr = std::mem::zeroed();
            header.msg_iov = &raw mut iov;
            header.msg_iovlen = 1;
            header.msg_control = control.as_mut_ptr().cast();
            header.msg_controllen = u32::try_from(space).unwrap();
            let cmsg = libc::CMSG_FIRSTHDR(&raw const header);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(data_len);
            let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
            for (i, fd) in fds.iter().enumerate() {
                data.add(i).write_unaligned(*fd);
            }
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &raw const header, 0), 1);
        }
        let mut received = Vec::new();
        let mut buf = [0; 1];
        let before = open_descriptors();
        let error = recv_with_descriptors(&b, &mut buf, &mut received).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(received.is_empty());
        // Other tests open descriptors concurrently, so the bound is loose; a leak here would be ~250.
        assert!(
            open_descriptors() < before + 64,
            "every descriptor that arrived was closed"
        );
    }

    // A long message is sent in full even when the socket takes it in parts; the descriptors arrive once.
    #[test]
    fn large_messages_are_sent_whole() {
        let (a, b) = UnixStream::pair().unwrap();
        let bytes = vec![7u8; 1 << 20];
        let reader = std::thread::spawn(move || {
            let mut received = Vec::new();
            let data = read_all(&b, 1 << 20, &mut received);
            (data, received.len())
        });
        send_with_descriptors(&a, &bytes, &[a.as_fd()]).unwrap();
        let (data, count) = reader.join().unwrap();
        assert_eq!(data, bytes);
        assert_eq!(count, 1);
    }

    // FR-LC-41: a peer that is waiting reads as present, whether or not bytes are queued, and nothing it sent is
    // consumed; once it closes (or shuts down its writing side, as a closed client does), it reads as closed.
    #[test]
    fn peer_closed_sees_a_disconnect_without_consuming_bytes() {
        let (mut client, server) = UnixStream::pair().unwrap();
        assert!(!super::peer_closed(&server), "connected and silent");
        client.write_all(b"x").unwrap();
        assert!(!super::peer_closed(&server), "a byte waiting");
        let mut byte = [0_u8; 1];
        (&server).read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x", "the peek took nothing");
        drop(client);
        assert!(super::peer_closed(&server));
    }
}
