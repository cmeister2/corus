//! IO abstraction for core-file output and `/proc` parsing.
//!
//! Faithful port of the IO helpers in `coredumper/elfcore.c`:
//!   - [`c_read`] / [`c_write`] - EINTR-looping syscall wrappers (no stdio).
//!   - [`Writer`] trait + [`SimpleWriter`] / [`LimitWriter`] - the
//!     function-pointer writer pattern (`SimpleWriter`/`LimitWriter`/`PipeDone`).
//!   - [`Io`] buffered reader + [`Io::get_char`] / [`Io::get_hex`] - the
//!     `struct io`/`GetChar`/`GetHex` machinery used to parse `/proc/self/maps`.
//!   - [`leading_zeros`] - the `LeadingZeros` page scan via a loopback pipe.
//!
//! Everything here is no-alloc: buffers live on the stack or are caller-provided.

use core::ffi::{c_int, c_void};

use corus_syscall::linux::{EAGAIN, EFAULT, EINTR, F_GETPIPE_SZ, F_SETPIPE_SZ, O_NONBLOCK};
use corus_syscall::sys;

/// Error returned by [`Writer::write_full`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    /// The writer returned a negative error marker.
    Failed,
    /// The writer reported an error or wrote fewer bytes than requested.
    ShortWrite {
        /// Number of bytes requested.
        requested: usize,
        /// Number of bytes the writer accepted.
        written: usize,
    },
}

/// Read buffer size for [`Io`].
const IO_BUF_SIZE: usize = 4096;

/// Staged segment output size, independent of the kernel pipe capacity.
pub(crate) const MEMORY_BUFFER_SIZE: usize = 64 * 1024;

/// Owned pipe file descriptors.
pub struct Pipe {
    /// Read end of the pipe.
    read_fd: c_int,
    /// Write end of the pipe.
    write_fd: c_int,
}

impl Pipe {
    /// Create a new pipe with `pipe2(2)`.
    ///
    /// # Errors
    /// Returns the kernel errno if pipe creation fails.
    pub fn new() -> Result<Self, i32> {
        let mut fds = [0i32; 2];
        unsafe { sys::pipe2(fds.as_mut_ptr(), 0) }?;
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Read end file descriptor.
    pub const fn read_fd(&self) -> c_int {
        self.read_fd
    }

    /// Write end file descriptor.
    pub const fn write_fd(&self) -> c_int {
        self.write_fd
    }

    /// Obtain the capacity used for safe synchronous memory probes.
    /// Growing the pipe is best-effort; an unprivileged limit keeps its current size.
    ///
    /// # Errors
    /// Returns the kernel errno if querying the pipe capacity fails.
    pub(crate) fn memory_capacity(&self) -> Result<usize, i32> {
        let capacity = unsafe { sys::fcntl(self.write_fd, F_GETPIPE_SZ, 0) }?;
        if capacity < MEMORY_BUFFER_SIZE {
            Ok(
                unsafe { sys::fcntl(self.write_fd, F_SETPIPE_SZ, MEMORY_BUFFER_SIZE) }
                    .unwrap_or(capacity),
            )
        } else {
            Ok(capacity)
        }
    }

    /// Transfer ownership of both file descriptors to the caller.
    pub fn into_fds(self) -> [c_int; 2] {
        let fds = [self.read_fd, self.write_fd];
        core::mem::forget(self);
        fds
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        sys::close(self.read_fd).ok();
        sys::close(self.write_fd).ok();
    }
}

/// `read(2)` that never returns `EINTR`. Returns bytes read (`0` at EOF) or
/// `Err(errno)`.
///
/// # Errors
/// Returns the kernel errno from `read(2)` after retrying `EINTR`.
///
/// # Safety
/// `buf`/`len` must describe a valid writable region.
pub unsafe fn c_read(fd: c_int, buf: *mut c_void, len: usize) -> Result<usize, i32> {
    if len == 0 {
        return Ok(0);
    }
    loop {
        match unsafe { sys::read(fd, buf, len) } {
            Err(EINTR) => continue,
            other => return other,
        }
    }
}

/// `write(2)` that never returns `EINTR` and never short-writes: it loops until
/// all `len` bytes are written, EOF (`rc == 0`), or error. Returns the number of
/// bytes actually written.
///
/// # Errors
/// Returns the kernel errno from `write(2)` after retrying `EINTR`.
///
/// # Safety
/// `buf`/`len` must describe a valid readable region.
pub unsafe fn c_write(fd: c_int, buf: *const c_void, len: usize) -> Result<usize, i32> {
    let mut remaining = len;
    let mut p = buf as *const u8;
    while remaining > 0 {
        match unsafe { sys::write(fd, p as *const c_void, remaining) } {
            Err(EINTR) => continue,
            Err(e) => return Err(e),
            Ok(0) => break,
            Ok(rc) => {
                // SAFETY: rc <= remaining bytes within the original buffer.
                p = unsafe { p.add(rc) };
                remaining -= rc;
            }
        }
    }
    Ok(len - remaining)
}

/// Output sink for the core file. Mirrors the C `writer`/`done` function-pointer
/// pair: `write` streams bytes, `done` reports whether the sink is exhausted
/// (e.g. a size limit was reached). A negative `write` return signals error.
pub trait Writer {
    /// Write `buf`; return bytes written (`>= 0`) or a negative error marker.
    fn write(&mut self, buf: &[u8]) -> isize;

    /// Write all of `buf`.
    ///
    /// # Errors
    /// Returns [`WriteError::Failed`] if the writer reports an error, or
    /// [`WriteError::ShortWrite`] if it writes fewer bytes than requested.
    fn write_full(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let written = self.write(buf);
        if written < 0 {
            return Err(WriteError::Failed);
        }
        let written = written as usize;
        if written == buf.len() {
            Ok(())
        } else {
            Err(WriteError::ShortWrite {
                requested: buf.len(),
                written,
            })
        }
    }

    /// Returns true when no more output should be produced (limit reached).
    fn done(&mut self) -> bool;
}

/// Synchronous writer to a single fd, with no size limit. Port of
/// `SimpleWriter`/`SimpleDone` (used when streaming to a pipe).
pub struct SimpleWriter {
    /// Destination file descriptor.
    pub fd: c_int,
}

impl Writer for SimpleWriter {
    fn write(&mut self, buf: &[u8]) -> isize {
        match unsafe { c_write(self.fd, buf.as_ptr() as *const c_void, buf.len()) } {
            Ok(n) => n as isize,
            Err(_) => -1,
        }
    }
    fn done(&mut self) -> bool {
        false
    }
}

/// Writer that honors a maximum output size, truncating the final write. Port of
/// `LimitWriter`/`PipeDone` operating on `WriterFds`.
pub struct LimitWriter {
    /// Destination file descriptor.
    pub fd: c_int,
    /// Remaining bytes allowed to be written.
    pub max_length: usize,
}

impl Writer for LimitWriter {
    fn write(&mut self, buf: &[u8]) -> isize {
        let mut bytes = buf.len();
        if bytes > self.max_length {
            bytes = self.max_length;
        }
        if bytes == 0 {
            return 0;
        }
        match unsafe { c_write(self.fd, buf.as_ptr() as *const c_void, bytes) } {
            Ok(n) => {
                self.max_length -= n;
                n as isize
            }
            Err(_) => -1,
        }
    }
    fn done(&mut self) -> bool {
        self.max_length == 0
    }
}

/// Buffered file reader - port of `struct io`. Reads in 4096-byte chunks via
/// [`c_read`]; supports single-character and hex-number extraction for parsing
/// `/proc/self/maps` without stdio.
pub struct Io {
    /// File descriptor being buffered.
    fd: c_int,
    /// Index of the next unread byte in `buf`.
    data: usize, // index into buf of next byte
    /// Index one past the last valid byte in `buf`.
    end: usize, // index one past last valid byte
    /// Fixed read buffer.
    buf: [u8; IO_BUF_SIZE],
}

impl Io {
    /// Wrap an open file descriptor.
    pub fn new(fd: c_int) -> Self {
        Io {
            fd,
            data: 0,
            end: 0,
            buf: [0u8; IO_BUF_SIZE],
        }
    }

    /// Read one byte, refilling the buffer as needed. Returns `None` at EOF or
    /// on error (matching `GetChar`'s `-1`).
    pub fn get_char(&mut self) -> Option<u8> {
        if self.data == self.end {
            let n = unsafe {
                c_read(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut c_void,
                    self.buf.len(),
                )
            };
            match n {
                Ok(0) | Err(_) => return None,
                Ok(n) => {
                    self.data = 0;
                    self.end = n;
                }
            }
        }
        let ch = self.buf[self.data];
        self.data += 1;
        Some(ch)
    }

    /// Parse a hexadecimal number starting at the next character. Returns
    /// `(value, terminator)` where `terminator` is the first non-hex byte read
    /// (or `None` at EOF). Port of `GetHex`.
    pub fn get_hex(&mut self) -> (usize, Option<u8>) {
        self.get_hex_helper(true, 0)
    }

    /// Like [`get_hex`](Self::get_hex) but the first character is supplied by the
    /// caller in `init_char` rather than read. Port of `GetHexWithInitChar`.
    pub fn get_hex_with_init_char(&mut self, init_char: u8) -> (usize, Option<u8>) {
        self.get_hex_helper(false, init_char)
    }

    /// Shared hexadecimal parser for `get_hex` and `get_hex_with_init_char`.
    fn get_hex_helper(&mut self, read_first: bool, init_char: u8) -> (usize, Option<u8>) {
        let mut hex: usize = 0;
        // First char: either the supplied init_char or freshly read; every
        // subsequent char is read (mirrors C's `read_first = true` after entry).
        let mut cur: Option<u8> = if read_first {
            self.get_char()
        } else {
            Some(init_char)
        };
        loop {
            let ch = match cur {
                Some(c) => c,
                None => return (hex, None),
            };
            let nibble = match ch {
                b'0'..=b'9' => (ch - b'0') as usize,
                b'A'..=b'F' => (ch - b'A') as usize + 10,
                b'a'..=b'f' => (ch - b'a') as usize + 10,
                _ => return (hex, Some(ch)),
            };
            hex = (hex << 4) | nibble;
            cur = self.get_char();
        }
    }
}

/// Copy process memory through a kernel pipe without directly dereferencing it.
/// Returns the number of readable bytes copied into `scratch`.
///
/// # Errors
/// Returns the syscall error if probing or draining the pipe fails.
///
/// # Safety
/// `mem` must describe a mapped address range of `scratch.len()` bytes;
/// individual pages may be unreadable. The range must remain mapped, but source
/// contents may change: only the kernel reads them, without a Rust reference.
/// Such changes give a best-effort observation. The pipe must be empty
/// with no other users, and `scratch.len()` must not exceed its capacity.
pub(crate) unsafe fn read_memory(
    loopback: &Pipe,
    mem: *const u8,
    scratch: &mut [u8],
) -> Result<usize, i32> {
    let wrote = loop {
        match unsafe { sys::write_memory_probe(loopback.write_fd(), mem.cast(), scratch.len()) } {
            Err(EINTR) => continue,
            Err(EFAULT) => {
                clear_probe_slots(loopback)?;
                return Err(EFAULT);
            }
            result => break result?,
        }
    };
    let mut read = 0;
    while read < wrote {
        let bytes = unsafe {
            c_read(
                loopback.read_fd(),
                scratch.as_mut_ptr().add(read).cast(),
                wrote - read,
            )
        }?;
        if bytes == 0 {
            break;
        }
        read += bytes;
    }
    if wrote < scratch.len() {
        clear_probe_slots(loopback)?;
    }
    Ok(read)
}

/// Release empty kernel pipe slots left behind by a faulted memory probe.
///
/// # Errors
/// Returns the kernel errno if draining or restoring descriptor flags fails.
fn clear_probe_slots(loopback: &Pipe) -> Result<(), i32> {
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    let flags = unsafe { sys::fcntl(loopback.read_fd(), F_GETFL, 0) }?;
    unsafe { sys::fcntl(loopback.read_fd(), F_SETFL, flags | O_NONBLOCK as usize) }?;
    let mut discarded = [0u8; 1];
    let drained = loop {
        match unsafe {
            c_read(
                loopback.read_fd(),
                discarded.as_mut_ptr().cast(),
                discarded.len(),
            )
        } {
            Ok(0) | Err(EAGAIN) => break Ok(()),
            Ok(_) => continue,
            Err(errno) => break Err(errno),
        }
    };
    unsafe { sys::fcntl(loopback.read_fd(), F_SETFL, flags) }?;
    drained
}

/// Counts leading zero bytes in `[mem, mem+len)`, rounded down to a page
/// boundary. Port of `LeadingZeros`.
///
/// Reads memory indirectly through a loopback pipe so that pages which are unreadable to the process
/// (e.g. exec-only under grsec) are treated as all-zero instead of faulting.
/// `scratch` must be at least `pagesize` bytes.
///
/// # Safety
/// `mem` must be a valid pointer to at least `len` bytes (in the address-space
/// sense; individual pages may be unreadable, which is the case this handles).
/// The range must remain mapped. Concurrent source changes are observed only
/// through kernel copies and give a best-effort result. `pagesize` must be a
/// nonzero power of two, `len` must be a multiple
/// of `pagesize`, and `scratch.len()` must be at least `pagesize`. The pipe must be empty,
/// exclusively used by this operation, have both ends open, and have capacity
/// for at least one page.
pub unsafe fn leading_zeros(
    loopback: &Pipe,
    mem: *const u8,
    len: usize,
    pagesize: usize,
    scratch: &mut [u8],
) -> usize {
    debug_assert!(scratch.len() >= pagesize);
    let mut count: usize = 0;
    let mut ptr: usize = 0; // index into scratch of next byte to inspect

    while count < len {
        if count.is_multiple_of(pagesize) {
            let read =
                unsafe { read_memory(loopback, mem.wrapping_add(count), &mut scratch[..pagesize]) };
            match read {
                Ok(bytes) if bytes == pagesize => {}
                Ok(_) | Err(EFAULT) => {
                    // Unreadable page: assume all zeros, skip it.
                    count += pagesize;
                    continue;
                }
                Err(_) => break,
            }
            ptr = 0;
        }
        if scratch[ptr] != 0 {
            break;
        }
        ptr += 1;
        count += 1;
    }
    count & !(pagesize - 1)
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn memory_capacity_matches_kernel_limit() {
        let pipe = Pipe::new().expect("pipe");
        unsafe { sys::fcntl(pipe.write_fd(), F_SETPIPE_SZ, 4096) }.expect("shrink pipe");
        let capacity = pipe.memory_capacity().expect("memory capacity");
        assert_eq!(
            unsafe { sys::fcntl(pipe.write_fd(), F_GETPIPE_SZ, 0) },
            Ok(capacity)
        );
        assert!(capacity > 0);
        let source = [0x5a; MEMORY_BUFFER_SIZE];
        let mut scratch = [0u8; MEMORY_BUFFER_SIZE];
        for bytes in source.chunks(capacity.min(MEMORY_BUFFER_SIZE)) {
            let read = unsafe { read_memory(&pipe, bytes.as_ptr(), &mut scratch[..bytes.len()]) };
            assert_eq!(read, Ok(bytes.len()));
            assert_eq!(&scratch[..bytes.len()], bytes);
        }
    }
}
